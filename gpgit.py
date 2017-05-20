#!/usr/bin/env python3

"""A Python script that automates the process of signing Git sources via GPG."""
from __future__ import print_function
import os
import sys
import argparse
import hashlib
import gzip
import lzma
import bz2
import signal
from contextlib import contextmanager
from github import Github, GithubException
import git
from git import Repo
import gnupg


class TimeoutException(Exception):
    """Timeout exception for time_limit function"""
    pass

@contextmanager
def time_limit(seconds):
    """Timeout helper function. Can be used as follows: with time_limit(seconds).
    Nested calls with multiple time_limits will not work!
    """
    def signal_handler(signum, frame):
        #pylint: disable=unused-argument
        raise TimeoutException
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

class Colors(object):
    RED = '\033[1;31m'
    BLUE = '\033[1;34m'
    CYAN = '\033[1;36m'
    MAGENTA = '\033[1;35m'
    YELLOW = '\033[1;33m'
    GREEN = '\033[1;32m'
    UNDERLINE = '\033[4m'
    BOLD = '\033[;1m'
    REVERSE = '\033[;7m'
    RESET = '\033[0;0m'

class Streamcmp(object):
    """Helper class to compare a stream without writing"""
    def __init__(self, strm):
        self.__strm = strm
        self.__equal = True
    def write(self, data):
        """Compare written data with input stream reading"""
        if data != self.__strm.read(len(data)):
            self.__equal = False
    def equal(self):
        """Check if both streams match completely."""
        if self.__strm.read(1) == b'' and self.__equal:
            return True

class Substep(object):
    """Contains name and execution functions of a Step"""
    def __init__(self, name, funct):
        # Params
        self.name = name
        self.funct = funct

        # Default values
        self.status = 'FAIL'
        self.msg = 'Internal error'
        self.infos = []

class Step(object):
    """Holds variable number of substeps. Step1-5 inherit from this class."""
    def __init__(self, name, *args):
        # Params
        self.name = name
        self.substeps = []
        for substep in args:
            self.substeps += [substep]

    @staticmethod
    def verbose(*args):
        """Verbose print used for substep execution"""
        print(Colors.BLUE + '::' + Colors.RESET, *args)

    def setstatus(self, subnumber, status, msg, *args):
        """Set variables of the substeps in a batch"""
        if subnumber > 0:
            self.substeps[subnumber - 1].status = status
            self.substeps[subnumber - 1].msg = msg
            self.substeps[subnumber - 1].infos = []
            for info in args:
                self.substeps[subnumber - 1].infos += [info]

class Step1(Step):
    """Generate a new GPG key"""
    # RFC4880 9.1. Public-Key Algorithms
    gpgAlgorithmIDs = {
        '1': 'RSA',
        '2': 'RSA Encrypt-Only',
        '3': 'RSA Sign-Only',
        '17': 'DSA',
        '18': 'Elliptic Curve',
        '19': 'ECDSA',
        '21': 'DH',
        }

    # TODO add elliptic curve support
    gpgSecureAlgorithmIDs = ['1', '3']
    gpgSecureKeyLength = ['2048', '4096']

    def __init__(self, config, gpg):
        # Params
        self.config = config
        self.gpg = gpg

        # Initialize parent
        Step.__init__(self, 'Generate a new GPG key',
                      Substep('Strong, unique, secret passphrase', self.substep1),
                      Substep('Key generation', self.substep2))

    def analyze(self):
        """Analyze: Generate a new GPG key"""
        # Get private keys
        private_keys = self.gpg.list_keys(True)
        for key in private_keys:
            # Check key algorithm gpgit support
            if key['algo'] not in self.gpgAlgorithmIDs:
                return 'Unknown key algorithm ID: ' + key['algo'] + ' Please report this error.'
            key['algoname'] = self.gpgAlgorithmIDs[key['algo']]

        # Check if a fingerprint was selected/found
        if self.config['fingerprint'] is None:
            # Check if GPG keys are available, but not yet configured
            if private_keys:
                print('\r\033[K', end='')
                print("GPG seems to be already configured on your system but Git is not.")
                print('Please select one of the existing keys below or generate a new one:')
                print()

                # Print option menu
                print('0: Generate a new RSA 4096 key')
                for i, key in enumerate(private_keys, start=1):
                    print(str(i) + ':', key['fingerprint'], key['uids'][0], key['algoname'],
                          key['length'])

                # User input
                try:
                    userinput = -1
                    while userinput < 0 or userinput > len(private_keys):
                        try:
                            userinput = int(input("Please select a key number from above: "))
                        except ValueError:
                            userinput = -1
                except KeyboardInterrupt:
                    print()
                    return 'Aborted by user'
                print()

                # Safe new fingerprint
                if userinput != 0:
                    self.config['fingerprint'] = private_keys[userinput - 1]['fingerprint']

        # Validate selected GPG key
        if self.config['fingerprint'] is not None:
            # Check if the full fingerprint is used
            if len(self.config['fingerprint']) != 40:
                return 'Please specify the full fingerprint. GPG ID: ' + self.config['fingerprint']

            # Find selected key
            gpgkey = None
            for key in private_keys:
                if key['fingerprint'] == self.config['fingerprint']:
                    gpgkey = key
                    break

            # Check if key is available in keyring
            if gpgkey is None:
                return 'Selected key not found in keyring. GPG ID: ' + self.config['fingerprint']

            # Check key algorithm security
            if gpgkey['algo'] not in self.gpgSecureAlgorithmIDs \
                    or gpgkey['length'] not in self.gpgSecureKeyLength:
                return 'Insecure key algorithm used: ' + gpgkey['algoname'] + ' ' \
                       + gpgkey['length'] + ' GPG ID: ' + self.config['fingerprint']

            # Check key algorithm security
            if gpgkey['trust'] == 'r':
                return 'Selected key is revoked. GPG ID: ' + self.config['fingerprint']

            # Use selected key
            self.setstatus(2, 'OK', 'Key already generated',
                           'GPG key: ' + gpgkey['uids'][0], 'GPG ID: [' + gpgkey['algoname'] + ' '
                           + gpgkey['length'] + '] ' + gpgkey['fingerprint'] + ' ')

            # Warn about strong passphrase
            self.setstatus(1, 'NOTE', 'Please use a strong, unique, secret passphrase')

        else:
            # Generate a new key
            self.setstatus(2, 'TODO', 'Generating an RSA 4096 GPG key for '
                           + self.config['username'] + ' ' + self.config['email']
                           + ' valid for 1 year.')

            # Warn about strong passphrase
            self.setstatus(1, 'TODO', 'Please use a strong, unique, secret passphrase')

    def substep1(self):
        """Strong, unique, secret passphrase"""
        self.verbose('More infos:',
                     'https://github.com/NicoHood/gpgit#11-strong-unique-secret-passphrase')

    def substep2(self):
        """Key generation"""
        # Generate RSA key command
        # https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
        input_data = """
        Key-Type: RSA
        Key-Length: 4096
        Key-Usage: cert sign auth
        Subkey-Type: RSA
        Subkey-Length: 4096
        Subkey-Usage: encrypt
        Name-Real: {0}
        Name-Email: {1}
        Expire-Date: 1y
        Preferences: SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
        %ask-passphrase
        %commit
        """.format(self.config['username'], self.config['email'])

        # Execute GPG key generation command
        self.verbose('We need to generate a lot of random bytes. It is a good idea to perform')
        self.verbose('some other action (type on the keyboard, move the mouse, utilize the')
        self.verbose('disks) during the prime generation; this gives the random number')
        self.verbose('generator a better chance to gain enough entropy.')
        self.config['fingerprint'] = str(self.gpg.gen_key(input_data))
        self.verbose('Key generation finished. You new fingerprint is: '
                     + self.config['fingerprint'])

class Step2(Step):
    """Publish your GPG key"""
    def __init__(self, config, gpg):
        # Params
        self.config = config
        self.gpg = gpg

        # Initialize parent
        Step.__init__(self, 'Publish your GPG key',
                      Substep('Send GPG key to a key server', self.substep1),
                      Substep('Publish full fingerprint', self.substep2),
                      Substep('Associate GPG key with Github', self.substep3))

    def analyze(self):
        """Analyze: Publish your GPG key"""
        # Add publish note
        if self.config['fingerprint'] is None:
            self.setstatus(2, 'TODO', 'Please publish the full GPG fingerprint on the project page')
        else:
            self.setstatus(2, 'NOTE', 'Please publish the full GPG fingerprint on the project page')

        # Check Github GPG key
        if self.config['github'] is True:
            # TODO Will associate your GPG key with Github
            self.setstatus(3, 'NOTE', 'Please associate your GPG key with Github')
        else:
            self.setstatus(3, 'OK', 'No Github repository used')

        # Only check if a fingerprint was specified
        if self.config['fingerprint'] is not None:
            # Check key on keyserver
            try:
                with time_limit(10):
                    key = self.gpg.recv_keys(self.config['keyserver'], self.config['fingerprint'])
            except TimeoutException:
                return 'Keyserver timed out. Please try again alter.'

            # Found key on keyserver
            if self.config['fingerprint'] in key.fingerprints:
                self.setstatus(1, 'OK', 'Key already published on ' + self.config['keyserver'])
                return

        # Upload key to keyserver
        self.setstatus(1, 'TODO', 'Publishing key on ' + self.config['keyserver'])

    def substep1(self):
        """Send GPG key to a key server"""
        self.verbose('Publishing key ' + self.config['fingerprint'])
        self.gpg.send_keys(self.config['keyserver'], self.config['fingerprint'])

    def substep2(self):
        """Publish your full fingerprint"""
        print('Your fingerprint is:', self.config['fingerprint'])

    def substep3(self):
        """Associate GPG key with Github"""
        #TODO
        pass

class Step3(Step):
    """Use Git with GPG"""
    def __init__(self, config, repo):
        # Params
        self.config = config
        self.repo = repo

        # Initialize parent
        Step.__init__(self, 'Use Git with GPG',
                      Substep('Configure Git GPG key', self.substep1),
                      Substep('Enable commit signing', self.substep2),
                      Substep('Create signed Git tag', self.substep3))

    def analyze(self):
        """Analyze: Use Git with GPG"""
        # Check if Git was already configured with the GPG key
        if self.config['signingkey'] != self.config['fingerprint'] \
                or self.config['fingerprint'] is None:
            # Check if Git was already configured with a different key
            if self.config['signingkey'] is None:
                self.config['config_level'] = 'global'

            self.setstatus(1, 'TODO', 'Configuring ' + self.config['config_level'] + 'Git GPG key')
        else:
            self.setstatus(1, 'OK', 'Git already configured with your GPG key')

        # Check commit signing
        if self.config['gpgsign'].lower() == 'true':
            self.setstatus(2, 'OK', 'Commit signing already enabled')
        else:
            self.setstatus(2, 'TODO', 'Enabling ' + self.config['config_level'] + ' commit signing')

        # Refresh tags
        try:
            self.repo.remotes.origin.fetch('--tags')
        except git.exc.GitCommandError:
            return 'Error fetching remote tags.'

        # Check if tag was already created
        tag = self.repo.tag('refs/tags/' + self.config['tag'])
        if tag in self.repo.tags:
            # Verify signature
            try:
                self.repo.create_tag(self.config['tag'], verify=True, ref=None)
            except git.exc.GitCommandError:
                if hasattr(tag.tag, 'message') \
                        and '-----BEGIN PGP SIGNATURE-----' in tag.tag.message:
                    return 'Invalid signature for tag ' + self.config['tag']
                self.setstatus(3, 'TODO', 'Signing existing tag: ' + self.config['tag'])
            else:
                self.setstatus(3, 'OK', 'Good signature for existing tag: ' + self.config['tag'])
        else:
            self.setstatus(3, 'TODO', 'Creating signed tag ' + self.config['tag']
                           + ' and pushing it to the remote Git')

    def substep1(self):
        """Configure Git GPG key"""
        # Configure Git signingkey settings
        with self.repo.config_writer(config_level=self.config['config_level']) as cfgwriter:
            cfgwriter.set("user", "signingkey", self.config['fingerprint'])

    def substep2(self):
        """Enable commit signing"""
        # Configure Git signingkey settings
        # TODO not working for repository (local) setting as config group does not yet exist
        # TODO also fix above?
        with self.repo.config_writer(config_level=self.config['config_level']) as cfgwriter:
            cfgwriter.set("commit", "gpgsign", True)

    def substep3(self):
        """Create signed Git tag"""
        self.verbose('Creating, signing and pushing tag ' + self.config['tag'])

        # Check if tag needs to be recreated
        force = False
        ref = 'HEAD'
        date = ''
        tag = self.repo.tag('refs/tags/' + self.config['tag'])
        if tag in self.repo.tags:
            force = True
            ref = self.config['tag']
            if hasattr(tag.tag, 'message'):
                self.config['message'] = tag.tag.message
            if hasattr(tag.tag, 'tagged_date'):
                date = str(tag.tag.tagged_date)

        # Create a signed tag
        newtag = None
        with self.repo.git.custom_environment(GIT_COMMITTER_DATE=date):
            try:
                newtag = self.repo.create_tag(
                    self.config['tag'],
                    ref=ref,
                    message=self.config['message'],
                    sign=True,
                    local_user=self.config['fingerprint'],
                    force=force)
            except git.exc.GitCommandError:
                return "Signing tag failed."

        # Push tag
        # TODO catch missing exception https://github.com/gitpython-developers/GitPython/issues/621
        self.repo.remotes.origin.push(newtag, force=force)

class Step4(Step):
    """Create a signed release archive"""
    compressionAlgorithms = {
        'gz': gzip,
        'gzip': gzip,
        'xz': lzma,
        'bz2': bz2,
        'bzip2': bz2,
    }

    def __init__(self, config, gpg, repo, assets):
        # Params
        self.config = config
        self.gpg = gpg
        self.repo = repo
        self.assets = assets

        # Expand hash info list
        self.hash = {}
        for sha in self.config['sha']:
            self.hash[sha] = {}

        # Initialize parent
        Step.__init__(self, 'Create a signed release archive',
                      Substep('Create compressed archive', self.substep1),
                      Substep('Sign the archive', self.substep2),
                      Substep('Create the message digest', self.substep3))

    def analyze(self):
        """Analyze: Create a signed release archive"""
        # Check all compression option tar files
        filename = self.config['project'] + '-' + self.config['tag']
        for tar in self.config['tar']:
            # Get tar filename
            tarfile = filename + '.tar.' + tar
            self.assets += [tarfile]
            tarfilepath = os.path.join(self.config['output'], tarfile)

            # Check if compressed tar files exist
            if os.path.isfile(tarfilepath):
                # Check if tag exists
                if self.repo.tag('refs/tags/' + self.config['tag']) not in self.repo.tags:
                    return 'Archive exists without corresponding tag: ' + tarfile

                # Verify existing archive
                try:
                    with self.compressionAlgorithms[tar].open(tarfilepath, "rb") as tarstream:
                        cmptar = Streamcmp(tarstream)
                        self.repo.archive(cmptar, treeish=self.config['tag'],
                                          prefix=filename + '/', format='tar')
                        if not cmptar.equal():
                            return 'Existing archive differs from local source:' + tarfilepath
                except lzma.LZMAError:
                    return 'Archive not in ' + tar + ' format: ' + tarfilepath

                # Successfully verified
                self.setstatus(1, 'OK', 'Existing archive(s) verified successfully',
                               'Path: ' + self.config['output'], 'Basename: ' + filename)
            else:
                self.setstatus(1, 'TODO', 'Creating new release archive(s): '
                               + ', '.join(str(x) for x in self.config['tar']),
                               'Path: ' + self.config['output'], 'Basename: ' + filename)

            # Get signature filename from setting
            if self.config['no_armor']:
                sigfile = tarfile + '.sig'
            else:
                sigfile = tarfile + '.asc'
            self.assets += [sigfile]
            sigfilepath = os.path.join(self.config['output'], sigfile)

            # Check if signature is existant
            if os.path.isfile(sigfilepath):
                # Check if signature for tar exists
                if not os.path.isfile(tarfilepath):
                    return 'Signature found without corresponding archive: ' + sigfilepath

                # Verify signature
                with open(sigfilepath, "rb") as sig:
                    verified = self.gpg.verify_file(sig, tarfilepath)
                    # Check trust level and fingerprint match
                    if verified.trust_level is None \
                            or verified.trust_level < verified.TRUST_FULLY \
                            or verified.fingerprint != self.config['fingerprint']:
                        if verified.trust_text is None:
                            verified.trust_text = 'Invalid signature'
                        return 'Signature verification failed: ' + sigfilepath \
                               + ' Trust level: ' + verified.trust_text

                # Successfully verified
                self.setstatus(2, 'OK', 'Existing signature(s) verified successfully')
            else:
                self.setstatus(2, 'TODO', 'Creating GPG signature(s) for archive(s)')

            # Verify all selected shasums if existant
            for sha in self.config['sha']:
                shafile = tarfile + '.' + sha
                self.assets += [shafile]
                shafilepath = os.path.join(self.config['output'], shafile)

                # Calculate hash of tarfile
                if os.path.isfile(tarfilepath):
                    hash_sha = hashlib.new(sha)
                    with open(tarfilepath, "rb") as filestream:
                        for chunk in iter(lambda: filestream.read(4096), b""):
                            hash_sha.update(chunk)
                    self.hash[sha][tarfile] = hash_sha.hexdigest()

                # Check if hash already exists
                if os.path.isfile(shafilepath):
                    # Check if tar for hash exists
                    if not os.path.isfile(tarfilepath):
                        return 'Message digest found without corresponding archive: ' + shafilepath

                    # Read hash and filename
                    with open(shafilepath, "r") as filestream:
                        hashinfo = filestream.readline().split()

                    # Verify hash
                    if len(hashinfo) != 2 \
                            or self.hash[sha][tarfile] != hashinfo[0] \
                            or os.path.basename(hashinfo[1]) != tarfile:
                        return 'Message digest verification failed: ' + shafilepath

                    # Successfully verified
                    self.setstatus(3, 'OK', 'Existing message digest(s) verified successfully')
                else:
                    self.setstatus(3, 'TODO', 'Creating message digest(s) for archive(s): '
                                   + ', '.join(str(x) for x in self.config['sha']))

    def substep1(self):
        """Create compressed archive"""
        # Check all compression option tar files
        filename = self.config['project'] + '-' + self.config['tag']
        for tar in self.config['tar']:
            # Get tar filename
            tarfile = filename + '.tar.' + tar
            tarfilepath = os.path.join(self.config['output'], tarfile)

            # Create compressed tar files if it does not exist
            if not os.path.isfile(tarfilepath):
                self.verbose('Creating ' + tarfilepath)
                with self.compressionAlgorithms[tar].open(tarfilepath, 'wb') as tarstream:
                    self.repo.archive(tarstream, treeish=self.config['tag'], prefix=filename + '/',
                                      format='tar')

    def substep2(self):
        """Sign the archive"""
        # Check all compression option tar files
        filename = self.config['project'] + '-' + self.config['tag']
        for tar in self.config['tar']:
            # Get tar filename
            tarfile = filename + '.tar.' + tar
            tarfilepath = os.path.join(self.config['output'], tarfile)

            # Get signature filename from setting
            if self.config['no_armor']:
                sigfilepath = tarfilepath + '.sig'
            else:
                sigfilepath = tarfilepath + '.asc'

            # Check if signature is existant
            if not os.path.isfile(sigfilepath):
                # Sign tar file
                with open(tarfilepath, 'rb') as tarstream:
                    self.verbose('Creating ' + sigfilepath)
                    signed_data = self.gpg.sign_file(
                        tarstream,
                        keyid=self.config['fingerprint'],
                        binary=bool(self.config['no_armor']),
                        detach=True,
                        output=sigfilepath,
                        #digest_algo='SHA512' #TODO v 2.x GPG module
                        )
                    if signed_data.fingerprint != self.config['fingerprint']:
                        return 'Signing data failed'
                    # TODO https://tools.ietf.org/html/rfc4880#section-9.4
                    #print(signed_data.hash_algo) -> 8 -> SHA256

    def substep3(self):
        """Create the message digest"""
        # Check all compression option tar files
        filename = self.config['project'] + '-' + self.config['tag']
        for tar in self.config['tar']:
            # Get tar filename
            tarfile = filename + '.tar.' + tar
            tarfilepath = os.path.join(self.config['output'], tarfile)

            # Verify all selected shasums if existant
            for sha in self.config['sha']:
                # Check if hash already exists
                shafilepath = tarfilepath + '.' + sha
                if not os.path.isfile(shafilepath):

                    # Calculate hash of tarfile
                    if tarfile not in self.hash[sha]:
                        hash_sha = hashlib.new(sha)
                        with open(tarfilepath, "rb") as filestream:
                            for chunk in iter(lambda: filestream.read(4096), b""):
                                hash_sha.update(chunk)
                        self.hash[sha][tarfile] = hash_sha.hexdigest()

                    # Write cached hash and filename
                    self.verbose('Creating ' + shafilepath)
                    with open(shafilepath, "w") as filestream:
                        filestream.write(self.hash[sha][tarfile] + '  ' + tarfile)

class Step5(Step):
    def __init__(self, config, assets):
        # Params
        self.config = config
        self.assets = assets
        self.newassets = []

        # Github API
        self.github = None
        self.githubuser = None
        self.githubrepo = None
        self.release = None

        # Initialize parent
        Step.__init__(self, 'Upload the release',
                      Substep('Configure HTTPS download server', self.substep1),
                      Substep('Upload to Github', self.substep2))

    def analyze(self):
        """Analyze: Upload the release"""
        # Check Github GPG key
        if self.config['github'] is True:
            self.setstatus(1, 'OK', 'Github uses well configured https')

            # Ask for Github token
            if self.config['token'] is None:
                try:
                    self.config['token'] = input('Enter Github token to access release API: ')
                except KeyboardInterrupt:
                    return 'Aborted by user'

            # Create Github API instance
            self.github = Github(self.config['token'])

            # Acces Github API
            try:
                self.githubuser = self.github.get_user()
                self.githubrepo = self.githubuser.get_repo(self.config['project'])
            except GithubException:
                # TODO improve exception:
                #https://github.com/PyGithub/PyGithub/issues/152#issuecomment-301249927
                return 'Error accessing Github API for project ' + self.config['project']

            # Check Release and its assets
            try:
                self.release = self.githubrepo.get_release(self.config['tag'])
            except GithubException:
                # TODO improve:
                #https://github.com/PyGithub/PyGithub/issues/152#issuecomment-301249927
                self.newassets = self.assets
                self.setstatus(2, 'TODO', 'Creating release and uploading release files to Github')
                return
            else:
                # Determine which assets need to be uploaded
                asset_list = [x.name for x in self.release.get_assets()]
                for asset in self.assets:
                    if asset not in asset_list:
                        self.newassets += [asset]

            # Check if assets already uploaded
            if self.newassets:
                self.setstatus(2, 'TODO', 'Uploading the release files to Github')
            else:
                self.setstatus(2, 'OK', 'Release already published on Github')

        else:
            self.setstatus(2, 'NOTE', 'Please upload the release files manually')
            self.setstatus(1, 'NOTE', 'Please configure HTTPS for your download server')

    def substep1(self):
        """Configure HTTPS download server"""
        pass

    def substep2(self):
        """Upload to Github"""
        # Create release if not existant
        if self.release is None:
            self.release = self.githubrepo.create_git_release(
                self.config['tag'],
                self.config['project'] + ' ' + self.config['tag'],
                self.config['message'],
                draft=False, prerelease=self.config['prerelease'])

        # Upload assets
        for asset in self.newassets:
            assetpath = os.path.join(self.config['output'], asset)
            self.verbose('Uploading ' + assetpath)
            # TODO not functional
            # see https://github.com/PyGithub/PyGithub/pull/525#issuecomment-301132357
            self.release.upload_asset(assetpath)

class GPGit(object):
    """Class that manages GPGit steps and substeps analysis, print and execution."""
    version = '2.0.0'

    colormap = {
        'OK': Colors.GREEN,
        'INFO': Colors.YELLOW,
        'WARN': Colors.RED,
        'FAIL': Colors.RED,
        'TODO': Colors.MAGENTA,
        'NOTE': Colors.BLUE,
        }

    def __init__(self, config):
        # Config via parameters
        self.config = config
        self.assets = []

        # GPG
        self.gpg = gnupg.GPG()

        # Git
        self.repo = None

        # Create Git repository instance
        try:
            self.repo = Repo(self.config['git_dir'], search_parent_directories=True)
        except git.exc.InvalidGitRepositoryError:
            self.error('Not inside a Git directory: ' + self.config['git_dir'])
        reader = self.repo.config_reader()

        gitconfig = [
            ['username', 'user', 'name'],
            ['email', 'user', 'email'],
            ['signingkey', 'user', 'signingkey'],
            ['gpgsign', 'commit', 'gpgsign'],
            ['output', 'user', 'gpgitoutput'],
            ['token', 'user', 'githubtoken']
        ]

        # Read in Git config values
        for cfg in gitconfig:
            # Create not existing keys
            if cfg[0] not in self.config:
                self.config[cfg[0]] = None

            # Check if gitconfig provides a setting
            if self.config[cfg[0]] is None and reader.has_option(cfg[1], cfg[2]):
                self.config[cfg[0]] = str(reader.get_value(cfg[1], cfg[2]))

        # Get default Git signing key
        if self.config['fingerprint'] is None and self.config['signingkey']:
            self.config['fingerprint'] = self.config['signingkey']

        # Check if Github URL is used
        if self.config['github'] is True:
            if 'github' not in self.repo.remotes.origin.url.lower():
                self.config['github'] = False

        # Default message
        if self.config['message'] is None:
            self.config['message'] = 'Release ' + self.config['tag'] + '\n\nCreated with GPGit ' \
                                     + self.version + '\nhttps://github.com/NicoHood/gpgit'

        # Default output path
        if self.config['output'] is None:
            self.config['output'] = os.path.join(self.repo.working_tree_dir, 'archive')

        # Check if path exists
        if not os.path.isdir(self.config['output']):
            # Create not existing path
            print('Not a valid path: ' + self.config['output'])
            try:
                ret = input('Create non-existing output path? [Y/n]')
            except KeyboardInterrupt:
                print()
                self.error('Aborted by user')
            if ret == 'y' or ret == '':
                os.makedirs(self.config['output'])
            else:
                self.error('Aborted by user')

        # Set default project name
        if self.config['project'] is None:
            url = self.repo.remotes.origin.url
            self.config['project'] = os.path.basename(url).replace('.git', '')

        # Default config level (repository == local)
        self.config['config_level'] = 'repository'

        # Create array fo steps to analyse and run
        step1 = Step1(self.config, self.gpg)
        step2 = Step2(self.config, self.gpg)
        step3 = Step3(self.config, self.repo)
        step4 = Step4(self.config, self.gpg, self.repo, self.assets)
        step5 = Step5(self.config, self.assets)
        self.steps = [step1, step2, step3, step4, step5]

    def analyze(self):
        """Analze all steps and substeps for later preview printing"""
        for i, step in enumerate(self.steps, start=1):
            print('Analyzing step', i, 'of', len(self.steps), end='...', flush=True)
            err_msg = step.analyze()
            if err_msg:
                return err_msg
            print('\r\033[K', end='')

    def printstatus(self):
        """Print preview list with step and substeps."""
        todo = False
        error = False
        for i, step in enumerate(self.steps, start=1):
            # Sample: "1. Generate a new GPG key"
            print(Colors.BOLD + str(i) + '.', step.name + Colors.RESET)
            for j, substep in enumerate(step.substeps, start=1):
                # Sample: "1.2 [ OK ] Key already generated"
                print(Colors.BOLD + '  ' + str(i) + '.' + str(j), self.colormap[substep.status]
                      + '[' + substep.status.center(4) + ']' + Colors.RESET, substep.msg)

                # Sample: " -> [INFO] GPG key: [rsa4096] 97312D5EB9D7AE7D0BD4307351DAE9B7C1AE9161"
                for info in substep.infos:
                    print(Colors.BOLD + '   -> ' + Colors.YELLOW + '[INFO]' + Colors.RESET, info)

                # Check for error or todos
                if substep.status == 'FAIL':
                    error = True
                elif substep.status == 'TODO':
                    todo = True

        # Return error or todo status
        if error:
            return -1
        if todo:
            return 1

    def run(self):
        """Execute all steps + substeps."""
        for i, step in enumerate(self.steps, start=1):
            # Run all substeps if enabled
            # Sample: "==> 2. Publish your key"
            print(Colors.GREEN + '==>', Colors.BOLD + str(i) + '.', step.name + Colors.RESET)
            for j, substep in enumerate(step.substeps, start=1):
                # Run selected step function if activated
                if substep.status == 'TODO':
                    # Sample: "  -> Will associate your GPG key with Github"
                    print(Colors.BLUE + '  ->', Colors.BOLD + str(i) +'.' + str(j),
                          substep.name + Colors.RESET)
                    err_msg = substep.funct()
                    if err_msg:
                        return err_msg

    @staticmethod
    def error(*args):
        """Print error and exit program. An optional integer param specifies the exit code."""
        status = 1
        for msg in args:
            if isinstance(msg, int):
                status = msg
            else:
                print(Colors.RED + '==> Error:' + Colors.RESET, msg)
        sys.exit(status)

def main():
    """Main entry point that parses configs and creates GPGit instance."""
    parser = argparse.ArgumentParser(description='A Python script that automates the process of ' \
                                     + 'signing Git sources via GPG.')
    parser.add_argument('tag', action='store', help='Tagname')
    parser.add_argument('-v', '--version', action='version', version='GPGit ' + GPGit.version)
    parser.add_argument('-m', '--message', action='store', help='tag message')
    parser.add_argument('-o', '--output', action='store',
                        help='output path of the archive, signature and message digest')
    parser.add_argument('-g', '--git-dir', action='store', default=os.getcwd(),
                        help='path of the Git project')
    parser.add_argument('-f', '--fingerprint', action='store',
                        help='(full) GPG fingerprint to use for signing/verifying')
    parser.add_argument('-p', '--project', action='store',
                        help='name of the project, used for archive generation')
    parser.add_argument('-e', '--email', action='store', help='email used for GPG key generation')
    parser.add_argument('-u', '--username', action='store',
                        help='username used for GPG key generation')
    parser.add_argument('-k', '--keyserver', action='store', default='hkps://pgp.mit.edu',
                        help='keyserver to use for up/downloading GPG keys')
    parser.add_argument('-n', '--no-github', action='store_false', dest='github',
                        help='disable Github API functionallity')
    parser.add_argument('-a', '--prerelease', action='store_true', help='Flag as Github prerelease')
    parser.add_argument('-t', '--tar', choices=['gz', 'gzip', 'xz', 'bz2', 'bzip2'], default=['xz'],
                        nargs='+', help='compression option')
    parser.add_argument('-s', '--sha', choices=['sha256', 'sha384', 'sha512'], default=['sha512'],
                        nargs='+', help='message digest option')
    parser.add_argument('-b', '--no-armor', action='store_true',
                        help='do not create ascii armored signature output')

    args = parser.parse_args()

    gpgit = GPGit(vars(args))
    err_msg = gpgit.analyze()
    if err_msg:
        print()
        gpgit.error(err_msg)

    ret = gpgit.printstatus()
    print()

    # Check if even something needs to be done
    if ret > 0:
        # User selection
        try:
            ret = input('Continue with the selected operations? [Y/n]')
        except KeyboardInterrupt:
            print()
            gpgit.error('Aborted by user')
        if ret == 'y' or ret == '':
            print()
            err_msg = gpgit.run()
            if err_msg:
                gpgit.error(err_msg)
            else:
                print('Finished without errors')
        else:
            gpgit.error('Aborted by user')
    elif ret < 0:
        gpgit.error('Exiting due to previous errors')
    else:
        print(Colors.GREEN + '==>', Colors.RESET, 'Everything looks okay. Nothing to do.')

if __name__ == '__main__':
    sys.exit(main())
