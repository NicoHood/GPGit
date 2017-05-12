#!/usr/bin/env python3

from __future__ import print_function
import os
import sys
import argparse
import tempfile
import filecmp
import hashlib
import gzip
import lzma
import bz2
from github import Github
import git
from git import Repo
import gnupg


# TODO: check == True to is True
# TODO proper document functions with """ to generate __docnames___
# TODO pylint analysis
# TODO add zip and lz support, make xz default
# TODO swap step 4.2 and 4.3
# TODO remove returns after self.error as it already exits
# TODO document compression level default: gzip/bz2 max and lzma/xz 6. see note about level 6 https://docs.python.org/3/library/lzma.html
# TODO replace armorfrom true/false to .sig/.asc?

class colors(object):
    RED   = "\033[1;31m"
    BLUE  = "\033[1;34m"
    CYAN  = "\033[1;36m"
    MAGENTA = "\033[1;35m"
    YELLOW = "\033[1;33m"
    GREEN = "\033[1;32m"
    UNDERLINE = '\033[4m'
    BOLD    = "\033[;1m"
    REVERSE = "\033[;7m"
    RESET = "\033[0;0m"

class Substep(object):
    color = {
        'OK': colors.GREEN,
        'FAIL': colors.RED,
        'INFO': colors.YELLOW,
        'WARN': colors.YELLOW,
        'TODO': colors.MAGENTA,
        'NOTE': colors.BLUE,
        }

    def __init__(self, number, name, funct):
        # Params
        self.number = number
        self.name = name
        self.funct = funct

        # Default values
        self.status = 'FAIL'
        self.msg = 'Aborting due to previous errors'
        self.infos = []

    def setstatus(self, status, msg, infos):
        self.status = status
        self.msg = msg
        self.infos = infos

    def printstatus(self):
        # Check if status is known
        if self.status not in self.color:
            raise SystemError('Internal error. Please report this issue.')

        # Sample: "1.2 [ OK ] Key already generated"
        print(colors.BOLD + '  ' + self.number, self.color[self.status] + '[' + self.status.center(4) + ']' + colors.RESET, self.msg)

        # Sample: " -> [INFO] GPG key: [rsa4096] 97312D5EB9D7AE7D0BD4307351DAE9B7C1AE9161"
        for info in self.infos:
            print(colors.BOLD + '   -> ' + self.color['INFO'] + '[INFO]' + colors.RESET, info)

        # Check for error
        if self.status == 'FAIL':
            return True

    def run(self):
        # Run selected step function if activated
        if self.status == 'TODO':
            # Sample: "  -> Will associate your GPG key with Github"
            print(colors.BLUE + "  ->", colors.BOLD + self.msg + colors.RESET)
            return self.funct()

class Step(object):
    def __init__(self, number, name, substeps):
        # Params
        self.number = number
        self.name = name
        self.substeps = substeps

    def printstatus(self):
        # Sample: "1. Generate a new GPG key"
        print(colors.BOLD + self.number, self.name + colors.RESET)
        err = False
        for substep in self.substeps:
            if substep.printstatus():
                err = True
        return err

    def run(self):
        # Run all substeps if enabled
        # Sample: "==> 2. Publish your key"
        print(colors.GREEN + "==>", colors.BOLD + self.number, self.name + colors.RESET)
        for substep in self.substeps:
            if substep.run():
                return True

# Helper class to compare a stream without writing
class strmcmp(object):
    def __init__(self, strmcmp):
        self.strmcmp = strmcmp
        self.__equal = True
    def write(self, data):
        if data != self.strmcmp.read(len(data)):
            self.__equal = False
    def equal(self):
        # Check end of file too
        if self.strmcmp.read(1) == b'' and self.__equal:
            return True

class GPGit(object):
    # RFC4880 9.1.  Public-Key Algorithms
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
    gpgSecureAlgorithmIDs = [ '1', '3' ]
    gpgSecureKeyLength = [ '2048', '4096' ]

    compressionAlgorithms = {
        'gz': gzip,
        'gzip': gzip,
        'xz': lzma,
        'bz2': bz2,
        'bzip2': bz2,
    }

    def __init__(self, config):
        self.Steps = [
            Step('1.', 'Generate a new GPG key', [
                Substep('1.1', 'Strong, unique, secret passphrase', self.step_1_1),
                Substep('1.2', 'Key generation', self.step_1_2),
                ]),
            Step('2.', 'Publish your key', [
                Substep('2.1', 'Submit your key to a key server', self.step_2_1),
                Substep('2.2', 'Associate GPG key with Github', self.step_2_2),
                Substep('2.3', 'Publish your full fingerprint', self.step_2_3),
                ]),
            Step('3.', 'Usage of GPG by git', [
                Substep('3.1', 'Configure git GPG key', self.step_3_1),
                Substep('3.2', 'Commit signing', self.step_3_2),
                Substep('3.3', 'Create signed git tag', self.step_3_3),
                ]),
            Step('4.', 'Creation of a signed compressed release archive', [
                Substep('4.1', 'Create compressed archive', self.step_4_1),
                Substep('4.2', 'Sign the sources', self.step_4_2),
                Substep('4.3', 'Create the message digest', self.step_4_3),
                ]),
            Step('5.', 'Upload the release', [
                Substep('5.1', 'Github', self.step_5_1),
                Substep('5.2', 'Configure HTTPS for your download server', self.step_5_2),
                ])
            ]

        self.config = config
        #self.config['signingkey'] = None
        # self.config['gpgsign'] = None

        # Github API
        self.github = None
        self.githubuser = None
        self.githubrepo = None
        self.release = None
        self.assets = []
        self.newassets = []
        self.todo = False

        # GPG
        self.gpg = gnupg.GPG()
        self.gpgkey = None

        # Git
        self.repo = None

        # Expand hash info list
        self.hash = {}
        for sha in self.config['sha']:
            self.hash[sha] = {}

    def load_defaults(self):
        # Create git repository instance
        try:
            self.repo = Repo(self.config['git_dir'], search_parent_directories=True)
        except git.exc.InvalidGitRepositoryError:
            self.error('Not inside a git directory: ' + self.config['git_dir'])
        reader = self.repo.config_reader()

        gitconfig = [
            ['username', 'user', 'name'],
            ['email', 'user', 'email'],
            ['signingkey', 'user', 'signingkey'],
            ['gpgsign', 'commit', 'gpgsign'],
            ['output', 'user', 'gpgitoutput'],
            ['token', 'user', 'githubtoken']
        ]

        # Read in git config values
        for config in gitconfig:
            # Create not existing keys
            if config[0] not in self.config:
                self.config[config[0]] = None

            # Check if gitconfig provides a setting
            if self.config[config[0]] is None and reader.has_option(config[1], config[2]):
                val = reader.get_value(config[1], config[2])
                if type(val) == int:
                    val = str(val)
                self.config[config[0]] = val

        # Get default git signing key
        if self.config['fingerprint'] is None and self.config['signingkey']:
            self.config['fingerprint'] = self.config['signingkey']

        # Check if Github URL is used
        if self.config['github'] is True:
            if 'github' not in self.repo.remotes.origin.url.lower():
                self.config['github'] = False

        # Default message
        if self.config['message'] is None:
            self.config['message'] = 'Release ' + self.config['tag'] + '\n\nCreated with GPGit\nhttps://github.com/NicoHood/gpgit'

        # Default output path
        if self.config['output'] is None:
            self.config['output'] = os.path.join(self.repo.working_tree_dir, 'archive')

        # Check if path exists
        if not os.path.isdir(self.config['output']):
            self.error('Not a valid path: ' + self.config['output'])

        # Set default project name
        if self.config['project'] is None:
            self.config['project'] = os.path.basename(self.repo.remotes.origin.url).replace('.git','')

        # Default config level (repository == local)
        self.config['config_level'] = 'repository'

    def set_substep_status(self, number, status, msg, infos=[]):
        # Flag execution of minimum one step
        if status == 'TODO':
            self.todo = True

        # Search for substep by number and add new data
        for step in self.Steps:
            for substep in step.substeps:
                if substep.number == number:
                    # Only overwrite if entry is relevant
                    if substep.status != 'TODO' or status == 'FAIL':
                        substep.setstatus(status, msg, infos)
                    return
        raise SystemError('Internal error. Please report this issue.')

    def analyze(self):
        # Checks to execute
        checks = [
            ['Analyzing gpg key', self.analyze_step_1],
            ['Receiving key from keyserver', self.analyze_step_2],
            ['Analyzing git settings', self.analyze_step_3],
            ['Analyzing existing archives/signatures/message digests', self.analyze_step_4],
            ['Analyzing server settings', self.analyze_step_5],
            ]

        # Execute checks and print status
        for check in checks:
            print(check[0], end='...', flush=True)
            err = check[1]()
            print('\r\033[K', end='')
            if err:
                return True

    def analyze_step_1(self):
        # Get private keys
        private_keys = self.gpg.list_keys(True)
        for key in private_keys:
            # Check key algorithm gpgit support
            if key['algo'] not in self.gpgAlgorithmIDs:
                raise SystemError('Unknown key algorithm. Please report this issue. ID: ' + key['algo'])
            else:
                key['algoname'] = self.gpgAlgorithmIDs[key['algo']]

        # Check if a fingerprint was selected/found
        if self.config['fingerprint'] is None:
            # Check if gpg keys are available, but not yet configured
            if len(private_keys):
                print('\r\033[K', end='')
                print("GPG seems to be already configured on your system but git is not.")
                print('Please select one of the existing keys below or generate a new one:')
                print()

                # Print option menu
                print('0: Generate a new RSA 4096 key')
                for i, key in enumerate(private_keys, start=1):
                    print(str(i) + ':', key['fingerprint'], key['uids'][0], key['algoname'], key['length'])

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
                    self.error('Aborted by user')
                print()

                # Safe new fingerprint
                if userinput != 0:
                    self.config['fingerprint'] = private_keys[userinput - 1]['fingerprint']

        # Validate selected gpg key
        if self.config['fingerprint'] is not None:
            # Check if the full fingerprint is used
            if len(self.config['fingerprint']) != 40:
                self.set_substep_status('1.2', 'FAIL',
                    'Please specify the full fingerprint',
                    ['GPG ID: ' + self.config['fingerprint']])
                return True

            # Find selected key
            for key in private_keys:
                if key['fingerprint'] == self.config['fingerprint']:
                    self.gpgkey = key
                    break;

            # Check if key is available in keyring
            if self.gpgkey is None:
                self.set_substep_status('1.2', 'FAIL',
                    'Selected key is not available in keyring',
                    ['GPG ID: ' + self.config['fingerprint']])
                return True

            # Check key algorithm security
            if self.gpgkey['algo'] not in self.gpgSecureAlgorithmIDs \
                    or self.gpgkey['length'] not in self.gpgSecureKeyLength:
                self.set_substep_status('1.2', 'FAIL',
                    'Insecure key algorithm used: '
                    + self.gpgkey['algoname'] + ' '
                    + self.gpgkey['length'],
                    ['GPG ID: ' + self.config['fingerprint']])
                return True

            # Check key algorithm security
            if self.gpgkey['trust'] == 'r':
                self.set_substep_status('1.2', 'FAIL',
                    'Selected key is revoked',
                    ['GPG ID: ' + self.config['fingerprint']])
                return True

            # Use selected key
            self.set_substep_status('1.2', 'OK',
                'Key already generated', [
                    'GPG key: ' + self.gpgkey['uids'][0],
                    'GPG ID: [' + self.gpgkey['algoname'] + ' '
                    + self.gpgkey['length'] + '] ' + self.gpgkey['fingerprint']
                    + ' '
                ])

            # Warn about strong passphrase
            self.set_substep_status('1.1', 'NOTE',
                'Please use a strong, unique, secret passphrase')

        else:
            # Generate a new key
            self.set_substep_status('1.2', 'TODO',
                'Generating an RSA 4096 GPG key for '
                + self.config['username']
                + ' ' + self.config['email']
                + ' valid for 3 years.')

            # Warn about strong passphrase
            self.set_substep_status('1.1', 'TODO',
                'Please use a strong, unique, secret passphrase')

    def analyze_step_2(self):
        # Add publish note
        self.set_substep_status('2.3', 'NOTE',
            'Please publish the full GPG fingerprint on your project page')

        # Check Github GPG key
        if self.config['github'] == True:
            # TODO Will associate your GPG key with Github
            self.set_substep_status('2.2', 'NOTE',
                'Please associate your GPG key with Github')
        else:
            self.set_substep_status('2.2', 'OK',
                'No Github repository used')

        if self.config['fingerprint'] is None:
            self.set_substep_status('2.3', 'TODO',
                'Please publish the full GPG fingerprint on your project page')
        else:
            self.set_substep_status('2.3', 'NOTE',
                'Please publish the full GPG fingerprint on your project page')

        # Only check if a fingerprint was specified
        if self.config['fingerprint'] is not None:
            # Check key on keyserver
            # TODO catch receive exception
            # TODO add timeout
            # https://stackoverflow.com/questions/366682/how-to-limit-execution-time-of-a-function-call-in-python
            key = self.gpg.recv_keys(self.config['keyserver'], self.config['fingerprint'])

            # Found key on keyserver
            if self.config['fingerprint'] in key.fingerprints:
                self.set_substep_status('2.1', 'OK',
                    'Key already published on ' + self.config['keyserver'])
                return

        # Upload key to keyserver
        self.set_substep_status('2.1', 'TODO',
            'Publishing key on ' + self.config['keyserver'])

    def analyze_step_3(self):
        # Check if git was already configured with the gpg key
        if self.config['signingkey'] != self.config['fingerprint'] \
                or self.config['fingerprint'] is None:
            # Check if git was already configured with a different key
            if self.config['signingkey'] is None:
                self.config['config_level'] = 'global'

            self.set_substep_status('3.1', 'TODO',
                'Configuring ' + self.config['config_level']
                + ' git settings with your GPG key')
        else:
            self.set_substep_status('3.1', 'OK',
                'Git already configured with your GPG key')

        # Check commit signing
        if self.config['gpgsign'] == True:
            self.set_substep_status('3.2', 'OK',
                'Commit signing already enabled')
        else:
            self.set_substep_status('3.2', 'TODO',
                'Enabling ' + self.config['config_level']
                + ' git settings with commit signing')

        # Refresh tags
        self.repo.remotes.origin.fetch('--tags')

        # Check if tag was already created
        if self.repo.tag('refs/tags/' + self.config['tag']) in self.repo.tags:
            # Verify signature
            try:
                self.repo.create_tag(self.config['tag'],
                    verify=True,
                    ref=None)
            except:
                self.set_substep_status('3.3', 'FAIL',
                    'Invalid signature for tag ' + self.config['tag'] + '. Was the tag even signed?')
                return True
            else:
                self.set_substep_status('3.3', 'OK',
                    'Good signature for existing tag ' + self.config['tag'])
        else:
            self.set_substep_status('3.3', 'TODO',
                'Creating signed tag ' + self.config['tag'] + ' and pushing it to the remote git')

    def analyze_step_4(self):
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
                    self.set_substep_status('4.1', 'FAIL',
                        'Archive exists but no corresponding tag!?', [tarfilepath])
                    return True

                # Verify existing archive
                try:
                    with self.compressionAlgorithms[tar].open(tarfilepath, "rb") as tarstream:
                        cmptar = strmcmp(tarstream)
                        self.repo.archive(cmptar, treeish=self.config['tag'], prefix=filename + '/', format='tar')
                        if not cmptar.equal():
                            self.set_substep_status('4.1', 'FAIL',
                                'Existing archive differs from local source', [tarfilepath])
                            return True
                except lzma.LZMAError:
                    self.set_substep_status('4.1', 'FAIL',
                        'Archive not in ' + tar + ' format', [tarfilepath])
                    return True

                # Successfully verified
                self.set_substep_status('4.1', 'OK',
                    'Existing archive(s) verified successfully', ['Path: ' + self.config['output'], 'Basename: ' + filename])
            else:
                self.set_substep_status('4.1', 'TODO',
                    'Creating new release archive(s)', ['Path: ' + self.config['output'], 'Basename: ' + filename])

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
                    self.set_substep_status('4.2', 'FAIL',
                        'Signature found without corresponding archive',
                        [sigfilepath])
                    return True

                # Verify signature
                with open(sigfilepath, "rb") as sig:
                    verified = self.gpg.verify_file(sig, tarfilepath)
                    # Check trust level and fingerprint match
                    if verified.trust_level is None \
                            or verified.trust_level < verified.TRUST_FULLY \
                            or verified.fingerprint != self.config['fingerprint']:
                        if verified.trust_text is None:
                            verified.trust_text = 'Invalid signature'
                        self.set_substep_status('4.2', 'FAIL',
                            'Signature could not be verified successfully with gpg',
                            [sigfilepath, 'Trust level: ' + verified.trust_text])
                        return True

                # Successfully verified
                self.set_substep_status('4.2', 'OK',
                    'Existing signature(s) verified successfully')
            else:
                self.set_substep_status('4.2', 'TODO',
                    'Creating GPG signature(s) for archive(s)')

            # Verify all selected shasums if existant
            for sha in self.config['sha']:
                shafile = tarfile + '.' + sha
                self.assets += [shafile]
                shafilepath = os.path.join(self.config['output'], shafile)

                # Calculate hash of tarfile
                if os.path.isfile(tarfilepath):
                    hash_sha = hashlib.new(sha)
                    with open(tarfilepath, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_sha.update(chunk)
                    self.hash[sha][tarfile] = hash_sha.hexdigest()

                # Check if hash already exists
                if os.path.isfile(shafilepath):
                    # Check if tar for hash exists
                    if not os.path.isfile(tarfilepath):
                        self.set_substep_status('4.3', 'FAIL',
                            'Message digest found without corresponding archive',
                            [shafilepath])
                        return True

                    # Read hash and filename
                    with open(shafilepath, "r") as f:
                        hashinfo = f.readline().split()

                    # Verify hash
                    if len(hashinfo) != 2 \
                            or self.hash[sha][tarfile] != hashinfo[0] \
                            or os.path.basename(hashinfo[1]) != tarfile:
                        self.set_substep_status('4.3', 'FAIL',
                            'Message digest could not be successfully verified',
                            [shafilepath])
                        return True

                    # Successfully verified
                    self.set_substep_status('4.3', 'OK',
                        'Existing message digest(s) verified successfully')
                else:
                    self.set_substep_status('4.3', 'TODO',
                        'Creating message digest(s) for archive(s)')

    def analyze_step_5(self):
        # Check Github GPG key
        if self.config['github'] == True:
            self.set_substep_status('5.2', 'OK',
                'Github uses well configured https')

            # Ask for Github token
            if self.config['token'] is None:
               self.config['token'] = input('Enter Github token to access release API: ')

            # Create Github API instance
            self.github = Github(self.config['token'])

            # Acces Github API
            try:
                self.githubuser = self.github.get_user()
                self.githubrepo = self.githubuser.get_repo(self.config['project'])
            except:
                self.error('Error accessing Github API for project ' + self.config['project'])

            # Check Release and its assets
            try:
                self.release = self.githubrepo.get_release(self.config['tag'])
            except:
                self.newassets = self.assets
                self.set_substep_status('5.1', 'TODO',
                    'Creating release and uploading release files to Github')
                return
            else:
                # Determine which assets need to be uploaded
                asset_list = [x.name for x in self.release.get_assets()]
                for asset in self.assets:
                    if asset not in asset_list:
                        self.newassets += [asset]

            # Check if assets already uploaded
            if len(self.newassets) == 0:
                self.set_substep_status('5.1', 'OK',
                    'Release already published on Github')
            else:
                self.set_substep_status('5.1', 'TODO',
                    'Uploading release files to Github')

        else:
            self.set_substep_status('5.1', 'NOTE',
                'Please upload the compressed archive, signature and message digest manually')
            self.set_substep_status('5.2', 'NOTE',
                'Please configure HTTPS for your download server')

    # Strong, unique, secret passphrase
    def step_1_1(self):
        print('More infos: https://github.com/NicoHood/gpgit#11-strong-unique-secret-passphrase')

    # Key generation
    def step_1_2(self):
        #TODO
        pass

    # Submit your key to a key server
    def step_2_1(self):
        self.gpg.send_keys(self.config['keyserver'], self.config['fingerprint'])

    # Associate GPG key with Github
    def step_2_2(self):
        pass

    # Publish your full fingerprint
    def step_2_3(self):
        print('Your fingerprint is:', self.config['fingerprint'])

    # Configure git GPG key
    def step_3_1(self):
        # Configure git signingkey settings
        with self.repo.config_writer(config_level=self.config['config_level']) as cw:
            cw.set("user", "signingkey", self.config['fingerprint'])

    # Commit signing
    def step_3_2(self):
        # Configure git signingkey settings
        with self.repo.config_writer(config_level=self.config['config_level']) as cw:
            cw.set("commit", "gpgsign", True)

    # Create signed git tag
    def step_3_3(self):
        print(':: Creating, signing and pushing tag', self.config['tag'])

        # Create a signed tag
        newtag = None
        try:
            newtag = self.repo.create_tag(
                self.config['tag'],
                message=self.config['message'],
                sign=True,
                local_user=self.config['fingerprint'])
        except:
            self.error("Signing tag failed")
            return True

        # Push tag
        try:
            self.repo.remotes.origin.push(newtag)
        except:
           self.error("Pushing tag failed")
           return True

    # Create compressed archive
    def step_4_1(self):
        # Check all compression option tar files
        filename = self.config['project'] + '-' + self.config['tag']
        for tar in self.config['tar']:
            # Get tar filename
            tarfile = filename + '.tar.' + tar
            tarfilepath = os.path.join(self.config['output'], tarfile)

            # Create compressed tar files if it does not exist
            if not os.path.isfile(tarfilepath):
                print(':: Creating', tarfilepath)
                with self.compressionAlgorithms[tar].open(tarfilepath, 'wb') as tarstream:
                    self.repo.archive(tarstream, treeish=self.config['tag'], prefix=filename + '/', format='tar')

    # Sign the sources
    def step_4_2(self):
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
                    print(':: Creating', sigfilepath)
                    signed_data = self.gpg.sign_file(
                        tarstream,
                        keyid=self.config['fingerprint'],
                        binary=bool(self.config['no_armor']),
                        detach=True,
                        output=sigfilepath,
                        #digest_algo='SHA512' #TODO v 2.x gpg module
                        )
                    if signed_data.fingerprint != self.config['fingerprint']:
                        self.error('Signing data failed')
                    # TODO https://tools.ietf.org/html/rfc4880#section-9.4
                    #print(signed_data.hash_algo) -> 8 -> SHA256

    # Create the message digest
    def step_4_3(self):
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
                        with open(tarfilepath, "rb") as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                hash_sha.update(chunk)
                        self.hash[sha][tarfile] = hash_sha.hexdigest()

                    # Write cached hash and filename
                    print(':: Creating', shafilepath)
                    with open(shafilepath, "w") as f:
                        f.write(self.hash[sha][tarfile] + '  ' + tarfile)

    # Github
    def step_5_1(self):
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
            print(':: Uploading', assetpath)
            # TODO not functional see https://github.com/PyGithub/PyGithub/pull/525#issuecomment-301132357
            # TODO change label and mime type
            self.release.upload_asset(assetpath, "Testlabel", "application/x-xz")

    # Configure HTTPS for your download server
    def step_5_2(self):
        pass

    def printstatus(self):
        # Print the status tree
        err = False
        for step in self.Steps:
            if step.printstatus():
                err = True
        if err:
            self.error('Exiting due to previous errors')
        return err

    def run(self):
        # Execute all steps
        for step in self.Steps:
            if step.run():
                self.error('Executing step failed')
                return True

    def error(self, msg):
        print(colors.RED + '==> Error:' + colors.RESET, msg)
        sys.exit(1)


def main(arguments):
    parser = argparse.ArgumentParser(description=
    'A Python script that automates the process of signing git sources via GPG')
    parser.add_argument('tag', action='store', help='Tagname')
    parser.add_argument('-v', '--version', action='version', version='GPGit 2.0.0')
    parser.add_argument('-m', '--message', action='store', help='tag message')
    parser.add_argument('-o', '--output', action='store', help='output path of the compressed archive, signature and message digest')
    parser.add_argument('-g', '--git-dir', action='store', default=os.getcwd(), help='path of the git project')
    parser.add_argument('-f', '--fingerprint', action='store', help='(full) GPG fingerprint to use for signing/verifying')
    parser.add_argument('-p', '--project', action='store', help='name of the project, used for archive generation')
    parser.add_argument('-e', '--email', action='store', help='email used for gpg key generation')
    parser.add_argument('-u', '--username', action='store', help='username used for gpg key generation')
    parser.add_argument('-c', '--comment', action='store', help='comment used for gpg key generation')
    parser.add_argument('-k', '--keyserver', action='store', default='hkps://hkps.pool.sks-keyservers.net', help='keyserver to use for up/downloading gpg keys')
    parser.add_argument('-n', '--no-github', action='store_false', dest='github', help='disable Github API functionallity')
    parser.add_argument('-a', '--prerelease', action='store_true', help='Flag as Github prerelease')
    parser.add_argument('-t', '--tar', choices=['gz', 'gzip', 'xz', 'bz2', 'bzip2'], default=['xz'], nargs='+', help='compression option')
    parser.add_argument('-s', '--sha', choices=['sha256', 'sha384', 'sha512'], default=['sha512'], nargs='+', help='message digest option')
    parser.add_argument('-b', '--no-armor', action='store_true', help='do not create ascii armored signature output')

    args = parser.parse_args()

    gpgit = GPGit(vars(args))
    gpgit.load_defaults()
    gpgit.analyze()
    gpgit.printstatus()
    print()

    # Check if even something needs to be done
    if gpgit.todo:
        # User selection
        ret = input('Continue with the selected operations? [Y/n]')
        if ret == 'y' or ret == '':
            print()
            if not gpgit.run():
                print('Finished without errors')
        else:
            gpgit.error('Aborted by user')
    else:
        print(colors.GREEN + "==>", colors.RESET, 'Everything looks okay. Nothing to do.')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
