# GPGit

![gpgit.png](img/gpgit.png)

# Introduction
As we all know, today more than ever before, it is crucial to be able to trust our computing environments. One of the main difficulties that package maintainers of Linux distributions face, is the difficulty to verify the authenticity and the integrity of the source code. With GPG signatures it is possible for packagers to verify source code releases quickly and easily.

#### Overview of the required tasks:
* Create and/or use a **[4096-bit RSA keypair][1]** for the file signing
* Use a **[strong, unique, secret passphrase][2]** for the key
* Upload the public key to a **[key server][3]** and **[publish the full fingerprint][4]**
* **[Sign][5]** every new Git **[commit][6]** and **[tag][7]**
* Create **[signed][8], [compressed][9]** (xz --best) release **archives**
* Upload a **[strong message digest][10]** (sha512) of the archive
* Configure **[HTTPS][11]** for your download server

### GPGit
[GPGit][12] is meant to bring GPG to the masses. It is not only a Python script that automates the process of [creating new signed Git releases with GPG][13], but also a [quick-start-guide][14] for learning how to use GPG. GPGit integrates perfectly with the [Github Release API][15] for uploading.

The security status of Linux projects will be tracked in the [Linux Security Database][16]. Thanks for your help in making Linux projects more secure by using GPG signatures.

[1]: https://github.com/NicoHood/gpgit#12-key-generation
[2]: https://github.com/NicoHood/gpgit#11-strong-unique-secret-passphrase
[3]: https://github.com/NicoHood/gpgit#21-send-key-to-a-key-server
[4]: https://github.com/NicoHood/gpgit#22-publish-full-fingerprint
[5]: https://github.com/NicoHood/gpgit#31-configure-git-gpg-key
[6]: https://github.com/NicoHood/gpgit#32-commit-signing
[7]: https://github.com/NicoHood/gpgit#33-create-signed-git-tag
[8]: https://github.com/NicoHood/gpgit#42-sign-the-archive
[9]: https://github.com/NicoHood/gpgit#41-create-compressed-archive
[10]: https://github.com/NicoHood/gpgit#43-create-the-message-digest
[11]: https://github.com/NicoHood/gpgit#51-configure-https-download-server
[12]: https://github.com/NicoHood/gpgit
[13]: https://github.com/NicoHood/gpgit#script-usage
[14]: https://github.com/NicoHood/gpgit#gpg-quick-start-guide
[15]: https://github.com/NicoHood/gpgit#52-upload-to-github
[16]: https://github.com/NicoHood/LSD

## Index
* [Introduction](#introduction)
* [GPGit Documentation](#gpgit-documentation)
* [GPG Quick Start Guide](#gpg-quick-start-guide)
* [Appendix](#appendix)

# GPGit Documentation

## Installation
### ArchLinux
You can install GPGit from [AUR](https://aur.archlinux.org/packages/gpgit/). Make sure to [build in a clean chroot](https://wiki.archlinux.org/index.php/DeveloperWiki:Building_in_a_Clean_Chroot). Please give the package a vote so I can move it to the official ArchLinux [community] repository for even simpler installation.

### Ubuntu/Debian/Other
GPGit dependencies can be easily installed via [pip](https://pypi.python.org/pypi/pip).

```bash
# Install dependencies
sudo apt-get install python3 python3-pip gnupg2 git
VERSION=2.0.2

# Download and verify source
wget https://github.com/NicoHood/gpgit/releases/download/${VERSION}/gpgit-${VERSION}.tar.xz
wget https://github.com/NicoHood/gpgit/releases/download/${VERSION}/gpgit-${VERSION}.tar.xz.asc
gpg2 --keyserver hkps://pgp.mit.edu --recv-keys 97312D5EB9D7AE7D0BD4307351DAE9B7C1AE9161
gpg2 --verify gpgit-${VERSION}.tar.xz.asc gpgit-${VERSION}.tar.xz

# Extract and install dependencies
tar -xf gpgit-${VERSION}.tar.xz
cd gpgit-${VERSION}
pip3 install --user -r requirements.txt

# Install  and run GPGit
sudo cp gpgit.py /usr/local/bin/gpgit
gpgit --help
```

## Script Usage
The script guides you through all 5 steps of the [GPG quick start guide](#gpg-quick-start-guide). **By default no extra arguments beside the tag are required.** Follow the instructions and you are good to go.

![screenshot](img/screenshot.png)

### Parameters

#### -h, --help
Show help message and exit.

#### -v, --version
Show program's version and exit.

#### tag
Tagname of the release. E.g. `1.0.0` or `20170521` with `$(date +%Y%m%d)`.

#### -m <msg>, --message <msg>
Use the given <msg> as the commit message.

#### -o <path>, --output <path>
Output path of the archive, signature and message digest. You can also set this option via configuration.

#### -g <path>, --git-dir <path>
Path to the Git project.

#### -n, --no-github
Disable Github API functionality. Github releases need to be created manually and release assets need to be uploaded manually. GPGit will not prompt for a Github token anymore.

#### -p, --prerelease
Flag as Github prerelease.

### Configuration
Additional configuration can be made via [git config](https://git-scm.com/docs/git-config). Example usage:

```bash
git config --global gpgit.token <token>
git config --global gpgit.output ~/gpgit
git config --local gpgit.tar xz
```

#### user.signingkey
Full GPG fingerprint to use for signing/verifying.

#### gpgit.output
Output path of the archive, signature and message digest. You can also set this option via parameter.

#### gpgit.tar
Archive compression option. Chose between "gz,gzip,xz,bz2,bzip2". Default: "xz"

#### gpgit.sha
Message digest algorithm. chose between "sha256,sha384,sha512". Default: "sha512"

#### gpgit.keyserver
Keyserver to use for GPG key check. Automatically set to "skip" after the first check was successfull. Default: "hkps://pgp.mit.edu"

#### gpgit.github
Enable or disable Github functionality with "true|false". Default: "true" (enabled)

#### gpgit.user
Username used for github uploading.

#### gpgit.project
Project name used for github uploading and archive naming.

#### gpgit.armor
Use ascii armored output of GPG (.asc instead of .sig) with "true|false". Default: "true" (armored output).

#### gpgit.token
Specify the Github token for Github API release uploading.


# GPG Quick Start Guide
GPGit guides you through 5 simple steps to get your software project ready with GPG signatures. Further details can be found below.

1. [Generate a new GPG key](#1-generate-a-new-gpg-key)
    1. [Strong, unique, secret passphrase](#11-strong-unique-secret-passphrase)
    2. [Key generation](#12-key-generation)
2. [Publish your key](#2-publish-your-key)
    1. [Send GPG key to a key server](#21-send-gpg-key-to-a-key-server)
    2. [Publish full fingerprint](#22-publish-full-fingerprint)
    3. [Associate GPG key with Github](#23-associate-gpg-key-with-github)    
3. [Use Git with GPG](#3-use-git-with-gpg)
    1. [Configure Git GPG key](#31-configure-git-gpg-key)
    2. [Enble commit signing](#32-enable-commit-signing)
    3. [Create signed Git tag](#33-create-signed-git-tag)
4. [Create a signed release archive](#4-create-a-signed-release-archive)
    1. [Create compressed archive](#41-create-compressed-archive)
    2. [Sign the archive](#42-sign-the-archive)
    3. [Create the message digest](#43-create-the-message-digest)
5. [Upload the release](#5-upload-the-release)
    1. [Configure HTTPS download server](#51-configure-https-download-server)
    2. [Upload to Github](#52-upload-to-github)

## 1. Generate a new GPG key
### 1.1 Strong, unique, secret passphrase
Make sure that your new passphrase for the GPG key meets high security standards. If the passphrase/key is compromised all of your signatures are compromised too.

Here are a few examples how to keep a passphrase strong but easy to remember:
* [How to Create a Secure Password](https://open.buffer.com/creating-a-secure-password/)
* [Mooltipass](https://www.themooltipass.com/)
* [Keepass](http://keepass.info/)
* [PasswordCard](https://www.passwordcard.org/en)

### 1.2 Key generation
If you don't have a GPG key yet, create a new one first. You can use RSA (4096 bits) or ECC (Curve 25519) for a strong key. The latter one does currently not work with Github. You want to stay with RSA for now.

**Make sure that your secret key is stored somewhere safe and use a unique strong password.**

Crucial key generation settings:
* (1) RSA and RSA
* 4096 bit key size
* 4096 bit subkey size
* Valid for 1 year (1y)
* Username and email

##### Example key generation:
```
$ gpg --full-gen-key --expert
[...]
gpg: /tmp/trustdb.gpg: trustdb created
gpg: key 61D68FF6279DF9A6 marked as ultimately trusted
gpg: directory '/tmp/openpgp-revocs.d' created
gpg: revocation certificate stored as
'/tmp/openpgp-revocs.d/3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6.rev'
public and secret key created and signed.

pub   rsa4096 2017-01-04 [SC] [expires: 2018-01-04]
      3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
      3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
uid                      John Doe <john@doe.com>
sub   rsa4096 2017-01-04 [E] [expires: 2018-01-04]
```

The generated key has the fingerprint `3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6` in this example. Share it with others so they can verify your source. [[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Create_key_pair)

If you ever move your installation make sure to backup `~/.gnupg/` as it contains the **private key** and the **revocation certificate**. Handle it with care. [[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Revoking_a_key)

## 2. Publish your key

### 2.1 Send GPG key to a key server
To make the public key widely available, upload it to a key server. Now the user can get your key by requesting the fingerprint from the keyserver: [[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Use_a_keyserver)

```bash
# Publish key
gpg --keyserver hkps://pgp.mit.edu --send-keys <fingerprint>6

# Import key
gpg --keyserver hkps://pgp.mit.edu --recv-keys <fingerprint>
```

### 2.2 Publish full fingerprint
To make it easy for everyone else to find your key it is crucial that you publish the [**full fingerprint**](https://lkml.org/lkml/2016/8/15/445) on a trusted platform, such as your website or Github. To give the key more trust other users can sign your key too. [[Read more]](https://wiki.debian.org/Keysigning)

### 2.3 Associate GPG key with Github
To make Github display your commits as "verified" you also need to add your public [GPG key to your Github profile](https://github.com/settings/keys). [[Read more]](https://help.github.com/articles/generating-a-gpg-key/)

```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

# Generate public key
gpg --armor --export <fingerprint>
```

## 3. Use Git with GPG
### 3.1 Configure Git GPG key
In order to make Git use your GPG key you need to set the default signing key for Git. [[Read more]](https://help.github.com/articles/telling-git-about-your-gpg-key/)

```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

git config --global user.signingkey <fingerprint>
```

### 3.2 Enable commit signing
To verify the Git history, Git commits needs to be signed. You can manually sign commits or enable it by default for every commit. It is recommended to globally enable Git commit signing. [[Read more]](https://help.github.com/articles/signing-commits-using-gpg/)

```bash
git config --global commit.gpgsign true
```

### 3.3 Create signed Git tag
Git tags need to be created from the command line and always need a switch to enable tag signing. [[Read more]](https://help.github.com/articles/signing-tags-using-gpg/)

```bash
# Creates a signed tag
git tag -s mytag

# Verifies the signed tag
git tag -v mytag
```

## 4. Create a signed release archive
### 4.1 Create compressed archive
You can use `git archive` to create archives of your tagged Git release. It is highly recommended to use a strong compression which is especially beneficial for those countries with slow and unstable internet connections. [[Read more]](https://git-scm.com/docs/git-archive)

```bash
# .tar.gz
git archive --format=tar.gz -o gpgit-1.0.0.tar.gz --prefix gpgit-1.0.0 1.0.0

# .tar.xz
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | xz > gpgit-1.0.0.tar.xz

# .tar.lz
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | lzip --best > gpgit-1.0.0.tar.xz

# Verify an existing archive
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | cmp <(xz -dc gpgit-1.0.0.tar.xz)
```

### 4.2 Sign the archive
Type the filename of the tarball that you want to sign and then run:
```bash
gpg --armor --detach-sign gpgit-1.0.0.tar.xz
```
**Do not blindly sign the Github source downloads** unless you have compared its content with the local files via `diff.` [[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Make_a_detached_signature)

To not need to retype your password every time for signing you can also use [gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#gpg-agent).

This gives you a file called `gpgit-1.0.0.tar.xz.asc` which is the GPG signature. Release it along with your source tarball and let everyone know to first verify the signature after downloading. [[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Verify_a_signature)

```bash
gpg --verify gpgit-1.0.0.tar.xz.asc
```

### 4.3 Create the message digest
Message digests are used to ensure the integrity of a file. It can also serve as checksum to verify the download. Message digests **do not** replace GPG signatures. They rather provide and alternative simple way to verify the source. Make sure to provide message digest over a secure channel like https.

```bash
sha512 gpgit-1.0.0.tar.xz > gpgit-1.0.0.tar.xz.sha512
```

## 5. Upload the release
### 5.1 Configure HTTPS download server
* [Why HTTPS Matters](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)
* [Let's Encrypt](https://letsencrypt.org/)
* [SSL Server Test](https://www.ssllabs.com/ssltest/)

### 5.2 Upload to Github
Create a new "Github Release" to add additional data to the tag. Then drag the .tar.xz .sig and .sha512 files onto the release.

The script also supports [uploading to Github](https://developer.github.com/v3/repos/releases/) directly. Create a new Github token first and then follow the instructions of the script.

How to generate a Github token:
* Go to ["Settings - Personal access tokens"](https://github.com/settings/tokens)
* Generate a new token with permissions "public_repo" and "admin:gpg_key"
* Store it safely

# Appendix

## Email Encryption
You can also use your GPG key for email encryption with [enigmail and thunderbird](https://wiki.archlinux.org/index.php/thunderbird#EnigMail_-_Encryption). [[Read more]](https://www.enigmail.net/index.php/en/)

## Contact
You can get securely in touch with me [here](http://contact.nicohood.de). Don't hesitate to [file a bug at Github](https://github.com/NicoHood/gpgit/issues). More cool projects from me can be found [here](http://www.nicohood.de).

## Version History
```
2.0.0 (xx.xx.2017)
* Switch to Python3 from bash
* New user interface with preview
* More verification
* Better GPG usage
* More parameters
* Configurable settings via git config
* Better error traces
* Resigning a tag is now possible
* General improvements
* New logo
* Improved documentation

1.2.0 (24.04.2017)
* Trap on errors
* Detect gpg2
* Fix Git tags pull/push
* Small code fixes
* Thanks @cmaglie with #3

1.1.2 (22.01.2017)
* Fixed Github uploading name

1.1.1 (17.01.2017)
* Verify existing signatures
* Added upload to Github functionality
* Only allow secure GPG keys

1.1.0 (13.01.2017)
* Added online source download
* Added source verification
* Added multiple compression algorithms
* Added multiple sha algorithms
* Minor fixes
* Updated Readme

1.0.0 (07.01.2017)
* Merged all scripts into gpgit.sh
* First release with all functions working except the uploading

Untagged Release (16.12.2016)
* Initial release of the software
```
