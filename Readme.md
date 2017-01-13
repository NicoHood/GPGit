# GPGit
A shell script that automates the process of signing git sources via GPG.

GPGit is meant to bring GPG to the masses. It is not only a shell script that
automates the process of creating new signed git releases with GPG but also
comes with this step-by-step readme guide for learning how to use GPG.

## Index
* [Introduction](#introduction)
* [Installation](#installation)
* [Script Usage](#script-usage)
* [GPG quick start guide](#gpg-quick-start-guide)
* [Appendix](#appendix)
* [A template for contacting upstreams](#a-template-for-contacting-upstreams)
* [Links](#links)
* [Contacted upstreams](#contacted-upstreams)
* [Version History](#version-history)

## Introduction
As we all know, today more than ever before, it is crucial to be able to trust
our computing environments. One of the main difficulties that package
maintainers of Linux distributions face, is the difficulty to verify the
authenticity and the integrity of the source code. With GPG signatures it is
possible to verify easily and quickly source code releases.

##### Overview of the required tasks:
* Create and/or use a 4096-bit RSA keypair for the file signing.
* Keep your key secret, use a strong unique passphrase for the key.
* Upload the public key to a key server and publish the [full fingerprint](https://lkml.org/lkml/2016/8/15/445).
* Sign every new git commit and tag.
* Create signed compressed (xz --best) release archives
* Upload a strong message digest (sha512) of the archive
* Configure https for your download server

### Explanation
Only a secure future-proof GPG key can guarantee the source authenticity in long
term. It is crucial to secure this key with a strong unique passphrase so nobody
is able to fake releases of your software. Do not put this key on an untrusted
device such as a Windows PC or a smartphone.

Every git commit/tag/release needs to be signed in order to verify the history
of the whole software as well as the latest source files. As an alternative
strong message digest can help to add another layer of securing the source
integrity.

Https ensure that your sources are downloaded over an encrypted, secure channel.
It also gives your public fingerprint and the message digest more trust.

Also see: [A template for contacting upstreams](#a-template-for-contacting-upstreams)

## Installation
### ArchLinux
You can install gpgit from [AUR](https://aur.archlinux.org/packages/gpgit/).
Make sure to [build in a Clean Chroot](https://wiki.archlinux.org/index.php/DeveloperWiki:Building_in_a_Clean_Chroot).

### Manual Installation
##### Dependencies:
* bash
* gnupg
* git
* coreutils

##### Optional Dependencies:
* wget (online source verification)
* curl (Github uploading)
* gzip (compression algorithm)
* xz (compression algorithm)
* lzip (compression algorithm)

```bash
PREFIX=/usr/local sudo make install
```

## Script Usage
The script guides you through all 5 steps of the
[GPG quick start guide](#gpg-quick-start-guide). **By default no extra arguments
beside the tag are required.** Follow the instructions and you are good to go.

```bash
$ gpgit 1.0.0
```

For additional tweaks you may use some optional parameters:
```bash
$ gpgit --help
Usage: gpgit <tag> [options]

Mandatory parameters:
<tag>           Tagname

Actions:
-h --help       Show this help message

Options:
-o, --output    The output path of the archive, signature and message digest.
                Default: "git rev-parse --show-toplevel)/archive"
-u, --username  Username of the user. Used for GPG key generation.
                Default: git config user.name
-e, --email     Email of the user. Used for GPG key generation.
                Default: "git config user.email"
-p, --project   The name of the project. Used for archive geneation.
                Default: "git config --local remote.origin.url \
                           | sed -n \'s#.*/\([^.]*\)\.git#\1#p\'"
-g, --gpg       Specify (full) GPG fingerprint to use for signing.
                Default: "git config user.signingkey"
-w, --wget      Download source from a user-specified URL.
                Default: Autodetection for Github URL
-t, --tar       Format used to compress tar archive: gz|xz|lz
                Default: gz
-s, --sha       Message digest algorithm to use: sha256|sha384|sha512
                Default: sha512
-m, --message   Specify the tag message.
                Default: "Release <tag>"
-y, --yes       Assume "yes" on all questions.
```

## GPG quick start guide
GPGit guides you through 5 simple steps to get your software project ready
with GPG signatures. Further details can be found below.

1. Generate a new GPG key
2. Publish your key
3. Usage of GPG by git
4. Creation of a signed compressed release archive
5. Upload the release

### 1. Generate a new GPG key
If you don't have a GPG key yet, create a new one first. You can use RSA
(4096 bits) or ECC (Curve 25519) for a strong key. The latter one does currently
not work with Github. You want to stay with RSA for now.

**Make sure that your secret key is stored somewhere safe and use a unique
strong password.**

Crucial key generation settings:
* (1) RSA and RSA
* 4096 bit key size
* 4096 bit subkey size
* Valid for 3 years (3y)
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

pub   rsa4096 2017-01-04 [SC] [expires: 2020-01-04]
      3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
      3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
uid                      John Doe (gpgit example) <john@doe.com>
sub   rsa4096 2017-01-04 [E] [expires: 2020-01-04]
```

The generated key has the fingerprint `3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6`
in this example. Share it with others so they can verify your source.
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Create_key_pair)

If you ever move your installation make sure to backup `~/.gnupg/` as it
contains the private key and the revocation certificate. Handle it with care.
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Revoking_a_key)

### 2. Publish your key

#### 2.1 Submit your key to a key server
To make the public key widely available, upload it to a key server.
Now the user can get your key by requesting the fingerprint from the keyserver:
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Use_a_keyserver)

```bash
# Publish key
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --send-keys 3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6

# Import key
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --recv-keys 3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
```

#### 2.2 Associate GPG key with github
To make Github display your commits as "verified" you also need to add your
public [GPG key to your Github profile](https://github.com/settings/keys).
[[Read more]](https://help.github.com/articles/generating-a-gpg-key/)

```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

# Generate public key
gpg --armor --export <fingerprint>
```

#### 2.3 Publish your fingerprint
To make it easy for everyone else to find your key it is crucial that you
publish the fingerprint on a trusted platform, such as your website or Github.
To give the key more trust other users can sign your key too.
[[Read more]](https://wiki.debian.org/Keysigning)

### 3. Usage of GPG by git
#### 3.1 Configure git GPG key
In order to make git use your GPG key you need to set the default signing key
for git.
[[Read more]](https://help.github.com/articles/telling-git-about-your-gpg-key/)

```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

git config --global user.signingkey <fingerprint>
```

#### 3.2 Commit signing
To verify the git history, git commits needs to be signed. You can manually sign
commits or enable it by default for every commit. It is recommended to globally
enable git commit signing.
[[Read more]](https://help.github.com/articles/signing-commits-using-gpg/)

```bash
git config --global commit.gpgsign true
```

#### 3.3 Create signed git tag
Git tags need to be created from the command line and always need a switch to
enable tag signing.
[[Read more]](https://help.github.com/articles/signing-tags-using-gpg/)

```bash
# Creates a signed tag
git tag -s mytag

# Verifies the signed tag
git tag -v mytag
```

### 4. Creation of a signed compressed release archive
#### 4.1 Create compressed archive
You can use `git archive` to create archives of your tagged git release. It is
highly recommended to use a strong compression which is especially beneficial
for those countries with slow and unstable internet connections.
[[Read more]](https://git-scm.com/docs/git-archive)

```bash
# .tar.gz
git archive --format=tar.gz -o gpgit-1.0.0.tar.gz --prefix gpgit-1.0.0 1.0.0

# .tar.xz
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | xz -9 > gpgit-1.0.0.tar.xz

# .tar.lz
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | lzip --best > gpgit-1.0.0.tar.xz

# Verify an existing archive
git archive --format=tar --prefix gpgit-1.0.0 1.0.0 | cmp <(xz -dc gpgit-1.0.0.tar.xz)
```

#### 4.2 Create the message digest
Message digests are used to ensure the integrity of a file. It can also serve as
checksum to verify the download. Message digests **do not** replace GPG
signatures. They rather provide and alternative simple way to verify the source.
Make sure to provide message digest over a secure channel like https.

```bash
sha512 gpgit-1.0.0.tar.xz > gpgit-1.0.0.tar.xz.sha512
```

#### 4.3 Sign the sources
Type the filename of the tarball that you want to sign and then run:
```bash
gpg --armor --detach-sign gpgit-1.0.0.tar.xz
```
Do not blindly sign the Github source downloads unless you have compared its
content with the local files via `diff.`
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Make_a_detached_signature)

To not need to retype your password every time for signing you can also use
[gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#gpg-agent).

This gives you a file called `gpgit-1.0.0.tar.xz.asc` which is the GPG
signature. Release it along with your source tarball and let everyone know
to first verify the signature after downloading.
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Verify_a_signature)

```bash
gpg --verify gpgit-1.0.0.tar.xz.asc
```

### 5. Upload the release
#### 5.1 Github
Create a new "Github Release" to add additional data to the tag. Then drag the
.tar.xz .sig and .sha512 file onto the release.

The script also supports uploading to Github directly. Create a new Github token
first and then follow the instructions of the script.

How to generate a Github token:
* Go to preferences
* Developer settings section on the left
* Personal access tokens
* Generate a new token
* Check "public_repo"
* Generate the token and store it safely

## Appendix

### Email encryption
You can also use this key for email encryption
with [enigmail and thunderbird](https://wiki.archlinux.org/index.php/thunderbird#EnigMail_-_Encryption).
[[Read more]](https://www.enigmail.net/index.php/en/)


## A template for contacting upstreams
If you try to contact an upstream source about missing GPG signatures you can
use this template. It will give them an overview of the importance of GPG, the
required steps to do and how they can be accomplished.

```
GPG signatures for source validation

As we all know, today more than ever before, it is crucial to be able to trust
our computing environments. One of the main difficulties that package
maintainers of Linux distributions face, is the difficulty to verify the
authenticity and the integrity of the source code.

The Arch Linux team would appreciate it if you would provide us GPG signatures
in order to verify easily and quickly your source code releases.

**Overview of the required tasks:**
* Create and/or use a 4096-bit RSA keypair for the file signing.
* Keep your key secret, use a strong unique passphrase for the key.
* Upload the public key to a key server and publish the full fingerprint.
* Sign every new git commit and tag.
* Create signed compressed (xz --best) release archives
* Upload a strong message digest (sha512) of the archive
* Configure https for your download server

[GPGit](https://github.com/NicoHood/gpgit) is meant to bring GPG to the masses.
It is not only a shell script that automates the process of creating new signed
git releases with GPG but also comes with this step-by-step readme guide for
learning how to use GPG.

**Additional Information:**
* https://github.com/NicoHood/gpgit
* https://help.github.com/categories/gpg/
* https://wiki.archlinux.org/index.php/GnuPG
* https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
* https://www.qubes-os.org/doc/verifying-signatures/
* https://lkml.org/lkml/2016/8/15/445
* https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https
* https://www.enigmail.net/index.php/en/

Thanks in advance.
```

## Links
### Resources
* https://help.github.com/categories/gpg/
* https://wiki.archlinux.org/index.php/GnuPG
* https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
* https://www.qubes-os.org/doc/verifying-signatures/
* https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https

### Hacks
* [Backdoored Linux Mint, and the Perils of Checksums](https://micahflee.com/2016/02/backdoored-linux-mint-and-the-perils-of-checksums/)
* [Backdoored vsftpd Source Code Served from Official Site](http://news.softpedia.com/news/Backdoored-vsftpd-Build-Served-from-Official-Website-209559.shtml)
* [TOR Exit Server Delivers Malicious Binaries](http://news.softpedia.com/news/TOR-Exit-Server-Delivers-Malicious-Binaries-463168.shtml)
* [Fake Linus Torvalds' Key Found in the Wild, No More Short-IDs.](https://lkml.org/lkml/2016/8/15/445)
* [Forensics of Chinese MITM on GitHub](http://www.netresec.com/?page=Blog&month=2013-02&post=Forensics-of-Chinese-MITM-on-GitHub)
* [Faking Git Commits](https://github.com/aguerrero/Faking-Git-Commits)
* [Malicious Git and Mercurial HTTP Server For CVE-2014-9390](https://www.rapid7.com/db/modules/exploit/multi/http/git_client_command_exec)

## Contacted upstreams
The following list summarizes the projects that I've contacted about using GPG.
The data might be outdated or semi correct. The intention behind the list is
to keep track of the projects that miss GPG signatures as well to show off about
the large number of projects who decided to use GPG. Thanks for all the support!

### Upstreams that started using GPG:
* [arc-gtk theme](https://github.com/horst3180/arc-theme/issues/695#issuecomment-261723347)
* [arc-icon theme](https://github.com/horst3180/arc-icon-theme/issues/35)
* [create_ap](https://github.com/oblique/create_ap/issues/214)
* [qtox](https://github.com/qTox/qTox/issues/3912)
* [utox](https://github.com/uTox/uTox/issues/502)
* [toxic](https://github.com/JFreegman/toxic/issues/417)
* [toxcore](https://github.com/irungentoo/toxcore/issues/1624)
* [snap-pac](https://github.com/wesbarnett/snap-pac/issues/9)
* [snap-sync](https://github.com/wesbarnett/snap-sync/issues/18)
* [duc](https://github.com/zevv/duc/issues/155)
* [libsodium](https://github.com/jedisct1/libsodium/issues/446)
* [libfilteraudio](https://github.com/irungentoo/filter_audio/issues/37)
* [tuntox](https://github.com/gjedeer/tuntox/issues/29)
* [ipod-shuffle-4g](https://github.com/nims11/IPod-Shuffle-4g/issues/39)

### Upstreams that refuse/postponed to use GPG:
* [atom](https://github.com/atom/atom/issues/13301)
* [mooltipass](https://github.com/limpkin/mooltipass/issues/289)
* [whipper](https://github.com/JoeLametta/whipper/issues/77)
* xfce -> irc, mail to xfce@xfce.org

### Upstreams that do not use GPG yet:
* [arduino](https://github.com/arduino/Arduino/issues/5619)
* [hyperion](https://github.com/hyperion-project/hyperion/issues/730)
* [snapper](https://github.com/openSUSE/snapper/issues/295)
* [antox](https://github.com/Antox/Antox/issues/368)
* [moolticute](https://github.com/raoulh/moolticute/issues/11)
* [fontbuilder](https://github.com/andryblack/fontbuilder/issues/26)
* [pypng](https://github.com/drj11/pypng/issues/74)
* [libarchive](https://github.com/libarchive/libarchive/issues/847)
* QT -> email to feedback@qt.io
* [compton](https://github.com/chjj/compton/issues/401)
* [icu](https://ssl.icu-project.org/trac/ticket/12871)

## Version History
```
1.1.1 (14.01.2017)
* Verify existing signatures
* Added upload to Github functionality

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
