# GPGit
GPGit is meant to bring GPG to everybody as easy as possible.
It is not only a shell script that automates the process of creating new
signed releases with GPG but also a step by step guide for you to understand
the process with GPG and gives your further reading information.

## Index
* [GPG quick start guide](#gpg-quick-start-guide)
* [A template for contacting upstream](#a-template-for-contacting-upstream)
* [Links](#links)
* [Version History](#version-history)

## Script Usage
The script guides you through all 5 steps of the
[GPG quick start guide](#gpg-quick-start-guide). By default no extra arguments
beside the tag are required. Follow the instructions and you are good to go.

```bash
gpgit 1.0.0
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
-o, --output    The output path of the .tar.gz, .sig and sha512
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

**Make sure that your secret key is stored somewhere safe and use a unique strong password.**

Crucial key generation settings:
* (1) RSA and RSA
* 4096 bit key size
* 4096 bit subkey size
* Valid for 3 years (3y)
* Username and email

##### Example key generation:
```
$ gpg --full-gen-key --expert
gpg (GnuPG) 2.1.17; Copyright (C) 2016 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
Your selection? 1
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want for the subkey? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 3y
Key expires at Sat 04 Jan 2020 03:31:16 PM CET
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: John Doe
Email address: john@doe.com
Comment: gpgit example
You selected this USER-ID:
    "John Doe (gpgit example) <john@doe.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /tmp/tmp.0Mw2k1KDcH/trustdb.gpg: trustdb created
gpg: key 61D68FF6279DF9A6 marked as ultimately trusted
gpg: directory '/tmp/tmp.0Mw2k1KDcH/openpgp-revocs.d' created
gpg: revocation certificate stored as '/tmp/tmp.0Mw2k1KDcH/openpgp-revocs.d/3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6.rev'
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
```bash
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --send-keys 3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
```

Now the user can get your key by requesting the fingerprint from the keyserver:
```bash
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --recv-keys 3D6B9B41CCDC16D0E4A66AC461D68FF6279DF9A6
```
[[Read more]](https://wiki.archlinux.org/index.php/GnuPG#Use_a_keyserver)

#### 2.2 Associate GPG key with github
To make Github display your commits as "verified" you also need to add your
public [GPG key to your Github profile](https://github.com/settings/keys).
```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

# Generate public key
gpg --armor --export <fingerprint>
```
[[Read more]](https://help.github.com/articles/generating-a-new-gpg-key/)
[[Read more]](https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/)

#### 2.3 Publish your fingerprint
To make it easy for everyone else to find your key it is crucial that you
publish the fingerprint on a trusted platform, such as your website or Github.
To give the key more trust other users can sign your key too.
[[Read more]](https://wiki.debian.org/Keysigning)

### 3. Usage of GPG by git
#### 3.1 Configure git GPG key
In order to make git use your GPG key you need to set the default signing key
for git.
```bash
# List keys + full fingerprint
gpg --list-secret-keys --keyid-format LONG

git config --global user.signingkey <fingerprint>
```
[[Read more]](https://help.github.com/articles/telling-git-about-your-gpg-key/)

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
```
# Creates a signed tag
git tag -s mytag

# Verifies the signed tag
git tag -v mytag
```
[[Read more]](https://help.github.com/articles/signing-tags-using-gpg/)

### 4. Creation of a signed compressed release archive
#### 4.1 Create compressed archive
You can use `git archive` to create archives of your tagged git release. It is
highly recommended to use `.xz -9` for compression as it gives you the best
compression possible which is especially beneficial for those countries with slow
and unstable internet connections.

```
git archive --format=tar --prefix "gpgit-1.0.0" 1.0.0 | xz -9 > gpgit-1.0.0.tar.xz"
```
[[Read more]](https://git-scm.com/docs/git-archive)

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
[Read more](https://wiki.archlinux.org/index.php/GnuPG#Make_a_detached_signature)

To not need to retype your password every time for signing you can also use
[gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#gpg-agent).

This gives you a file called `gpgit-1.0.0.tar.xz.asc` which is the GPG
signature. Release it along with your source tarball and let everyone know
to first verify the signature after downloading.

```bash
gpg --verify mysoftware-0.4.tar.gz.asc
```
[Read more](https://wiki.archlinux.org/index.php/GnuPG#Verify_a_signature)

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

### Appendix

#### Email encryption
You can also use this key for email encryption
with [enigmail and thunderbird](https://wiki.archlinux.org/index.php/thunderbird#EnigMail_-_Encryption).
[[Read more]](https://www.enigmail.net/index.php/en/)


## A template for contacting upstream
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
* Upload the public key to a key server and publish the [full fingerprint](https://lkml.org/lkml/2016/8/15/445).
* Sign every new git commit and tag.
* Create signed compressed release archives.

[GPGit](https://github.com/NicoHood/gpgit) is meant to bring GPG to
everybody as easy as possible. It is not only a shell script that automates the
process of creating new signed releases with GPG but also a step by step guide
for you to understand the process with GPG and gives your further reading
information.

**Additional Information:**
* https://github.com/NicoHood/gpgit
* https://help.github.com/categories/gpg/
* https://wiki.archlinux.org/index.php/GnuPG
* https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
* https://www.qubes-os.org/doc/verifying-signatures/
* https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https
* https://www.enigmail.net/index.php/en/

Thanks in advance.
```

## Links
* https://help.github.com/categories/gpg/
* https://wiki.archlinux.org/index.php/GnuPG
* https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
* https://www.qubes-os.org/doc/verifying-signatures/
* https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https

## Contacted upstreams
The following list summarizes the projects that I've contacted about using GPG.
The data might be outdated or semi correct. The intention behind the list is
to keep track of the projects that miss GPG signatures as well to show off about
the large number of projects who decided to use GPG. Thanks for all the support!

### Upstreams that started using GPG (Hall of fame):
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

### Upstreams that refuse to use GPG (Hall of shame):
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
* [ipod-shuffle-4g](https://github.com/nims11/IPod-Shuffle-4g/issues/39)
* [fontbuilder](https://github.com/andryblack/fontbuilder/issues/26)
* [pypng](https://github.com/drj11/pypng/issues/74)
* [libarchive](https://github.com/libarchive/libarchive/issues/847)
* [tuntox](https://github.com/gjedeer/tuntox/issues/29)
* QT -> email to feedback@qt.io
* [compton](https://github.com/chjj/compton/issues/401)

## Version History
```
1.0.0 (xx.xx.201x)
* Merged all scripts into gpgit.sh

Untagged Release (16.12.2016)
* Initial release of the software
```
