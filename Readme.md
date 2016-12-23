# GPGithub

GPGithub is a set of tools to easily use GPG on your Github projects.
Also see http://www.nicohood.de for more information about GPG usage.

## gpgtag
This script is meant to provide a simple way to:
* Create a gpg signed tag
* Push the tag
* Create a Github Release
* Compare the github tarball against the local files
* Sign and hash the tarball of the release

How to generate a github token:
* Go to preferences
* Developer settings section on the left
* Personal access tokens
* Generate a new token
* Check "public_repo"
* Generate the token and store it safely

## gpgverify
Verifies git tag local source against Github download. Username and project name
for a different Github url can be specified optionally.
```
Usage: gpgverify <tag> [username] [project name]
```

## gpgsign
Create the tarball of the tag source, signs it and creates a hash. Default
output path is ./archive but can be specified optionally. The project name can
be specified as well for the generated tar archive which defaults to the
folder name.
```
Usage: gpgsign <tag> [output path] [project name]
```

## Version History
```
1.0.0 (xx.xx.201x)
* Added gpgverify
* Added gpgsign

Untagged Release (16.12.2016)
* Initial release of the software
```
