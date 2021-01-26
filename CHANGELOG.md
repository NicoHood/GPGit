# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This changlog uses the [ISO 8601 date format](https://www.iso.org/iso-8601-date-and-time-format.html) of (YYYY-MM-DD).

## [Unreleased]

## [1.4.0] - 2021-01-26

### Added

* Added CHANGELOG.md file with [Keep A Changelog format](https://keepachangelog.com)
* Added support for parsing changelog via `-c, --changelog`
* Added [additional quoting for command substitution](https://unix.stackexchange.com/q/118433)
* Detect default github branch automatically when tagging a specific commit
* Added [ShellCheck](https://www.shellcheck.net/) makefile `test` target
* Added detection of used remote/upstream.
* Show github release link after uploading.

### Changed

* Explicitly use annotated git tag using `-a`
* Improved grep handing using -F option
* Add a better error message if signing git tag failed.
* Disable interactive mode for first run only when script finishes properly #20
* Improved compression and hash bash array handling

### Removed

* Remove not required exit command
* Remove unused MAGENTA and CYAN colors

### Fixed

* Fixed reading private repository information by always specifying the token
* Fix --no-github param
* Fixed --force option for github releases #24
* Added support for BSD based systems #19 (thanks @WoLpH)

## [1.3.4] - 2020-03-23

### Added

* Add additional keyserver error message #18

### Fixed
* Fix crash when using a none github repo

## [1.3.3] - 2018-10-31

### Fixed
* Create parent directories if not existant.

## [1.3.2] - 2018-04-15

### Fixed
* Change directory to git root path, so "git archive" is working properly

## [1.3.1] - 2018-03-14

### Added
* Added -f, --force option
* Added version identifier in default tag message
* Added option to specify the commit/object to tag

### Changed

* Improved hash algorithm usage for non linux systems
* Improved keyid parameter to fit better with git tag and gpg

### Fixed

* Fixed shebang for non linux systems
* Fixed #17 git config reading for commit.gpgsign setting

## [1.3.0] - 2018-01-24

### Added

* Added environment variable and git config support
* Added color output options
* Added zip support
* Added support for multiple compression/hash algorithms

### Changed

* Reworked bash script completely
* Simplified parameters
* Reduced output verbosity
* Generate archive from local git source rather than downloading it from github
* Do less unnecessary error checking, but simplify the code instead
* Create signatures with strongest hash algorithm
* Use ECC keys for GPG key generation if available

### Fixed
* Fix pushing tag if a branch with the same name also exists

## [2.0.7] - 2017-06-27

**Note: The 2.x.x series is written in Python, but was discontinued because of multiple issues with the python libraries. A Bash script is much easier to integrate and set up, so development was refocused on that.**

### Added

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

## [1.2.0] - 2017-04-24

### Added
* Trap on errors
* Detect gpg2

### Fixed
* Fix Git tags pull/push
* Small code fixes #3 (Thanks @cmaglie)

## [1.1.2] - 2017-01-22

### Fixed
* Fixed Github uploading name

## [1.1.1] - 2017-01-17

### Added
* Verify existing signatures
* Added upload to Github functionality

### Changed
* Only allow secure GPG keys

## [1.1.0] - 2017-01-13

### Added
* Added online source download
* Added source verification
* Added multiple compression algorithms
* Added multiple sha algorithms

### Changed
* Updated Readme

### Fixed

* Minor fixes

## [1.0.0] - 2017-01-07

### Added
- First release with all functions working except the uploading

### Changed
- Merged all scripts into gpgit.sh

## [0.1.0] - 2016-12-16

### Added
- Initial release of the software

[Unreleased]: https://github.com/NicoHood/gpgit/compare/1.4.0...HEAD
[1.4.0]: https://github.com/NicoHood/gpgit/compare/1.3.4...1.4.0
[1.3.4]: https://github.com/NicoHood/gpgit/compare/1.3.3...1.3.4
[1.3.3]: https://github.com/NicoHood/gpgit/compare/1.3.2...1.3.3
[1.3.2]: https://github.com/NicoHood/gpgit/compare/1.3.1...1.3.2
[1.3.1]: https://github.com/NicoHood/gpgit/compare/1.3.0...1.3.1
[1.3.0]: https://github.com/NicoHood/gpgit/compare/1.2.0...1.3.0
[2.0.7]: https://github.com/NicoHood/gpgit/releases/tag/2.0.7
[1.2.0]: https://github.com/NicoHood/gpgit/compare/1.1.2...1.2.0
[1.1.2]: https://github.com/NicoHood/gpgit/compare/1.1.1...1.1.2
[1.1.1]: https://github.com/NicoHood/gpgit/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/NicoHood/gpgit/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/NicoHood/gpgit/compare/0.1.0...1.0.0
[0.1.0]: https://github.com/NicoHood/gpgit/releases/tag/0.1.0
