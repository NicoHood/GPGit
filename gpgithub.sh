#!/bin/bash

# Stop on errors
set -e -u -o pipefail

# Avoid any encoding problems
export LANG=C

# Check if messages are to be printed using color
unset ALL_OFF BOLD BLUE GREEN RED YELLOW
if [[ -t 2 ]]; then
	# prefer terminal safe colored and bold text when tput is supported
	if tput setaf 0 &>/dev/null; then
		ALL_OFF="$(tput sgr0)"
		BOLD="$(tput bold)"
		BLUE="${BOLD}$(tput setaf 4)"
		GREEN="${BOLD}$(tput setaf 2)"
		RED="${BOLD}$(tput setaf 1)"
		YELLOW="${BOLD}$(tput setaf 3)"
	else
		ALL_OFF="\e[1;0m"
		BOLD="\e[1;1m"
		BLUE="${BOLD}\e[1;34m"
		GREEN="${BOLD}\e[1;32m"
		RED="${BOLD}\e[1;31m"
		YELLOW="${BOLD}\e[1;33m"
	fi
fi
readonly ALL_OFF BOLD BLUE GREEN RED YELLOW

PROGNAME=$(basename "$0")
ARGS=( "$@" )

usage() {
    echo "Usage: ${PROGNAME} <tag>"
}

# Usage: gpgithub <tag> [options]
# <tag>         tagname
# Actions:
# -h --help     Show this help message
# -g --generate Helps you creating a new GPG key and upload it to a keyserver
# -t --tag      Creates a new release tag
# -v --verify   Verifies a release against the github download
# -s --sign     Signs the release (creates .sig and .sha512)
# -x --upload   Uploads the detached signature and the message digest to GitHub
# Settings:
# -o --output   The output path of the .tar.gz, .sig and sha512
#               Defaults to ./archive
# -n --username Username of the Github repository. Used for Github url parsing.
# -p --project  The name of the project. Used for Github url parsing
# -u --url      Use user-specified URL for source download to verify
#               Example URL: https://github.com/NicoHood/gpgithub

#
# # Parse input params an ovrwrite possible default or config loaded options
# GETOPT_ARGS=$(getopt -o "hd:c:a:l:d:u:o:" \
#             -l "help,config:,apconfig:,length:,dict:,umask:,output:"\
#             -n "$PROGNAME" -- "$@")
# eval set -- "$GETOPT_ARGS"
#
# # Handle all params
# while true ; do
#     case "$1" in
#         # Settings
#         -o|--output)
#             config[OUTPUT]="$2"
#             shift
#             ;;
#
#         # Internal
#         -h|--help)
#             usage
#             exit 0
#             ;;
#         --)
#             # No more options left.
#             shift
#             break
#            ;;
#         *)
#             echo "Internal error!" 1>&2
#             exit 1
#             ;;
#     esac
#
#     shift
# done
#



# Check input param number
if [[ $# -ne 1 ]]; then
    echo "Error: Usage: ${PROGNAME} <tag>" 1>&2
    exit 1
fi

# Set default values in config array
typeset -A config
config=(
    [TAG]="$1"
    [CONFIG]=".gpgithub"
    [OUTPUT]="./archive"
    [USERNAME]="$(git config user.name)"
    [PROJECT]="$(git config --local remote.origin.url|sed -n 's#.*/\([^.]*\)\.git#\1#p')"
    [GPG]="$(git config --global user.signingkey)"
    [URL]=""
)

################################################################################
# Functions
################################################################################

gpgithub_yesno() {
    read -rp "Continue? [Y/n]" yesno
    if [[ "${yesno}" != [Yy]"es" && "${yesno}" != [Yy] && -n "${yesno}" ]]; then
        echo "Aborted by user"
        exit 0
    fi
}

msg() {
	local mesg=$1; shift
	printf "${GREEN}==>${ALL_OFF}${BOLD} ${mesg}${ALL_OFF}\n" "$@" >&2
}

msg2() {
	local mesg=$1; shift
	printf "${BLUE}  ->${ALL_OFF}${BOLD} ${mesg}${ALL_OFF}\n" "$@" >&2
}

plain() {
	local mesg=$1; shift
	printf "${BOLD}    ${mesg}${ALL_OFF}\n" "$@" >&2
}

################################################################################
msg "1. Generate new GPG key"
################################################################################

# Check for existing key
if [[ -z "${config[GPG]}" ]]; then
    if gpg --list-secret-keys | grep uid | grep -v -q revoked; then
        echo "GPG seems to be already configured on your system but git is not."
        echo "Please use gpg --list-secret-keys to show existing keys."
        echo "Afterwards set the key with git config --global user.signingkey <key>."
        echo "See the readme for mor information."
        exit 1
    else
        echo "Generating an RSA 4096 bit GPG key valid for 3 years."
        # TODO
        # https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
        git config --global user.signingkey # TODO add new fingerprint
        # TODO gpg --list-secret-keys --keyid-format LONG
        # TODO grep for email?
    fi
fi



################################################################################
msg "2. Publish your key"
################################################################################

# Check if key was just created
if [[ -z "${config[GPG]}" ]]; then
    # Refresh setting
    config[GPG]="$(git config --global user.signingkey)"

    # Upload key
    msg2 "2.1 Submit your key to a key server"
    gpg --keyserver hkps://hkps.pool.sks-keyservers.net --send-keys "${config[GPG]}"

    # Generate public key
    msg2 "2.2 Associate GPG key with github"
    echo "Please visit Github and add the following GPG key to your profile."
    echo "https://github.com/settings/keys"
    gpgithub_yesno
    gpg --armor --export "${config[GPG]}"

    msg2 "2.3 Publish your fingerprint"
    echo "Publish your GPG fingerprint (${config[GPG]}) on your project site."
    echo "Also see https://wiki.debian.org/Keysigning"
    gpgithub_yesno
fi

################################################################################
msg "3. Usage of GPG by git"
################################################################################

# Check if commit signing is enabled for this repo and ask for a switch if not
msg2 "3.1 Configure git GPG key"
# Already done in step 1 to simplify the process and make the script more reliable

msg2 "3.2 Commit signing"
if [[ $(git config commit.gpgsign) != "true" ]]; then
    echo 'Warning: Commit signing is disabled. Will enable it now.'
    gpgithub_yesno
    git config --global commit.gpgsign true
else
    echo "Commit signing already enabled."
fi

# Refresh tags
msg2 "3.3 Create signed git tag"
echo "Refreshing tags from upstream."
git pull --tags

# Check if tag exists
if ! git tag | grep "^${config[TAG]}$" -q; then
    # Create new tag if not existant
    echo "Creating signed tag ${config[TAG]} and pushing it to the remote git."
    gpgithub_yesno

    # Create and push new git tag
    git tag -s "${config[TAG]}" -m "Release ${config[TAG]}"
    git push --tags
else
    echo "Tag ${config[TAG]} already exists."
fi

################################################################################
msg "4. Creation of a signed compressed release archive"
################################################################################

# Check if output path exists and ask for creation
if [[ ! -d "${config[OUTPUT]}" ]]; then
    echo "Output path does not exist. Create ${config[OUTPUT]} ?"
    gpgithub_yesno
    mkdir -p "${config[OUTPUT]}"
fi

# Build .tar path
config[TAR]="${config[OUTPUT]}/${config[PROJECT]}-${config[TAG]}.tar"

# Create .tar.xz archive with maximum compression if not existant
msg2 "4.1 Create compressed archive"
if [[ -f "${config[TAR]}.xz" ]]; then
    echo "Archive ${config[TAR]}.xz already exists."
    gpgithub_yesno
else
    echo "Creating release archive file ${config[TAR]}.xz"
    git archive --format=tar --prefix "${config[PROJECT]}-${config[TAG]}/" "${config[TAG]}" | xz -9 > "${config[TAR]}.xz"
fi

# Create sha512 of the .tar.xz
msg2 "4.2 Create the message digest"
sha512sum "${config[TAR]}.xz" > "${config[TAR]}.xz.sha512"

# Sign .tar.xz if not existant
msg2 "4.3 Sign the sources"
if [[ -f "${config[TAR]}.xz.sig" ]]; then
    echo "Signature for ${config[TAR]}.xz already exists."
    gpgithub_yesno
else
    echo "Creating signature for file ${config[TAR]}.xz"
    gpg --output "${config[TAR]}.xz.sig" --armor --detach-sign "${config[TAR]}.xz"
fi

################################################################################
msg "5. Upload the release"
################################################################################

msg2 "5.1 Github"
echo "TODO"
# Create new Github release if not existant
# Upload files to Github
