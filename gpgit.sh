#!/bin/bash

# Stop on errors
set -e -u -o pipefail

# Avoid any encoding problems
export LANG=C

PROGNAME=$(basename "$0")

usage()
{
    echo "Usage: ${PROGNAME} <tag> [options]"
    echo
    echo 'Mandatory parameters:'
    echo '<tag>           Tagname'
    echo
    echo 'Actions:'
    echo '-h --help       Show this help message'
    echo
    echo 'Options:'
    echo '-o, --output    The output path of the .tar.gz, .sig and sha512'
    echo '                Default: "git rev-parse --show-toplevel)/archive"'
    echo '-u, --username  Username of the user. Used for GPG key generation.'
    echo '                Default: git config user.name'
    echo '-e, --email     Email of the user. Used for GPG key generation.'
    echo '                Default: "git config user.email"'
    echo '-p, --project   The name of the project. Used for archive geneation.'
    echo "                Default: \"git config --local remote.origin.url \\"
    echo "                           | sed -n \'s#.*/\([^.]*\)\.git#\1#p\'\""
	echo '-g, --gpg       Specify (full) GPG fingerprint to use for signing.'
    echo '                Default: "git config user.signingkey"'
	echo '-m, --message   Specify the tag message.'
	echo '                Default: "Release <tag>"'
	echo '-y, --yes       Assume "yes" on all questions.'
}

################################################################################
# Functions
################################################################################

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

warning() {
    local mesg=$1; shift
    printf "${YELLOW}==> WARNING:${ALL_OFF}${BOLD} ${mesg}${ALL_OFF}\n" "$@" >&2
}

error() {
    local mesg=$1; shift
    printf "${RED}==> ERROR:${ALL_OFF}${BOLD} ${mesg}${ALL_OFF}\n" "$@" >&2
}

info() {
    local mesg=$1; shift
    printf "${YELLOW}[!]:${ALL_OFF}${BOLD} ${mesg}${ALL_OFF}\n" "$@" >&2
}

gpgit_yesno() {
	[[ "${config[YES]}" == true ]] && return
    read -rp "${BOLD}    Continue? [Y/n]${ALL_OFF}" yesno
    if [[ "${yesno}" != [Yy]"es" && "${yesno}" != [Yy] && -n "${yesno}" ]]; then
        warning "Aborted by user"
        exit 0
    fi
}

################################################################################
# Parameters
################################################################################

# Check if inside a git folder
if [[ "$(git rev-parse --is-inside-work-tree)" != "true" ]]; then
    error "Not a git repository."
fi

# Check input param number
if [[ $# -lt 1 ]]; then
    error "Usage: ${PROGNAME} <tag>" 1>&2
    plain "Use --help for more information."
    exit 1
fi

# Print help
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage 1>&2
    exit 0
fi

# Set default values in config array
typeset -A config
config=(
    [TAG]="$1"
    [OUTPUT]="$(git rev-parse --show-toplevel)/archive"
    [USERNAME]="$(git config user.name)"
    [EMAIL]="$(git config user.email)"
    [PROJECT]="$(git config --local remote.origin.url | sed -n 's#.*/\([^.]*\)\.git#\1#p')"
    [GPG]="$(git config user.signingkey)"
	[MESSAGE]="Release $1"
	[YES]=false
)
shift

# Parse input params an ovrwrite possible default or config loaded options
GETOPT_ARGS=$(getopt -o "ho:u:e:p:g:m:y" \
            -l "help,output:,username:,email:,project:,gpg:,message:,yes"\
            -n "$PROGNAME" -- "$@")
eval set -- "$GETOPT_ARGS"

# Handle all params
while true ; do
    case "$1" in
        # Options
        -o|--output)
            config[OUTPUT]="$2"
            shift
            ;;
        -u|--username)
            config[USERNAME]="$2"
            shift
            ;;
        -e|--email)
            config[EMAIL]="$2"
            shift
            ;;
        -p|--project)
            config[PROJECT]="$2"
            shift
            ;;
		-g|--gpg)
            config[GPG]="$2"
            shift
            ;;
		-m|--message)
			config[MESSAGE]="$2"
			shift
			;;
		-y|--yes)
			config[YES]=true
			;;
        # Internal
        -h|--help)
            usage 1>&2
            exit 0
            ;;
        --)
            # No more options left.
            shift
            break
           ;;
        *)
            error "Internal error!"
            exit 1
            ;;
    esac
    shift
done

################################################################################
msg "1. Generate new GPG key"
################################################################################

# Check for existing key
if [[ -z "${config[GPG]}" ]]; then
    if gpg --list-secret-keys | grep uid | grep -v -q revoked; then
        error "GPG seems to be already configured on your system but git is not."
        plain "Please use gpg --list-secret-keys to show existing keys."
        plain "Afterwards set the key with git config --global user.signingkey <key>."
        plain "See the readme for more information."
        exit 1
    else
        plain "Generating an RSA 4096 GPG key for ${config[USERNAME]} <${config[EMAIL]}> valid for 3 years."
        gpgit_yesno

        # Generate ECC key command (currently not supported by Github)
        #gpg --quick-generate-key "testuser (comment) <name@mail.com>" future-default default 3y

        # Generate RSA key command
        # https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
        # gpg: revocation certificate stored as '/tmp/tmp.81v03YSxmI/openpgp-revocs.d/F4EDF85EFF03D746D17094D3C28B8F6BCCDF8671.rev'
        config[GPG]="$(gpg --batch --generate-key <( cat << EOF
            Key-Type: RSA
            Key-Length: 4096
            Key-Usage: cert sign auth
            Subkey-Type: RSA
            Subkey-Length: 4096
            Subkey-Usage: encrypt
            Name-Real: ${config[USERNAME]}
            #Name-Comment: Generated with gpgit
            Name-Email: ${config[EMAIL]}
            Expire-Date: 3y
            # Preferences: TODO https://security.stackexchange.com/questions/82216/how-to-change-default-cipher-in-gnupg-on-both-linux-and-windows
            %ask-passphrase
            %echo We need to generate a lot of random bytes. It is a good idea to perform
            %echo some other action (type on the keyboard, move the mouse, utilize the
            %echo disks) during the prime generation; this gives the random number
            %echo generator a better chance to gain enough entropy.
            %commit
            %echo Key generation finished
EOF
        ) 2>&1 | tee -a /dev/fd/2 | grep "revocation certificate stored as " \
               | sed 's,.*/\(.*\).rev.*,\1,')"
        NEW_GPG_KEY=true

        # Print new fingerprint
        plain "Your new GPG fingerprint is: ${config[GPG]}"
        gpg -u "${config[GPG]}" --list-secret-keys --keyid-format LONG
    fi
else
    plain "Key already generated. Using key: ${config[GPG]}"
	NEW_GPG_KEY=false

	# Check if the full fingerprint is used
	if [[ ${#config[GPG]} -ne 40 ]]; then
		error "Please specify the full fingerprint."
		exit 1
	fi

    # Check if key exists
    if ! gpg --keyid-format LONG --list-secret-keys "0x${config[GPG]}"; then
        error "This GPG key is not known on this system."
        plain "Check your git config or your GNUPGHOME variable."
        exit 1
    fi
fi

################################################################################
msg "2. Publish your key"
################################################################################

# Check if key was just created
if [[ "${NEW_GPG_KEY}" = true ]]; then
    # Refresh setting
    config[GPG]="$(git config --global user.signingkey)"

    # Upload key
    msg2 "2.1 Submit your key to a key server"
    plain "Uploading key ${config[GPG]} to hkps://hkps.pool.sks-keyservers.net"
    gpgit_yesno
    gpg --keyserver hkps://hkps.pool.sks-keyservers.net --send-keys "${config[GPG]}"

    # Generate public key
    msg2 "2.2 Associate GPG key with github"
    plain "Please visit Github and add the following GPG key to your profile."
    plain "https://github.com/settings/keys"
    gpgit_yesno
    gpg --armor --export "${config[GPG]}"

    msg2 "2.3 Publish your fingerprint"
    plain "Publish your GPG fingerprint (${config[GPG]}) on your project site."
    plain "Also see https://wiki.debian.org/Keysigning"
    gpgit_yesno
else
	plain "Assuming key was already publish with its generation. If not please do so."
fi

################################################################################
msg "3. Usage of GPG by git"
################################################################################

# Differenciate between new created key and (temporary) different key
if [[ "${NEW_GPG_KEY}" = true ]]; then
    GIT_CONFIG="global"
else
    GIT_CONFIG="local"
fi

#  3.1 Configure git GPG key
msg2 "3.1 Configure git GPG key"
if [[ "${config[GPG]}" != "$(git config user.signingkey)" ]]; then
    # If the key differs from the local>global>system configured key, set it locally
	plain "Git is not configured with this key."
    plain "Configuring ${GIT_CONFIG} git settings with your GPG key."
    gpgit_yesno
    git config --"${GIT_CONFIG}" user.signingkey "${config[GPG]}"
else
    plain "Git already configured with your GPG key"
fi

# Check if commit signing is enabled for this repo and ask for a switch if not
msg2 "3.2 Commit signing"
if [[ $(git config commit.gpgsign) != true ]]; then
    warning "Commit signing is disabled. Will enable it now ${GIT_CONFIG}ly."
    gpgit_yesno
    git config --"${GIT_CONFIG}" commit.gpgsign true
else
    plain "Commit signing already enabled."
fi

# Refresh tags
msg2 "3.3 Create signed git tag"
plain "Refreshing tags from upstream."
gpgit_yesno
git pull --tags

# Check if tag exists
if ! git tag | grep "^${config[TAG]}$" -q; then
    # Check if every added file has been commited
    if ! git diff --cached --exit-code > /dev/null; then
        warning 'You have added new changes but did not commit them yet. See "git status" or "git diff".'
        gpgit_yesno
    fi

    # Create new tag if not existant
    plain "Creating signed tag ${config[TAG]} and pushing it to the remote git."
    gpgit_yesno

    # Create and push new git tag
    git tag -s "${config[TAG]}" -m "${config[MESSAGE]}"
    git push --tags
else
    plain "Tag ${config[TAG]} already exists."
fi

################################################################################
msg "4. Creation of a signed compressed release archive"
################################################################################

# Check if output path exists and ask for creation
if [[ ! -d "${config[OUTPUT]}" ]]; then
    plain "Output path does not exist. Create ${config[OUTPUT]} ?"
    gpgit_yesno
    mkdir -p "${config[OUTPUT]}"
fi

# Build .tar path
config[TAR]="${config[OUTPUT]}/${config[PROJECT]}-${config[TAG]}.tar"

# Create .tar.xz archive with maximum compression if not existant
# TODO detect for github url and download + compare archive instead
msg2 "4.1 Create compressed archive"
if [[ -f "${config[TAR]}.xz" ]]; then
    plain "Archive ${config[TAR]}.xz already exists."
    gpgit_yesno
else
    plain "Creating release archive file ${config[TAR]}.xz"
	gpgit_yesno
    git archive --format=tar --prefix "${config[PROJECT]}-${config[TAG]}/" "${config[TAG]}" | xz -9 > "${config[TAR]}.xz"
fi

# Create sha512 of the .tar.xz
msg2 "4.2 Create the message digest"
gpgit_yesno
sha512sum "${config[TAR]}.xz" > "${config[TAR]}.xz.sha512"

# Sign .tar.xz if not existant
msg2 "4.3 Sign the sources"
if [[ -f "${config[TAR]}.xz.sig" ]]; then
    plain "Signature for ${config[TAR]}.xz already exists."
    gpgit_yesno
else
    plain "Creating signature for file ${config[TAR]}.xz"
	gpgit_yesno
    gpg --local-user "${config[GPG]}" --output "${config[TAR]}.xz.sig" --armor --detach-sign "${config[TAR]}.xz"
fi

################################################################################
msg "5. Upload the release"
################################################################################

#TODO
msg2 "5.1 Github"
plain "TODO"
# Create new Github release if not existant
# Upload files to Github
#
# # Create github release and upload the signature
# # http://www.barrykooij.com/create-github-releases-via-command-line/
# # https://developer.github.com/v3/repos/releases/
# # https://developer.github.com/changes/2013-09-25-releases-api/
# read -rsp "Enter your Github token (Github->Settings->Personal access tokens; public repo access):" TOKEN
# API_JSON=$(printf '{"tag_name": "%s","target_commitish": "%s","name": "%s","body": "Release %s","draft": false,"prerelease": false}' "${TAG}" "${BRANCH}" "${TAG}" "${TAG}")
# if ! RESULT=$(curl --data "$API_JSON" "https://api.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases" \
# -H "Accept: application/vnd.github.v3+json" -H "Authorization: token ${TOKEN}" ); then
#     echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
#     exit 1
# fi
# RELEASE_ID=$(echo "${RESULT}" | grep '^  "id": ' | tr -dc '[:digit:]')
#
# if ! curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sig" \
# -H "Content-Type: application/pgp-signature" \
# -H "Accept: application/vnd.github.v3+json" \
# -H "Authorization: token ${TOKEN}" \
# --data-binary @"${TAR_GZ}.sig"; then
#     echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
#     exit 1
# fi
#
# if ! curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sha512" \
# -H "Content-Type: text/sha512" \
# -H "Accept: application/vnd.github.v3+json" \
# -H "Authorization: token ${TOKEN}" \
# --data-binary @"${TAR_GZ}.sha512"; then
#     echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
#     exit 1
# fi
