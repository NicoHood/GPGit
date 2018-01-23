#!/bin/bash
VERSION="1.3.0"

# Avoid any encoding problems
export LANG=C

function setcolors()
{
    # Prefer terminal safe colored and bold text when tput is supported
    unset ALL_OFF BOLD BLUE GREEN RED YELLOW MAGENTA CYAN
    if tput setaf 0 &>/dev/null; then
        ALL_OFF="$(tput sgr0)"
        BOLD="$(tput bold)"
        BLUE="${BOLD}$(tput setaf 4)"
        GREEN="${BOLD}$(tput setaf 2)"
        RED="${BOLD}$(tput setaf 1)"
        YELLOW="${BOLD}$(tput setaf 3)"
        MAGENTA="${BOLD}$(tput setaf 5)"
        CYAN="${BOLD}$(tput setaf 6)"
    else
        ALL_OFF="\\e[1;0m"
        BOLD="\\e[1;1m"
        BLUE="${BOLD}\\e[1;34m"
        GREEN="${BOLD}\\e[1;32m"
        RED="${BOLD}\\e[1;31m"
        YELLOW="${BOLD}\\e[1;33m"
        MAGENTA="${BOLD}\\e[1;35m"
        CYAN="${BOLD}\\e[1;36m"
    fi
}

# Check if messages are to be printed using color
if [[ -t 2 ]]; then
    setcolors
fi

# Help page
USAGE_SHORT="Usage: gpgit [-h] [-m <msg>] [-C <path>] [-o <path>] [-p] [-n] [-i] <tag>"
read -r -d '' USAGE << EOF
Usage: gpgit [options] <tag>

GPGit ${VERSION} https://github.com/NicoHood/gpgit
A shell script that automates the process of signing Git sources via GPG.

${BOLD}Mandatory arguments:${ALL_OFF}
  <tag>                    The name of the tag to create.

${BOLD}Optional arguments:${ALL_OFF}
  -h, --help               Show this help message and exit.
  -m, --message <msg>      Use the given <msg> as the commit message.
                           If multiple -m options are given, their values are
                           concatenated as separate paragraphs.
  -C, --directory <path>   Run as if GPGit was started in <path> instead of the
                           current working directory.
  -S, --signingkey <keyid> Use the given GPG key.
  -o, --output <path>      Safe all release assets to the specified <path>.
  -p, --pre-release        Flag as Github pre-release.
  -n, --no-github          Disable Github API functionallity.
  -i, --interactive        Run in interactive mode, step-by-step.

${BOLD}Examples:${ALL_OFF}
  gpgit 1.0.0
  gpgit -p -m "First alpha release." 0.1.0
  gpgit -C git/myproject/ -o /tmp/gpgit -n -m "Internal test release." 0.0.1

${BOLD}Configuration options:${ALL_OFF}
  gpgit.signingkey <keyid>, user.signingkey <keyid>
  gpgit.output <path>
  gpgit.token <token>
  gpgit.compression <xz | gzip | bzip2 | lzip>
  gpgit.hash <sha512 | sha384 | sha256 | sha1 | md5>
  gpgit.keyserver <keyserver>
  gpgit.githubrepo <username/projectname>
  gpgit.project <projectname>

  Note: All 'gpgit.option' configuration options are also available as temporary
  command line parameter '--option' or captical environment variable 'OPTION'.

${BOLD}Examples:${ALL_OFF}
  git config --global gpgit.output ~/gpgit
  git config --local user.signingkey 97312D5EB9D7AE7D0BD4307351DAE9B7C1AE9161
  git config --local compression gzip
EOF

function interactive()
{
    if [[ "${INTERACTIVE}" == "true" ]]; then
        [[ "${#}" -gt 0 ]] && echo "${*}" >&2
        read -rp "Continue? [Y/n]" yesno
        if [[ "${yesno}" != [Yy]"es" && "${yesno}" != [Yy] && -n "${yesno}" ]]; then
            INTERACTIVE="false"
            warning "Aborted by user."
            exit 0
        fi
    fi
}

function msg()
{
    echo "${GREEN}==>${ALL_OFF}${BOLD} ${1}${ALL_OFF}" >&2
}

function msg2()
{
    echo "${BLUE}  ->${ALL_OFF}${BOLD} ${1}${ALL_OFF}" >&2
}

function plain()
{
    echo "    ${1}" >&2
}

function warning()
{
    echo "${YELLOW}==> WARNING:${ALL_OFF}${BOLD} ${1}${ALL_OFF}" >&2
    interactive
}

function error()
{
    echo "${RED}==> ERROR:${ALL_OFF}${BOLD} ${1}${ALL_OFF}" >&2
}

function die()
{
    error "${1}"
    exit 1
}

function kill_exit
{
    echo ""
    INTERACTIVE="false"
    warning "Exited due to user intervention."
    exit 1
}

function command_not_found_handle
{
    die "${BASH_SOURCE[0]}: line ${BASH_LINENO[0]}: ${1}: command not found."
}

function check_dependency()
{
    local RET=0
    for dependency in "${@}"
    do
        if ! command -v "${dependency}" &> /dev/null; then
            error "Required dependency '${dependency}' not found."
            RET=1
        fi
    done
    return "${RET}"
}

# Trap errors
set -o errexit -o errtrace -u
trap 'die "Error on or near line ${LINENO}. Please report this issue: https://github.com/NicoHood/gpgit/issues"' ERR
trap kill_exit SIGTERM SIGINT SIGHUP

# Parse input params an ovrwrite possible default or config loaded options
GETOPT_ARGS=$(getopt -o "hm:C:k:u:s:S:o:O:pndi" \
            -l "help,message:,directory:,signingkey:,local-user:,gpg-sign:,output:,pre-release,no-github,interactive,token:,compression:,hash:,keyserver:,githubrepo:,project:,debug,color:"\
            -n "gpgit" -- "${@}") || die "${USAGE_SHORT}"
eval set -- "$GETOPT_ARGS"

# Handle all params
while true ; do
    case "$1" in
        # Command line options
        -h|--help)
            echo "${USAGE}" >&2
            exit 0
            ;;
        -m|--message)
            MESSAGE+="$2\\n"
            shift
            ;;
        -C|--directory)
            cd "${2}"
            shift
            ;;
        -o|-O|--output)
            OUTPUT="${2}"
            shift
            ;;
        -k|-u|-s|-S|--signingkey|--local-user|--gpg-sign)
            SIGNINGKEY="${2}"
            shift
            ;;
        -p|--prerelease)
            PRERELEASE="true"
            ;;
        -n|--no-github)
            GITHUB=""
            ;;
        -i|--interactive)
            INTERACTIVE="true"
            ;;
        # Additional config options
        --token)
            TOKEN="${2}"
            shift
            ;;
        --compression)
            COMPRESSION="${2}"
            shift
            ;;
        --hash)
            HASH="${HASH}"
            shift
            ;;
        --keyserver)
            KEYSERVER="${2}"
            shift
            ;;
        --githubrepo)
            GITHUBREPO="${2}"
            shift
            ;;
        --project)
            PROJECT="${2}"
            shift
            ;;
        # Internal
        --color)
            # En/disable colors
            if [[ "${2}" == "never" ]]; then
                ALL_OFF="" BOLD="" BLUE="" GREEN="" RED="" YELLOW="" MAGENTA="" CYAN=""
            elif [[ "${2}" == "force" ]]; then
                setcolors
            fi
            shift
            ;;
        -d|--debug)
            set -x
            ;;
        --)
            # No more options left.
            shift
            break
           ;;
        *)
            die "Internal error."
            ;;
    esac
    shift
done
readonly ALL_OFF BOLD BLUE GREEN RED YELLOW MAGENTA CYAN

# Get tag parameter
if [[ "$#" -lt 1 ]]; then
    die "${USAGE_SHORT}"
fi
TAG="${1}"
shift

# Check if run inside Git directory
check_dependency git sed grep awk || die "Please check your \$PATH variable or install the missing dependency."
if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]]; then
    die "Not a Git repository: $(pwd)"
fi

# Initialize variable config/defaults
INTERACTIVE=${INTERACTIVE:-"$(git config gpgit.interactive || true)"}
MESSAGE="${MESSAGE:-"Release ${TAG}"$'\n\nCreated with GPGit\nhttps://github.com/NicoHood/gpgit'}"
KEYSERVER="${KEYSERVER:-"$(git config gpgit.keyserver || true)"}"
KEYSERVER="${KEYSERVER:-"hkps://pgp.mit.edu"}"
COMPRESSION="${COMPRESSION:-"$(git config gpgit.compression || true)"}"
COMPRESSION="${COMPRESSION:-xz}"
HASH="${HASH:-"$(git config gpgit.hash || true)"}"
HASH="${HASH:-sha512}"
GPG_BIN="${GPG_BIN:-"$(git config gpg.program || true)"}"
GPG_BIN="${GPG_BIN:-gpg2}"
OUTPUT="${OUTPUT:-"$(git config gpgit.output || true)"}"
OUTPUT="${OUTPUT:-"./gpgit"}"
PROJECT="${PROJECT:-"$(git config gpgit.project || true)"}"
PROJECT="${PROJECT:-"$(git config --local remote.origin.url | sed -n 's#.*/\([^.]*\)\.git#\1#p')"}"
FILENAME="${FILENAME:-"${PROJECT}-${TAG}"}"
SIGNINGKEY="${SIGNINGKEY:-"$(git config gpgit.signingkey || true)"}"
SIGNINGKEY="${SIGNINGKEY:-"$(git config user.signingkey || true)"}"
TOKEN="${TOKEN:-"$(git config gpgit.token || true)"}"
GPG_USER="${GPG_USER:-"$(git config user.name || true)"}"
GPG_USER="${GPG_USER:-"${USER}"}"
GPG_EMAIL="${GPG_EMAIL:-"$(git config user.email || true)"}"
FILE="${OUTPUT}/${FILENAME}.tar.${COMPRESSION}"
GITHUBREPO="${GITHUBREPO:-"$(git config gpgit.githubrepo || true)"}"
GITHUBREPO="${GITHUBREPO:-"$(git config --local remote.origin.url | sed -e 's/.*github.com[:/]//' | sed -e 's/.git$//')"}"
GITHUB="${GITHUB:-"$(git config --local remote.origin.url | grep -i 'github.com')"}"
PRERELEASE="${PRERELEASE:-"false"}"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
NEW_SIGNINGKEY="false"

# Check if dependencies are available
# Dependencies: bash, gnupg2, git, tar, xz, coreutils, gawk, grep, sed
# Optional dependencies: gzip, bzip2, lzip, file, jq, curl
check_dependency "${GPG_BIN}" "${COMPRESSION}" "${HASH}sum" \
     || die "Please check your \$PATH variable or install the missing dependencies."

# Print initial welcome message with version information
echo "${BOLD}GPGit ${VERSION} https://github.com/NicoHood/gpgit${ALL_OFF}" >&2
echo "" >&2

if [[ -z "${INTERACTIVE}" ]]; then
    INTERACTIVE=true
    interactive "Running GPGit for the first time. This will guide you through all steps of secure source code signing once. If you wish to run interactively again pass the -i option to GPGit. For more options see --help."
    git config --global gpgit.interactive "false"
fi

####################################################################################################
msg "1. Generate a new GPG key"
####################################################################################################

msg2 "1.1 Strong, unique, secret passphrase"
plain "See: https://github.com/NicoHood/gpgit#11-strong-unique-secret-passphrase"

# Create new GPG key if required
msg2 "1.2 Key generation"
if [[ -z "${SIGNINGKEY}" ]]; then
    # Ask user about used name and email
    plain "No GPG key registered with Git. Generating a new GPG key."
    if [[ -n "$(${GPG_BIN} --list-secret-keys)" ]]; then
        warning "Detected existing GPG keys."
        plain "You can abort the script and set an existing key with:"
        plain "${GPG_BIN} --list-secret-keys"
        plain "git config --global user.signingkey <fingerprint>"
    fi
    read -rp "Enter username: " -e -i "${GPG_USER}" GPG_USER
    [[ -z "${GPG_USER}" ]] && die "Empty username specified"
    read -rp "Enter email: " -e -i "${GPG_EMAIL}" GPG_EMAIL
    [[ -z "${GPG_EMAIL}" ]] && die "Empty email specified"
    echo ""

    # Generate strongest possible GPG key (ECC or RSA4096, depending on gnupg version)
    interactive "Will generate the new GPG key with the selected parameters now."
    ${GPG_BIN} --quick-generate-key "${GPG_USER} <${GPG_EMAIL}>" future-default default 1y \
        &> /dev/null || die "GPG key generation aborted."
    SIGNINGKEY=$(${GPG_BIN} --with-colons --list-secret-keys | grep "${GPG_USER} <${GPG_EMAIL}>" -B 2 | awk -F: '$1 == "fpr" {print $10;}')
    NEW_SIGNINGKEY="true"
    plain "Your new GPG fingerprint is: '${SIGNINGKEY}'"
else
    # Check if the full fingerprint is used
    if [[ ${#SIGNINGKEY} -ne 40 ]]; then
        die "Invalid GPG key fingerprint: '${SIGNINGKEY}'"
    fi

    # Print email and key information
    SIGNINGKEY_OUTPUT="$(${GPG_BIN} --with-colons -k "${SIGNINGKEY}" 2>/dev/null)" || die "No public GPG key for fingerprint '${SIGNINGKEY}' found."
    GPG_USER_EMAIL="$(echo "${SIGNINGKEY_OUTPUT}" | awk -F: '$1 == "uid" {print $10; exit}')"
    plain "Using existing GPG key: '${GPG_USER_EMAIL}'"
    plain "Fingerprint: '${SIGNINGKEY}'"
    interactive
fi


####################################################################################################
msg "2. Publish your key"
####################################################################################################

if [[ "${NEW_SIGNINGKEY}" == "true" ]]; then
    msg2 "2.1 Send GPG key to a key server"
    plain "Registering new GPG key with Git and uploading it to keyserver '${KEYSERVER}'."
    interactive
    ${GPG_BIN} --keyserver "${KEYSERVER}" --send-keys "${SIGNINGKEY}" &> /dev/null
else
    msg2 "2.1 Send GPG key to a key server"
    plain "Make sure your key is available on a keyserver:"
    plain "${GPG_BIN} --search-keys ${SIGNINGKEY}"
    plain "${GPG_BIN} --keyserver ${KEYSERVER} --send-keys ${SIGNINGKEY}"
    interactive
fi

msg2 "2.2 Publish full fingerprint"
plain "Please publish the full GPG fingerprint on the project page."
interactive

msg2 "2.3 Associate GPG key with Github"
plain "Paste the following command output to your Github profile GPG key settings:"
plain "https://github.com/settings/keys"
plain "${GPG_BIN} --armor --export ${SIGNINGKEY}"
if [[ "${NEW_SIGNINGKEY}" == "true" ]]; then
    ${GPG_BIN} --armor --export "${SIGNINGKEY}"
fi
interactive


####################################################################################################
msg "3. Use Git with GPG"
####################################################################################################

# Set new signingkey
msg2 "3.1 Configure Git GPG key"
if [[ "${NEW_SIGNINGKEY}" == "true" ]]; then
    plain "Configuring Git with the new GPG key."
    interactive
    git config --global user.signingkey "${SIGNINGKEY}"
else
    plain "Git already configured with your GPG key."
    interactive
fi

# Enable commit signing
msg2 "3.2 Enable commit signing"
if [[ "$(git config --global commit.gpgsign || true)" != "true" ]]; then
    # Enable global commit signing. Can be still disabled locally.
    plain "Enabling global commit signing."
    git config --global commit.gpgsign true
else
    plain "Commit signing already enabled."
fi

# Check if tag exists
msg2 "3.3 Create signed Git tag"
plain "Fetching Git tags from origin."
interactive
git fetch origin --tags &> /dev/null
if [[ -z "$(git tag -l "${TAG}")" ]] ; then
    plain "Creating signed tag '${TAG}' and pushing it to the remote Git."
    interactive
    git tag -s "${TAG}" -m "${MESSAGE}" -u "${SIGNINGKEY}"
    git push origin "refs/tags/${TAG}" &> /dev/null
else
    warning "Tag '${TAG}' already exists."
fi


####################################################################################################
msg "4. Create a signed release archive"
####################################################################################################

# Create output directory
interactive "Creating output directory if not existing."
mkdir -p "${OUTPUT}"

# Create new archive
msg2 "4.1 Create compressed archive"
if [[ ! -f "${FILE}" ]]; then
    plain "Creating new release archive: '${FILE}'"
    interactive
    git archive --format=tar --prefix "${FILENAME}/" "${TAG}" | "${COMPRESSION}" --best > "${FILE}"
else
    warning "Found existing archive '${FILE}'."
fi

# Sign archive
msg2 "4.2 Sign the archive"
if [[ ! -f "${FILE}.asc" ]]; then
    plain "Creating GPG signature: '${FILE}.asc'"
    interactive
    ${GPG_BIN} --digest-algo SHA512 -u "${SIGNINGKEY}" --output "${FILE}.asc" --armor --detach-sign "${FILE}"
else
    warning "Found existing signature '${FILE}.asc'."
fi

# Creating hash
msg2 "4.3 Create the message digest"
if [[ ! -f "${FILE}.${HASH}" ]]; then
    plain "Creating message digest: '${FILE}.${HASH}'"
    interactive
    "${HASH}sum" "${FILE}" > "${FILE}.${HASH}"
else
    warning "Found existing message digest '${FILE}.${HASH}'."
fi


####################################################################################################
msg "5. Upload the release"
####################################################################################################

msg2 "5.1 Configure HTTPS download server"
if [[ -z "${GITHUB}" ]]; then
    plain "Please configure HTTPS for your download server."
else
    plain "Github uses well configured https."
fi
interactive

function get_token()
{
    if [[ -z "${TOKEN}" ]]; then
        plain "Please enter your Github token or generate a new one (permission: 'public_repo'):"
        plain "https://github.com/settings/tokens"
        plain "Tip: Configure your Github token permanant with:"
        plain "git config --global gpgit.token <token>"
        read -rs TOKEN
    fi
}

function github_upload_asset()
{
    local filename="${1}"
    local file="${2}"
    local message
    local mimetype
    mimetype="$(file -b --mime-type "${filename}")"

    # Upload Github asset
    get_token
    plain "Uploading release asset '${filename}'"
    interactive
    if ! RESULT=$(curl --proto-redir =https -s \
            "https://uploads.github.com/repos/${GITHUBREPO}/releases/${GITHUB_RELEASE_ID}/assets?name=${filename}" \
            -H "Content-Type: ${mimetype}" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Authorization: token ${TOKEN}" \
            --data-binary @"${file}"); then
        die "Uploading file ${filename} to Github failed."
    fi

    # Abort in API error
    message="$(echo "${RESULT}" | jq -r .message)"
    if [[ "${message}" != "null" ]]; then
        die "Github API message: ${message}"
    fi
}

# Upload to Github
msg2 "5.2 Upload to Github"
if [[ -z "${GITHUB}" ]]; then
    plain "Please upload the release files manually"
    interactive
else
    if check_dependency jq file curl; then
        # Parse existing Github release
        if ! GITHUB_RELEASE="$(curl --proto-redir =https -s \
                "https://api.github.com/repos/${GITHUBREPO}/releases/tags/${TAG}")"; then
            die "Accessing Github failed."
        fi

        # Check for existing release and assets
        GITHUB_RELEASE_ID="$(echo "${GITHUB_RELEASE}" | jq -r .id)"
        GITHUB_ASSETS="$(echo "${GITHUB_RELEASE}" | jq -r .assets[]?.name)"

        # Create new Github release
        if [[ "${GITHUB_RELEASE_ID}" == "null" ]]; then
            plain "Creating new Github release '${TAG}'."
            interactive
            API_JSON=$(printf '{"tag_name": "%s","target_commitish": "%s","name": "%s","body": "%s","draft": false,"prerelease": %s}' \
                       "${TAG}" "${BRANCH}" "${TAG}" "${MESSAGE//$'\n'/'\n'}" "${PRERELEASE}")
            get_token
            if ! GITHUB_RELEASE=$(curl --proto-redir =https -s --data "${API_JSON}" \
                    "https://api.github.com/repos/${GITHUBREPO}/releases" \
                    -H "Accept: application/vnd.github.v3+json" \
                    -H "Authorization: token ${TOKEN}" ); then
                die "Uploading release to Github failed"
            fi

            # Abort on API error
            message="$(echo "${GITHUB_RELEASE}" | jq -r .message)"
            if [[ "${message}" != "null" ]]; then
                die "Github API message: ${message}"
            fi

            # Safe new ID
            GITHUB_RELEASE_ID="$(echo "${GITHUB_RELEASE}" | jq -r .id)"
        else
            warning "Found existing release on Github."
        fi

        # Upload archive
        if grep -q "^${FILENAME}.tar.${COMPRESSION}$" <(echo "${GITHUB_ASSETS}"); then
            warning "Found existing archive on Github."
        else
            github_upload_asset "${FILENAME}.tar.${COMPRESSION}" "${FILE}"
        fi

        # Upload signature
        if grep -q "^${FILENAME}.tar.${COMPRESSION}.asc$" <(echo "${GITHUB_ASSETS}"); then
            warning "Found existing signature on Github."
        else
            github_upload_asset "${FILENAME}.tar.${COMPRESSION}.asc" "${FILE}.asc"
        fi

        # Upload message digest
        if grep -q "^${FILENAME}.tar.${COMPRESSION}.${HASH}$" <(echo "${GITHUB_ASSETS}"); then
            warning "Found existing message digest on Github."
        else
            github_upload_asset "${FILENAME}.tar.${COMPRESSION}.${HASH}" "${FILE}.${HASH}"
        fi
    else
        warning "Please upload the release files manually to Github."
    fi
fi

msg "Finished without errors."
