#!/usr/bin/env bash

# Copyright (c) 2016-2021 NicoHood
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.

VERSION="1.5.0"

# Avoid any encoding problems
export LANG=C

function setcolors()
{
    # Prefer terminal safe colored and bold text when tput is supported
    unset ALL_OFF BOLD BLUE GREEN RED YELLOW
    if tput setaf 0 &>/dev/null; then
        ALL_OFF="$(tput sgr0)"
        BOLD="$(tput bold)"
        BLUE="${BOLD}$(tput setaf 4)"
        GREEN="${BOLD}$(tput setaf 2)"
        RED="${BOLD}$(tput setaf 1)"
        YELLOW="${BOLD}$(tput setaf 3)"
    else
        ALL_OFF="\\e[1;0m"
        BOLD="\\e[1;1m"
        BLUE="${BOLD}\\e[1;34m"
        GREEN="${BOLD}\\e[1;32m"
        RED="${BOLD}\\e[1;31m"
        YELLOW="${BOLD}\\e[1;33m"
    fi
}

# Check if messages are to be printed using color
if [[ -t 2 ]]; then
    setcolors
fi

# Help page
USAGE_SHORT="Usage: gpgit [-h] [-m <msg>] [-C <path>] [-u <keyid>] [-o <path>] [-p] [-f] [-i] <tagname> [<commit> | <object>]"
read -r -d '' USAGE << EOF
Usage: gpgit [options] <tagname> [<commit> | <object>]

GPGit ${VERSION} https://github.com/NicoHood/gpgit
A shell script that automates the process of signing Git sources via GPG.

${BOLD}Mandatory arguments:${ALL_OFF}
  <tagname>                The name of the tag to create.

${BOLD}Optional arguments:${ALL_OFF}
  -h, --help               Show this help message and exit.
  -m, --message <msg>      Use the given <msg> as the commit message.
                           If multiple -m options are given, their values are
                           concatenated as separate paragraphs.
  -C, --directory <path>   Run as if GPGit was started in <path> instead of the
                           current working directory.
  -u, --local-user <keyid> Use the given GPG key (same as --signingkey).
  -o, --output <path>      Safe all release assets to the specified <path>.
  -a, --asset              Add additional Github assets, e.g. software bundles.
  -t, --title              Custom Github release title (instead of tag name).
  -p, --pre-release        Flag as Github pre-release.
  -f, --force              Force the recreation of Git tag and release assets.
  -i, --interactive        Run in interactive mode, step-by-step.
      --<option>           Temporary set a 'gpgit.<option>' from config below.
  <commit>, <object>       The object that the new tag will refer to.

${BOLD}Examples:${ALL_OFF}
  gpgit 1.0.0
  gpgit -p -m "First alpha release." 0.1.0 --hash "sha256 sha512"
  gpgit -C git/myproject/ -o /tmp/gpgit -n -m "Internal test release." 0.0.1

${BOLD}Configuration options:${ALL_OFF}
  gpgit.signingkey <keyid>, user.signingkey <keyid>
  gpgit.output <path>
  gpgit.token <token>
  gpgit.compression <xz | gzip | bzip2 | lzip | zstd | zip>
  gpgit.hash <sha512 | sha384 | sha256 | sha1 | md5>
  gpgit.changelog <auto | true | false>
  gpgit.github <auto | true | false>
  gpgit.githubrepo <username/projectname>
  gpgit.project <projectname>
  gpgit.keyserver <keyserver>

${BOLD}Examples:${ALL_OFF}
  git config --global gpgit.output ~/gpgit
  git config --local user.signingkey 97312D5EB9D7AE7D0BD4307351DAE9B7C1AE9161
  git config --local gpgit.compression "xz zip"
EOF

function interactive()
{
    if [[ -z "${INTERACTIVE}" || "${INTERACTIVE}" == "true" ]]; then
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
    local ret=0
    for dependency in "${@}"
    do
        if ! command -v "${dependency}" &> /dev/null; then
            error "Required dependency '${dependency}' not found."
            ret=1
        fi
    done
    return "${ret}"
}

# Extracts the relevant changelog section for the provided tag.
# See keep a changelog spec:
# https://keepachangelog.com/en/1.0.0/
function parse_keepachangelog()
{
    local changelog="${1}"
    local tag="${2}"
    local commit="${3}"
    local skip_lines="false"
    local ret=()

    # Process changelog
    while read -r line ; do
        # 1. Search for h2 headline and get the first word (the version)
        # 2. Strip any leading markdown link "["
        # 3. Strip any trailing markdown link "]" or "](/url)"
        # 4. Do an exact match against the specified tag
        if echo "${line}" | \
          sed -n "s/^## \(\S\+\)\($\| .*\)/\1/p" | \
          sed "s/\[//g" | \
          sed "s/\].*//g" | \
          grep -q -F "${tag}"; then
            ret+=("${line}")

        # When the tag was already found, add each following line to the output
        elif [[ "${#ret[@]}" -gt 0 ]]; then
            # But ignore everything after the next h1 or h2 section (except footnote links)
            if echo "${line}" | grep -q -E "^##? .+"; then
                skip_lines="true"
                continue
            fi

            # Skip links, except the current tag
            local footnote
            footnote="$(echo "${line}" | sed -n "s/^\[\(\S\+\)\]: \S\+$/\1/p")"
            if [[ "${skip_lines}" != "true" && -z "${footnote}" ]] \
              || grep -F -q "${tag}" <<< "${footnote}"; then
                ret+=("${line}")
            fi
        fi
    done < <(git show "${commit}:${changelog}")

    if [[ "${#ret[@]}" -eq 0 ]]; then
        echo "No corresponding changelog section for tag ${tag} found."
        return 1
    fi

    printf '%s\n' "${ret[@]}"
    return 0
}

# Trap errors
set -o errexit -o errtrace -u
trap 'die "Error on or near line ${LINENO}. Please report this issue: https://github.com/NicoHood/gpgit/issues"' ERR
trap kill_exit SIGTERM SIGINT SIGHUP

# Initialize variables
unset INTERACTIVE MESSAGE KEYSERVER COMPRESSION HASH OUTPUT PROJECT SIGNINGKEY
unset TOKEN GPG_USER GPG_EMAIL GITHUB_REPO_NAME GITHUB PRERELEASE BRANCH GPG_BIN
unset FORCE NEW_SIGNINGKEY REMOTE CHANGELOG CHANGELOG_FILE GITHUB_TITLE
declare -A GITHUB_ASSET=()
declare -a HASH=() COMPRESSION=()

# BSD getopt works completely different from gnu-getopt,
# so check if have an alternative getopt install.
if [[ -x /usr/local/opt/gnu-getopt/bin/getopt ]]; then
    export PATH="/usr/local/opt/gnu-getopt/bin/:${PATH}"
fi

# Use gnu date on mac
if command -v gdate &> /dev/null; then
    alias date="gdate"
fi

# Parse input params an ovrwrite possible default or config loaded options
GETOPT_PARAMS_SHORT="hvcm:C:k:u:s:S:o:O:a:t:pnfdi"
GETOPT_ARGS="$(getopt -o "${GETOPT_PARAMS_SHORT}" \
            -l "help,version,message:,directory:,signingkey:,local-user:,gpg-sign:,output:,asset:,title:,pre-release,no-github,force,interactive,changelog:,token:,compression:,hash:,keyserver:,github:,githubrepo:,project:,remote:,debug,color:"\
            -n "gpgit" -- "${@}")" || die "${USAGE_SHORT}"
eval set -- "${GETOPT_ARGS}"

# Handle all params
while true ; do
    case "${1}" in
        # Command line options
        -h|--help)
            echo "${USAGE}" >&2
            exit 0
            ;;
        -v|--version)
            echo "${VERSION}"
            exit 0
            ;;
        -m|--message)
            MESSAGE+="${2}\\n"
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
        -a|--asset)
            [[ -f "${2}" ]] || die "Asset '${2}' not a valid file."
            GITHUB_ASSET["$(basename "${2}")"]="${2}"
            shift
            ;;
        -t|--title)
            GITHUB_TITLE="${2}"
            shift
            ;;
        -p|--prerelease)
            PRERELEASE="true"
            ;;
        # DEPRECATED: use '--github false' or git config 'gpgit.github false'
        -n|--no-github)
            INTERACTIVE=false warning "Parameter '--no-github' is deprecated. Please use '--github false' instead."
            GITHUB="false"
            ;;
        -f|--force)
            FORCE="true"
            ;;
        -i|--interactive)
            INTERACTIVE="true"
            ;;
        # Additional config options
        --changelog)
            CHANGELOG="${2}"
            shift
            ;;
        --token)
            TOKEN="${2}"
            shift
            ;;
        --compression)
            IFS=" " read -r -a COMPRESSION <<< "${2}"
            shift
            ;;
        --hash)
            IFS=" " read -r -a HASH <<< "${2}"
            shift
            ;;
        --keyserver)
            KEYSERVER="${2}"
            shift
            ;;
        --github)
            GITHUB="${2}"
            shift
            ;;
        --githubrepo)
            GITHUB_REPO_NAME="${2}"
            shift
            ;;
        --project)
            PROJECT="${2}"
            shift
            ;;
        --remote)
            REMOTE="${2}"
            shift
            ;;
        # Internal
        --color)
            # En/disable colors
            if [[ "${2}" == "never" ]]; then
                ALL_OFF="" BOLD="" BLUE="" GREEN="" RED="" YELLOW=""
            elif [[ "${2}" == "force" || "${2}" == "always" ]]; then
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
readonly ALL_OFF BOLD BLUE GREEN RED YELLOW

# Get tag parameter
if [[ "$#" -lt 1 ]]; then
    die "${USAGE_SHORT}"
fi

# Sanity check. If we're using the BSD getopt this will be broken:
if [[ "${GETOPT_PARAMS_SHORT}" == "${1}" ]]; then
    die "GPGit requires GNU getopt to function."
fi

TAG="${1}"
shift
COMMIT="${1:-"HEAD"}"

# Check if run inside Git directory
check_dependency git sed grep awk md5sum shasum date || die "Please check your \$PATH variable or install the missing dependency."
if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]]; then
    die "Not a Git repository: $(pwd)"
fi

# Change directory to git root path, so "git archive" is working properly
cd "$(git rev-parse --show-toplevel)"

# Initialize variable config/defaults
INTERACTIVE=${INTERACTIVE:-"$(git config gpgit.interactive || true)"}
REMOTE="${REMOTE:-"$(git for-each-ref --format='%(upstream:remotename)' "$(git symbolic-ref -q HEAD)")"}"
REMOTE="${REMOTE:-"origin"}"
CHANGELOG_FILE=""
CHANGELOG="${CHANGELOG:-"$(git config gpgit.changelog || true)"}"
CHANGELOG="${CHANGELOG:-"auto"}"
MESSAGE="${MESSAGE:-"Release created with GPGit ${VERSION}"$'\nhttps://github.com/NicoHood/gpgit'}"
KEYSERVER="${KEYSERVER:-"$(git config gpgit.keyserver || true)"}"
KEYSERVER="${KEYSERVER:-"hkps://keyserver.ubuntu.com"}"
if [[ "${#COMPRESSION[@]}" -eq 0 ]]; then
    IFS=" " read -r -a COMPRESSION <<< "$(git config gpgit.compression || true)"
    if [[ "${#COMPRESSION[@]}" -eq 0 ]]; then
        COMPRESSION=("xz")
    fi
fi
if [[ "${#HASH[@]}" -eq 0 ]]; then
    IFS=" " read -r -a HASH <<< "$(git config gpgit.hash || true)"
    if [[ "${#HASH[@]}" -eq 0 ]]; then
        HASH=("sha512")
    fi
fi
OUTPUT="${OUTPUT:-"$(git config gpgit.output || true)"}"
OUTPUT="${OUTPUT:-"./gpgit"}"
PROJECT="${PROJECT:-"$(git config gpgit.project || true)"}"
PROJECT="${PROJECT:-"$(git config --local "remote.${REMOTE}.url" | sed -n 's#.*/\([^.]*\)\.git#\1#p')"}"
PROJECT="${PROJECT:-"$(git config --local "remote.${REMOTE}.url" | sed -n 's#.*/##p')"}"
SIGNINGKEY="${SIGNINGKEY:-"$(git config gpgit.signingkey || true)"}"
SIGNINGKEY="${SIGNINGKEY:-"$(git config user.signingkey || true)"}"
TOKEN="${TOKEN:-"$(git config gpgit.token || true)"}"
GPG_USER="$(git config user.name || true)"
GPG_USER="${GPG_USER:-"${USER}"}"
GPG_EMAIL="$(git config user.email || true)"
GITHUB_REPO_NAME="${GITHUB_REPO_NAME:-"$(git config gpgit.githubrepo || true)"}"
GITHUB_REPO_NAME="${GITHUB_REPO_NAME:-"$(git config --local "remote.${REMOTE}.url" | sed -e 's/.*github.com[:/]//' | sed -e 's/.git$//')"}"
GITHUB="${GITHUB:-"$(git config gpgit.github || true)"}"
GITHUB="${GITHUB:-auto}"
GITHUB_TITLE="${GITHUB_TITLE:-"${TAG}"}"
PRERELEASE="${PRERELEASE:-"false"}"
GPG_BIN="$(git config gpg.program || true)"
GPG_BIN="${GPG_BIN:-gpg2}"
FORCE="${FORCE:-}"
NEW_SIGNINGKEY="false"

# Check if dependencies are available
# Dependencies: bash, gnupg2, git, tar, xz, coreutils, gawk, grep, sed
# Optional dependencies: gzip, bzip2, lzip, zstd, file, jq, curl
check_dependency "${GPG_BIN}" "${COMPRESSION[@]}" \
    || die "Please check your \$PATH variable or install the missing dependencies."

# Print initial welcome message with version information
echo "${BOLD}GPGit ${VERSION} https://github.com/NicoHood/gpgit${ALL_OFF}" >&2
echo "" >&2

if [[ -z "${INTERACTIVE}" ]]; then
    interactive "Running GPGit for the first time. This will guide you through all steps of secure source code signing once. If you wish to run interactively again pass the -i option to GPGit. For more options see --help."
fi

# Preprend changelog to tag message, if available
if [[ "${CHANGELOG}" == "auto" || "${CHANGELOG}" == "true" ]]; then
    # Find Changelog file in git (not on disk!)
    if [[ -n "${CHANGELOG_FILE}" ]]; then
        if ! git cat-file -e "${COMMIT}:${CHANGELOG_FILE}" &>/dev/null; then
            CHANGELOG_FILE=""
        fi
    else
        for filename in CHANGELOG.md Changelog.md changelog.md CHANGELOG Changelog changelog
        do
            if git cat-file -e "${COMMIT}:${filename}" &>/dev/null; then
                CHANGELOG_FILE="${filename}"
                break
            fi
        done
    fi

    # Parse Keep a Changelog
    if [[ -z "${CHANGELOG_FILE}" ]]; then
        if [[ "${CHANGELOG}" != "auto" ]]; then
            die "Changelog file not found. Did you commit the file to git?"
        fi
    else
        if ! KEEPACHANGELOG="$(parse_keepachangelog "${CHANGELOG_FILE}" "${TAG}" "${COMMIT}")"; then
            if [[ "${CHANGELOG}" != "auto" ]]; then
                die "${KEEPACHANGELOG-"Parsing changelog failed"}. See https://keepachangelog.com/ for more information."
            fi
        else
            MESSAGE="${KEEPACHANGELOG}"$'\n\n'"${MESSAGE}"
        fi
    fi
fi

# Autodetect github repository
if [[ "${GITHUB}" == "auto" ]]; then
    if git config --local "remote.${REMOTE}.url" | grep -Fiq 'github.com' \
      && check_dependency jq file curl; then
        GITHUB="true"
        if [[ -z "${TOKEN}" ]]; then
            plain "A Github repository was detected, but no token was provided."
            plain "You can disable Github release uploading with:"
            plain "git config gpgit.github false"
        fi
    else
        GITHUB="false"
    fi
fi

# When using a Github remote ask for github token first,
# as all (when using private repositories) commands require a valid token.
if [[ "${GITHUB}" == "true" ]]; then
    check_dependency jq file curl \
        || die "Please install the missing dependencies in order to use Github release asset uploading."

    if [[ -z "${TOKEN}" ]]; then
        plain "Please enter your Github token or generate a new one (permission: 'public_repo'):"
        plain "https://github.com/settings/tokens"
        plain "Tip: Configure your Github token permanant with:"
        plain "git config --global gpgit.token <token>"
        read -rs TOKEN
    fi
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
    plain "Generating the new GPG key with the selected parameters now."
    interactive
    ${GPG_BIN} --quick-generate-key "${GPG_USER} <${GPG_EMAIL}>" future-default default 1y \
        &> /dev/null || die "GPG key generation aborted."
    SIGNINGKEY="$(${GPG_BIN} --with-colons --list-secret-keys | grep -F -B 2 "${GPG_USER} <${GPG_EMAIL}>" | awk -F: '$1 == "fpr" {print $10;}')"
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

    # Check key expire date
    GPG_EXPIRE_DATE="$(echo "${SIGNINGKEY_OUTPUT}" | awk -F: '$1 == "pub" {print $7; exit}')"
    CURRENT_DATE="${EPOCHSECONDS:-"$(date '+%s')"}"
    if [[ "${GPG_EXPIRE_DATE}" -lt "${CURRENT_DATE}" ]]; then
        die "GPG key expired on $(date -d "@${GPG_EXPIRE_DATE}" +%F)"
    elif [[ "${GPG_EXPIRE_DATE}" -lt "$(( "${CURRENT_DATE}" + 7776000 ))" ]]; then
        warning "GPG key will expire in less than 3 month: $(date -d "@${GPG_EXPIRE_DATE}" +%F)"
    else
        interactive
    fi
fi

####################################################################################################
msg "2. Publish your key"
####################################################################################################

if [[ "${NEW_SIGNINGKEY}" == "true" ]]; then
    msg2 "2.1 Send GPG key to a key server"
    plain "Registering new GPG key with Git and uploading it to keyserver '${KEYSERVER}'."
    interactive
    ${GPG_BIN} --keyserver "${KEYSERVER}" --send-keys "${SIGNINGKEY}" &> /dev/null || die "Sending GPG key to keyserver '${KEYSERVER}' failed."
else
    msg2 "2.1 Send GPG key to a key server"
    plain "Make sure your key is available on a keyserver:"
    plain "${GPG_BIN} --keyserver ${KEYSERVER} --search-keys ${SIGNINGKEY}"
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
if [[ "$(git config commit.gpgsign || true)" != "true" ]]; then
    # Enable global commit signing. Can be still disabled locally.
    plain "Enabling global commit signing."
    git config --global commit.gpgsign true
else
    plain "Commit signing already enabled."
fi

# Check if tag exists
msg2 "3.3 Create signed Git tag"
if [[ -n "${FORCE}" ]]; then

    # Delete existing Github release when using --force option
    # It needs to get deleted before the tag, otherwise a release draft is kept as ghost online.
    if [[ "${GITHUB}" == "true" ]]; then
        # Parse existing Github release
        if ! GITHUB_RELEASE="$(curl --proto-redir =https -s \
                "https://api.github.com/repos/${GITHUB_REPO_NAME}/releases/tags/${TAG}" \
                -H "Accept: application/vnd.github.v3+json" \
                -H "Authorization: token ${TOKEN}" )"; then
            die "Accessing Github failed."
        fi

        GITHUB_RELEASE_ID="$(echo "${GITHUB_RELEASE}" | jq -r .id)"
        if [[ "${GITHUB_RELEASE_ID}" != "null" ]]; then
            plain "Deleting existing Github release."
            interactive
            curl --proto-redir =https -s -X DELETE \
                "https://api.github.com/repos/${GITHUB_REPO_NAME}/releases/${GITHUB_RELEASE_ID}" \
                -H "Accept: application/vnd.github.v3+json" \
                -H "Authorization: token ${TOKEN}"
        fi
    fi

    # Now delete the actual git tags
    plain "Deleting existing Git tag."
    interactive
    git tag -d "${TAG}" &> /dev/null || true
    git push --delete "${REMOTE}" "refs/tags/${TAG}" &> /dev/null || true
else
    plain "Fetching Git tags from ${REMOTE}."
    interactive
    git fetch "${REMOTE}" "refs/tags/${TAG}" &> /dev/null || true
fi
if [[ -z "$(git tag -l "${TAG}")" ]] ; then
    plain "Creating signed Git tag '${TAG}' and pushing it to the remote Git."
    interactive
    git tag -s -a -m "${MESSAGE}" -u "${SIGNINGKEY}" "${TAG}" "${COMMIT}" &> /dev/null \
        || die "Signing Git tag failed or aborted."
    git push "${REMOTE}" "refs/tags/${TAG}" &> /dev/null
else
    warning "Tag '${TAG}' already exists."
fi


####################################################################################################
msg "4. Create a signed release archive"
####################################################################################################

# Create output directory
if [[ ! -d "${OUTPUT}" ]]; then
    plain "Creating not existing output directory: '${OUTPUT}'."
    interactive
    mkdir -p "${OUTPUT}"
fi

# Create new archive
msg2 "4.1 Create compressed archive"
for util in "${COMPRESSION[@]}"
do
    if [[ "${util}" == "zip" ]]; then
        FILE="${OUTPUT}/${PROJECT}-${TAG}.${util}"
    else
        FILE="${OUTPUT}/${PROJECT}-${TAG}.tar.${util}"
    fi
    if [[ ! -f "${FILE}" || -n "${FORCE}" ]]; then
        plain "Creating new release archive: '${FILE}'"
        interactive
        if [[ "${util}" == "zip" ]]; then
            git archive --format=zip --prefix "${PROJECT}-${TAG}/" "refs/tags/${TAG}" > "${FILE}"
        else
            git archive --format=tar --prefix "${PROJECT}-${TAG}/" "refs/tags/${TAG}" | "${util}" > "${FILE}"
        fi
    else
        warning "Found existing archive '${FILE}'."
    fi
    GITHUB_ASSET["${PROJECT}-${TAG}.tar.${util}"]="${FILE}"
done

# Sign archive
msg2 "4.2 Sign the archive"
for util in "${COMPRESSION[@]}"
do
    if [[ "${util}" == zip ]]; then
        FILE="${OUTPUT}/${PROJECT}-${TAG}.${util}"
    else
        FILE="${OUTPUT}/${PROJECT}-${TAG}.tar.${util}"
    fi
    if [[ ! -f "${FILE}.asc" || -n "${FORCE}" ]]; then
        plain "Creating GPG signature: '${FILE}.asc'"
        interactive
        ${GPG_BIN} --digest-algo SHA512 -u "${SIGNINGKEY}" --output "${FILE}.asc" --armor --detach-sign --batch --yes "${FILE}"
    else
        warning "Found existing signature '${FILE}.asc'."
    fi
    GITHUB_ASSET["${PROJECT}-${TAG}.tar.${util}.asc"]="${FILE}.asc"
done

# Creating hash
msg2 "4.3 Create the message digest"
for util in "${COMPRESSION[@]}"
do
    if [[ "${util}" == zip ]]; then
        FILE="${OUTPUT}/${PROJECT}-${TAG}.${util}"
    else
        FILE="${OUTPUT}/${PROJECT}-${TAG}.tar.${util}"
    fi
    for algorithm in "${HASH[@]}"
    do
        if [[ ! -f "${FILE}.${algorithm}" || -n "${FORCE}" ]]; then
            plain "Creating message digest: '${FILE}.${algorithm}'"
            interactive
            if [[ "${algorithm}" == "md5" ]]; then
                md5sum "${FILE}" > "${FILE}.${algorithm}"
            else
                shasum -a "${algorithm#sha}" "${FILE}" > "${FILE}.${algorithm}"
            fi
        else
            warning "Found existing message digest '${FILE}.${algorithm}'."
        fi
        GITHUB_ASSET["${PROJECT}-${TAG}.tar.${util}.${algorithm}"]="${FILE}.${algorithm}"
    done
done


####################################################################################################
msg "5. Upload the release"
####################################################################################################

msg2 "5.1 Configure HTTPS download server"
if [[ "${GITHUB}" != "true" ]]; then
    plain "Please configure HTTPS for your download server."
else
    plain "Github uses well configured https."
fi
interactive

function github_upload_asset()
{
    local filename="${1}"
    local file="${2}"
    local message
    local mimetype
    mimetype="$(file -b --mime-type "${filename}")"

    # Upload Github asset
    plain "Uploading release asset '${filename}'"
    interactive
    if ! RESULT="$(curl --proto-redir =https -s \
            "https://uploads.github.com/repos/${GITHUB_REPO_NAME}/releases/${GITHUB_RELEASE_ID}/assets?name=${filename}" \
            -H "Content-Type: ${mimetype}" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Authorization: token ${TOKEN}" \
            --data-binary @"${file}")"; then
        die "Uploading file ${filename} to Github failed."
    fi

    # Abort in API error
    message="$(echo "${RESULT}" | jq -r .message)"
    if [[ "${message}" != "null" ]]; then
        die "Github API message: '${message}'. Check your token configuration: https://github.com/settings/tokens"
    fi
}

# Upload to Github
msg2 "5.2 Upload to Github"
if [[ "${GITHUB}" != "true" ]]; then
    plain "Please upload the release files manually"
    interactive
else
    # Parse existing Github release
    if ! GITHUB_RELEASE="$(curl --proto-redir =https -s \
            "https://api.github.com/repos/${GITHUB_REPO_NAME}/releases/tags/${TAG}" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Authorization: token ${TOKEN}" \
            )"; then
        die "Accessing Github failed."
    fi

    # Check for existing release and assets
    GITHUB_RELEASE_ID="$(echo "${GITHUB_RELEASE}" | jq -r .id)"
    GITHUB_ASSETS="$(echo "${GITHUB_RELEASE}" | jq -r .assets[]?.name)"

    # Create new Github release
    if [[ "${GITHUB_RELEASE_ID}" == "null" ]]; then
        plain "Creating new Github release '${TAG}'."
        interactive

        # Make sure we are tagging the current head on a branch
        if [[ -z "${COMMIT}" || "${COMMIT}" == "HEAD" ]] && git symbolic-ref HEAD &> /dev/null; then
            BRANCH="$(git rev-parse --abbrev-ref=strict HEAD)"
        else
            # Get default branch from github
            if ! GITHUB_REPO_INFORMATION="$(curl --proto-redir =https -s \
                    "https://api.github.com/repos/${GITHUB_REPO_NAME}" \
                    -H "Accept: application/vnd.github.v3+json" \
                    -H "Authorization: token ${TOKEN}" )"; then
                die "Getting default Github branch failed."
            fi
            BRANCH="$(echo "${GITHUB_REPO_INFORMATION}" | jq -r .default_branch)"
            warning "Publishing release on default Github branch '${BRANCH}'."
        fi

        API_JSON="$(jq -n -c -M \
          --arg tag_name "${TAG}" \
          --arg target_commitish "${BRANCH}" \
          --arg name "${GITHUB_TITLE}" \
          --arg body "${MESSAGE}" \
          --argjson prerelease "${PRERELEASE}" \
          '{tag_name: $tag_name, target_commitish: $target_commitish, name: $name, body: $body, draft: false, prerelease: $prerelease}')"
        if ! GITHUB_RELEASE="$(curl --proto-redir =https -s --data "${API_JSON}" \
                "https://api.github.com/repos/${GITHUB_REPO_NAME}/releases" \
                -H "Accept: application/vnd.github.v3+json" \
                -H "Authorization: token ${TOKEN}" )"; then
            die "Uploading release to Github failed."
        fi

        # Abort on API error
        message="$(echo "${GITHUB_RELEASE}" | jq -r .message)"
        if [[ "${message}" != "null" ]]; then
            die "Github API message: '${message}'. Check your token configuration: https://github.com/settings/tokens"
        fi

        # Safe new ID
        GITHUB_RELEASE_ID="$(echo "${GITHUB_RELEASE}" | jq -r .id)"
    else
        warning "Found existing release on Github."
    fi

    # Upload release assets
    for filename in "${!GITHUB_ASSET[@]}"
    do
        if grep -q -F -x "${filename}" <(echo "${GITHUB_ASSETS}"); then
            warning "Found existing asset on Github: '${filename}'."
        else
            github_upload_asset "${filename}" "${GITHUB_ASSET[${filename}]}"
        fi
    done

    plain "Github release created: https://github.com/${GITHUB_REPO_NAME}/releases/tag/${TAG}"
fi

if [[ -z "${INTERACTIVE}" ]]; then
    git config --global gpgit.interactive "false"
fi

msg "Finished without errors."
