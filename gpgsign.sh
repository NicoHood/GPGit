#!/bin/bash

# Stop on errors
set -e -u -o pipefail

# Settings
TAG=$1
OUT_PATH=${2:-'./archive/'}
PROJECT_NAME=${3:-${PWD##*/}}

# Check input param number
if [[ $# -lt 1 || $# -gt 3 || "$1" == "--help" ]]; then
    echo "Usage: $0 <tag> [output path] [project name]" 1>&2
    exit 1
fi

# Ask for mkdir
if [[ ! -d "${OUT_PATH}" ]]; then
    read -rp "Output path does not exist. Create ${OUT_PATH} ?" yesno
    if [[ "${yesno}" != [Yy]"es" && "${yesno}" != [Yy] && -n "${yesno}" ]]; then
        echo "Aborted by user"
        exit 0
    fi

    mkdir -p "${OUT_PATH}"
fi

# Use short variables for pathes
TAR_GZ="${OUT_PATH}/${PROJECT_NAME}-${TAG}.tar.gz"

# Download tags
echo "Refreshing tags from upstream."
git pull --tags

# Check if tag even exists
if ! git tag | grep "^${TAG}$" -q; then
    echo "Error: Tag does not exist" 1>&2
    exit 1
fi

# Generate archive
# Could be hidden via tee, but having the archive + sig + sha512 makes more sense
git archive --format=tar.gz -o "${TAR_GZ}" --prefix "${PROJECT_NAME}-${TAG}/" "${TAG}"

# Create signature and message digest of the archive
echo "Generating sha512sum and gpg signature"
sha512sum "${TAR_GZ}" > "${TAR_GZ}.sha512"
gpg --output "${TAR_GZ}.sig" --armor --detach-sign "${TAR_GZ}"
