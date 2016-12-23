#!/bin/bash

# Stop on errors
set -e -u -o pipefail

# Settings
TAG=$1
USER_NAME=${2:-$(git config user.name)}
PROJECT_NAME=${3:-${PWD##*/}}

# Check input param number
if [[ $# -ne 1 && $# -ne 3 || "$1" == "--help" ]]; then
    echo "Usage: $0 <tag> [username] [project name]" 1>&2
    exit 1
fi

# Download tags
echo "Refreshing tags from upstream."
git pull --tags

# Check if tag even exists
if ! git tag | grep "^${TAG}$" -q; then
    echo "Error: Tag does not exist" 1>&2
    exit 1
fi

# Download github created archive and compare against local file
echo "Verifying archive against github download..."
echo "Using url: https://github.com/${USER_NAME}/${PROJECT_NAME}/archive/${TAG}.tar.gz"
if ! cmp \
<(curl -L "https://github.com/${USER_NAME}/${PROJECT_NAME}/archive/${TAG}.tar.gz") \
<(git archive --format=tar.gz --prefix "${PROJECT_NAME}-${TAG}/" "${TAG}")
then
    echo "Error: Local archive differs from github download or download not found" 1>&2
    exit 1
fi

echo "Source verified successfully."
