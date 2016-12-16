#!/bin/bash

# Stop on errors
set -e -u -o pipefail

# Settings
OUT_PATH=archive/
PROJECT_NAME=${PWD##*/}
USER_NAME=$(git config user.name)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
TAG=$1

# Use short variables for pathes
mkdir -p "${OUT_PATH}"
TAR_GZ="${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz"

# Check input param number
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 tag"
    exit 1
fi

# Check if commit signing is enabled for this repo and ask for a switch if not
if [[ $(git config commit.gpgsign) != "true" ]]; then
    read -rp 'Warning: Commit signing is disabled. Enable with: "git config --global commit.gpgsign true" Press enter to continue.'
fi

# Check if this is a github project
if ! git config --get remote.origin.url | grep github -iq; then
    read -rp "Warning: This is (possibly) not a github project."
fi

# Check if every added file has been commited
if ! git diff --cached --exit-code; then
    read -rp "Warning: You have added new changes but did not commit them yet. Press enter to continue."
fi

# Check if tag exists or ask to create a new one
if ! git tag | grep "^${TAG}$" -q; then
    # Tag new signed release and upload
    echo "Git tag is missing. Creating it and uploading it now."
    git tag -s "${TAG}" -m "Release ${TAG}"
    git push --tags
else
    echo "Release already tagged (make sure it is also pushed)"
fi

# Create archive of the tag
if [[ -f "${TAR_GZ}" ]]; then
    echo "Archive file .tar.gz already exists. Skipping generation"
else
    echo "Generating .tar.gz archive"
    git archive --format=tar.gz -o "${TAR_GZ}" --prefix "${PROJECT_NAME}-${TAG}/" "${TAG}"
fi


# Download github created archive and compare against local file
echo "Verifying archive against github download"
if ! cmp "${TAR_GZ}" <(curl -L "https://github.com/${USER_NAME}/${PROJECT_NAME}/archive/${TAG}.tar.gz"); then
    echo "Error: Local archive differs from github download" 1>&2
    exit 1
fi

# Create signature and message digest of the archive
echo "Generating sha512sum and gpg signature"
sha512sum "${TAR_GZ}" > "${TAR_GZ}.sha512"
gpg --output "${TAR_GZ}.sig" --armor --detach-sign "${TAR_GZ}"

# Create github release and upload the signature
# http://www.barrykooij.com/create-github-releases-via-command-line/
# https://developer.github.com/v3/repos/releases/
# https://developer.github.com/changes/2013-09-25-releases-api/
read -rp "Enter your Github token (Github->Settings->Personal access tokens; public repo access)" TOKEN
API_JSON=$(printf '{"tag_name": "%s","target_commitish": "%s","name": "%s","body": "Release %s","draft": false,"prerelease": false}' "${TAG}" "${BRANCH}" "${TAG}" "${TAG}")
if ! RESULT=$(curl --data "$API_JSON" "https://api.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases" \
-H "Accept: application/vnd.github.v3+json" -H "Authorization: token ${TOKEN}" ); then
    echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
    exit 1
fi
RELEASE_ID=$(echo "${RESULT}" | grep '^  "id": ' | tr -dc '[:digit:]')

if ! curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sig" \
-H "Content-Type: application/pgp-signature" \
-H "Accept: application/vnd.github.v3+json" \
-H "Authorization: token ${TOKEN}" \
--data-binary @"${TAR_GZ}.sig"; then
    echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
    exit 1
fi

if ! curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sha512" \
-H "Content-Type: text/sha512" \
-H "Accept: application/vnd.github.v3+json" \
-H "Authorization: token ${TOKEN}" \
--data-binary @"${TAR_GZ}.sha512"; then
    echo "Error: Uploading failed. Release already exists or token is wrong?" 1>&2
    exit 1
fi

echo "Release successfully tagged, signed and uploaded. Consider to also create a .tar.xz + sig with -9 compression for larger projects."
