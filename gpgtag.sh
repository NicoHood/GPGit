#!/bin/bash -ex

# Settings
OUT_PATH=archive/
PROJECT_NAME=${PWD##*/}
USER_NAME=$(git config user.name)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
TAG=$1

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
if ! git config --get remote.origin.url | grep github -i; then
    echo "Error: This is (possibly) not a github project. Please fix your origin URL."
    exit 1
fi

# Check if every added file has been commited
if ! git diff --cached --exit-code; then
    read -rp "Warning: You have added new changes but did not commit them yet. Press enter to continue."
fi

# Tag new signed release and upload
git tag -s "${TAG}" -m "Release ${TAG}"
git push --tags

# Create archive of the tag
mkdir -p "${OUT_PATH}"
git archive --format=tar.gz -o "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz" --prefix "${PROJECT_NAME}-${TAG}/" "${TAG}"

# Download github created archive and compare against local file
curl -L "https://github.com/${USER_NAME}/${PROJECT_NAME}/archive/${TAG}.tar.gz" | cmp "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz"

# Create signature and message digest of the archive
sha512sum "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz" > "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz.sha512"
gpg --output "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz.sig" --armor --detach-sign "${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz"

# Create github release and upload the signature
# http://www.barrykooij.com/create-github-releases-via-command-line/
# https://developer.github.com/v3/repos/releases/
# https://developer.github.com/changes/2013-09-25-releases-api/
read -rp "Enter your Github token (Github->Settings->Personal access tokens; public repo access)" TOKEN
API_JSON=$(printf '{"tag_name": "%s","target_commitish": "%s","name": "%s","body": "Release %s","draft": false,"prerelease": false}' "${TAG}" "${BRANCH}" "${TAG}" "${TAG}")
#RESULT=$(curl --data "$API_JSON" https://api.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases?access_token=${TOKEN})
RESULT=$(curl --data "$API_JSON" "https://api.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases" \
-H "Accept: application/vnd.github.v3+json" -H "Authorization: token ${TOKEN}" )

RELEASE_ID=$(echo "${RESULT}" | grep '^  "id": ' | tr -dc '[:digit:]')

curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sig" \
-H "Content-Type: application/pgp-signature" \
-H "Accept: application/vnd.github.v3+json" \
-H "Authorization: token ${TOKEN}" \
--data-binary @"${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz.sig"

curl "https://uploads.github.com/repos/${USER_NAME}/${PROJECT_NAME}/releases/${RELEASE_ID}/assets?name=${PROJECT_NAME}-${TAG}.tar.gz.sha512" \
-H "Content-Type: text/sha512" \
-H "Accept: application/vnd.github.v3+json" \
-H "Authorization: token ${TOKEN}" \
--data-binary @"${OUT_PATH}${PROJECT_NAME}-${TAG}.tar.gz.sha512"

echo "Release successfully tagged, signed and uploaded. Consider to also create a .tar.xz + sig with -9 compression for larger projects."
