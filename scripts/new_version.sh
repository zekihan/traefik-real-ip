#!/bin/bash

set -e

DIR=$(cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P)

cd "${DIR}/.."

if [ -n "$(git status --porcelain)" ]; then
	echo "Working directory dirty"
	exit 1
fi

vers=$(tr -d '[:space:]' <VERSION)
echo "Current version: ${vers}"

new_vers=$(echo "${vers}" | awk -F. '{$NF = $NF + 1;} 1' | sed 's/ /./g')

if [ -n "$1" ]; then
	new_vers=$1
	if ! echo "${new_vers}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
		echo "Invalid version: ${new_vers}"
		exit 1
	fi
fi

echo "New version: ${new_vers}"

echo "${new_vers}" >VERSION

readme=$(cat README.md)
readme="${readme//${vers}/${new_vers}}"
echo "${readme}" >README.md

git add VERSION
git add README.md

git commit -m "Bump version to ${new_vers}"
git tag -s -a "v${new_vers}" -m "Version ${new_vers}"

git push origin main
git push origin "v${new_vers}"
