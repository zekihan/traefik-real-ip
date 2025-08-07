#!/bin/sh

set -e

DIR=$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )

cd "${DIR}/.."

PROJECT_DIR=$(pwd)

export CONFIG_DIR="$PROJECT_DIR"

go test "$@"
