#!/bin/sh

set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null
git -c init.templateDir= init -q -b main "$tmp/fixture"
cd "$tmp/fixture"
git config user.name 'Release Test'
git config user.email 'release-test@example.invalid'
mkdir scripts
cp "$script_dir/new_version.sh" scripts/
printf '0.4.0\n' >VERSION
cat >README.md <<'EOF'
[![Version](https://img.shields.io/badge/version-0.4.0-green)](https://github.com/zekihan/traefik-real-ip/releases/tag/v0.4.0)

      version: v0.4.0

      version: v0.4.0

Unrelated text: 0x4y0
EOF
git add README.md VERSION scripts/new_version.sh
git commit -qm 'Create 0.4.0 fixture'
base=$(git rev-parse HEAD)

git clone -q "$tmp/fixture" "$tmp/clone"
cd "$tmp/clone"
git config user.name 'Release Test'
git config user.email 'release-test@example.invalid'
ssh-keygen -q -t ed25519 -N '' -f "$tmp/signing-key"
printf 'release-test@example.invalid %s\n' "$(cat "$tmp/signing-key.pub")" >"$tmp/allowed-signers"
git config gpg.format ssh
git config user.signingkey "$tmp/signing-key"
git config gpg.ssh.allowedSignersFile "$tmp/allowed-signers"

touch dirty
if output=$(dash ./scripts/new_version.sh 0.4.1 2>&1); then
    echo 'Release preparation accepted a dirty worktree' >&2
    exit 1
fi
printf '%s\n' "$output" | grep -Fx 'Working directory dirty'
test "$(git status --porcelain)" = '?? dirty'
test "$(git rev-parse HEAD)" = "$base"
test -z "$(git tag --list)"
rm dirty

dash ./scripts/new_version.sh 0.4.1
printf '0.4.1\n' >"$tmp/expected-version"
diff -u "$tmp/expected-version" VERSION
cat >"$tmp/expected-readme" <<'EOF'
[![Version](https://img.shields.io/badge/version-0.4.1-green)](https://github.com/zekihan/traefik-real-ip/releases/tag/v0.4.1)

      version: v0.4.1

      version: v0.4.1

Unrelated text: 0x4y0
EOF
diff -u "$tmp/expected-readme" README.md
test -z "$(git status --porcelain)"
test "$(git rev-parse HEAD^)" = "$base"
test "$(git rev-parse 'v0.4.1^{commit}')" = "$(git rev-parse HEAD)"
git tag -v v0.4.1
test "$(git -C "$tmp/fixture" rev-parse HEAD)" = "$base"
test -z "$(git -C "$tmp/fixture" tag --list)"
