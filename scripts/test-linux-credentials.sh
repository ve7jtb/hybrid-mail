#!/bin/bash
# Run only inside a disposable D-Bus session, never the user's desktop session.
set -euo pipefail
testdir=$(mktemp -d)
trap 'rm -rf "$testdir"' EXIT
export XDG_DATA_HOME="$testdir/data" XDG_RUNTIME_DIR="$testdir/runtime"
mkdir -m 700 -p "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
printf '%s' 'disposable-ci-keyring' | gnome-keyring-daemon --unlock --components=secrets
helper=build/native/hybrid-mail-credentials
printf '%s' 'disposable-oauth-test' | "$helper" put ci-self-test
[[ "$("$helper" get ci-self-test)" == disposable-oauth-test ]]
"$helper" delete ci-self-test
set +e
"$helper" get ci-self-test
result=$?
set -e
[[ "$result" == 2 ]]
echo 'PASS Linux Secret Service store/read/delete/missing; disposable test only'
