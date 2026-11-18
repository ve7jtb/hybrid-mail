#!/bin/bash
# Run only inside a disposable D-Bus session, never the user's desktop session.
set -euo pipefail
testdir=$(mktemp -d)
trap 'rm -rf "$testdir"' EXIT
export XDG_DATA_HOME="$testdir/data" XDG_RUNTIME_DIR="$testdir/runtime"
export GNOME_KEYRING_CONTROL="$testdir/control"
mkdir -m 700 -p "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR" "$GNOME_KEYRING_CONTROL"
printf '%s' 'disposable-ci-keyring' | gnome-keyring-daemon --unlock --components=secrets --control-directory="$GNOME_KEYRING_CONTROL"
# --unlock alone can leave the daemon uninitialized on a headless runner.
# Register Secret Service on this private bus before the helper can auto-activate
# a second, locked daemon using the runner's desktop environment.
gnome-keyring-daemon --start --components=secrets --control-directory="$GNOME_KEYRING_CONTROL"
helper="${PQ_MAIL_CREDENTIAL_HELPER:-build/native/hybrid-mail-credentials}"
printf '%s' 'disposable-oauth-test' | "$helper" put ci-self-test
[[ "$("$helper" get ci-self-test)" == disposable-oauth-test ]]
"$helper" delete ci-self-test
set +e
"$helper" get ci-self-test
result=$?
set -e
[[ "$result" == 2 ]]
echo 'PASS Linux Secret Service store/read/delete/missing; disposable test only'
