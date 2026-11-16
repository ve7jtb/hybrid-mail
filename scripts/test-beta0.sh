#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo 'Usage: YKMAN_SERIAL=your-serial ./scripts/test-beta0.sh public.pem new-output-directory [--no-ui]' >&2
  exit 1
fi
: "${YKMAN_SERIAL:?Set YKMAN_SERIAL to the intended device serial}"
export YKMAN_BIN="${YKMAN_BIN:-/usr/local/bin/ykman}"
exec java -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Beta0Test "$1" "$PWD/adapters/ykman-mu.py" "$2" "${@:3}"
