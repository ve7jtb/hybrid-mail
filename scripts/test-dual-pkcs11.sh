#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 && $# -le 2 ]] || { echo 'Usage: test-dual-pkcs11.sh new-output [--no-ui]' >&2; exit 1; }
: "${PKCS11_TRADITIONAL_SLOT:?Set PKCS11_TRADITIONAL_SLOT to the existing RSA-3072 slot (not 9c)}"
export PKCS11_TRADITIONAL_ALGORITHM=RSA
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export PKCS11_TRADITIONAL_PUBLIC="$temporary/traditional-public.der"
export PKCS11_ML_PUBLIC="$temporary/ml-public.der"
./adapters/pkcs11-mu.py --export-traditional > "$PKCS11_TRADITIONAL_PUBLIC"
./adapters/pkcs11-mu.py --export-ml > "$PKCS11_ML_PUBLIC"
./scripts/test-pkcs11.sh . "$@"
