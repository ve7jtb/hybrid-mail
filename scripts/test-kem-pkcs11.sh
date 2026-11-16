#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 2 && $# -le 3 ]] || { echo 'Usage: test-kem-pkcs11.sh existing-signing-identities new-output [--no-ui]' >&2; exit 1; }
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
: "${PKCS11_KEM_SLOT:?Set ML-KEM-768 slot}"
: "${PKCS11_ECDH_SLOT:?Set P-256 ECDH slot}"
[[ "$PKCS11_KEM_SLOT" != "$PKCS11_ECDH_SLOT" ]] || { echo 'KEM and ECDH need distinct slots' >&2; exit 1; }
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
echo "Reading ML-KEM public key through PKCS#11…"
./adapters/pkcs11-kem.py --export-mlkem > "$temporary/ml-public.der"
echo "Reading ECDH public key through PKCS#11…"
./adapters/pkcs11-kem.py --export-ecdh > "$temporary/ec-public.der"
java -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Pkcs11KemTest "$1" "$temporary/ml-public.der" "$temporary/ec-public.der" "$PWD/adapters/pkcs11-mu.py" "$PWD/adapters/pkcs11-kem.py" "$2" "${@:3}"
