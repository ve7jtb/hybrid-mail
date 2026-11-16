#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo 'Usage: ./scripts/test-pkcs11.sh existing-identity-directory new-output-directory [--no-ui]' >&2
  exit 1
fi
: "${OPENSSL_BIN:?Set the absolute OpenSSL 3.5+ executable path}"
: "${PKCS11_PROVIDER:?Set the absolute PR 818 provider library path}"
: "${PKCS11_MODULE:?Set the absolute Yubico PKCS11 module path}"
: "${PKCS11_SERIAL:?Set the intended token serial}"
export OPENSSL_BIN PKCS11_PROVIDER PKCS11_MODULE PKCS11_SERIAL
exec java -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Pkcs11Test "$1" "$PWD/adapters/pkcs11-mu.py" "$2" "${@:3}"
