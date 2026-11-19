#!/bin/bash
# Build the macOS single-process signer against the OpenSSL bundled by package.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'This helper packaging script currently targets macOS.' >&2; exit 1; }
prefix="${HYBRID_OPENSSL_ROOT:-/opt/homebrew/opt/openssl@3}"
mkdir -p build/native
for source in native-src/pkcs11-sign.c tests/test_pkcs11_sign.c; do
  if [[ "$source" == native-src/* ]]; then output=pqmail-pkcs11-sign; else output=test-pkcs11-sign; fi
  clang -O2 -Wall -Wextra -Werror -I "$prefix/include" "$source" "$prefix/lib/libcrypto.3.dylib" \
    -Wl,-rpath,@executable_path/../lib -o "build/native/$output"
done
# Software-only tests: no PKCS#11 module, YubiKey, credentials or account access.
OPENSSL_CONF=/dev/null DYLD_LIBRARY_PATH="$prefix/lib" build/native/test-pkcs11-sign
