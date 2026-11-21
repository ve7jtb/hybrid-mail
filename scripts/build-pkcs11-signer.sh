#!/bin/bash
# Compile and software-test against the same OpenSSL used by the package.
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -s)" in
  Darwin) platform=mac; prefix="${HYBRID_OPENSSL_ROOT:-/opt/homebrew/opt/openssl@3}"; compiler="${CC:-clang}"; extension= ;;
  Linux) platform=linux; prefix="${HYBRID_OPENSSL_ROOT:-$PWD/.deps/openssl-install}"; compiler="${CC:-cc}"; extension= ;;
  MINGW*|MSYS*|CYGWIN*) platform=windows; prefix="${HYBRID_OPENSSL_ROOT:-${MINGW_PREFIX:?Run in an MSYS2 compiler environment}}"; compiler="${CC:-cc}"; extension=.exe ;;
  *) echo 'Unsupported platform' >&2; exit 1 ;;
esac
mkdir -p build/native build/tests
for source in native-src/pkcs11-sign.c tests/test_pkcs11_sign.c native-src/pkcs11-kem.c tests/test_pkcs11_kem.c; do
  if [[ "$source" == native-src/* ]]; then output="build/native/pqmail-pkcs11-sign$extension"; else output="build/tests/test-pkcs11-sign$extension"; fi
  if [[ "$source" == *kem.c ]]; then output="${output/sign/kem}"; fi
  case "$platform" in
    mac) link=("$prefix/lib/libcrypto.3.dylib" '-Wl,-rpath,@executable_path/../lib') ;;
    linux) link=(-L "$prefix/lib" -lcrypto '-Wl,-rpath,$ORIGIN/../lib') ;;
    windows) link=(-L "$prefix/lib" -lcrypto) ;;
  esac
  "$compiler" -O2 -Wall -Wextra -Werror -I "$prefix/include" "$source" "${link[@]}" -o "$output"
done
# Software keys only: never load PKCS#11 or access hardware/accounts.
case "$platform" in
  mac) OPENSSL_CONF=/dev/null DYLD_LIBRARY_PATH="$prefix/lib" build/tests/test-pkcs11-sign ;;
  linux) OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$prefix/lib" build/tests/test-pkcs11-sign ;;
  windows) OPENSSL_CONF=NUL PATH="$prefix/bin:$PATH" build/tests/test-pkcs11-sign.exe ;;
esac

case "$platform" in
  mac) OPENSSL_CONF=/dev/null DYLD_LIBRARY_PATH="$prefix/lib" build/tests/test-pkcs11-kem ;;
  linux) OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$prefix/lib" build/tests/test-pkcs11-kem ;;
  windows) OPENSSL_CONF=NUL PATH="$prefix/bin:$PATH" build/tests/test-pkcs11-kem.exe ;;
esac
