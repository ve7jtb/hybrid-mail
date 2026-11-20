#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .deps build/native
prefix="$PWD/.deps/openssl-install"
source scripts/openssl-source.env
curl --fail --location --retry 3 "https://github.com/openssl/openssl/archive/$OPENSSL_REVISION.tar.gz" -o .deps/openssl.tar.gz
echo "$OPENSSL_SOURCE_SHA256  .deps/openssl.tar.gz" | sha256sum --check
tar -xzf .deps/openssl.tar.gz -C .deps
(cd ".deps/openssl-$OPENSSL_REVISION" && ./Configure --prefix="$prefix" --libdir=lib shared no-tests && make -j2 && make install_sw)
cp scripts/openssl-source.env "$prefix/pq-mail-source.env"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bash scripts/build-pkcs11.sh
bash scripts/build-provision.sh
cc -O2 -Wall -Wextra native-src/credentials-linux.c -o build/native/hybrid-mail-credentials $(pkg-config --cflags --libs libsecret-1)

HYBRID_OPENSSL_ROOT="$prefix" bash scripts/build-pkcs11-signer.sh

bash scripts/build-passkey-linux.sh
