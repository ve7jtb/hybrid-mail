#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .deps build/native
prefix="$PWD/.deps/openssl-install"
curl --fail --location --retry 3 https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz -o .deps/openssl.tar.gz
echo '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  .deps/openssl.tar.gz' | sha256sum --check
tar -xzf .deps/openssl.tar.gz -C .deps
(cd .deps/openssl-3.5.9 && ./Configure --prefix="$prefix" --libdir=lib shared no-tests && make -j2 && make install_sw)
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bash scripts/build-pkcs11.sh
bash scripts/build-provision.sh
cc -O2 -Wall -Wextra native-src/credentials-linux.c -o build/native/hybrid-mail-credentials $(pkg-config --cflags --libs libsecret-1)

HYBRID_OPENSSL_ROOT="$prefix" bash scripts/build-pkcs11-signer.sh

bash scripts/build-passkey-linux.sh
