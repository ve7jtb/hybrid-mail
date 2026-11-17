#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_PROFILE_RELEASE_STRIP=none
cargo build --locked --release --manifest-path native-src/provision/Cargo.toml
mkdir -p build/native
cp native-src/provision/target/release/hybrid-mail-provision build/native/
if [[ "$(uname -s)" == Darwin ]]; then codesign --force --sign - --identifier dev.hybridmail.provision build/native/hybrid-mail-provision; fi
