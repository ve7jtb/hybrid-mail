#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Linux ]] || { echo 'This package helper targets Linux'; exit 1; }
# Tests only synthetic protocol data. Never run upstream device tests.
cargo test --locked --manifest-path native-src/passkey-linux/Cargo.toml
cargo build --locked --release --manifest-path native-src/passkey-linux/Cargo.toml
mkdir -p build/native
cp native-src/passkey-linux/target/release/pqmail-passkey build/native/
build/native/pqmail-passkey --probe
