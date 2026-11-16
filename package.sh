#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
[[ -f build/hybrid-mail.jar ]] || { echo 'Run ./build.sh first.' >&2; exit 1; }
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp build/hybrid-mail.jar lib/*.jar "$stage/"
jpackage --type app-image --name 'Hybrid Mail' --input "$stage" \
  --main-jar hybrid-mail.jar --main-class dev.hybridmail.MailApp \
  --dest dist --app-version 1.0.0 \
  --add-modules java.desktop,java.naming,java.security.jgss,jdk.crypto.ec,jdk.unsupported
