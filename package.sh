#!/bin/bash
# macOS desktop image with Java, OpenSSL and the locally built PKCS#11 modules.
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
[[ "$(uname -s)" == Darwin ]] || { echo 'This bundled package script targets macOS.' >&2; exit 1; }
[[ -f build/hybrid-mail.jar ]] || { echo 'Run ./build.sh first.' >&2; exit 1; }
OPENSSL_ROOT="${HYBRID_OPENSSL_ROOT:-/opt/homebrew/opt/openssl@3}"
DEST="${HYBRID_MAIL_PACKAGE_DIR:-$PWD/dist}"
for file in native/pkcs11.dylib native/libykcs11.dylib "$OPENSSL_ROOT/bin/openssl" "$OPENSSL_ROOT/lib/libcrypto.3.dylib" "$OPENSSL_ROOT/lib/libssl.3.dylib"; do
  [[ -f "$file" ]] || { echo "Missing dependency: $file" >&2; exit 1; }
done
[[ ! -e "$DEST/Hybrid Mail.app" ]] || { echo 'Destination app exists; choose another HYBRID_MAIL_PACKAGE_DIR.' >&2; exit 1; }
/usr/bin/python3 --version >/dev/null
mkdir -p "$DEST"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/adapters" "$stage/native/bin" "$stage/native/lib" "$stage/notices"
cp build/hybrid-mail.jar lib/*.jar "$stage/"
cp build/native/hybrid-mail-keychain "$stage/native/bin/"
cp adapters/*.py "$stage/adapters/"
cp native/*.dylib "$stage/native/lib/"
cp -L "$OPENSSL_ROOT/bin/openssl" "$stage/native/bin/openssl"
cp -L "$OPENSSL_ROOT/lib/libcrypto.3.dylib" "$OPENSSL_ROOT/lib/libssl.3.dylib" "$stage/native/lib/"
cp "$OPENSSL_ROOT/LICENSE.txt" "$stage/notices/OpenSSL-LICENSE.txt"
cp docs/THIRD-PARTY.txt "$stage/notices/"
# Change only copies. All non-system OpenSSL dependencies become bundle-relative.
for binary in "$stage/native/bin/openssl" "$stage/native/lib/"*.dylib; do
  chmod u+w "$binary"
  if [[ "$binary" == */bin/* ]]; then relative='@loader_path/../lib'; else relative='@loader_path'; fi
  while IFS= read -r dependency; do
    case "$dependency" in
      /*/libcrypto.3.dylib|/*/libssl.3.dylib)
        install_name_tool -change "$dependency" "$relative/$(basename "$dependency")" "$binary" ;;
    esac
  done < <(otool -L "$binary" | tail -n +2 | awk '{print $1}')
  if otool -l "$binary" | grep -q LC_ID_DYLIB; then install_name_tool -id "@rpath/$(basename "$binary")" "$binary"; fi
  codesign --force --sign - "$binary"
done
jpackage --type app-image --name 'Hybrid Mail' --input "$stage" \
  --main-jar hybrid-mail.jar --main-class dev.hybridmail.MailApp \
  --dest "$DEST" --app-version 1.1.0 --mac-package-identifier dev.hybridmail.desktop \
  --add-modules java.desktop,java.naming,java.security.jgss,java.security.sasl,java.net.http,jdk.httpserver,jdk.crypto.ec,jdk.unsupported
codesign --force --deep --sign - "$DEST/Hybrid Mail.app"
codesign --verify --deep --strict "$DEST/Hybrid Mail.app"
echo "Ready: $DEST/Hybrid Mail.app"
