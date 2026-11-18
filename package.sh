#!/bin/bash
# macOS desktop image with Java, OpenSSL and the locally built PKCS#11 modules.
set -euo pipefail
cd "$(dirname "$0")"
source scripts/check-java.sh
[[ "$(uname -s)" == Darwin ]] || { echo 'This bundled package script targets macOS.' >&2; exit 1; }
[[ -f build/hybrid-mail.jar ]] || { echo 'Run ./build.sh first.' >&2; exit 1; }
OPENSSL_ROOT="${HYBRID_OPENSSL_ROOT:-/opt/homebrew/opt/openssl@3}"
DEST="${HYBRID_MAIL_PACKAGE_DIR:-$PWD/dist}"
for file in native/pkcs11.dylib native/libykcs11.dylib "$OPENSSL_ROOT/bin/openssl" "$OPENSSL_ROOT/lib/libcrypto.3.dylib" "$OPENSSL_ROOT/lib/libssl.3.dylib"; do
  [[ -f "$file" ]] || { echo "Missing dependency: $file" >&2; exit 1; }
done
[[ ! -e "$DEST/PQ Mail.app" ]] || { echo 'Destination app exists; choose another HYBRID_MAIL_PACKAGE_DIR.' >&2; exit 1; }
/usr/bin/python3 --version >/dev/null
mkdir -p "$DEST"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/adapters" "$stage/native/bin" "$stage/native/lib" "$stage/notices"
cp build/hybrid-mail.jar lib/*.jar "$stage/"
ditto build/native/PQMailShare.app "$stage/native/PQMailShare.app"
cp build/native/hybrid-mail-keychain "$stage/native/bin/"
./scripts/build-provision.sh
cp build/native/hybrid-mail-provision "$stage/native/bin/"
cp adapters/*.py "$stage/adapters/"
cp native/*.dylib "$stage/native/lib/"
cp -L "$OPENSSL_ROOT/bin/openssl" "$stage/native/bin/openssl"
cp -L "$OPENSSL_ROOT/lib/libcrypto.3.dylib" "$OPENSSL_ROOT/lib/libssl.3.dylib" "$stage/native/lib/"
cp "$OPENSSL_ROOT/LICENSE.txt" "$stage/notices/OpenSSL-LICENSE.txt"
cp docs/THIRD-PARTY.txt docs/YUBIKIT-LICENSE.txt "$stage/notices/"
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
jpackage --type app-image --name 'PQ Mail' --icon assets/pq-mail.icns --input "$stage" \
  --main-jar hybrid-mail.jar --main-class dev.hybridmail.MailApp \
  --dest "$DEST" --app-version 1.2.1 --mac-package-identifier dev.hybridmail.desktop \
  --add-modules java.desktop,java.naming,java.security.jgss,java.security.sasl,java.net.http,jdk.httpserver,jdk.crypto.ec,jdk.unsupported
python3 scripts/register-certificate-bundle.py "$DEST/PQ Mail.app"
if [[ -n "${PQ_MAIL_APPLE_TEAM:-}" ]]; then
  : "${PQ_MAIL_SIGNING_IDENTITY:?Set PQ_MAIL_SIGNING_IDENTITY to your signing certificate identity}"
  ./scripts/build-keychain-helper.sh
  mkdir -p "$DEST/PQ Mail.app/Contents/Helpers"
  ditto build/keychain-derived/Build/Products/Release/PQMailKeychain.app "$DEST/PQ Mail.app/Contents/Helpers/PQMailKeychain.app"
  # Preserve the helper's profile and entitlements; never deep re-sign it ad hoc.
  if [[ "${PQ_MAIL_DISTRIBUTION:-0}" == 1 ]]; then
    bash scripts/sign-macos.sh "$DEST/PQ Mail.app"
  else
    codesign --force --sign "$PQ_MAIL_SIGNING_IDENTITY" "$DEST/PQ Mail.app"
  fi
else
  codesign --force --deep --sign - "$DEST/PQ Mail.app"
fi
codesign --verify --deep --strict "$DEST/PQ Mail.app"
echo "Ready: $DEST/PQ Mail.app"

java scripts/CheckJava.java "$DEST/PQ Mail.app/Contents/runtime/Contents/Home" "$DEST/java-runtime.txt"
