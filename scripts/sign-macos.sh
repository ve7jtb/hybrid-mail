#!/bin/bash
# Sign nested code inside-out, preserving the separately provisioned helper.
set -euo pipefail
cd "$(dirname "$0")/.."
app="${1:?Usage: sign-macos.sh app-path}"
: "${PQ_MAIL_SIGNING_IDENTITY:?Set Developer ID Application identity}"
[[ -d "$app/Contents/Helpers/PQMailKeychain.app" ]] || { echo 'Provisioned Keychain helper is required.' >&2; exit 1; }
codesign --verify --strict "$app/Contents/Helpers/PQMailKeychain.app"
if [[ -d "$app/Contents/Helpers/PQMailPasskey.app" ]]; then
  python3 scripts/verify-passkey-helper.py "$app/Contents/Helpers/PQMailPasskey.app"
fi
while IFS= read -r -d '' binary; do
  if file -b "$binary" | grep -q 'Mach-O'; then
    codesign --force --timestamp --options runtime --sign "$PQ_MAIL_SIGNING_IDENTITY" "$binary"
  fi
done < <(find "$app/Contents" -path "$app/Contents/Helpers" -prune -o -type f -print0)
if [[ -d "$app/Contents/app/native/PQMailShare.app" ]]; then
  codesign --force --timestamp --options runtime --sign "$PQ_MAIL_SIGNING_IDENTITY" "$app/Contents/app/native/PQMailShare.app"
fi
if [[ -d "$app/Contents/runtime" ]]; then
  codesign --force --timestamp --options runtime --sign "$PQ_MAIL_SIGNING_IDENTITY" "$app/Contents/runtime"
fi
codesign --force --timestamp --options runtime --entitlements native-src/macos-runtime.entitlements --sign "$PQ_MAIL_SIGNING_IDENTITY" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
