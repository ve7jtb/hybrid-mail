#!/bin/bash
# Associated Domains requires a paid team and a matching provisioning profile.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PQ_MAIL_APPLE_TEAM:?Set PQ_MAIL_APPLE_TEAM to the provisioned Apple team ID}"
signing_args=()
if [[ "${PQ_MAIL_SIGNING_IDENTITY:-}" == *"Developer ID Application"* || "${PQ_MAIL_DISTRIBUTION:-0}" == 1 ]]; then
  : "${PQ_MAIL_PASSKEY_PROFILE:?Set PQ_MAIL_PASSKEY_PROFILE to the passkey helper Developer ID provisioning profile name or UUID}"
  signing_args+=(CODE_SIGN_STYLE=Manual "CODE_SIGN_IDENTITY=$PQ_MAIL_SIGNING_IDENTITY" "PROVISIONING_PROFILE_SPECIFIER=$PQ_MAIL_PASSKEY_PROFILE" OTHER_CODE_SIGN_FLAGS=--timestamp)
fi
xcodebuild -project native-src/passkey-helper/PQMailPasskey.xcodeproj \
  -scheme PQMailPasskey -configuration Release -derivedDataPath build/passkey-derived \
  DEVELOPMENT_TEAM="$PQ_MAIL_APPLE_TEAM" "${signing_args[@]}" -allowProvisioningUpdates -allowProvisioningDeviceRegistration build
python3 scripts/verify-passkey-helper.py build/passkey-derived/Build/Products/Release/PQMailPasskey.app "$PQ_MAIL_APPLE_TEAM"
