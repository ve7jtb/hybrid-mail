#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PQ_MAIL_APPLE_TEAM:?Set PQ_MAIL_APPLE_TEAM to your Apple development team ID}"
xcodebuild -project native-src/keychain-helper/PQMailKeychain.xcodeproj \
  -scheme PQMailKeychain -configuration Release -derivedDataPath build/keychain-derived \
  DEVELOPMENT_TEAM="$PQ_MAIL_APPLE_TEAM" -allowProvisioningUpdates -allowProvisioningDeviceRegistration build
codesign --verify --deep --strict build/keychain-derived/Build/Products/Release/PQMailKeychain.app
