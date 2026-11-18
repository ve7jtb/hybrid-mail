#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
app=build/native/PQMailShare.app
mkdir -p "$app/Contents/MacOS"
swiftc native-src/share.swift -o "$app/Contents/MacOS/PQMailShare"
python3 - <<'PY'
import plistlib
from pathlib import Path
Path('build/native/PQMailShare.app/Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'org.pqmail.share','CFBundleName':'PQ Mail Share','CFBundleExecutable':'PQMailShare','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','LSMinimumSystemVersion':'13.0','NSHighResolutionCapable':True}))
PY
codesign --force --sign - "$app"
