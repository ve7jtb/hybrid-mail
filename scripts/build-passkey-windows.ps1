$ErrorActionPreference='Stop'
Set-Location (Join-Path $PSScriptRoot '..')
# Run in the target x64/ARM64 MSVC developer environment. No WebAuthn DLL is bundled.
New-Item -ItemType Directory -Force build/native | Out-Null
& cl /nologo /O2 /EHsc /std:c++17 /utf-8 /MT /W4 native-src/passkey-win.cpp /Fo:build/native/passkey-win.obj /Fe:build/native/pqmail-passkey.exe user32.lib
if ($LASTEXITCODE -ne 0) { throw 'Windows passkey helper compilation failed' }
& ./build/native/pqmail-passkey.exe --self-test
if ($LASTEXITCODE -ne 0) { throw 'Windows passkey helper self-test failed' }
$probe=& ./build/native/pqmail-passkey.exe --probe
if ($LASTEXITCODE -ne 0) { throw 'Windows WebAuthn API probe failed' }
$probe | Set-Content -Encoding utf8 build/native/passkey-capabilities.json
$capabilities=$probe | ConvertFrom-Json
Write-Host "System WebAuthn API version: $($capabilities.apiVersion); PRF API available: $($capabilities.available)"
