param([ValidateSet('x64','arm64')][string]$Architecture='x64')
$ErrorActionPreference='Stop'
Set-Location (Join-Path $PSScriptRoot '..')
function Checked { if ($LASTEXITCODE -ne 0) { throw "Native command failed ($LASTEXITCODE)" } }
if (!$env:JAVA_HOME) { throw 'Set JAVA_HOME to a patched JDK 25 (25.0.5.1 or newer).' }
& "$env:JAVA_HOME/bin/java.exe" scripts/CheckJava.java; Checked
& "$env:JAVA_HOME/bin/java.exe" scripts/CheckJava.java --test; Checked
$stage=Join-Path $PWD 'build/windows-stage'
New-Item -ItemType Directory -Force "$stage/native/bin","$stage/native/lib","$stage/native/python","$stage/adapters","$stage/notices","dist/windows" | Out-Null
Copy-Item build/hybrid-mail.jar,lib/*.jar $stage
Copy-Item adapters/*.py "$stage/adapters"
Copy-Item docs/THIRD-PARTY.txt,docs/YUBIKIT-LICENSE.txt "$stage/notices"
Copy-Item build/native/*.exe "$stage/native/bin"
Copy-Item build/native/*.dll "$stage/native/lib"
Copy-Item build/native/openssl/* "$stage/native/bin"
# Provider DLL dependencies are beside the provider as well as OpenSSL.
Copy-Item build/native/openssl/*.dll "$stage/native/lib"
$pythonArch=if($Architecture -eq 'arm64'){'arm64'}else{'amd64'}
Invoke-WebRequest "https://www.python.org/ftp/python/3.13.9/python-3.13.9-embed-$pythonArch.zip" -OutFile build/python.zip
Expand-Archive build/python.zip "$stage/native/python" -Force
# App-local VC runtime also supports the native helpers and PKCS#11 DLL.
Get-ChildItem "$stage/native/python" -Filter 'vcruntime*.dll' | Copy-Item -Destination "$stage/native/bin"
Get-ChildItem "$stage/native/python" -Filter 'vcruntime*.dll' | Copy-Item -Destination "$stage/native/lib"
# Embedded Python's stdlib is sufficient for all adapters.
$env:PATH="$stage/native/bin;$env:PATH"
& "$stage/native/bin/openssl.exe" version; Checked
$env:PKCS11_PROVIDER_MODULE="$stage/native/lib/ykcs11.dll"
& "$stage/native/bin/openssl.exe" list -providers -provider default -provider "$stage/native/lib/pkcs11.dll"; Checked
& "$stage/native/python/python.exe" -m py_compile adapters/pkcs11-mu.py adapters/pkcs11-kem.py adapters/pkcs11-presence.py; Checked
foreach($test in @('SelfTest','TokenIdentityTest','TokenKemTest','Token87Test','SoftwareProfilesTest','GmailApiTest','CertificateBundleTest','OnKeyBundleTest')) {
 & "$env:JAVA_HOME/bin/java.exe" '-Djava.awt.headless=true' -cp "$stage/*" "dev.hybridmail.$test"; Checked
}
# Isolated native credential-store test; never accesses an actual OAuth credential.
$helper="$stage/native/bin/hybrid-mail-credentials.exe"
'installer-disposable-test' | & $helper put self-test; Checked
$read=& $helper get self-test; Checked
if($read.Trim() -ne 'installer-disposable-test'){throw 'Credential store roundtrip failed'}
& $helper delete self-test; Checked
& "$env:JAVA_HOME/bin/jpackage.exe" --type app-image --name 'PQ Mail' --icon assets/pq-mail.ico --input $stage --main-jar hybrid-mail.jar --main-class dev.hybridmail.MailApp --dest build/windows-image --app-version 1.2.1 --add-modules java.desktop,java.naming,java.security.jgss,java.security.sasl,java.net.http,jdk.httpserver,jdk.crypto.ec,jdk.unsupported; Checked
& "$env:JAVA_HOME/bin/java.exe" scripts/CheckJava.java "build/windows-image/PQ Mail/runtime" "dist/windows/java-runtime-$Architecture.txt"; Checked
$iscc=Get-ChildItem 'C:/Program Files (x86)/Inno Setup*/ISCC.exe','C:/Program Files/Inno Setup*/ISCC.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if(!$iscc){
 Invoke-WebRequest https://files.jrsoftware.org/is/6/innosetup-6.4.3.exe -OutFile build/inno-setup.exe
 Start-Process build/inno-setup.exe -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-' -Wait
 $iscc='C:/Program Files (x86)/Inno Setup 6/ISCC.exe'
}
& $iscc "/DTargetArch=$Architecture" scripts/windows-installer.iss; Checked
