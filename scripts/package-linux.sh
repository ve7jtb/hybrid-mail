#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/check-java.sh
source scripts/openssl-source.env
cmp scripts/openssl-source.env .deps/openssl-install/pq-mail-source.env
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
stage="$PWD/build/linux-stage"
image="$PWD/build/linux-image"
out="$PWD/dist/linux"
[[ ! -e "$stage" && ! -e "$image" ]] || { echo 'Use a clean Linux build directory' >&2; exit 1; }
mkdir -p "$stage/native/bin" "$stage/native/lib" "$stage/adapters" "$stage/notices" "$out"
cp build/hybrid-mail.jar lib/*.jar "$stage/"
cp adapters/*.py "$stage/adapters/"
cp build/native/pqmail-passkey build/native/pqmail-pkcs11-sign build/native/hybrid-mail-provision build/native/hybrid-mail-credentials "$stage/native/bin/"
cp native/*.so .deps/openssl-install/lib/libcrypto.so.3 .deps/openssl-install/lib/libssl.so.3 "$stage/native/lib/"
cp .deps/openssl-install/bin/openssl "$stage/native/bin/"
cp docs/THIRD-PARTY.txt docs/YUBIKIT-LICENSE.txt ".deps/openssl-$OPENSSL_REVISION/LICENSE.txt" "$stage/notices/"
patchelf --set-rpath '$ORIGIN/../lib' "$stage/native/bin/openssl"
patchelf --set-rpath '$ORIGIN/../lib' "$stage/native/bin/pqmail-pkcs11-sign"
for file in "$stage/native/lib/"*.so*; do patchelf --set-rpath '$ORIGIN' "$file"; done
unset LD_LIBRARY_PATH
# Test against the staged libraries, then check the helper can load without them
# being added to the environment (its bundle-relative RPATH must work).
OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$stage/native/lib" build/tests/test-pkcs11-sign
set +e
helper_output=$(OPENSSL_CONF=/dev/null "$stage/native/bin/pqmail-pkcs11-sign" 2>&1)
helper_status=$?
set -e
[[ "$helper_status" == 1 && "$helper_output" == 'PQ Mail single-session signer failed at arguments; no retry' ]] || { echo 'Packaged signing helper load test failed' >&2; exit 1; }

"$stage/native/bin/openssl" version | tee "$out/openssl-version-$arch.txt"
cp scripts/openssl-source.env "$stage/notices/openssl-source.env"
cp scripts/openssl-source.env "$out/openssl-source.env"
PKCS11_PROVIDER_MODULE="$stage/native/lib/libykcs11.so" "$stage/native/bin/openssl" list -providers -provider default -provider "$stage/native/lib/pkcs11.so"
"$stage/native/bin/pqmail-passkey" --probe
java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.LinuxPasskeyTest "$stage/native/bin/pqmail-passkey"
ldd "$stage/native/bin/pqmail-passkey" > "$out/fido-helper-libraries-$arch.txt"
! grep -q "not found" "$out/fido-helper-libraries-$arch.txt"
python3 -m py_compile adapters/*.py
jpackage --type app-image --name 'PQ Mail' --icon assets/pq-mail.png --input "$stage" --main-jar hybrid-mail.jar --main-class dev.hybridmail.MailApp --dest "$image" --app-version 1.2.1 --add-modules java.desktop,java.naming,java.security.jgss,java.security.sasl,java.net.http,jdk.httpserver,jdk.crypto.ec,jdk.unsupported
java scripts/CheckJava.java "$image/PQ Mail/lib/runtime" "$out/java-runtime-$arch.txt"
# Test the real bundled JVM in a disposable app copy, without mail or hardware.
cp -a "$image/PQ Mail" "$PWD/build/linux-smoke"
sed -i 's/app.mainclass=dev.hybridmail.MailApp/app.mainclass=dev.hybridmail.SoftwareProfilesTest/' 'build/linux-smoke/lib/app/PQ Mail.cfg'
'build/linux-smoke/bin/PQ Mail'
jpackage --type deb --name 'PQ Mail' --icon assets/pq-mail.png --resource-dir assets/linux --app-image "$image/PQ Mail" --dest "$out" --app-version 1.2.1 --linux-package-name pq-mail --linux-deb-maintainer ve7jtb@gmail.com --vendor 'PQ Mail' --linux-menu-group Network --linux-shortcut --linux-package-deps 'python3, pcscd, libccid, libsecret-1-0, libudev1, libu2f-udev, xdg-utils' --install-dir /opt
mv "$out/"*.deb "$out/PQ-Mail-1.2.1-Linux-$arch.deb"
# jpackage's Debian step can generate a separate launcher icon; verify that
# the desktop entry points to our artwork, not the default Java icon.
icon_check=$(mktemp -d)
dpkg-deb --extract "$out/PQ-Mail-1.2.1-Linux-$arch.deb" "$icon_check"
python3 - "$icon_check" <<'PYICON'
from pathlib import Path
import sys
root=Path(sys.argv[1])
entry=next(root.glob('opt/pq-mail/lib/*.desktop'))
assert 'StartupWMClass=PQ Mail' in entry.read_text(), 'Missing desktop window association'
icon=next(line[5:] for line in entry.read_text().splitlines() if line.startswith('Icon='))
assert (root/icon.lstrip('/')).read_bytes()==Path('assets/pq-mail.png').read_bytes(), 'Debian desktop launcher uses the wrong icon'
assert (root/"opt/pq-mail/lib/app/native/bin/pqmail-passkey").is_file(), "Missing native FIDO helper"
print('PASS Debian desktop launcher artwork and native FIDO helper')
PYICON
rm -rf "$icon_check"
cp docs/LINUX-PASSKEYS.md "$out/Native-passkeys.txt"
tar -czf "$out/PQ-Mail-1.2.1-Linux-$arch.tar.gz" -C "$image" 'PQ Mail'
(cd "$out" && sha256sum *.deb *.tar.gz > SHA256SUMS)
