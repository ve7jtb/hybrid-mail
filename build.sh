#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
command -v javac >/dev/null || { echo 'Install JDK 25 and set JAVA_HOME.' >&2; exit 1; }
[[ -f lib/bcprov-jdk18on-1.88-SNAPSHOT.jar ]] || { echo 'Run ./scripts/build-dependencies.sh first.' >&2; exit 1; }
mkdir -p build/classes
if [[ "$(uname -s)" == Darwin ]]; then
  mkdir -p build/native
  clang -O2 -framework Security -framework CoreFoundation native-src/keychain.c -o build/native/hybrid-mail-keychain
  codesign --force --sign - --identifier dev.hybridmail.keychain build/native/hybrid-mail-keychain
fi
javac -encoding UTF-8 -cp 'lib/*' -d build/classes src/dev/hybridmail/*.java
# Optional shared installed-app client. Keep configuration out of source control.
python3 scripts/bundle-google-client.py
jar --create --file build/hybrid-mail.jar --main-class dev.hybridmail.MailApp -C build/classes .
if [[ "${1:-}" == test ]]; then
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.SelfTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.TokenIdentityTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.TokenKemTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Token87Test
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.DesktopStateTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.MailAccountTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.GmailApiTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.SoftwareProfilesTest
  python3 -m unittest discover -s tests -v
fi
