#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Independent Bouncy Castle OpenPGP interoperability checks (tested with bcpg 1.81).
: "${BCPG_JAR:?Set BCPG_JAR to bcpg-jdk18on-1.81.jar}"
mkdir -p build/interop-tests
javac -cp "build/classes:lib/*:$BCPG_JAR" -d build/interop-tests tests/java/dev/hybridmail/ClassicalOpenPgpTest.java
java -cp "build/interop-tests:build/classes:lib/*:$BCPG_JAR" dev.hybridmail.ClassicalOpenPgpTest
