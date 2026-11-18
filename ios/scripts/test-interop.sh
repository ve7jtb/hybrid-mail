#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
fixtures="${1:?Pass an empty directory for synthetic private-key fixtures}"
mkdir -p "$fixtures"
fixtures="$(cd "$fixtures" && pwd)"
java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
javac_bin="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
classpath="$root/../build/hybrid-mail.jar:$root/../lib/*"
mkdir -p "$fixtures/classes"
"$javac_bin" -cp "$classpath" -d "$fixtures/classes" "$root/Tests/Interop/DesktopInterop.java"
"$java_bin" -cp "$fixtures/classes:$classpath" dev.hybridmail.DesktopInterop generate "$fixtures/bc"
PQ_MAIL_INTEROP_DIR="$fixtures" swift test --package-path "$root"
"$java_bin" -cp "$fixtures/classes:$classpath" dev.hybridmail.DesktopInterop verify "$fixtures/bc"
