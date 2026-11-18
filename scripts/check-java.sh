#!/bin/bash
# Source this script so every Java tool comes from the checked JDK.
: "${JAVA_HOME:?Set JAVA_HOME to a patched JDK 25 (25.0.5.1 or newer).}"
for tool in java javac jar jlink jpackage; do
  [[ -x "$JAVA_HOME/bin/$tool" ]] || { echo "Missing $JAVA_HOME/bin/$tool" >&2; exit 1; }
done
export PATH="$JAVA_HOME/bin:$PATH"
"$JAVA_HOME/bin/java" "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/CheckJava.java"
