#!/bin/bash
# Optional interoperability check. Only generated software fixtures are used.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/check-java.sh
if [[ $# != 2 ]]; then
  echo 'Usage: scripts/test-chat-sequoia.sh /path/to/sq NEW-result-directory' >&2
  exit 2
fi
[[ -x "$1" ]] || { echo 'Sequoia executable not found' >&2; exit 2; }
[[ ! -e "$2" ]] || { echo 'Use a new result directory; existing results are preserved' >&2; exit 2; }
mkdir -p build/classes
javac -encoding UTF-8 -cp 'lib/*' -d build/classes src/dev/hybridmail/*.java
java -Djava.awt.headless=true -cp 'build/classes:lib/*' dev.hybridmail.ChatBundleSequoiaTest "$1" "$2"
