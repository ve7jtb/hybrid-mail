#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
exec java -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.MailApp
