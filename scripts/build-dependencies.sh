#!/bin/bash
# Build the exact fork revisions used for the app, rather than unpinned snapshots.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${HYBRID_DEPS_DIR:-$ROOT/.deps}"
mkdir -p "$DEPS"
DEPS="$(cd "$DEPS" && pwd)"
source "$ROOT/scripts/check-java.sh"
for tool in git java javac mvn; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }; done
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$DEPS/cache/gradle}"
M2="$DEPS/cache/m2"
mkdir -p "$DEPS/repos" "$DEPS/logs" "$ROOT/lib"
checkout() {
  local name="$1" revision="$2" destination="$DEPS/repos/$1"
  if [[ ! -d "$destination/.git" ]]; then
    git init "$destination"
    git -C "$destination" remote add origin "https://github.com/ve7jtb/$name.git"
    git -C "$destination" fetch --depth 1 origin "$revision"
    git -C "$destination" checkout --detach FETCH_HEAD
  fi
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$revision" ]] || { echo "Wrong revision in $destination; use a fresh HYBRID_DEPS_DIR." >&2; exit 1; }
  [[ -z "$(git -C "$destination" status --porcelain --untracked-files=no)" ]] || { echo "Tracked changes in $destination; refusing to build." >&2; exit 1; }
}
checkout mail-api 09b27cf52b4b382c55cc8736858456f3aa43b369
checkout angus-mail d33de7563efdf5a3cb0691994500d6cad8aecafd
checkout bc-java fad147c4440df867930bd9d8c14e85fbaca1c377
maven() { mvn -B -ntp "-Dmaven.repo.local=$M2" "$@"; }
echo 'Building Jakarta Mail API (log: mail-api.log)…'
maven -DskipTests -f "$DEPS/repos/mail-api/api/pom.xml" source:jar install > "$DEPS/logs/mail-api.log" 2>&1
echo 'Building Angus Mail (log: angus.log)…'
maven -DskipTests -Dmail-api.version=2.2.0-SNAPSHOT -f "$DEPS/repos/angus-mail/pom.xml" install > "$DEPS/logs/angus.log" 2>&1
echo 'Building Bouncy Castle (log: bc-build.log)…'
(cd "$DEPS/repos/bc-java" && ./gradlew --no-daemon --max-workers=4 :prov:jar :util:jar :pkix:jar :jmail:jar :pg:jar) > "$DEPS/logs/bc-build.log" 2>&1
# Resolve the two activation jars explicitly, rather than rely on incidental transitive versions.
for artifact in jakarta.activation:jakarta.activation-api:2.2.0-M2 org.eclipse.angus:angus-activation:2.1.0-M1 com.google.code.gson:gson:2.13.2; do
  maven org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get "-Dartifact=$artifact" -Dtransitive=false
 done
cp "$DEPS/repos/mail-api/api/target/jakarta.mail-api-2.2.0-SNAPSHOT.jar" "$ROOT/lib/"
cp "$DEPS/repos/angus-mail/providers/angus-mail/target/angus-mail-2.1.0-SNAPSHOT.jar" "$ROOT/lib/"
for module in prov util pkix jmail pg; do
  cp "$DEPS/repos/bc-java/$module/build/libs/bc${module}-jdk18on-1.88-SNAPSHOT.jar" "$ROOT/lib/"
done
cp "$M2/jakarta/activation/jakarta.activation-api/2.2.0-M2/jakarta.activation-api-2.2.0-M2.jar" "$ROOT/lib/"
cp "$M2/org/eclipse/angus/angus-activation/2.1.0-M1/angus-activation-2.1.0-M1.jar" "$ROOT/lib/"
cp "$M2/com/google/code/gson/gson/2.13.2/gson-2.13.2.jar" "$ROOT/lib/"
echo "Dependencies ready in $ROOT/lib. Logs: $DEPS/logs"
