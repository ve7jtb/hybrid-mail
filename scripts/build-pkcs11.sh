#!/bin/bash
# Build optional native dependencies without installing or changing system OpenSSL.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${HYBRID_PKCS11_DEPS_DIR:-$ROOT/.deps/pkcs11}"
mkdir -p "$DEPS"
DEPS="$(cd "$DEPS" && pwd)"
for tool in git cargo rustc meson ninja pkg-config python3; do command -v "$tool" >/dev/null || { echo "Missing $tool; see docs/PKCS11.md" >&2; exit 1; }; done
checkout() {
  local name="$1" remote="$2" revision="$3" destination="$DEPS/$1" patch="$ROOT/patches/$4"
  if [[ ! -d "$destination/.git" ]]; then
    git init "$destination"
    git -C "$destination" remote add origin "$remote"
    git -C "$destination" fetch --depth 1 origin "$revision"
    git -C "$destination" checkout --detach FETCH_HEAD
  fi
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$revision" ]] || { echo "Wrong revision in $destination; choose a fresh HYBRID_PKCS11_DEPS_DIR." >&2; exit 1; }
  if [[ -n "$(git -C "$destination" status --porcelain --untracked-files=no)" ]]; then
    git -C "$destination" apply --reverse --check "$patch" 2>/dev/null || { echo "Unexpected changes in $destination" >&2; exit 1; }
    git -C "$destination" diff --binary > "$DEPS/$name-local.diff"
    cmp -s "$DEPS/$name-local.diff" "$patch" || { echo "Unexpected patch in $destination" >&2; exit 1; }
    [[ -z "$(git -C "$destination" diff --cached --name-only)" ]] || { echo 'Unexpected staged changes' >&2; exit 1; }
  else
    git -C "$destination" apply --check "$patch"
    git -C "$destination" apply "$patch"
  fi
}
checkout pkcs11-provider-818 https://github.com/joostd/pkcs11-provider.git 8e01f28b98bb0543a9d5600ebd9e061edb21de53 pkcs11-pin-prompt.patch
checkout yubico-pkcs11 https://github.com/Yubico/yubico-pkcs11.git c28419969d0ac2ead2e94065b77ebbd281cc52de ykcs11-ec-metadata.patch
if [[ ! -d "$DEPS/pkcs11-provider-818/build/meson-private" ]]; then
  meson setup "$DEPS/pkcs11-provider-818/build" "$DEPS/pkcs11-provider-818" -Dbuild_info=PR818-8e01f28
fi
meson compile -C "$DEPS/pkcs11-provider-818/build"
# Build only the PIV module; do NOT run upstream hardware tests (some reset PIV).
# Rust's post-link stripping can produce a dylib macOS 27 rejects. Keep the
# LINKEDIT layout emitted by the linker (rust-lang/rust#157750).
if [[ "$(uname -s)" == Darwin ]]; then export CARGO_PROFILE_RELEASE_STRIP=none; fi
cargo build --locked --manifest-path "$DEPS/yubico-pkcs11/Cargo.toml" -p ykcs11 --release
case "$(uname -s)" in
  Darwin) extension=dylib ;;
  Linux) extension=so ;;
  *) echo 'Only macOS/Linux build scripts are provided.' >&2; exit 1 ;;
esac
mkdir -p "$ROOT/native"
cp "$DEPS/pkcs11-provider-818/build/src/pkcs11.$extension" "$ROOT/native/"
cp "$DEPS/yubico-pkcs11/target/release/libykcs11.$extension" "$ROOT/native/"
python3 - "$ROOT/native/libykcs11.$extension" <<'PYLOAD'
import ctypes, sys
ctypes.CDLL(sys.argv[1])
print("Yubico module dynamic-load check passed")
PYLOAD
printf 'Built native libraries in %s/native\n' "$ROOT"
