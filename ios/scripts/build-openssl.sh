#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="${1:?Pass the pinned OpenSSL 3.5 LTS source directory}"
source_dir="$(cd "$source_dir" && pwd)"
source "$root/../scripts/openssl-source.env"
expected="$OPENSSL_REVISION"
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$expected" ]]; then
  echo "Expected pinned OpenSSL 3.5 LTS commit $expected" >&2; exit 1
fi
build_root="${2:-$root/.native-build/$expected}"
if [[ -d "$build_root" && ! -f "$build_root/source-revision" ]]; then
  echo "Use a fresh build directory: source revision is not recorded" >&2; exit 1
fi
if [[ -f "$build_root/source-revision" && "$(cat "$build_root/source-revision")" != "$expected" ]]; then
  echo "Use a fresh build directory for the updated OpenSSL source" >&2; exit 1
fi
[[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ]] || { echo "OpenSSL source has tracked changes" >&2; exit 1; }
mkdir -p "$build_root" "$root/Frameworks"
printf "%s\n" "$expected" > "$build_root/source-revision"
for variant in macos simulator device; do
  mkdir -p "$build_root/$variant"
  case "$variant" in
    macos) target=darwin64-arm64-cc; sdk=macosx; triple=arm64-apple-macos13.0 ;;
    simulator) target=iossimulator-arm64-xcrun; sdk=iphonesimulator; triple=arm64-apple-ios16.0-simulator ;;
    device) target=ios64-xcrun; sdk=iphoneos; triple=arm64-apple-ios16.0 ;;
  esac
  (
    cd "$build_root/$variant"
    if [[ ! -f Makefile ]]; then
      CFLAGS="-target $triple" perl "$source_dir/Configure" "$target" no-shared no-tests no-apps no-module no-dso no-engine --prefix="$build_root/$variant/install"
    fi
    make -j6 build_libs
    xcrun --sdk "$sdk" clang -target "$triple" -O2 -I include -I "$source_dir/include" -I "$root/Native/include" -c "$root/Native/crypto.c" -o pq_crypto.o
    cp libcrypto.a libPQNative.a
    ar r libPQNative.a pq_crypto.o
    mkdir -p headers
    cp "$root/Native/include/CNative.h" headers/
    printf 'module CNative { header "CNative.h" export * }\n' > headers/module.modulemap
  ) > "$build_root/$variant.log" 2>&1
done
# Only replace this generated build output after all slices succeeded.
if [[ -d "$root/Frameworks/PQNative.xcframework" ]]; then mv "$root/Frameworks/PQNative.xcframework" "$build_root/previous-$(date +%s).xcframework"; fi
xcodebuild -create-xcframework \
 -library "$build_root/macos/libPQNative.a" -headers "$build_root/macos/headers" \
 -library "$build_root/simulator/libPQNative.a" -headers "$build_root/simulator/headers" \
 -library "$build_root/device/libPQNative.a" -headers "$build_root/device/headers" \
 -output "$root/Frameworks/PQNative.xcframework"
