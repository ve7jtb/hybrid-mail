#!/bin/bash
# Independent GnuPG interoperability with disposable, unprotected test-only keys.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v gpg >/dev/null
TEST_HOME="$(mktemp -d /tmp/pq-v4.XXXXXX)"
chmod 700 "$TEST_HOME"
cleanup(){ gpgconf --homedir "$TEST_HOME" --kill all >/dev/null 2>&1 || true; rm -rf "$TEST_HOME"; }
trap cleanup EXIT
mkdir -p build/v4-interop
GPG=(gpg --homedir "$TEST_HOME" --batch --yes --pinentry-mode loopback --passphrase '')
"${GPG[@]}" --quick-generate-key 'PQ Mail v4 test <legacy@example.com>' ed25519 cert 1y
TEST_FP="$("${GPG[@]}" --with-colons --list-keys legacy@example.com | awk -F: '$1=="fpr" {print $10; exit}')"
[[ "$TEST_FP" =~ ^[A-F0-9]{40}$ ]]
"${GPG[@]}" --quick-add-key "$TEST_FP" ed25519 sign 1y
"${GPG[@]}" --quick-add-key "$TEST_FP" cv25519 encr 1y
"${GPG[@]}" --armor --export legacy@example.com > build/v4-interop/public.asc
printf 'Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nIndependent v4 verification =E2=9C=93\r\n' > build/v4-interop/content.mime
"${GPG[@]}" --armor --detach-sign --output build/v4-interop/signature.asc build/v4-interop/content.mime
"${GPG[@]}" --sign --output build/v4-interop/signed.pgp build/v4-interop/content.mime
java -cp 'build/classes:lib/*' dev.hybridmail.LegacyOpenPgpTest build/v4-interop "$@"
"${GPG[@]}" --unwrap --output build/v4-interop/unwrapped.pgp --decrypt build/v4-interop/encrypted.pgp
cmp build/v4-interop/expected-signed.pgp build/v4-interop/unwrapped.pgp
echo 'PASS independent GnuPG decryption preserves the complete hybrid-signed packet stream'
