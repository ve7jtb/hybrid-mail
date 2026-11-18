# OpenPGP preview

PQ Mail supports signed and optionally encrypted PGP/MIME on macOS, Windows,
Android and iOS. This is an experimental implementation of
[draft-ietf-openpgp-nist-bp-comp-05](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-nist-bp-comp-05),
with version 6 keys/signatures and authenticated encryption. It is not a claim
of compatibility with all OpenPGP clients or a stable final standard.

## Supported profile

Use the **Level 3 hybrid** identity: ML-DSA-65 + ECDSA P-384 signing (algorithm
41), and ML-KEM-768 + ECDH P-384 encryption (algorithm 37). Both signature
components must verify. Encryption uses AES-256 and authenticated SEIPDv2
packets; GCM and OCB are supported when receiving.

The existing Level 2, Level 5 P-384 and pure PQ identities remain S/MIME-only.
In particular, the draft's Level 5 OpenPGP profile requires P-521, so it cannot
reuse PQ Mail's Level 5 P-384 keys. S/MIME composite signatures and OpenPGP
hybrid signatures have different encodings and domain separation.

## Getting started

1. Create/import a Level 3 software identity, or select an existing Level 3
   YubiKey identity with all four keys and matching public certificates.
2. Open **OpenPGP** on desktop or **OpenPGP public identities** on Android.
   On iOS use the OpenPGP public-identity controls in local mail.
3. Create your OpenPGP public identity, or import its existing `.asc` file.
   Creation signs its key bindings with your selected signing keys.
4. Export the public `.asc` file. Exchange it with correspondents and compare
   fingerprints through a trusted channel. Import recipient and signer public
   identities before encrypting or verifying their messages.
5. Select **OpenPGP** in Compose. Encryption is optional. Save/open `.eml`
   files; desktop and Android can also use their existing send/receive paths.
   iOS currently works with local files only.

For a self-test, choose your own public identity as recipient and verifier.
For another installation, transfer the same public `.asc` identity together
with the matching password-protected software `.p12` or public YubiKey
credential bundle. A new OpenPGP identity can have a different fingerprint
even when backed by the same keys. Importing your own public identity checks
that its keys and email match the selected credential.

## Private keys and trust

Software private keys remain in the password-protected `.p12`. Hardware
operations use the existing PIV keys: bundled PKCS#11 on desktop, YubiKit on
Android, and YubiKit transport/raw PIV on iOS. No OpenPGP applet provisioning
is required. The host performs public-key encryption and the hybrid combiner;
the YubiKey performs private-key signing, decapsulation and ECDH.

An operation reuses its entered PIN across its components, then clears the
operation cache. PINs are not saved. Public `.asc` files contain no private keys.
Import verifies the public identity's self-signatures and key bindings, but
does **not** establish ownership or trust. S/MIME certificate fingerprint trust
does not automatically transfer to OpenPGP identities.

## Current limits and validation

Only plain-text mail, one recipient, one email user ID and the Level 3 hybrid
profile are supported. Attachments remain available through S/MIME. There is
no OpenPGP secret-key import/export, compression, legacy algorithm support or
general-purpose OpenPGP keyring/trust-management implementation.

Validation includes published draft vectors, signature/ciphertext tampering,
software and simulated hardware round trips, JavaMail serialization, Android
emulator instrumentation and bidirectional Java/OpenSSL message exchange.
Physical YubiKey OpenPGP testing and Windows runtime testing remain pending.

Run `./build.sh test` for Java tests. Android's
`OpenPgpAndroidTest` and `YubiBackendTest` run through
`./android/gradlew -p android :app:connectedDebugAndroidTest` with an emulator
or device. See [the iOS guide](../ios/README.md) for OpenSSL framework setup and
Swift tests. Cross-platform fixtures must be generated locally: they contain
temporary software private keys and must not be published as user credentials.
