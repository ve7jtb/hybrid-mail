# PQ Mail for iOS — S/MIME and OpenPGP preview

Native SwiftUI app with **OpenSSL 3.5 LTS (patched 3.5.10-dev snapshot)** for software cryptography and
**YubiKit Swift 1.4.0 source** for NFC/USB-C transport and a bounded raw PIV adapter for PQ operations. Builds for
Apple Silicon iOS Simulator and arm64 iOS devices, iOS 16+.

## What works

- Create four software keys (ML-DSA, ECDSA, ML-KEM, ECDH), with pure and hybrid
  S/MIME certificates. Save them in encrypted, password-protected `.p12` files.
- Import/export PQ Mail `.p12` identities; select and unlock saved software
  identities after restarting. Passwords are not saved.
- Import a desktop/Android device-sharing `.pqcert` bundle, review the public
  certificates and serial/slot mappings, and select the pure or hybrid YubiKey
  credential. Private token keys are never exported.
- Sign plain-text mail with optional authenticated encryption; save/open `.eml`.
- Choose **S/MIME** or **OpenPGP (Level 3 hybrid draft)** for outgoing messages.
- Import recipient encryption certificates for S/MIME or OpenPGP public keys.
  Verify incoming signatures against the corresponding certificate/public key;
  a valid signature does not automatically establish trust.
- Use the YubiKey's existing PIV keys for signing and decryption over NFC/USB-C.
  The PIN is collected before connecting. Serial and public slot keys are checked
  before PIN submission. A logical hybrid operation reuses its PIN for both
  components and clears its operation buffer on completion/cancellation.
- Read-only serial/slot diagnostics remain in the YubiKey tab.

Software identities are stored under the application's Application Support directory,
with AES-256 password protection and SHA-256 MAC in PKCS#12, 200,000 iterations,
atomic writes and iOS complete file protection. Newly created/imported identities
require a password of at least 12 characters. Desktop PKCS#12 protection is
accepted on import and re-encrypted for local storage. Unlocked software keys are
released when explicitly locked or when the app enters the background while idle.
Swift does not guarantee erasure of every temporary string copy; PIN/password
fields are cleared and no PIN or password is written to the identity store.

**Physical YubiKey operations remain unverified on an iPhone/iPad.** Automated
protocol tests use simulated cards with real OpenSSL signing/decapsulation.
They do not prove NFC timing, USB permissions or Beta0 firmware interoperability.

This preview does not yet have mail accounts/sending, attachments, conventional
S/MIME, a certificate trust store, or detached multipart S/MIME verification.
Self-issued certificates are test identities. Outer email headers are unsigned.

## OpenPGP usage and supported subset

1. Select a **Level 3 hybrid** software or YubiKey identity.
2. Choose **Create OpenPGP public identity** once. This adds an OpenPGP primary
   signing key, direct self-signature, email user ID certification and bound
   encryption subkey using the existing four component keys. It changes no
   YubiKey slots. On a YubiKey, one PIN entry covers all three hybrid
   self-signatures; a key's touch policy still applies.
3. Export **PQ-Mail-public.asc** and share it with your correspondent. If moving
   the same keys between devices, import this existing public identity instead of
   creating another one, so creation times and OpenPGP fingerprints stay identical.
   Import checks that all four public keys and the email match the selected
   local credential; a different existing OpenPGP identity is not overwritten.
4. Choose **OpenPGP (Level 3 hybrid draft)** in Compose. Import the recipient's
   OpenPGP public key before encrypting to another person. For self-tests, the
   selected identity is the default recipient.
5. Import the sender's OpenPGP public key before opening their messages. Check
   its fingerprint independently. Import verifies self-signatures and subkey
   binding, but does not mark the person trusted.

The implemented profile is
[draft-ietf-openpgp-nist-bp-comp-05](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-nist-bp-comp-05):
ML-DSA-65 + ECDSA P-384 (algorithm 41), ML-KEM-768 + ECDH P-384 (algorithm 37).
It uses the v6 formats in [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) and
the PQ combiner from [RFC 9980](https://www.rfc-editor.org/rfc/rfc9980).
These NIST-curve algorithm assignments are draft-specific. The current Level 2
and Level 5 P-384 identities are **S/MIME-only**: the draft has no corresponding
Level 2 profile and pairs Level 5 with P-521, not P-384. No private algorithm
numbers or silent algorithm substitution are used.

OpenPGP signature digests, empty ML-DSA context, fixed-width ECDSA encoding and
KEM domain separation are separate from CMS. Crypto primitives, software keys,
PIN handling and PIV transport are shared. OpenSSL is not used as an OpenPGP
packet parser; the bounded Swift layer implements these packets explicitly.

Supported mail formats are PGP/MIME detached binary signatures and
signed-and-encrypted PGP/MIME with a v6 PKESK and v2 SEIPD. Outgoing signatures
use SHA-384; verification also accepts SHA-256/512 and SHA3-256/512. Encryption
uses AES-256-GCM or AES-256-OCB according to authenticated recipient preferences,
HKDF-SHA256, AES-256 key wrap, chunk tags and the final length-authentication tag.
Both signature components and all encryption tags must verify before plaintext
is returned. EC public points receive full OpenSSL public-key validation.

This is a deliberately narrow preview: one primary key, one email user ID,
one encryption subkey and one recipient. Additional/revoked keys, unsupported
algorithms, compression, clear-signed text, legacy OpenPGP packets and secret
OpenPGP key import/export are rejected. Public key exchange is separate from
X.509 certificate exchange; private software material stays in encrypted `.p12`
storage. It is not a general-purpose OpenPGP client or a claim of compatibility
with every existing OpenPGP mail application.

## Profiles

Definitions and OIDs match desktop `TokenProfile.java`:

| Level label | Pure signing | Hybrid signing | Pure encryption | Hybrid encryption |
|---|---|---|---|---|
| 2 | ML-DSA-44 | MLDSA44-ECDSA-P256-SHA256 | ML-KEM-768 | MLKEM768-ECDH-P256-SHA3-256 |
| 3 | ML-DSA-65 | MLDSA65-ECDSA-P384-SHA512 | ML-KEM-768 | MLKEM768-ECDH-P384-SHA3-256 |
| 5 | ML-DSA-87 | MLDSA87-ECDSA-P384-SHA512 | ML-KEM-1024 | MLKEM1024-ECDH-P384-SHA3-256 |

The level label refers to ML-DSA's NIST category, not every component. Each
identity has four independent keys so pure and hybrid modes can use the same keys.
New credentials use 9c, 83, 9d and 82; imported legacy credentials keep their explicit 9a mapping until migration.

## Crypto implementation

OpenSSL provides key generation, ML-DSA signing/verification, ML-KEM
encapsulation/decapsulation, ECDSA/ECDH, hashes, HKDF, AES key wrap and AES-GCM.
It is statically linked; the app does not run command-line programs or download
cryptographic code at runtime. There is no Java runtime or Bouncy Castle in iOS.

The Swift layer implements the application's exact composite signature/KEM
encodings and bounded CMS parsing, rather than assuming OpenSSL's stock CMS
supports the composite profiles. Signatures use the profile's COMPSIG domain,
message representative and ML-DSA context. The KEM combiner is SHA3-256 over
ML-KEM secret, ECDH secret, ephemeral point, recipient point and profile label.
CMS uses signed attributes, KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap, and
AuthEnvelopedData with AES-256-GCM and a 128-bit tag. Plaintext is returned only
after successful authentication. Message size is bounded at 20 MiB, and ASN.1
nesting, node counts, lengths, algorithms and critical certificate extensions
are checked. Unsupported structures fail explicitly.

This is new experimental code, not an audited production cryptographic library.
Interoperability tests cover the project's current Bouncy Castle encodings; they
are not a claim of compatibility with every S/MIME implementation or older draft.

## Build

Use Xcode with Swift 6.1+ on Apple Silicon. OpenSSL source is pinned to
`81162ed421d98f527f55bfff205994f53831223b` (3.5.10-dev, containing the November 2026 security fixes). Generated libraries and private
test fixtures are not source files and must not be committed.

```sh
git init /tmp/pq-mail-openssl
git -C /tmp/pq-mail-openssl fetch --depth 1 https://github.com/openssl/openssl.git 81162ed421d98f527f55bfff205994f53831223b
git -C /tmp/pq-mail-openssl checkout --detach FETCH_HEAD
cd ios
bash scripts/build-openssl.sh /tmp/pq-mail-openssl
swift test
xcodebuild -project PQMail.xcodeproj -scheme PQMail -configuration Debug \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build
```

The build script produces a static XCFramework with Mac arm64 (unit tests), iOS
Simulator arm64 and iOS device arm64 slices. OpenSSL's Apache-2.0 license is in
`Native/LICENSE-OpenSSL.txt`. Keep SwiftPM lockfiles when updating dependencies.
A generic unsigned device build can use `-sdk iphoneos -destination
'generic/platform=iOS'`. For installation on a physical phone, open
`PQMail.xcodeproj`, select your paid Apple team, and configure an iOS provisioning
profile with NFC Tag Reading and Smart Card entitlements. No new Apple signing
configuration or TestFlight submission is made by these build commands.

## Test

`swift test` covers all six profiles, signed and encrypted round trips, rejection
of modified ML-DSA/ECDSA signatures, KEM ciphertexts, GCM tags, wrong recipients,
truncated ASN.1, invalid slot mappings and MIME header injection. It also checks
that a changed unsigned From header is reported as a mismatch.

For Bouncy Castle interoperability, use the desktop build and Java 25:

```sh
# Run from ios; JAVA_HOME should point at your Java 25 installation.
bash scripts/test-interop.sh /tmp/pq-mail-ios-interop
```

This creates synthetic private-key fixtures in the specified test directory.
It generates desktop messages, opens them with Swift, writes Swift replies, then
verifies/decrypts those replies with desktop Bouncy Castle. Do not publish the
fixture directory or use its keys as real identities.

In the simulator app, **Test all six profiles — no email** runs twelve round
trips and tampering checks. For repeatable interoperability testing only, launching
a Debug simulator build with `--crypto-self-test` also writes synthetic key/cert
fixtures under Documents/CryptoSelfTest and a Documents/crypto-results.txt report.
This export is unavailable in Release builds and never exports a user's session
identity. The desktop `DesktopInterop verify` helper can verify those simulator
messages and their self-issued certificate signatures.

Validated November 17, 2026 with Xcode 27.2:

- Mac Swift tests and desktop → Swift → desktop interoperability across all six profiles.
- iPhone 18 Pro / iOS 27.2 Simulator: twelve signed/encrypted round trips and tamper rejection.
- Desktop Bouncy Castle: all twelve simulator messages plus native-issued certificate signatures.
- UI: create a four-key identity, compose encrypted mail, open the file exporter.
- Encrypted PKCS#12 import/export: desktop → Swift → desktop for all six profiles.
- OpenPGP: published draft-05 P-384 key/signature/encrypted-message vectors,
  software PGP/MIME round trips, persistence, both AEAD modes, tampered signature
  components/tags and wrong-recipient rejection.
- Simulated PIV: real external-mu signing, ECDSA and KEM/ECDH for S/MIME and
  OpenPGP; wrong serial/public key rejected before PIN, PIN failure not retried.
- Simulator: OpenPGP signed/encrypted messages and persisted identities.
- Physical YubiKey operations remain untested; Release device builds are unsigned.

In a Debug simulator build, `--openpgp-self-test` runs a temporary software
identity test and writes `Documents/openpgp-results.txt`. It sends no email,
does not access a YubiKey and removes its temporary encrypted identity afterwards.
Published vectors and their provenance are in `Tests/Fixtures/`.

## YubiKit audit

Pinned [YubiKit Swift](https://github.com/Yubico/yubikit-swift) commit
`e19212f2efbca9af280e57542e669885de5acdc1`. Its `PIV.KeyType` includes RSA, EC,
Ed25519 and X25519; no ML-DSA, ML-KEM, external-mu or KEM decapsulation API exists
in this checkout. The typed metadata parser also rejects PQ algorithm IDs.

The adapter uses `SmartCardConnection.send(data:)` with bounded short-command
chaining and GET RESPONSE handling. It selects PIV, checks the saved serial and
public slot metadata, then performs PIN verification and GENERAL AUTHENTICATE
for external-mu ML-DSA, ECDSA, ML-KEM decapsulation or ECDH. It uses the YubiKey's
**PIV application**, including for OpenPGP mail; the separate OpenPGP card
application is not required. No PQ support is assumed in YubiKit's typed PIV API.
NFC/USB-C testing on physical PQ hardware remains required.

## Cross-platform OpenPGP

Desktop and Android implement the same Level 3 hybrid OpenPGP wire format. Export/import the same `.asc` public identity alongside the corresponding software `.p12` or public YubiKey credential bundle to retain fingerprints. Bidirectional Java/OpenSSL signed and encrypted message exchange passes; the Swift suite now has 19 passing tests. See the [shared OpenPGP guide](../docs/OPENPGP.md). Physical iPhone YubiKey testing remains pending.

## USB-only development build

A USB-only variant enables CryptoTokenKit smart-card access without NFC Tag
Reading. It hides NFC controls and defaults all YubiKey operations to USB-C.
Use `App/USB.entitlements`, `App/USBInfo.plist` and the `USB_ONLY` compilation
condition. This is useful when the Apple development team cannot provision NFC.
Hardware access still needs testing on the connected phone.

```sh
xcodebuild -project PQMail.xcodeproj -scheme PQMail -configuration Debug \
  -destination 'generic/platform=iOS' DEVELOPMENT_TEAM=YOUR_TEAM_ID \
  CODE_SIGN_ENTITLEMENTS=App/USB.entitlements INFOPLIST_FILE=App/USBInfo.plist \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS='DEBUG USB_ONLY' \
  -allowProvisioningUpdates build
```

The separate `SOFTWARE_ONLY` condition hides all token controls and uses
`App/Software.entitlements` with `App/SoftwareInfo.plist`. Neither variant changes
the full build's NFC and USB capability settings.

## On-key certificate bundles

The identity screen now offers saving/importing signed public bundles directly
from a YubiKey and explicit ECDSA migration from 9a to empty 83. Existing mappings
remain intact until migration. Public reads do not require a PIN; writes/migration
require management-key authentication. See [format and recovery](../docs/ON-KEY-CERTIFICATES.md).
Hardware access on iOS still requires appropriate entitlements. Physical storage
and migration tests are pending; installing this build changes no keys.
