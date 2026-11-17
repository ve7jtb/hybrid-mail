# PQ Mail

PQ Mail is an experimental post-quantum S/MIME mail application for **desktop and Android**, built with **Jakarta Mail, Eclipse Angus Mail, and Bouncy Castle**. Desktop token operations use bundled **PKCS#11** adapters; Android uses **YubiKit 3.3.0** directly. It supports software identities and keys generated and used on a PQC Ready YubiKey. Formerly **Hybrid Mail**, the project now lives at [ve7jtb/pq-mail](https://github.com/ve7jtb/pq-mail).

## Android preview

An [Android version](android/README.md) uses **YubiKit 3.3.0 directly over USB and NFC**, with the same three software `.p12`, pure PQ, and hybrid profiles. It includes local S/MIME, IMAPS/SMTP, and public-only YubiKey identities. See the Android guide for build instructions, hardware testing, and preview limitations; Google OAuth and token provisioning remain desktop features.

## Platform capabilities

| Capability | Desktop | Android preview |
|---|---|---|
| Software `.p12`, Level 2/3/5, pure and hybrid | Yes | Yes |
| YubiKey signing and decryption | Bundled PKCS#11 | Direct YubiKit; Level 3 NFC verified, physical USB testing pending |
| Generate four keys on an empty YubiKey | Yes | No; use existing keys |
| Signed mail with optional encryption; `.eml` files | Yes | Yes |
| Ten-message IMAPS inbox; SMTP STARTTLS | Yes | Yes |
| Google OAuth and persistent refresh tokens | Yes | Not yet |
| Certificate management and trusted fingerprints | Full desktop interface | Certificate import/export and persistent signer fingerprints; recipient selection is session-only |

## Desktop features

- Compose signed text messages, optionally encrypt them, and save/open `.eml` files.
- Send through SMTP with STARTTLS and show the **10 most recent inbox messages** through read-only IMAP over TLS.
- Sign in to Gmail with Google Desktop OAuth, including PKCE and a loopback callback. Save the client configuration and refresh token in **macOS Keychain** or **Windows Credential Manager**.
- Select the outgoing signing identity and recipient encryption certificate independently.
- Manage signing and encryption certificates, inspect SHA-256 fingerprints, export PEM/DER, and explicitly mark certificates trusted. Successfully verified incoming signers can be added to the trust store.
- Keep **software identities in password-protected `.p12` files** separate from **YubiKey identities**, whose private keys stay on the device.
- Remember the serial and slots for each YubiKey identity, prompt for the correct device, and show the algorithm in PIN/operation dialogs.
- Update YubiKey certificate email addresses using the existing keys, including up to four additional email SANs.
- Export certificates with suggested `.pem` filenames or select DER `.cer`; identity and message save dialogs default to `.p12` and `.eml`. Missing extensions are added automatically.

This is an experimental interoperability application. Generated certificates are local test certificates; composite formats and OIDs follow the pinned Bouncy Castle implementation. It is not a production mail client or a claim of interoperability with every S/MIME implementation.

## Cryptographic profiles

| Profile | Signing | Encryption / KEM |
|---|---|---|
| Level 2 pure | ML-DSA-44 | ML-KEM-768 |
| Level 2 hybrid | MLDSA44-ECDSA-P256-SHA256 | MLKEM768-ECDH-P256-SHA3-256 |
| Level 3 pure | ML-DSA-65 | ML-KEM-768 |
| Level 3 hybrid | MLDSA65-ECDSA-P384-SHA512 | MLKEM768-ECDH-P384-SHA3-256 |
| Level 5 pure | ML-DSA-87 | ML-KEM-1024 |
| Level 5 hybrid | MLDSA87-ECDSA-P384-SHA512 | MLKEM1024-ECDH-P384-SHA3-256 |

Software creation offers the same Level 2, 3 and 5 choices as YubiKey creation. Each creates four software keys and stores both pure and hybrid identities in one password-protected `.p12` bundle; the PQ components are shared between the two views. Importing that bundle restores both selections. The empty-device provisioning flow offers levels 2, 3 and 5. Every option creates four keys and saves both pure and hybrid identities for selection when sending. Level labels refer to the ML-DSA NIST category; ML-KEM-768 is category 3 in both levels 2 and 3. These labels do not claim FIPS validation of the device or application.

Software and YubiKey creation accept up to four additional comma-separated email addresses. All signing and encryption certificates, pure and hybrid, include the primary address plus these `rfc822Name` Subject Alternative Names. The subject CN remains the primary email. Duplicate or invalid addresses are rejected. Pending YubiKey setup metadata preserves the additional addresses for certificate issuance retries.

Messages use opaque CMS SignedData, optionally wrapped in AuthEnvelopedData. Encryption uses KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM. Encryption is performed on the host with the recipient's public key; the recipient's YubiKey performs private-key decapsulation and ECDH during decryption. The host combines hybrid secrets.

Bouncy Castle computes ML-DSA external μ, including composite domain separation, and assembles composite signatures. The app's OpenSSL/PKCS#11 adapter uses the provider's external-μ support from [PR #818](https://github.com/openssl-projects/pkcs11-provider/pull/818). Returned signatures are verified before use. A composite operation shares one entered PIN between its two components and clears the cache when the operation finishes; PINs are never persisted.

## Getting started on desktop

1. In **Keys**, select or create a software identity, or select a saved YubiKey identity. Software creation requires a new `.p12` file and a password of at least 12 characters.
2. In **Certificates**, import the recipient's encryption certificate. Check its fingerprint through a trusted channel. Signing-certificate trust is an explicit, separate action.
3. In **Compose**, choose **Sign with**, enter matching sender/recipient addresses, and optionally enable **Also encrypt for recipient** and select **Encrypt to**.
4. Save the message locally or send it with SMTP. Use **Read & verify** for a local message or open a message from **Inbox**.

For Gmail, create your own Google OAuth client of type **Desktop app**, add your account as a test user when applicable, and import its JSON or use **Enter Google client credentials…**. Then choose **Sign in with Google** and **Connect Gmail**. SMTP also supports Google OAuth. Refresh tokens restore access after restart; sign-out removes the saved token. Server passwords and YubiKey PINs are not saved. See the [desktop and Gmail guide](docs/DESKTOP.md).

### Android hardware testing

Install the development APK built from `android/`, then open **Identities & certificates**. Import a software bundle, import an existing YubiKey signing/encryption certificate pair, or issue local certificates for an already-provisioned YubiKey. The app stores public token certificates and their serial binding; it does not copy private keys from the device.

To test a saved YubiKey identity:

1. Open **Identities & certificates** and tap the saved pure or hybrid identity. Selection returns to Home.
2. Open **Identities & certificates** again and scroll below the certificate export buttons.
3. Choose **Test selected YubiKey identity — no email**. This button appears only after selecting a YubiKey identity.
4. Connect over USB or follow the fresh-tap prompt and hold the key at the NFC antenna through each operation. Enter the PIN first, then follow the fresh-tap prompt. A round trip normally asks for one signing PIN and one decryption PIN; each composite operation reuses its PIN for both components.

**Android NFC status:** Level 3 pure and hybrid signing/decryption have passed on a physical Beta0 key with Pixel 10 / Android 17. The app resolves development firmware through Management, requests the PIN before a fresh NFC tap, and checks serial/public keys before PIN submission. The test now displays explicit hold/remove instructions and pauses between signing and decryption. Subsequent runs with that UI failed during NFC PIV selection (`Transceive failed`), before PIN submission; reliable operation with the latest flow remains under investigation. Physical Android USB validation remains pending.

## YubiKey identities

**Create identity on empty YubiKey…** checks every user PIV slot before asking for provisioning credentials and checks again under an exclusive device connection before generation. Any occupied or unreadable slot stops the operation. The factory attestation slot is excluded. The flow does not reset a device or replace existing keys.

| Slot | Level 2 | Level 3 | Level 5 |
|---|---|---|---|
| `9c` signing | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| `9a` signing | ECDSA P-256 / SHA-256 | ECDSA P-384 / SHA-384 | ECDSA P-384 / SHA-384 |
| `9d` decryption | ML-KEM-768 | ML-KEM-768 | ML-KEM-1024 |
| `82` decryption | ECDH P-256 | ECDH P-384 | ECDH P-384 |

Composite KEM identifiers follow [draft-ietf-lamps-cms-composite-kem-04](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-composite-kem-04), including MLKEM768-ECDH-P384-SHA3-256. ML-DSA categories are defined in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final); ML-KEM parameters in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf).

Keys are generated on the device with PIN policy **Always** and touch policy **Never**. Local identity records contain public certificates, serial and slot bindings, not token private keys. A missing or different device produces a connect/retry prompt. Generation is not atomic: a partial failure leaves generated keys in place and a subsequent creation attempt refuses the nonempty device. **Finish pending certificates…** can resume certificate issuance after successful key generation without generating keys again. Select the saved `setup.properties` file; the app checks the device serial and public keys before issuing certificates. It cannot resume partial key generation. The adjacent **ⓘ** button explains this recovery flow.

**Update YubiKey certificate email…** issues new local signing and encryption certificates for saved token profiles using their existing keys. Enter the primary email and up to four additional comma-separated email SANs; duplicates and invalid addresses are rejected. Old identities are preserved, PIN prompts authorize certificate signing, and no email is sent. This changes certificate identity information, not your Google account.

Desktop provisioning reads the device’s actual beta firmware version through YubiKey Management before opening PIV, allowing Beta0 devices to pass detection while preserving the empty-slot checks.

The packaged provisioning helper uses Yubico's Rust yubikit directly. **ykman is not required for this flow or for PKCS#11 signing/decryption.** The older optional `ykman-mu.py` adapter and Terminal setup scripts still require the Beta0 ykman CLI. See [PKCS#11 signing](docs/PKCS11.md), [KEM decryption](docs/PKCS11-KEM.md), and [external-μ protocol](docs/EXTERNAL-MU.txt).

## Build from source

Use **JDK 25**, **Maven 3.9.9**, Python 3, Git and Bash on macOS/Linux. Initial dependency builds require network access and several GB of disk space. macOS native helpers also require Xcode Command Line Tools and a current Rust toolchain.

```sh
git clone https://github.com/ve7jtb/pq-mail.git
cd pq-mail
# Set JAVA_HOME and PATH for your JDK and Maven.
./scripts/build-dependencies.sh
./build.sh test
./run.sh
```

Dependencies are pinned to these public source revisions:

| Repository | Revision |
|---|---|
| [mail-api](https://github.com/ve7jtb/mail-api) | `09b27cf52b4b382c55cc8736858456f3aa43b369` |
| [angus-mail](https://github.com/ve7jtb/angus-mail) | `d33de7563efdf5a3cb0691994500d6cad8aecafd` |
| [bc-java](https://github.com/ve7jtb/bc-java) | `6b4f58259d2b3ee8301fda1d6c8798f816abc5ea` |

Activation uses `jakarta.activation-api:2.2.0-M2` and `angus-activation:2.1.0-M1`. The dependency script keeps checkouts, caches and logs under `.deps/`, validates existing checkouts, and writes runtime jars to `lib/`. Set `HYBRID_DEPS_DIR` to change the cache location. Upstream dependency test suites are skipped; app tests run with `build.sh test`. Subsequent app-only builds use the local jars. Builds are not claimed to be byte-for-byte reproducible.

### macOS app

```sh
./scripts/build-pkcs11.sh
./package.sh
```

This creates **`dist/PQ Mail.app`**, bundling Java, OpenSSL, PKCS#11 modules, and native provisioning/Keychain helpers. Python 3 must be installed on the Mac; its path is configurable. `HYBRID_OPENSSL_ROOT` selects OpenSSL (default `/opt/homebrew/opt/openssl@3`); `HYBRID_MAIL_PACKAGE_DIR` selects the output directory. Existing app images are not overwritten. The development app is ad-hoc signed, not notarized.

### Windows x64 and ARM64

The [Windows installer workflow](https://github.com/ve7jtb/pq-mail/actions/workflows/windows-installers.yml) builds on separate x64 and ARM64 runners and packages Java, Python, OpenSSL, the PKCS#11 provider/module and native helpers. Successful runs publish architecture-specific `PQ-Mail-Windows-*` installer artifacts. These are development installers, not Authenticode-signed releases. See [Windows build instructions and validation status](docs/WINDOWS.md). A configured workflow alone is not evidence of a successful installer or hardware test; check the run result and artifacts.

### Android APK

After building the pinned shared dependencies above, set `ANDROID_HOME` to an SDK with platform **37.0** installed:

```sh
cd android
./gradlew :app:assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
```

The build pins AGP 9.3.3, Gradle 9.7.1 and YubiKit 3.3.0. The APK supports API 26 and later; testing so far used a Pixel 10 running Android 17. This is a debug-signed preview. Android uses Activation 2.1.3 / Angus Activation 2.0.2 for runtime compatibility. See the [Android guide](android/README.md) for installation, device tests, storage behavior and limitations.

### Compatibility with existing installations

The display name and repository changed to PQ Mail. Existing settings, identity references, trust records and OAuth credential-store identifiers remain compatible. The application deliberately retains the legacy **`Hybrid Mail`** data directory (`~/Library/Application Support/Hybrid Mail` on macOS and `%LOCALAPPDATA%\Hybrid Mail` on Windows), Java package names, helper filenames and `HYBRID_*` environment variables. No key regeneration or credential migration is needed for the rename.

## Validation and limitations

- **Current Level 3 hardware:** physical Beta0 tests passed on macOS through PKCS#11 for ML-DSA-65 / ML-KEM-768 and MLDSA65-ECDSA-P384-SHA512 / MLKEM768-ECDH-P384-SHA3-256. All four keys were generated on-device with PIN Always / Touch Never. Both signed-and-encrypted S/MIME round trips passed. The new pure/hybrid public certificate pairs were copied into Android and independently read back byte-for-byte. Subsequent Android NFC round trips passed for both profiles.
- **Android software and adapter tests:** five instrumented test groups passed on Pixel 10 / Android 17, covering all six profiles, encrypted `.p12` reload, wrong-password rejection, tampering, UI startup, and actual YubiKit PIV code exercised with a simulated APDU card. Desktop PQ Mail decrypted and verified 12 Android-generated messages and loaded the corresponding `.p12` bundles. Physical Level 3 NFC round trips also passed; physical Android USB testing is pending.
- **Earlier hardware tests:** physical Beta0 hardware tests passed for pure ML-DSA-65 and composite MLDSA65-RSA3072-PSS-SHA512 signing through PKCS#11, and pure ML-KEM-768 / hybrid MLKEM768-ECDH-P256 decryption. Saved messages were independently reopened and verified. The earlier ykman external-μ signing demo also passed.
- Automated tests cover software profiles, simulated external signing/decryption including all three provisioning levels in pure and hybrid modes, serialization, tampering, key matching, PIN cache cleanup, identity bindings, and provisioning refusal/partial failures. Simulators do not establish physical-device support. Level 2 and Level 5 physical hardware round trips remain unverified; the normal provisioning UI requires an empty compatible key.
- Gmail OAuth, Keychain restoration after restart, and the ten-message IMAP inbox have been observed in the Mac app. Live SMTP delivery, third-party interoperability, Windows hardware use and a production security audit are not established by these tests.
- The reader handles signed text/plain mail and AuthEnvelopedData, plus ordinary plain text explicitly marked unsigned. HTML rendering, attachments and legacy EnvelopedData are not supported. Verification/decryption failures are not downgraded to unsigned mail.
- Trust uses exact certificate fingerprints, validity and key-usage checks. There is no CA chain building or revocation checking. Outer mail headers are not signed or encrypted. The app distinguishes signature validity from trust and flags sender/certificate mismatches.

Public demonstration certificates are separately published in [hybrid-mail-test-certificates](https://github.com/ve7jtb/hybrid-mail-test-certificates). Private keys, user identity files, device identifiers, OAuth credentials and local hardware artifacts are excluded from this source repository.

## Source map

The Android UI, USB/NFC backend, build instructions and instrumentation tests are under `android/`. Its build reuses the canonical S/MIME sources and substitutes Android platform adapters.

Desktop Java code is under `src/dev/hybridmail/`: `MailApp` is the Swing UI; `MailEngine` handles S/MIME and mail transport; `Identity` and `DesktopState` manage identities and storage; `ExternalMu` / `ExternalKem` bridge token operations; `TokenProvision` invokes the native provisioning helper. `adapters/` contains the Python OpenSSL/PKCS#11 and legacy ykman adapters. `native-src/` contains platform credential helpers and Rust provisioning code. Tests are in the Java sources, `tests/`, and the Rust helper.

Third-party components retain their own licenses; see [notices](docs/THIRD-PARTY.txt). No project license has been selected yet.
