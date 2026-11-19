# PQ Mail

<img src="assets/pq-mail.png" alt="PQ Mail: PQ shield, lime envelope and YubiKey on a dark teal background" width="160" />

PQ Mail is an experimental post-quantum mail application supporting **S/MIME and OpenPGP on macOS, Windows, Linux, Android and iOS**. Desktop and Android use **Jakarta Mail, Eclipse Angus Mail, and Bouncy Castle**; the SwiftUI iOS preview uses **OpenSSL**. Desktop token operations use bundled **PKCS#11** adapters; Android uses **YubiKit 3.3.0** directly. It supports software identities and keys generated and used on a PQC Ready YubiKey. Formerly **Hybrid Mail**, the project now lives at [ve7jtb/pq-mail](https://github.com/ve7jtb/pq-mail).

## Demonstration video

[Watch the Google OAuth and post-quantum S/MIME demonstration](https://youtu.be/RGiaAeGTCmc) (3:20). The desktop demo shows Gmail read/send consent, a YubiKey-signed message, and a signed-and-encrypted message decrypted locally with the YubiKey. It uses ML-DSA-87 + ECDSA P-384 signatures and ML-KEM-1024 + ECDH P-384 encryption. PIN prompts are included with their fields masked; unrelated inbox content and pauses are removed. Recorded November 17, 2026 using synthetic messages sent to the same account. The video is unlisted on YouTube and accessible through this link.

## On-key certificates and migration

Use **Keys → Back up certificate bundle to YubiKey…** to carry the pure/hybrid S/MIME
certificates, existing OpenPGP public identity and serial/slot mappings with the
key. **Restore certificate bundle from YubiKey…** verifies the bundle and actual public
keys, then asks for review; it does not grant trust. Android and iOS expose the
same backup/restore actions in their identity screens.

New provisioning uses ECDSA slot **83**, leaving 9a available for authentication.
The migration action has been removed from the interfaces now that the test keys
have been migrated. Saved slot mappings and bundle recovery remain supported.
Public storage
contains no PINs, private keys, passwords or Google OAuth refresh tokens.

See [on-key format, workflows and recovery](docs/ON-KEY-CERTIFICATES.md).
**Hardware validation (November 18, 2026):** A YubiKey 6.0.0 Beta0 passed the following tests:

- **On-key bundle:** macOS saved a 24,434-byte signed bundle containing the existing Level 3 pure/hybrid signing and encryption certificates and serial/slot mappings. Read-back through a new PC/SC connection, clean-profile import, restart and duplicate import passed. No private keys were imported and no certificate trust was granted automatically.
- **Slot migration:** the existing P-384 signing key moved from **9a to empty 83**, retaining its public key and PIN Always / Touch Never policies. Slot 9a became empty. Before/after snapshots confirmed all PIV certificates and other keys' public metadata were unchanged. Desktop mappings were updated, and hybrid signing verified the refreshed bundle using slot 83.
- **Android NFC import:** Pixel 10 read the refreshed bundle directly from the key and updated both existing Level 3 identities to **9c / 83 / 9d / 82** (ML-DSA signing / ECDSA signing / ML-KEM decryption / ECDH decryption).
- **NFC S/MIME round trips:** Pixel 10 passed pure **ML-DSA-65 / ML-KEM-768** and hybrid **MLDSA65-ECDSA-P384-SHA512 / MLKEM768-ECDH-P384-SHA3-256** signing and decryption with the imported certificates. Hybrid signing used the saved slot 83 mapping and its composite signature verified. No email was sent.

One pre-PIN NFC retry occurred during hybrid decryption: the public-metadata read
`F7 P2=9C` failed with an IOException after 305 ms; a fresh tap recovered and the
round trip passed. The same trace successfully read slot 83 (`SW=9000`, 28 ms).
These successful tests do not establish that the Pixel 10's intermittent NFC
transport issue is resolved. No saved OpenPGP identity was present in this bundle,
so this hardware run did not validate OpenPGP bundle transfer. Physical iOS bundle
testing remains pending.

Use **Keys → Forget YubiKey identity…** to remove one local YubiKey profile, its certificates, slot mappings and saved OpenPGP identity. Other profiles and contact trust remain unchanged. This does not connect to or erase the YubiKey; on-key bundles remain available for reimport.

## Android preview

An [Android version](android/README.md) uses **YubiKit 3.3.0 directly over USB and NFC**, with the same three software `.p12`, pure PQ, and hybrid profiles. It includes local S/MIME, IMAPS/SMTP, and public-only YubiKey identities. See the Android guide for build instructions, hardware testing, and preview limitations; Google OAuth and token provisioning remain desktop features.

## iOS development preview

The [native SwiftUI iOS preview](ios/README.md) uses **OpenSSL 3.6.5** for Level 2/3/5 pure and hybrid S/MIME, persistent password-protected `.p12` identities, and public YubiKey credential bundles. **OpenPGP is an alternative for Level 3 hybrid identities**, using draft-05 ML-DSA-65 + P-384 / ML-KEM-768 + P-384 profiles, separate OpenPGP public identities and PGP/MIME. Both formats share software primitives and the YubiKit NFC/USB-C raw PIV backend. Tests cover published OpenPGP vectors, simulator round trips, simulated hardware operations, and desktop S/MIME/PKCS#12 interoperability. **Physical iPhone YubiKey testing remains pending.** This local-file preview has no mail accounts/sending or attachments yet; see the iOS README for supported formats and limitations.

## OpenPGP profiles

Select **OpenPGP** in Compose with a supported hybrid identity:

| Selected identity | OpenPGP signing / encryption | Platforms |
|---|---|---|
| Level 3 hybrid | ML-DSA-65 + P-384 / ML-KEM-768 + P-384 (experimental draft-05) | Desktop, Android, iOS |
| Level 3 + extra YubiKey keys | ML-DSA-65 + Ed25519 / ML-KEM-768 + X25519 (RFC 9980) | Desktop and Android |
| Existing Level 5 classical OpenPGP | Receive/verify/decrypt only; outgoing signing disabled | Desktop and Android |
| Imported v4 classical certificate | Verify incoming signatures; encrypt to a valid recipient subkey | Desktop and Android |

Existing Level 5 OpenPGP reuses the classical keys in slots **83/82** for new YubiKey identities; its pure/hybrid S/MIME profiles remain unchanged. Pure-only and Level 2 identities do not support OpenPGP. Public OpenPGP identities have separate fingerprints from X.509 certificates. Create/import the same `.asc` identity on other installations, or restore it through a supported on-key bundle, to preserve those fingerprints.

Desktop outgoing OpenPGP uses v6 hybrid signatures by default. For a selected v4 recipient only, the RFC 9980 YubiKey identity uses Ed25519 compatibility signing after confirmation; it attaches both v4 and v6 public certificates. This exception requires the existing Ed25519/X25519 keys in slots 84/85; identities without those keys cannot use this compatibility mode. Android retains hybrid-only outgoing signing. In desktop **Compose**, selecting OpenPGP looks up the complete **To** email address on **keys.openpgp.org** after a short typing delay. Android Compose provides the same lookup and recipient-key selection. Imported keys remain usable without a keyserver lookup. Encryption is enabled only for a matching, usable recipient certificate; its encryption choices come from that certificate, not the sender’s S/MIME profile. Changing To clears the selected recipient and turns encryption off. Lookup results never confer trust; review the fingerprint.

V4 compatibility verifies RSA (2048+), ECDSA and legacy Ed25519 signatures with SHA-2, validates self-certifications and signing-subkey cross-certifications, and rejects revoked/expired keys and unsupported critical metadata. Encryption uses a current bound RSA/ECDH subkey, AES and integrity-protected v1 SEIPD with v3 PKESK. Desktop v4 compatibility messages use Ed25519 signatures, which are classical. V4 encryption can be hybrid when a valid algorithm-35 subkey is present; otherwise it is classical and requires confirmation. SHA-1 is used only for the mandated v4 fingerprint/MDC formats, not accepted for document or certification signatures.

Signed and optionally encrypted PGP/MIME is supported. The desktop reader verifies signatures before extracting plain text or HTML from multipart bodies; HTML is displayed as text without loading remote content. Outgoing OpenPGP bodies remain plain-text; compatibility messages include the full v4, signing-only v4, and v6 public-key attachments automatically. User-added file attachments remain S/MIME-only. New supported YubiKey credentials default to creating an OpenPGP identity, with an opt-out. See the [OpenPGP guide](docs/OPENPGP.md) for setup, profile distinctions and validation limits.


### Sequoia OpenPGP v6 interoperability

Local tests against **Sequoia sq 1.5.0 / sequoia-openpgp 2.4.1** passed detached-signature verification and signed/encrypted payload exchange **in both directions**, using ML-DSA-65 + Ed25519 signing and ML-KEM-768 + X25519 encryption. These tests used disposable software keys; they were not a new YubiKey hardware or mail-delivery test.

PQ Mail now accepts the tested Sequoia v6 certificate structure: multiple certified email addresses, a certification-only primary, a separate cross-certified signing subkey, an authentication subkey, and an encryption subkey. It supports default encrypted-message padding and the RFC 9580 implicit AES-128/OCB preference. Tests reject modified content, unbound subkeys and revoked primary keys. Importing still does not grant trust. Existing PQ Mail v6 certificates remain compatible; no regeneration or fingerprint change is required. See [OpenPGP details](docs/OPENPGP.md) and the public fixtures in `tests/fixtures/sequoia`.

### Proton Mail PGP/MIME interoperability — November 18, 2026

The desktop reader successfully displayed and verified a real message sent from
Proton Mail using a **classical OpenPGP v4 signature**. Multipart/HTML content is
shown as text, without fetching remote images or executing HTML. The message was
**not encrypted**; the classical, non-post-quantum warning remained visible.

A second test used the installed desktop reader with **empty temporary contacts,
no selected signer and no local identity**. It discovered Proton's attached public
certificate, verified the signature and displayed the message as **NOT TRUSTED**.
Both the in-memory and reloaded contact stores remained empty, and no trust was
granted. Existing user contacts were unchanged; message MIME stayed in memory.

Attached certificates are verification candidates, not proof of sender identity.
**Save sender OpenPGP certificate…** explicitly saves a contact without granting
trust. **Trust signer fingerprint…** is a separate review that scopes trust to
selected certified email addresses and the full primary-key fingerprint. Invalid
certificate bindings and altered signatures are rejected. Certificates contained
inside encrypted payloads still require an available sender key before opening.

**Hybrid interoperability did not pass:** Proton Mail web version **5.0.142.3**
rejected our RFC 9980 v6 contact certificate with “Version 6 keys are currently not
supported.” Consequently, Proton verification of our hybrid signatures and Proton
encryption to our hybrid KEM remain untested. The successful inbound v4 test does
not establish v6 or post-quantum interoperability.

## Platform capabilities

| Capability | Desktop (macOS / Windows / Linux) | Android preview | iOS preview |
|---|---|---|---|
| Software `.p12`, Level 2/3/5 pure/hybrid S/MIME | Yes | Yes | Yes |
| Level 3 hybrid OpenPGP | Yes | Yes | Yes |
| Level 5 classical P-384 OpenPGP | Yes | Yes | Not yet |
| Forget a local YubiKey identity | Yes | Yes | Not yet |
| YubiKey private-key backend | Bundled PKCS#11 | YubiKit USB/NFC | YubiKit raw PIV NFC/USB-C; physical testing pending |
| Generate four keys on an empty YubiKey | Yes | Use existing keys | Use existing keys |
| Local signed/encrypted `.eml` files | Yes | Yes | Yes |
| S/MIME attachments | Yes | Yes | Not yet |
| Conventional RSA/ECDSA S/MIME | Yes | Yes | Not yet |
| IMAPS inbox / SMTP | Yes | Yes | Not yet |
| Gmail API / Google OAuth | Yes | Not yet | Not yet |
| Persistent certificate trust | Yes | Yes | Verification only; no automatic trust |

Level 3 OpenPGP validation includes published draft vectors, desktop/Android adapter tests, Swift tests and bidirectional Java/OpenSSL message exchange. Level 5 classical validation includes software/simulated-token round trips, Android instrumentation, and independent Bouncy Castle signature verification and bidirectional ECDH/v2-SEIPD exchange. A Level 3 hybrid OpenPGP USB round trip was reported successful by the tester; unlike the saved S/MIME tests, that manual flow did not persist a hardware report. Physical OpenPGP NFC and Windows runtime testing remain pending. Existing S/MIME hardware test results do not constitute OpenPGP hardware validation.

## Desktop features

- Compose signed messages with attachments, optionally encrypt them, and save/open `.eml` files.
- For other hosts, send through SMTP with STARTTLS and show the **10 most recent inbox messages** through read-only IMAP over TLS. Gmail uses its API with 50-message pages and an optional S/MIME-only filter.
- Sign in to Gmail with Google Desktop OAuth, including PKCE and a loopback callback, requesting only Gmail API read-only and send scopes. Save the client configuration and refresh token in **macOS Keychain** or **Windows Credential Manager**.
- Select the outgoing signing identity and recipient encryption certificate independently.
- Manage signing and encryption certificates, inspect SHA-256 fingerprints, export PEM/DER, and explicitly mark certificates trusted. Successfully verified incoming signers can be added to the trust store.
- Keep **software identities in password-protected `.p12` files** separate from **YubiKey identities**, whose private keys stay on the device.
- Remember the serial and slots for each YubiKey identity, prompt for the correct device, and show the algorithm in PIN/operation dialogs.
- Update YubiKey certificate email addresses using the existing keys, including up to four additional email SANs.
- Export certificates with suggested `.pem` filenames or select DER `.cer`; identity and message save dialogs default to `.p12` and `.eml`. Missing extensions are added automatically.

This is an experimental interoperability application. Generated certificates are local test certificates; composite formats and OIDs follow the pinned Bouncy Castle implementation. It is not a production mail client or a claim of interoperability with every S/MIME implementation.

## S/MIME cryptographic profiles

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

Outgoing S/MIME messages use opaque CMS SignedData, optionally wrapped in AuthEnvelopedData. PQ encryption uses KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM. Encryption is performed on the host with the recipient's public key; the recipient's YubiKey performs private-key decapsulation and ECDH during decryption. The host combines hybrid secrets.

Bouncy Castle computes ML-DSA external μ, including composite domain separation, and assembles composite signatures. The app's OpenSSL/PKCS#11 adapter uses the provider's external-μ support from [PR #818](https://github.com/openssl-projects/pkcs11-provider/pull/818). Returned signatures are verified before use. A composite operation shares one entered PIN between its two components and clears the cache when the operation finishes; PINs are never persisted.

## Getting started on desktop

1. In **Keys**, select or create a software identity, or select a saved YubiKey identity. Software creation requires a new `.p12` file and a password of at least 12 characters.
2. In **Certificates**, import the recipient's encryption certificate. Check its fingerprint through a trusted channel. Signing-certificate trust is an explicit, separate action.
3. In **Compose**, choose **Sign with**, enter matching sender/recipient addresses, and optionally enable **Also encrypt for recipient** and select **Encrypt to**.
4. Save the message locally or send it with SMTP. Use **Read & verify** for a local message or open a message from **Inbox**.

For Gmail, the desktop app includes a shared **PQ Mail** Google OAuth registration; new installations do not need their own client ID. Choose **Sign in with Google**, then **Connect Gmail**. The shared project is **In production**, so accounts do not need to be added as named test users. Google verification is pending; the unverified-app warning and Google's unverified-user limit still apply. The shared client loads directly from the app without a credential-store read. Older custom registrations can be reselected by importing their JSON in Advanced settings; choose **Inbox → Advanced settings… → Use PQ Mail Google client** to switch, then sign in again. Developers can still import their own Desktop client JSON or use **Advanced settings… → Enter Google client credentials…**. Google connections use the Gmail API with only `gmail.readonly` and `gmail.send`; other hosts retain IMAP/SMTP. Gmail shows 50 header-only messages per page with **Newer/Older** controls for the entire inbox. Message MIME is fetched when opened and is not cached to disk. Refresh tokens restore access after restart; sign-out removes the saved token. Server passwords and YubiKey PINs are not saved. See the [desktop and Gmail guide](docs/DESKTOP.md).

### Android hardware testing

Install the development APK built from `android/`, then open **Identities & certificates**. Import a software bundle, import an existing YubiKey signing/encryption certificate pair, or issue local certificates for an already-provisioned YubiKey. The app stores public token certificates and their serial binding; it does not copy private keys from the device.

To test a saved YubiKey identity:

1. Open **Identities & certificates** and tap the saved pure or hybrid identity. Selection returns to Home.
2. Open **Identities & certificates** again and scroll below the certificate export buttons.
3. Choose **Test selected YubiKey identity — no email**. This button appears only after selecting a YubiKey identity.
4. Connect over USB or follow the fresh-tap prompt and hold the key at the NFC antenna through each operation. Enter the PIN first, then follow the fresh-tap prompt. A round trip normally asks for one signing PIN and one decryption PIN; each composite operation reuses its PIN for both components.

**Android NFC comparison (November 17, 2026):** With the same APK and Level 3 Beta0 YubiKey, Pixel 9 / Android 17 completed **five NFC S/MIME round trips: three hybrid and two pure**, with no recorded pre-PIN retries. Pixel 10 / Android 17 completed one of four hybrid runs in its comparison batch, with three failures and seven recorded pre-PIN setup failures. The Pixel 10 honored the new 240-byte public-metadata response requests, but transport errors persisted. This points toward a phone-dependent NFC interaction, not a proven root cause or universal reliability claim. Earlier Pixel 10 Level 5 pure/hybrid NFC and Level 3 pure/hybrid USB tests also passed. **22 focused emulator tests passed.** See the [YubiKit integration and phone-comparison report](docs/ANDROID-NFC-YUBIKIT.md) for exact scope and limitations.

## YubiKey identities

**Create identity on empty YubiKey…** checks every user PIV slot before asking for provisioning credentials and checks again under an exclusive device connection before generation. Any occupied or unreadable slot stops the operation. The factory attestation slot is excluded. The flow does not reset a device or replace existing keys.

| Slot | Level 2 | Level 3 | Level 5 |
|---|---|---|---|
| `9c` signing | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| `83` signing (new identities) | ECDSA P-256 / SHA-256 | ECDSA P-384 / SHA-384 | ECDSA P-384 / SHA-384 |
| `9d` decryption | ML-KEM-768 | ML-KEM-768 | ML-KEM-1024 |
| `82` decryption | ECDH P-256 | ECDH P-384 | ECDH P-384 |

Composite KEM identifiers follow [draft-ietf-lamps-cms-composite-kem-04](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-composite-kem-04), including MLKEM768-ECDH-P384-SHA3-256. ML-DSA categories are defined in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final); ML-KEM parameters in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf).

Keys are generated on the device with PIN policy **Always** for all four slots. Touch policy is **Always** for ML-DSA signing (9c) and ML-KEM decryption (9d), and **Never** for ECDH (82) and ECDSA (83). This applies to newly generated keys; existing keys and their policies are unchanged. Local identity records contain public certificates, serial and slot bindings, not token private keys. A missing or different device produces a connect/retry prompt. Generation is not atomic: a partial failure leaves generated keys in place and a subsequent creation attempt refuses the nonempty device. **Finish pending certificates…** can resume certificate issuance after successful key generation without generating keys again. Select the saved `setup.properties` file; the app checks the device serial and public keys before issuing certificates. It cannot resume partial key generation. The adjacent **ⓘ** button explains this recovery flow.

**Update YubiKey certificate email…** issues new local signing and encryption certificates for saved token profiles using their existing keys. Enter the primary email and up to four additional comma-separated email SANs; duplicates and invalid addresses are rejected. Old identities are preserved, PIN prompts authorize certificate signing, and no email is sent. This changes certificate identity information, not your Google account.

Desktop provisioning reads the device’s actual beta firmware version through YubiKey Management before opening PIV, allowing Beta0 devices to pass detection while preserving the empty-slot checks.

The packaged provisioning helper uses Yubico's Rust yubikit directly. **ykman is not required for this flow or for PKCS#11 signing/decryption.** The older optional `ykman-mu.py` adapter and Terminal setup scripts still require the Beta0 ykman CLI. See [PKCS#11 signing](docs/PKCS11.md), [KEM decryption](docs/PKCS11-KEM.md), and [external-μ protocol](docs/EXTERNAL-MU.txt).

## Build from source

Use **JDK 25.0.5.1 or newer within the Java 25 GA release line**, **Maven 3.9.9**, Python 3, Git and Bash on macOS/Linux. Initial dependency builds require network access and several GB of disk space. macOS native helpers also require Xcode Command Line Tools and a current Rust toolchain.

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

## S/MIME attachments

In desktop Compose, use **Add attachments…** and **Remove selected**. Files and the text body are signed together. Enable **Also encrypt for recipient** to encrypt the complete signed message, including attachment filenames and contents, using the selected PQ, hybrid, or conventional recipient certificate. Gmail API and SMTP use the same protected message. Outer email headers remain unprotected.

For signed mail, signature verification must succeed before attachments are available. Decrypted-only mail is explicitly labeled unsigned, and its attachments carry no signer assurance. Decrypted attachments remain in memory until you explicitly save one. Desktop saving refuses to overwrite existing files; Android uses the system save dialog. The composer supports up to 20 attachments and a combined body/file payload of 10 MiB, subject to the final 20 MiB encoded-message limit. Android also supports attachment selection and saving through the system document picker.

## Conventional S/MIME interoperability

RSA and ECDSA signatures can be received and explicitly trusted by certificate fingerprint. Recipient encryption certificates support RSA (2048 bits or larger) and ECDH P-256/P-384 alongside PQ KEM profiles. Key usage and emailProtection extended key usage are checked when present; an ECDH certificate requires keyAgreement when key usage is present. Trust for signing and encryption is separate and does not imply CA-chain validation.

Import a recipient certificate or use **Trust signer for encryption** on verified mail if the signer certificate also permits encryption. A separate encryption certificate must be imported when the signing certificate is signing-only. Conventional software `.p12` files with one unambiguous signing key and at most one encryption key can be imported, including arbitrary aliases. Classical decryption requires the matching software private key; PQ YubiKey profiles remain unchanged.

The reader accepts signed messages inside AuthEnvelopedData or conventional EnvelopedData (including AES-CBC), and plain-text content in common mixed/alternative/related MIME layouts. HTML is not rendered. Encrypted messages without a signature are shown explicitly as unsigned and cannot be used to establish signer trust. Encryption to a conventional recipient does not provide post-quantum confidentiality, even when the message carries a PQ signature.


## Share certificates between instances

Select a saved **YubiKey identity**, then choose **Share certificates…** (Mac: **Keys**; Android: **Identities & certificates**). PQ Mail gathers the saved pure/hybrid profiles for the same device and PQ key pair and shows the email addresses, algorithms, fingerprints, serial and all four PIV slots before sharing. A normal pure/hybrid pair contains four public certificates. If only one profile is saved, only that profile can be shared; no new certificates or keys are generated.

The versioned `.pqcert` bundle contains public signing/encryption certificates and YubiKey serial/slot mappings. It contains **no private keys, PINs, passwords, OAuth credentials or trust decisions**. The Mac opens its native sharing picker, including AirDrop when available, and also offers **Save bundle…**. Android opens its system share sheet, including Quick Share when available. Transport availability depends on the OS/device; this feature does not implement AirDrop itself.

On the receiving Mac, open the `.pqcert` file with PQ Mail or use **Import certificate bundle from file…**. On Android, share/open it with PQ Mail when offered, or select it with **Import certificate bundle from file…**. Review all fingerprints and device mappings, then choose:

- **Use with my YubiKey / My YubiKey**: save public-only identities for that device. Select the imported pure or hybrid identity afterward. The existing signing/decryption backend checks serial and public keys when the key is used; imported metadata alone does not prove possession.
- **Add contact certificates / Contact certificates**: save certificates for another person's mailbox. Mark fingerprints trusted separately after confirming them with the owner.

Existing trust decisions are preserved, but imports never grant new trust. Repeated identity imports are idempotent; conflicting existing bindings are rejected. No YubiKey slots are written or provisioned. ML-DSA signing currently uses slot `9c`; the traditional-signing, ML-KEM and ECDH mappings travel with each profile. Software private identities remain separate `.p12` imports.

Validation covers public-only bundle round trips, malformed/oversized input, conflicting mappings, idempotent imports, trust separation, Android provider access restrictions and simulated token operations. Physical Mac–Android AirDrop/Quick Share delivery still requires testing on the two devices.

## Validation and limitations

- **Current Level 3 hardware:** physical Beta0 tests passed on macOS through PKCS#11 for ML-DSA-65 / ML-KEM-768 and MLDSA65-ECDSA-P384-SHA512 / MLKEM768-ECDH-P384-SHA3-256. All four keys were generated on-device with PIN Always / Touch Never. Both signed-and-encrypted S/MIME round trips passed. The new pure/hybrid public certificate pairs were copied into Android and independently read back byte-for-byte. Subsequent Android NFC round trips passed for both profiles.
- **Android software and adapter tests:** five instrumented test groups passed on Pixel 10 / Android 17, covering all six profiles, encrypted `.p12` reload, wrong-password rejection, tampering, UI startup, and actual YubiKit PIV code exercised with a simulated APDU card. Desktop PQ Mail decrypted and verified 12 Android-generated messages and loaded the corresponding `.p12` bundles. Physical Level 3 NFC round trips also passed; physical Level 3 pure and hybrid USB round trips passed twice each.
- **Earlier hardware tests:** physical Beta0 hardware tests passed for pure ML-DSA-65 and composite MLDSA65-RSA3072-PSS-SHA512 signing through PKCS#11, and pure ML-KEM-768 / hybrid MLKEM768-ECDH-P256 decryption. Saved messages were independently reopened and verified. The earlier ykman external-μ signing demo also passed.
- Automated tests cover software profiles, simulated external signing/decryption including all three provisioning levels in pure and hybrid modes, serialization, tampering, key matching, PIN cache cleanup, identity bindings, and provisioning refusal/partial failures. Simulators do not establish physical-device support. Level 2 and Level 5 pure physical hardware round trips remain unverified; the Level 5 hybrid Gmail demonstration below passed; the normal provisioning UI requires an empty compatible key.
- Gmail API OAuth with the shared client and read/send scopes was observed in the Mac app: 12 inbox messages loaded, with 3 matching the S/MIME-only filter. Mock API tests cover paging and pure/hybrid signed/encrypted MIME transfer for all three levels. On November 17, 2026, two synthetic self-addressed messages were sent and received through the live Gmail API: one signed and one signed-and-encrypted. MLDSA87-ECDSA-P384-SHA512 signatures verified, and MLKEM1024-ECDH-P384-SHA3-256 YubiKey decryption completed with authenticated AES-256-GCM decryption. Earlier full-mail OAuth, Keychain restoration after restart, and the ten-message IMAP inbox were also observed. Live SMTP delivery, third-party interoperability, Windows hardware use and a production security audit are not established by these tests.
- The reader accepts opaque and detached signatures, AuthEnvelopedData and conventional EnvelopedData, common text MIME layouts, and attachments. Encrypted-only messages are explicitly labeled unsigned; signature or decryption failures are not downgraded. HTML rendering is not supported.
- **Attachment and conventional interoperability tests:** desktop regression tests and Android emulator tests passed for binary/Unicode-named attachments in all six PQ profiles, RSA/ECDSA signatures, RSA/ECDH encryption, arbitrary-alias software `.p12` import, detached signatures, AES-GCM and legacy AES-CBC envelopes, and unsigned encrypted messages. These are local generated-message tests, not independent third-party client or physical YubiKey validation of the new features.
- Trust uses exact certificate fingerprints, validity and key-usage checks. There is no CA chain building or revocation checking. Outer mail headers are not signed or encrypted. The app distinguishes signature validity from trust and flags sender/certificate mismatches.

Public demonstration certificates are separately published in [hybrid-mail-test-certificates](https://github.com/ve7jtb/hybrid-mail-test-certificates). Private keys, user identity files, device identifiers, user OAuth tokens, custom client credentials and local hardware artifacts are excluded from this source repository.

## Source map

The Android UI, USB/NFC backend, build instructions and instrumentation tests are under `android/`. Its build reuses the canonical S/MIME sources and substitutes Android platform adapters.

Desktop Java code is under `src/dev/hybridmail/`: `MailApp` is the Swing UI; `MailEngine` handles S/MIME and mail transport; `Identity` and `DesktopState` manage identities and storage; `ExternalMu` / `ExternalKem` bridge token operations; `TokenProvision` invokes the native provisioning helper. `adapters/` contains the Python OpenSSL/PKCS#11 and legacy ykman adapters. `native-src/` contains platform credential helpers and Rust provisioning code. Tests are in the Java sources, `tests/`, and the Rust helper.

Third-party components retain their own licenses; see [notices](docs/THIRD-PARTY.txt). No project license has been selected yet.

Gmail **S/MIME only** filters each page using its top-level Content-Type (opaque S/MIME and multipart/signed with a PKCS#7 signature protocol). It does not fetch message bodies or establish signature validity. Pages cover 50 inbox entries before filtering, so a page may show fewer or no matches while **Older** remains available. S/MIME nested inside forwarded messages or ordinary attachments is not included.

### Bundled Java security baseline

Desktop builds require Java 25.0.5.1 or newer in the Java 25 GA line. Set `JAVA_HOME` to that JDK; compilation, dependency builds and packaging reject older runtimes and early-access builds. Windows CI pins Azul Zulu 25.0.5.1 (November 2026 security update). Mac and Windows packaging also check the actual bundled runtime and produce a `java-runtime*.txt` report alongside the package. Updating system Java does not update an already installed PQ Mail app; replace the app with the rebuilt package.

This baseline includes the November Base64 intrinsic fix (CVE-2026-114938); see [Azul’s November release notes](https://docs.azul.com/core/release-notes). Android uses ART and iOS uses OpenSSL, so this desktop JDK change does not replace their runtimes.

### Linux amd64 and ARM64

Linux builds provide a `.deb` installer and a portable `.tar.gz` app image for each architecture. They target Ubuntu 24.04 or newer (glibc 2.39+), bundle patched Java 25.0.5.1, OpenSSL 3.5.9 LTS, the PKCS#11 provider/module and YubiKey provisioning helper. No system JDK or ykman is required. Install the Debian package with `sudo apt install ./PQ-Mail-1.2.1-Linux-amd64.deb` (use `arm64` for ARM). The desktop menu entry launches PQ Mail.

The portable archive requires Python 3, PC/SC (`pcscd`, `libccid`, `libpcsclite1`), GTK/X11/font libraries and `libsecret-1-0`. Run `PQ Mail/bin/PQ Mail` after extraction. A graphical desktop session is required; Wayland desktops need XWayland for Java Swing. Enable the distribution’s PC/SC service/socket if it is not active. Do not run PQ Mail as root.

Settings and identities use `$XDG_DATA_HOME/pq-mail`, normally `~/.local/share/pq-mail`. Google OAuth refresh tokens and custom client credentials use the desktop Secret Service (for example GNOME Keyring or a compatible KWallet service); there is no plaintext fallback. The keyring must be available and unlocked. Software `.p12` passwords and YubiKey PINs are not saved. Certificate sharing uses file export/import on Linux.

The Linux workflow builds natively on amd64 and ARM64, tests software S/MIME/OpenPGP and simulated token operations, tests a disposable Secret Service store/read/delete cycle, and runs the software profiles in the packaged JVM. Physical YubiKey operation on Linux still requires hardware testing. Build with `scripts/build-dependencies.sh`, `build.sh test`, `scripts/build-linux-native.sh`, and `scripts/package-linux.sh`; see `.github/workflows/linux-packages.yml` for the build prerequisites.

Linux 1.2.1 validation (November 18, 2026): native Ubuntu 24.04 amd64 and ARM64 [build/profile/Secret Service tests](https://github.com/ve7jtb/pq-mail/actions/runs/44366025968) passed. Both `.deb` packages passed checksum verification, installation and desktop-window startup in [clean-runner installation tests](https://github.com/ve7jtb/pq-mail/actions/runs/44368695400). Download the `.deb` and portable archive from the build run’s `PQ-Mail-Linux-amd64` or `PQ-Mail-Linux-arm64` artifacts. These checks use synthetic software identities and simulated token operations; they do not establish physical Linux YubiKey compatibility.

The ARM64 Debian package was also installed in the local **Codex Linux** UTM VM (Ubuntu 26.04.1 ARM64). Level 2/3/5 pure/hybrid software identity round trips passed in the installed bundled JVM, and the installed desktop window opened under Xvfb as the normal non-root user. No accounts, email or physical YubiKey were used.

New Level 3 YubiKey provisioning offers **Also create OpenPGP public identity**, selected by default; uncheck it to opt out. The choice is saved for pending-certificate recovery. The public identity uses the existing Level 3 hybrid keys and is included when saving an on-key bundle. Level 5 offers classical P-384 OpenPGP, selected by default with an opt-out; Level 2 is unsupported. Existing credentials can use the OpenPGP creation action without generating new keys.

### Existing Level 5 classical OpenPGP and certificate backups

**Current outgoing policy:** these classical certificates remain readable and can be restored for incoming verification/decryption, but Compose requires a hybrid post-quantum signer. The earlier classical round-trip results below describe compatibility testing, not an enabled outgoing signing option.

Desktop and Android can use a Level 5 **hybrid identity's P-384 components** for RFC 9580 v6 OpenPGP: ECDSA in slot **83**, ECDH in **82** (explicit legacy mappings remain supported). This OpenPGP profile is **classical, not post-quantum**; Level 5 pure/hybrid S/MIME remains unchanged. Both P-384 slots use their existing PIN/touch policies. Level 5 pure-only certificates do not contain the classical public keys; select the hybrid identity for OpenPGP.

New desktop YubiKey provisioning offers OpenPGP creation by default for Level 3 (hybrid PQ) and Level 5 (classical P-384), with an opt-out. Android offers the same choice when issuing certificates for existing keys. Creation and desktop email/SAN updates prompt **Back up now / Not now**. **Back up certificate bundle to YubiKey…** regenerates a signed bundle from the selected email/SAN profile set, including both S/MIME profiles, any saved OpenPGP public identity, serial and slot mappings. **Restore certificate bundle from YubiKey…** reviews and restores it without granting trust. This backs up public certificates, not private keys, PINs or account credentials. Adding SANs preserves a saved OpenPGP identity when its primary email remains unchanged; changing that email creates new OpenPGP certifications if enabled.

Software and simulated-token P-384 round trips, independent Bouncy Castle OpenPGP signature checks and bidirectional ECDH/v2-SEIPD exchange are tested. Physical P-384 OpenPGP token testing remains pending. iOS currently supports the earlier Level 3 hybrid OpenPGP profile only and cannot restore a Level 5 bundle containing this new classical OpenPGP identity yet.

### RFC 9980 OpenPGP with additional YubiKey keys

Desktop Level 3 YubiKey identities can create an RFC 9980 OpenPGP certificate
using ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519, with additional keys in slots
84/85. Creation offers **Back up certificate bundle to YubiKey**, preserving the
S/MIME certificates and their existing slots. The alternative P-384 composite
OpenPGP profile is **experimental NIST/Brainpool draft** support.
See [OpenPGP setup, backup and platform limitations](docs/OPENPGP.md#rfc-9980-certificates-with-extra-yubikey-keys).

### OpenPGP v4 interoperability validation

The v4 adapter uses `bcpg` built from the same pinned Bouncy Castle revision as the other jars. Tests cover Ed25519, RSA and ECDSA signatures, key/subkey revocation and expiration, unsupported critical metadata, tampering and wrong keys. `scripts/test-v4-openpgp.sh` generates disposable GnuPG keys, verifies detached and compressed v4 signatures in PQ Mail, then independently decrypts PQ Mail’s v4 envelope in GnuPG and compares the hybrid-signed contents. No email or hardware keys are used. The published `dkg@fifthhorseman.net` certificate was also checked locally; its current encryption subkey was selected instead of its expired predecessor.

The new v4 adapter and Compose lookup are shared by the Java desktop/Android implementation; they have not been ported to the separate Swift/OpenSSL iOS implementation.

Classical-only encryption requires an **Encrypt anyway** confirmation, and valid classical-only signatures carry a **not post-quantum resistant** warning. These warnings also apply to conventional S/MIME. A hybrid signature containing ML-DSA or a hybrid KEM containing ML-KEM does **not** get the corresponding warning. Signing and encryption are assessed independently; a hybrid signature does not upgrade classical ciphertext protection. Trust and post-quantum algorithm status are separate.

### Saved OpenPGP contacts and trust (desktop)

Imported sender/recipient keys and successful Compose keyserver lookups are saved as **untrusted OpenPGP contacts** in Certificates. They survive app restarts and can be used offline. Choose **Details**, **Use selected certificate**, **Export**, or **Remove** just as for S/MIME contacts. Earlier session-only imports must be imported or looked up once again. Your own identity certificates remain in their existing identity storage.

**Mark trusted** requires explicit confirmation of the contact email and **entire primary-key fingerprint**, checked independently with its owner. Trust is scoped to that email/fingerprint pair, including valid bound subkeys; it does not transfer to another email or replacement primary key. A refreshed valid certificate with the same primary fingerprint retains that pair’s trust. **Remove trust** persists across restarts. Removing the contact also removes its trust and retains its public certificate in `removed-contacts`. Trust does not bypass certificate validation or suppress classical-only algorithm warnings.

Read & verify reports the saved trust decision for the actual From mailbox only after signature validation and a matching certified email. Saved contacts can supply incoming verification keys after restart; if an encrypted message has multiple matching signer certificates, select one explicitly before decrypting to avoid repeated token operations.

**Choosing trusted OpenPGP email addresses:** In Certificates, select an OpenPGP contact and choose **Mark trusted…**. The dialog lists every currently validated, self-certified email address, shows the full primary-key fingerprint, and provides **Select all email addresses**. Existing trust choices and the selected contact are checked initially. **Save trust choices** trusts checked addresses and removes trust from unchecked addresses for this primary key; selected aliases are added to Certificates. **Cancel** saves nothing. This covers valid signing and encryption subkeys bound to that primary key, while retaining expiry, revocation, usage checks and classical-algorithm warnings.

### Manual mail servers and sent confirmation

Use **Mail servers…** in Compose or Inbox to save IMAP/SMTP hostnames, ports and usernames without starting a connection or sending mail. IMAP uses TLS (normally 993); SMTP requires STARTTLS (normally 587). Passwords/app passwords are requested in **Inbox → Connect IMAP…** and **Send… → Other host (SMTP)** and are not saved. Gmail API remains separate and uses Google sign-in. After Gmail or the SMTP server accepts a message, PQ Mail displays a **Message sent** confirmation with recipient, subject and sending service. This confirms submission, not delivery or reading; failed sends do not display it.

Incoming signed PGP/MIME can use attached OpenPGP public certificates for signature verification without saving them or granting trust. The reader provides separate **Save sender OpenPGP certificate…** and **Trust signer fingerprint…** actions; trust remains scoped to selected certified emails and the full primary-key fingerprint. Discovery is bounded and accepts only certificates whose self-signatures/key bindings validate. Certificates hidden inside encrypted payloads still require an available sender key before opening.

### Desktop recipient preference and compatibility

PQ Mail prefers a matching v6 certificate over v4, then prefers a usable supported hybrid encryption subkey within that certificate. Classical encryption requires confirmation; no usable subkey means encryption is unavailable. V6 does not itself mean post-quantum: a classical v6 certificate still outranks a hybrid v4 certificate under this policy. Certificate import or receipt never grants trust automatically.

For v4 recipients, the desktop RFC 9980 YubiKey identity signs with its existing Ed25519 key and attaches `public-key-v4.asc` (Ed25519 primary, ML-KEM-768 + X25519 subkey) and `public-key-v6.asc` (hybrid signing/encryption). Both attachments are covered by the message signature and are inside encryption when enabled. Their fingerprints remain stable because the compatibility certificate reuses the original key creation timestamps. Public certificates are generated during composition; this does not generate token keys or write an updated on-key backup. A receiving client must support algorithm 35 to use the hybrid subkey. Proton/Thunderbird interoperability for this new outbound mode is not yet established.

Local regression tests cover v6-first selection (including classical v6 over hybrid v4), hybrid subkey preference and revocation fallback, Ed25519 certificate/message validation, both attached certificates, v3 hybrid encryption/decryption and tamper rejection, and continued v6 hybrid signing for v6 or unknown recipients. Hardware calls were simulated in these tests; no email was sent.
