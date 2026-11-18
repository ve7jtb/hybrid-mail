# PQ Mail for Android (preview)

Native Android mail UI using the same PQ Mail S/MIME/identity core as the desktop app, with **YubiKit Android 3.3.0** for direct **USB and NFC** PIV operations. No ykman, OpenSSL, PKCS#11 module, or native helper is installed on Android.

## Supported profiles

| Profile | Pure signature | Hybrid signature | Pure encryption | Hybrid encryption |
|---|---|---|---|---|
| Level 2 | ML-DSA-44 | MLDSA44-ECDSA-P256-SHA256 | ML-KEM-768 | MLKEM768-ECDH-P256-SHA3-256 |
| Level 3 | ML-DSA-65 | MLDSA65-ECDSA-P384-SHA512 | ML-KEM-768 | MLKEM768-ECDH-P384-SHA3-256 |
| Level 5 | ML-DSA-87 | MLDSA87-ECDSA-P384-SHA512 | ML-KEM-1024 | MLKEM1024-ECDH-P384-SHA3-256 |

Levels refer to ML-DSA categories. ML-KEM-768 is category 3. Hybrid algorithms use the same Bouncy Castle implementation and identifiers as desktop PQ Mail; draft-profile compatibility is tied to the pinned dependency revision.

- Create four software keys per profile, with pure and hybrid certificate views in one password-protected `.p12`.
- Import/export desktop-compatible software `.p12` files; unlock and select the pure or hybrid view. Support a primary email SAN plus four additional emails.
- Import existing YubiKey signing/encryption certificates, or issue local test certificates for an already-provisioned four-key profile. Token identities contain public certificates and the detected serial only.
- Sign messages, optionally encrypt to an imported recipient certificate, and save/open `.eml` with Android's file picker. Export public certificates as DER (the importer accepts DER/PEM).
- Verify signatures, show sender-SAN matching and SHA-256 fingerprints, and explicitly trust incoming signer fingerprints.
- Read the ten newest messages with IMAPS (993); send a prepared message with SMTP + required STARTTLS (587), after an explicit Send confirmation. Account passwords are not saved.

## Install and use

Install `PQ-Mail-Android-preview.apk` on Android 8.0 (API 26) or later. This is a **debug-signed development preview**, not a Play Store or production release. Only Android 17 on Pixel 10 has been device-tested so far.

For software keys, open **Identities & certificates → Create software .p12 — four keys** or **Import software .p12**. Choose an identity and its pure/hybrid view before composing or decrypting. Encryption is optional; an encryption certificate is needed only when encryption is enabled.

For YubiKeys:

1. Use a PQ-capable YubiKey already provisioned with the desired profile. This preview **does not generate, reset, replace, or delete token keys**.
2. Plug it into USB (approve Android's USB permission), or enable NFC and hold it at the phone's NFC antenna while PQ Mail is in the foreground.
3. Choose **Use existing YubiKey keys — issue certificates**, select the matching profile and email/SANs, and complete four PIN dialogs. This creates new local certificates for the existing keys. Alternatively, use **Import existing YubiKey certificate pair** twice to retain your existing pure and hybrid certificates.
4. Select a saved YubiKey identity; selection returns to Home. Open **Identities & certificates** again and scroll below the export buttons to find the test button. Its serial and public keys must match the inserted device before a PIN is submitted.
5. Choose **Test selected YubiKey identity — no email**. Expect one PIN dialog for signing and one for decryption, including hybrid mode. A successful result names the transport and both algorithms. Repeat with the other identity and then the other transport.

Fixed token slot mapping matches the desktop default: **9c ML-DSA, 9a ECDSA, 9d ML-KEM, 82 ECDH**. Legacy RSA composite token profiles and custom slot maps are not supported in this Android preview. Pure ML certificates can be imported without an ECDSA key.

Wait for **Connect your YubiKey**, remove the key from NFC range, then tap and hold until the operation completes. Repeat the fresh tap when prompted for the next operation (signing and decryption use separate taps). Removal, cancellation, a rejected PIN, or a transport error aborts the operation; no PIN retry occurs automatically. Reconnect/re-tap before retrying. Touch is required only if the key's existing policy requires it. Multiple YubiKeys are not auto-selected by serial: the most recently discovered key is checked, and a mismatch fails closed.

## Storage and scope

Encrypted `.p12` bundles and public token certificates are stored in app-private storage; Android backup is disabled. No YubiKey PIN, `.p12` password, or mail account password is persisted. A token PIN is cached in a mutable character array for one logical operation, used for PIN_ALWAYS verification of each component, and cleared in `finally` along with the connection. Software keys remain unlocked in process memory until **Lock software identity**, process termination, or replacement; Java does not guarantee erasure of provider private-key objects. Screenshots are disabled for the app, including PIN dialogs.

This preview does not yet include Google OAuth/refresh-token storage, Android token provisioning, background synchronization, HTML rendering, or the desktop's full certificate-management interface. Gmail requires an app password if the account permits it. The current recipient selection is session-only; trusted signing/encryption fingerprints and trusted encryption certificates persist and can be selected again from Identities & certificates. Self-signed demo certificates are not automatically trusted by other mail clients.

## Build

Prerequisites: **JDK 25**, Maven 3.9.9, Python 3, Git, Android SDK platform **37.0**, and platform-tools. AGP 9.3.3 / Gradle 9.7.1 are pinned. Set `ANDROID_HOME` to your SDK and `JAVA_HOME` to the JDK. Android Studio can open this directory after dependency preparation.

From the repository root:

```sh
./scripts/build-dependencies.sh
cd android
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

`prepare.py` reuses the canonical Java crypto sources, excluding desktop executable adapters, adapting the fingerprint formatter and one collection API call, and removing multi-release JAR entries. Android uses Jakarta Activation 2.1.3 / Angus Activation 2.0.2 because the desktop 2.2 milestone requires `System.Logger`, unavailable on Android. Cryptographic algorithms and CMS encoding are unchanged.

With a dedicated test device connected and USB debugging authorized:

```sh
./gradlew :app:connectedDebugAndroidTest :app:lintDebug
```

**Gradle's connected tests may uninstall the test app afterward.** For preserving an installed preview, install both APKs yourself, run instrumentation, then uninstall only the test package:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w org.pqmail.android.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall org.pqmail.android.test
adb shell am start -n org.pqmail.android/dev.hybridmail.MainActivity
```

Tests generate temporary software keys only. They cover all profiles, `.p12` reload/wrong-password rejection, signed/encrypted mail, authenticated-ciphertext tamper rejection, external interfaces, and the actual YubiKit PIV APDU implementation with a simulated card. They verify serial/key mismatch rejection before PIN submission, one prompt per composite operation, clearing cached PIN arrays, and no automatic retry after a PIN failure. **Simulated-card tests are not physical USB/NFC certification.** The on-screen YubiKey test is provided for hardware validation.

## Current physical-device status

The latest controlled comparison used the **identical APK** (verified by SHA-256), the same Level 3 PQC Ready YubiKey Beta0, and the same public certificates/slot mappings on two phones running Android 17:

| Saved S/MIME results, November 17, 2026 | Pixel 9 | Pixel 10 |
|---|---|---|
| Complete NFC signing/decryption passes | 5: three hybrid, two pure | 1 hybrid |
| Failed runs | 0 | 3 hybrid |
| Recorded pre-PIN setup failures | 0 | 7 |

Every successful run verified the signature and decrypted the message; no email was sent or token keys changed. The Pixel 9 has no saved PIN-free diagnostic runs: its five records are full round trips. Its retry-history file was absent, consistent with no recorded pre-PIN retries. This is a small, unequal sample, not a failure-rate estimate. It points toward a phone-dependent NFC interaction without identifying hardware, firmware, RF coupling or Android as the root cause.

Earlier Pixel 10 Level 5 tests completed three ten-cycle public-read checks and pure/hybrid round trips. Level 3 pure/hybrid USB controls also passed twice each. Those earlier successes do not establish reliable NFC on Pixel 10: later transport failures persisted even with smaller response requests.

The app uses unmodified YubiKit 3.3.0 with application-side lifecycle and APDU-wrapper changes. It waits for removal before a fresh tap, caps NFC public-metadata reads and their continuations at 240 data bytes, checks serial/public keys before PIN submission, and retains verified key types only within the current connection. Pixel 10 traces confirm `Le=240` produced 242-byte responses including status; later continuations could still fail. The public-read diagnostic initializes PIV once and reads serial/public keys ten times. **22 focused emulator tests passed.** See the [technical integration report](../docs/ANDROID-NFC-YUBIKIT.md).

Pre-PIN transport failures are saved before the recovery prompt, including failures that precede an eventual success and the final exhausted attempt. App-private `nfc-retries` preferences retain up to 50 timestamped entries with expected serial, profile, operation, attempt number, failing command headers, request/response lengths, status and timing. No PINs or APDU payloads are recorded. These entries do not include detailed failures after PIN submission, and successful round trips do not persist complete APDU traces. Retry behavior remains limited to two user-confirmed fresh taps during read-only setup; VERIFY/private commands are not automatically retried.

During the local round-trip test:

1. Enter the signing PIN with the NFC key away from the phone.
2. At **Connect your YubiKey**, tap and hold. **Hold your YubiKey in place** stays visible during the operation.
3. At **Signing complete — remove your key**, remove the NFC key. Choose **Continue to decryption** when ready.
4. Enter the decryption PIN, then re-tap when prompted and hold until completion.
5. **Test complete — remove your key** confirms both operations finished. No email is sent.

The latest physical passes used the updated hold/remove flow. Timestamped results retain up to 20 history entries, including failures. A PIN-free diagnostic is available under **Identities & certificates → Check YubiKey connection — no PIN** after selecting a YubiKey identity. It performs public reads only.

## Attachments

Compose → **Add attachment…** uses Android’s document picker. Remove individual files before preparing the message. Enable encryption to protect the body, filenames and files; otherwise all are signed only. Pure and hybrid profiles use the same shared S/MIME engine as desktop. Up to 20 files and 10 MiB body/file payload are supported, subject to the 20 MiB encoded-message limit. Selected files are held in memory; drafts are not persisted. For signed mail, verification must succeed before attachments are available. Encrypted-only mail is labeled unsigned and provides no signer assurance. Use **Save attachment** to choose a destination for the decrypted file. No broad storage permission is required.

### Conventional S/MIME interoperability

RSA and ECDSA signatures can be received and explicitly trusted by certificate fingerprint. Recipient encryption certificates support RSA (2048 bits or larger) and ECDH P-256/P-384 alongside PQ KEM profiles. Key usage and emailProtection extended key usage are checked when present; an ECDH certificate requires keyAgreement when key usage is present. Trust for signing and encryption is separate and does not imply CA-chain validation.

Import a recipient certificate or use **Trust signer for encryption** on verified mail if the signer certificate also permits encryption. A separate encryption certificate must be imported when the signing certificate is signing-only. Conventional software `.p12` files with one unambiguous signing key and at most one encryption key can be imported, including arbitrary aliases. Classical decryption requires the matching software private key; PQ YubiKey profiles remain unchanged.

The reader accepts signed messages inside AuthEnvelopedData or conventional EnvelopedData (including AES-CBC), and plain-text content in common mixed/alternative/related MIME layouts. HTML is not rendered. Encrypted messages without a signature are shown explicitly as unsigned and cannot be used to establish signer trust. Encryption to a conventional recipient does not provide post-quantum confidentiality, even when the message carries a PQ signature.

The attachment and conventional S/MIME update passed Android build/lint and emulator instrumentation tests on November 17, 2026. Physical YubiKey tests of these new features and third-party mail-client interoperability remain pending.

## Share certificates between instances

Select a saved **YubiKey identity**, then choose **Share certificates…** (Mac: **Keys**; Android: **Identities & certificates**). PQ Mail gathers the saved pure/hybrid profiles for the same device and PQ key pair and shows the email addresses, algorithms, fingerprints, serial and all four PIV slots before sharing. A normal pure/hybrid pair contains four public certificates. If only one profile is saved, only that profile can be shared; no new certificates or keys are generated.

The versioned `.pqcert` bundle contains public signing/encryption certificates and YubiKey serial/slot mappings. It contains **no private keys, PINs, passwords, OAuth credentials or trust decisions**. The Mac opens its native sharing picker, including AirDrop when available, and also offers **Save bundle…**. Android opens its system share sheet, including Quick Share when available. Transport availability depends on the OS/device; this feature does not implement AirDrop itself.

On the receiving Mac, open the `.pqcert` file with PQ Mail or use **Import certificate bundle…**. On Android, share/open it with PQ Mail when offered, or select it with **Import certificate bundle…**. Review all fingerprints and device mappings, then choose:

- **Use with my YubiKey / My YubiKey**: save public-only identities for that device. Select the imported pure or hybrid identity afterward. The existing signing/decryption backend checks serial and public keys when the key is used; imported metadata alone does not prove possession.
- **Add contact certificates / Contact certificates**: save certificates for another person's mailbox. Mark fingerprints trusted separately after confirming them with the owner.

Existing trust decisions are preserved, but imports never grant new trust. Repeated identity imports are idempotent; conflicting existing bindings are rejected. No YubiKey slots are written or provisioned. ML-DSA signing currently uses slot `9c`; the traditional-signing, ML-KEM and ECDH mappings travel with each profile. Software private identities remain separate `.p12` imports.

Validation covers public-only bundle round trips, malformed/oversized input, conflicting mappings, idempotent imports, trust separation, Android provider access restrictions and simulated token operations. Physical Mac–Android AirDrop/Quick Share delivery still requires testing on the two devices.

## OpenPGP alternative

Select a Level 3 hybrid identity, then open **OpenPGP public identities** to create or import its public identity. Export its `.asc` file for another installation or correspondent; import recipient/signer public identities and review their fingerprints. In Compose, enable **OpenPGP** and optionally encryption. The existing SMTP send and local file workflows use the selected format. Incoming OpenPGP messages use the imported signer public identity for verification.

Software keys stay in the password-protected `.p12`; YubiKey signing/decryption uses the same YubiKit PIV adapter. No OpenPGP applet or new token keys are required. OpenPGP is currently plain-text, one-recipient, Level 3 hybrid only; use S/MIME for attachments and other profiles. A valid signature does not establish correspondent trust. See [the shared OpenPGP guide](../docs/OPENPGP.md).

The OpenPGP build passed eight Android emulator instrumentation tests, including the simulated PIV backend. The tester reported a successful Level 3 hybrid OpenPGP USB signature/decryption round trip; the manual flow did not save a hardware report. Physical OpenPGP NFC testing remains pending.

## On-key certificate bundles

The identity screen now offers saving/importing signed public bundles directly
from a YubiKey and explicit ECDSA migration from 9a to empty 83. Existing mappings
remain intact until migration. Public reads do not require a PIN; writes/migration
require management-key authentication. See [format and recovery](../docs/ON-KEY-CERTIFICATES.md).
Hardware access on iOS still requires appropriate entitlements. Physical storage
and migration tests are pending; installing this build changes no keys.
