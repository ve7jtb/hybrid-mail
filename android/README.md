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

This preview does not yet include Google OAuth/refresh-token storage, Android token provisioning, background synchronization, attachment/HTML viewing, or the desktop's full certificate-management interface. Gmail requires an app password if the account permits it. Recipient encryption certificates are selected for the current session; trusted signer fingerprints persist. Self-signed demo certificates are not automatically trusted by other mail clients.

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

Level 3 pure and hybrid signing/decryption have passed on a physical Beta0 YubiKey over NFC using Pixel 10 / Android 17. Saved results confirm both signing and decryption used NFC, the signatures verified, and the messages decrypted. Desktop PKCS#11 round trips also passed. Physical Android USB testing remains pending.

The NFC flow resolves Beta firmware qualifiers through the device's Management session, collects the PIN before opening a fresh NFC connection, verifies the serial/public keys before submitting the PIN, and clears the PIN after each operation. Earlier disabled-PIV and stale-tag errors were resolved during testing.

During the local round-trip test:

1. Enter the signing PIN with the NFC key away from the phone.
2. At **Connect your YubiKey**, tap and hold. **Hold your YubiKey in place** stays visible during the operation.
3. At **Signing complete — remove your key**, remove the NFC key. Choose **Continue to decryption** when ready.
4. Enter the decryption PIN, then re-tap when prompted and hold until completion.
5. **Test complete — remove your key** confirms both operations finished. No email is sent.

The new stage/removal dialogs have passed a UI startup smoke test; the recorded physical NFC passes precede this wording/transition update. Timestamped results remain stored separately for each signing profile, including failures.
