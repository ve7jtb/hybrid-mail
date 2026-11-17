# PQ Mail

PQ Mail is a desktop application for experimenting with post-quantum S/MIME using **Jakarta Mail, Eclipse Angus Mail, Bouncy Castle, and YubiKey PKCS#11**. It supports software identities and keys generated and used on a PQC Ready YubiKey. Formerly **Hybrid Mail**, the project now lives at [ve7jtb/pq-mail](https://github.com/ve7jtb/pq-mail).

## What the app does

- Compose signed text messages, optionally encrypt them, and save/open `.eml` files.
- Send through SMTP with STARTTLS and show the **10 most recent inbox messages** through read-only IMAP over TLS.
- Sign in to Gmail with Google Desktop OAuth, including PKCE and a loopback callback. Save the client configuration and refresh token in **macOS Keychain** or **Windows Credential Manager**.
- Select the outgoing signing identity and recipient encryption certificate independently.
- Manage signing and encryption certificates, inspect SHA-256 fingerprints, export PEM/DER, and explicitly mark certificates trusted. Successfully verified incoming signers can be added to the trust store.
- Keep **software identities in password-protected `.p12` files** separate from **YubiKey identities**, whose private keys stay on the device.
- Remember the serial and slots for each YubiKey identity, prompt for the correct device, and show the algorithm in PIN/operation dialogs.

This is an experimental interoperability application. Generated certificates are local test certificates; composite formats and OIDs follow the pinned Bouncy Castle implementation. It is not a production mail client or a claim of interoperability with every S/MIME implementation.

## Cryptographic profiles

| Profile | Signing | Encryption / KEM |
|---|---|---|
| Pure 65 / 768 | ML-DSA-65 | ML-KEM-768 |
| Hybrid 65 / P-256 | MLDSA65-ECDSA-P256-SHA512 | MLKEM768-ECDH-P256-SHA3-256 |
| RSA token demo | MLDSA65-RSA3072-PSS-SHA512 | ML-KEM-768 or the P-256 hybrid recipient profile |
| Pure 87 / 1024 | ML-DSA-87 | ML-KEM-1024 |
| Hybrid 87 / P-384 | MLDSA87-ECDSA-P384-SHA512 | MLKEM1024-ECDH-P384-SHA3-256 |

Software creation offers the pure and ECDSA hybrid profiles. The existing RSA demo uses both signing keys through PKCS#11. The new empty-device provisioning flow creates the 87 / 1024 profiles, optionally including both P-384 components.

Messages use opaque CMS SignedData, optionally wrapped in AuthEnvelopedData. Encryption uses KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM. Encryption is performed on the host with the recipient's public key; the recipient's YubiKey performs private-key decapsulation and ECDH during decryption. The host combines hybrid secrets.

Bouncy Castle computes ML-DSA external μ, including composite domain separation, and assembles composite signatures. The app's OpenSSL/PKCS#11 adapter uses the provider's external-μ support from [PR #818](https://github.com/openssl-projects/pkcs11-provider/pull/818). Returned signatures are verified before use. A composite operation shares one entered PIN between its two components and clears the cache when the operation finishes; PINs are never persisted.

## Getting started

1. In **Keys & token**, select or create a software identity, or select a saved YubiKey identity. Software creation requires a new `.p12` file and a password of at least 12 characters.
2. In **Certificates**, import the recipient's encryption certificate. Check its fingerprint through a trusted channel. Signing-certificate trust is an explicit, separate action.
3. In **Compose**, choose **Sign with**, enter matching sender/recipient addresses, and optionally enable **Also encrypt for recipient** and select **Encrypt to**.
4. Save the message locally or send it with SMTP. Use **Read & verify** for a local message or open a message from **Inbox**.

For Gmail, create your own Google OAuth client of type **Desktop app**, add your account as a test user when applicable, and import its JSON or use **Enter Google client credentials…**. Then choose **Sign in with Google** and **Connect Gmail**. SMTP also supports Google OAuth. Refresh tokens restore access after restart; sign-out removes the saved token. Server passwords and YubiKey PINs are not saved. See the [desktop and Gmail guide](docs/DESKTOP.md).

## YubiKey identities

**Create identity on empty YubiKey…** checks every user PIV slot before asking for provisioning credentials and checks again under an exclusive device connection before generation. Any occupied or unreadable slot stops the operation. The factory attestation slot is excluded. The flow does not reset a device or replace existing keys.

| Slot | Pure profile | Additional hybrid component |
|---|---|---|
| `9c` | ML-DSA-87 signing | — |
| `9d` | ML-KEM-1024 decryption | — |
| `9a` | — | ECDSA P-384 signing |
| `82` | — | ECDH P-384 decryption |

Keys are generated on the device with PIN policy **Always** and touch policy **Never**. Local identity records contain public certificates, serial and slot bindings, not token private keys. A missing or different device produces a connect/retry prompt. Generation is not atomic: a partial failure leaves generated keys in place and a subsequent creation attempt refuses the nonempty device. **Finish pending certificates…** can resume certificate issuance after successful key generation without generating keys again.

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

### Compatibility with existing installations

The display name and repository changed to PQ Mail. Existing settings, identity references, trust records and OAuth credential-store identifiers remain compatible. The application deliberately retains the legacy **`Hybrid Mail`** data directory (`~/Library/Application Support/Hybrid Mail` on macOS and `%LOCALAPPDATA%\Hybrid Mail` on Windows), Java package names, helper filenames and `HYBRID_*` environment variables. No key regeneration or credential migration is needed for the rename.

## Validation and limitations

- Physical Beta0 hardware tests passed for pure ML-DSA-65 and composite MLDSA65-RSA3072-PSS-SHA512 signing through PKCS#11, and pure ML-KEM-768 / hybrid MLKEM768-ECDH-P256 decryption. Saved messages were independently reopened and verified. The earlier ykman external-μ signing demo also passed.
- Automated tests cover software profiles, simulated external signing/decryption including 87 / 1024 and P-384, serialization, tampering, key matching, PIN cache cleanup, identity bindings, and provisioning refusal/partial failures. Simulators do not establish physical-device support. Fresh-device generation and high-profile hardware round trips still require an empty compatible key.
- Gmail OAuth, Keychain restoration after restart, and the ten-message IMAP inbox have been observed in the Mac app. Live SMTP delivery, third-party interoperability, Windows hardware use and a production security audit are not established by these tests.
- The reader handles signed text/plain mail and AuthEnvelopedData, plus ordinary plain text explicitly marked unsigned. HTML rendering, attachments and legacy EnvelopedData are not supported. Verification/decryption failures are not downgraded to unsigned mail.
- Trust uses exact certificate fingerprints, validity and key-usage checks. There is no CA chain building or revocation checking. Outer mail headers are not signed or encrypted. The app distinguishes signature validity from trust and flags sender/certificate mismatches.

Public demonstration certificates are separately published in [hybrid-mail-test-certificates](https://github.com/ve7jtb/hybrid-mail-test-certificates). Private keys, user identity files, device identifiers, OAuth credentials and local hardware artifacts are excluded from this source repository.

## Source map

Java code is under `src/dev/hybridmail/`: `MailApp` is the Swing UI; `MailEngine` handles S/MIME and mail transport; `Identity` and `DesktopState` manage identities and storage; `ExternalMu` / `ExternalKem` bridge token operations; `TokenProvision` invokes the native provisioning helper. `adapters/` contains the Python OpenSSL/PKCS#11 and legacy ykman adapters. `native-src/` contains platform credential helpers and Rust provisioning code. Tests are in the Java sources, `tests/`, and the Rust helper.

Third-party components retain their own licenses; see [notices](docs/THIRD-PARTY.txt). No project license has been selected yet.
