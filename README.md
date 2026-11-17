# Hybrid Mail

A native Java desktop development app for post-quantum S/MIME, built with Jakarta Mail, Eclipse Angus Mail and Bouncy Castle. Compose text messages, save/open `.eml`, sign and verify, encrypt and decrypt, send with SMTP, and browse the 10 most recent inbox messages over IMAP.

This is an experimental interoperability app, not a production mail client. A Beta0 ykman external-μ adapter is included. It uses an existing ML-DSA-65 key in PIV slot `9c`, with PIN entry handled directly by ykman in Terminal. Both pure and composite S/MIME signing have been verified with a physical Beta0 key; see the validation section below.

## Cryptographic profiles

| Operation | Pure profile | Composite profile |
|---|---|---|
| Signing | ML-DSA-65 | MLDSA65-ECDSA-P256-SHA512; token demo also MLDSA65-RSA3072-PSS-SHA512 |
| Encryption KEM | ML-KEM-768 | MLKEM768-ECDH-P256-SHA3-256 |

S/MIME opaque SignedData is optionally wrapped in AuthEnvelopedData. Encryption uses CMS KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM content encryption. Signing and encryption profiles can be selected independently through the sender identity and recipient certificate. Composite formats/OIDs follow the pinned Bouncy Castle revision below.

Both signing profiles can send the ML-DSA component through an external-μ adapter. Bouncy Castle handles composite domain separation and signature assembly. The app verifies the adapter's returned signature and the complete outgoing signature before use. The PKCS#11 backend supports both composite signing components and both hybrid decryption components on the token.

## Build from source

Prerequisites: **JDK 25**, **Maven 3.9.9**, Python 3 (standard library only), Git and Bash on macOS or Linux. Set `JAVA_HOME` to your JDK and put Maven on `PATH`. The Bouncy Castle Gradle wrapper downloads its pinned Gradle distribution. Initial dependency builds require internet access and several GB of disk space. macOS is the tested desktop platform; Windows is not supported by these scripts or the POSIX identity-file permissions.

```sh
git clone https://github.com/ve7jtb/hybrid-mail.git
cd hybrid-mail
# Set JAVA_HOME and PATH for your installed JDK and Maven before continuing.
java -version
mvn -version
./scripts/build-dependencies.sh
./build.sh test
./run.sh
```

The repository and dependency forks are public. The dependency forks are fetched at exact revisions, not floating branch heads:

| Repository | Revision |
|---|---|
| [ve7jtb/mail-api](https://github.com/ve7jtb/mail-api) | `09b27cf52b4b382c55cc8736858456f3aa43b369` |
| [ve7jtb/angus-mail](https://github.com/ve7jtb/angus-mail) | `d33de7563efdf5a3cb0691994500d6cad8aecafd` |
| [ve7jtb/bc-java](https://github.com/ve7jtb/bc-java) | `6b4f58259d2b3ee8301fda1d6c8798f816abc5ea` |

Activation dependencies: `jakarta.activation-api:2.2.0-M2` and `angus-activation:2.1.0-M1`. These snapshots/milestones are deliberate, matching the local development stack. Source revisions are pinned; builds are not claimed to be byte-for-byte reproducible, and upstream transitive build dependencies still come from their configured repositories.

`build-dependencies.sh` creates `.deps/repos`, `.deps/cache`, `.deps/logs` and `lib/`. It skips dependency test suites; `build.sh test` runs the app's crypto and adapter tests. On failure, inspect the named dependency log. Reruns reuse caches and check that existing dependency checkouts match the pinned commits and have no tracked changes. To use another cache/root, set `HYBRID_DEPS_DIR` to an absolute directory. To restart a failed checkout, choose a fresh directory. No global Java/Maven configuration is modified.

Subsequent app-only builds need no network:

```sh
./build.sh test
./run.sh
```

## Package a desktop app

```sh
./package.sh
```

On macOS this produces `dist/Hybrid Mail.app` with Java, OpenSSL and the locally built PKCS#11 modules. Build the native modules first using `scripts/build-pkcs11.sh`; set `HYBRID_OPENSSL_ROOT` if OpenSSL is not under `/opt/homebrew/opt/openssl@3`. Python 3 must exist on the target Mac (default `/usr/bin/python3`, configurable in the app). `HYBRID_MAIL_PACKAGE_DIR` selects an alternate output directory. Existing app images are not overwritten. The image is ad-hoc signed for local use, not notarized for public distribution.

Open the app from Finder. Use **Keys & token → YubiKey configuration** to save the serial and slot assignments. Certificate-only identities restore without an identity password; software identities retain their PKCS#12 encryption and require their password. PINs and mail account passwords are never saved. [Desktop and Gmail setup](docs/DESKTOP.md).

## Local demonstration

1. In **Keys & token**, create Alice's and Bob's identities with their email addresses. Choose Pure or Hybrid and save each under a new `.p12` filename with a password of at least 12 characters.
2. Export Alice's signing certificate and Bob's encryption certificate.
3. Load Alice, import Bob's encryption certificate, and compare its fingerprint with Bob through a trusted channel.
4. Compose with matching From/To addresses. Leave encryption enabled and save an `.eml` file.
5. Load Bob, pin Alice's signing certificate, and open the message in **Read & verify**.

You can also send to yourself with one identity and its own encryption certificate. Uncheck encryption to produce a signed-only message. Existing files are not overwritten. Identities, certificate pins and non-secret settings are saved locally.

See [user guide](docs/USER-GUIDE.txt) for transport and scope details, and [external-μ integration](docs/EXTERNAL-MU.txt) for the executable protocol and certificate-only token identity setup.

## Beta0 YubiKey signing

Use **ykman 6.0.0-beta.0** with its `piv keys sign --mu` command and an **existing ML-DSA-65 key in slot 9c**. The adapter never generates or replaces a token key, changes PIN policy, or writes a certificate to the token. It explicitly selects `YKMAN_SERIAL` and verifies the exported slot public key against the mail identity before requesting a signature.

Launch from Terminal: the adapter attaches ykman's PIN/touch prompts to `/dev/tty`. Neither Java nor Python receives the PIN, and it is not put in arguments, environment variables or files. This adapter does not work when the app is launched from Finder without a controlling terminal. Set `YKMAN_BIN` if ykman is installed somewhere other than `/usr/local/bin/ykman`.

```sh
export YKMAN_SERIAL=YOUR_DEVICE_SERIAL
# Read-only public-key export; no --verify challenge is requested.
/usr/local/bin/ykman --device "$YKMAN_SERIAL" piv keys export 9c /absolute/path/token-public.pem
./scripts/test-beta0.sh /absolute/path/token-public.pem /absolute/path/new-test-output
```

The test prompts for a new local identity-file password, then makes **four token signatures**: a pure signing certificate, a pure S/MIME message, a composite signing certificate, and a composite S/MIME message. With `always` PIN/touch policies, expect four PIN entries/touches. The conventional P-256 component is generated in software. No email is sent. Each certificate and message is verified with Bouncy Castle, and each identity is reloaded from PKCS#12 to verify that the ML-DSA private key is absent. Artifacts are saved under the new output directory. The mail UI then opens with the verified pure message and its token identity loaded. Append `--no-ui` to run just the test.

For later sessions:

```sh
export YKMAN_SERIAL=YOUR_DEVICE_SERIAL
./run.sh
```

Load `pure.p12` or `hybrid.p12`, choose `adapters/ykman-mu.py` under **Keys & token**, and use the certificate's From address (`beta0@example.test` for test identities). The generated token identities are signing-only; they have no decryption key. They can encrypt outgoing messages for imported recipient certificates.

The adapter uses pure ML-DSA external μ, **not** `--prehashed` or `--compute-mu`: Java/BC has already computed the correct 64-byte μ, including composite domain separation when applicable. Invalid responses fail closed; no software fallback or automatic PIN retry. See [adapter details](docs/EXTERNAL-MU.txt).

The earlier public SDK/source inspection did not include the installed Beta0 CLI. Its `--mu` interface supplies the missing integration route without guessing APDUs. The [historical source notes](docs/YUBIKEY-MANAGER.txt) are retained with that scope clarified.

## Optional PKCS#11 backend

`adapters/pkcs11-mu.py` provides a second external-μ backend using OpenSSL pkcs11-provider [PR #818](https://github.com/openssl-projects/pkcs11-provider/pull/818) and the Rust Yubico PKCS#11 module. It selects `CKM_ML_DSA_EXTERNAL_MU` through `mu:1`, reuses the same host-side composite handling, and verifies signatures in Bouncy Castle. [Build, configuration and hardware-test instructions](docs/PKCS11.md).

## Validation and limits

**Hardware test completed on 2026-11-16:** an existing ML-DSA-65 key in a physical Beta0 YubiKey's slot 9c signed both pure ML-DSA-65 and composite MLDSA65-ECDSA-P256-SHA512 S/MIME messages via `ykman 6.0.0-beta.0 --mu`. Both local test certificates and both serialized `.eml` messages verified with Bouncy Castle. Certificate-only PKCS#12 identities were reloaded successfully with no ML-DSA private key present. The saved messages were independently re-opened and verified after the interactive run. No email was sent or token keys changed. Device identifiers, certificates, identity files, and hardware test artifacts are not included in the repository.


50 local checks passed on macOS/Java 25: all four signing/encryption combinations; Unicode MIME bodies; AES-GCM tampering and wrong-recipient rejection; pure and composite external-μ signing; corruption of each composite signature component; PKCS#12 reload and wrong-password rejection; address mismatch handling; and an executable-adapter round trip. [Recorded core results](docs/TEST-RESULTS.txt). Additional tests cover pure and ECDSA/RSA composite token identities, certificate-only persistence, per-signature PIN cache cleanup and 40 adapter/provisioning, command, key-match, failure and cleanup cases across the ykman and PKCS#11 backends.

The automated software tests do not use a YubiKey or send mail. The interactive hardware test produces a separate local `result.txt`; do not infer hardware success from a software test run. Live SMTP delivery, third-party mail client interoperability and a production security audit remain outstanding. SMTP requires STARTTLS (default 587); IMAP uses TLS (default 993). Google Desktop OAuth is supported for Gmail IMAP and SMTP; import your own Desktop OAuth client JSON. The reader supports signed text/plain messages, optionally inside AuthEnvelopedData; ordinary plain-text mail is shown explicitly as unsigned. Legacy EnvelopedData, rendered HTML and attachments remain unsupported.

Generated certificates are local test identities, not publicly trusted credentials. Trust uses exact certificate pinning, validity and key-usage checks; no CA chain building or revocation checking. Outer From/To/Subject headers are not signed or encrypted. The UI distinguishes signature validity from pin trust and flags a From/certificate mismatch. Passwords are not persisted; loaded keys remain in process memory until exit.

## Source layout

- `MailApp.java`: Swing UI and account dialogs
- `MailEngine.java`: S/MIME and SMTP/IMAP
- `Identity.java`: identity generation, PKCS#12 and signer selection
- `ExternalMu.java`: provider SPI and executable adapter
- `TokenSetup.java`: certificate-only token identity utility
- `Beta0Test.java`: interactive hardware-backed S/MIME test and mail UI launch
- `adapters/ykman-mu.py`: terminal-based ykman external-μ adapter
- `adapters/pkcs11-mu.py`, `Pkcs11Test.java`: OpenSSL/PKCS#11 backend and hardware test
- `SelfTest.java`, `TokenIdentityTest.java`, `TestMuAdapter.java`, `tests/`: tests and software fixtures

All Java sources are under `src/dev/hybridmail/`. Third-party source and binaries are not vendored; their own licenses apply. No project license has been selected yet.

For hybrid signing with **ML-DSA-65 and RSA-3072 keys on the YubiKey**, use the [dual-token PKCS#11 demo](docs/PKCS11.md#both-hybrid-signing-keys-on-the-token). It uses slot 9c plus RSA-3072 in 9a, creates certificate-only local identities, and prompts for the YubiKey PIN in the app. Each composite signature reuses one PIN for both components and then clears it. Hardware validation passed on 2026-11-16 for pure ML-DSA-65 and MLDSA65-RSA3072-PSS-SHA512 through PKCS#11, with PIN-protected, no-touch keys. Both saved messages were independently verified.

## Token-backed S/MIME decryption

Pure ML-KEM-768 and hybrid MLKEM768-ECDH-P256-SHA3-256 decryption are available through PKCS#11, using separate token keys and one app PIN per message. Encryption uses the recipient’s public certificate on the host. See [build, provisioning, demo and app instructions](docs/PKCS11-KEM.md). Hardware validation passed on 2026-11-16 for both profiles: saved messages were reopened, token-decrypted, AES-GCM authenticated and signature-verified. Signing slots remained unchanged.

## Inbox and Google account

The **Inbox** tab lists the ten most recent arrivals, newest first, using a read-only IMAP folder. Refresh updates headers; double-click a row or choose **Open selected message** to fetch its body. Message UIDs preserve the selection when another client removes messages. The reader never fetches remote images or renders HTML. S/MIME verification/decryption failures are not downgraded to unsigned content.

For Gmail, import a Google **Desktop app** client JSON (or enter its ID and secret with **Enter Google client credentials**) and choose **Sign in with Google**. Authorization uses the system browser, a loopback callback, state verification and S256 PKCE. **Connect Gmail** uses IMAP TLS/XOAUTH2; **Send via SMTP → Google OAuth** uses STARTTLS/XOAUTH2. The Mac app saves the Google client configuration and refresh token in the login Keychain. Access tokens remain in memory and are renewed on the next Gmail connection or SMTP operation when needed, including after restart. Sign out deletes the saved refresh token. Other servers can use password authentication; only host, port and username persist. No network connection is made on startup.

Public demonstration certificates are published separately at [hybrid-mail-test-certificates](https://github.com/ve7jtb/hybrid-mail-test-certificates). User certificate files, identities, Google client JSON and device identifiers are not bundled in this source repository.

## Recipient certificates and optional encryption

Compose provides **Sign with** and **Encrypt to** selectors for independently choosing among saved signing identities and recipient encryption certificates. YubiKey progress dialogs identify the current component algorithm. Mail is signed by default. Enable **Also encrypt for recipient (optional)** to encrypt. The **Certificates** tab manages saved signing/trust and encryption certificates by email and purpose, with fingerprint details, PEM/DER export and recoverable removal. **Mark trusted…** and **Remove trust** manage persistent, exact SHA-256 certificate trust. The reader can save trusted signer fingerprints from successfully verified incoming messages. Multiple trusted signers coexist. **Use selected certificate** selects a certificate without granting trust, or an encryption recipient. Encryption requires a matching recipient email SAN and is never silently disabled on error. Your own signing identity remains under **Keys & token**. See [desktop guide](docs/DESKTOP.md).

Live Google OAuth and Gmail IMAP listing have been observed in the packaged app. The user’s client configuration and tokens are not included in this repository.

## Additional software signing profiles

**Keys & token → Create identity…** also offers pure ML-DSA-87 and `MLDSA87-ECDSA-P384-SHA512` composite signatures (ECDSA P-384 with SHA-384). These software identities are stored in password-protected PKCS#12 files and appear in **Sign with**. Encryption remains ML-KEM-768 or ML-KEM-768/ECDH P-256 respectively. Existing YubiKey provisioning/adapters remain configured for ML-DSA-65 profiles; creating these identities does not alter token keys.

On macOS `build.sh` also compiles `native-src/keychain.c` using Apple clang and the Security/CoreFoundation frameworks. Xcode Command Line Tools are required. `package.sh` bundles the narrowly scoped Keychain helper.
