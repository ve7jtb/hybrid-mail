# Hybrid Mail

A native Java desktop development app for post-quantum S/MIME, built with Jakarta Mail, Eclipse Angus Mail and Bouncy Castle. Compose text messages, save/open `.eml`, sign and verify, encrypt and decrypt, send with SMTP, and fetch the latest message over IMAP.

This is an experimental interoperability app, not a production mail client. Real YubiKey ML-DSA signing is **not yet implemented**; the external-μ integration boundary is implemented and tested with a software simulator.

## Cryptographic profiles

| Operation | Pure profile | Composite profile |
|---|---|---|
| Signing | ML-DSA-65 | MLDSA65-ECDSA-P256-SHA512 |
| Encryption KEM | ML-KEM-768 | MLKEM768-ECDH-P256-SHA3-256 |

S/MIME opaque SignedData is optionally wrapped in AuthEnvelopedData. Encryption uses CMS KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM content encryption. Signing and encryption profiles can be selected independently through the sender identity and recipient certificate. Composite formats/OIDs follow the pinned Bouncy Castle revision below.

Both signing profiles can send the ML-DSA component through an external-μ adapter. Bouncy Castle handles composite domain separation and signature assembly. The app verifies the adapter's returned signature and the complete outgoing signature before use. The conventional signing component and encryption keys remain in software.

## Build from source

Prerequisites: **JDK 25**, **Maven 3.9.9**, Git and Bash on macOS or Linux. Set `JAVA_HOME` to your JDK and put Maven on `PATH`. The Bouncy Castle Gradle wrapper downloads its pinned Gradle distribution. Initial dependency builds require internet access and several GB of disk space. macOS is the tested desktop platform; Windows is not supported by these scripts or the POSIX identity-file permissions.

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

The repository is private; cloning requires your GitHub credentials or an authorized SSH remote. The dependency forks are fetched at exact revisions, not floating branch heads:

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

On macOS this produces `dist/Hybrid Mail.app` with its Java runtime. On Linux `jpackage` produces a platform-specific app image. Packaging must run on the target platform. Move an older generated image out of `dist/` before rerunning; the script does not overwrite it. The image is not signed with a distribution identity or notarized. Generated binaries are excluded from Git.

## Local demonstration

1. In **Keys & token**, create Alice's and Bob's identities with their email addresses. Choose Pure or Hybrid and save each under a new `.p12` filename with a password of at least 12 characters.
2. Export Alice's signing certificate and Bob's encryption certificate.
3. Load Alice, import Bob's encryption certificate, and compare its fingerprint with Bob through a trusted channel.
4. Compose with matching From/To addresses. Leave encryption enabled and save an `.eml` file.
5. Load Bob, pin Alice's signing certificate, and open the message in **Read & verify**.

You can also send to yourself with one identity and its own encryption certificate. Uncheck encryption to produce a signed-only message. Existing files are not overwritten. Certificates and pins are session-only.

See [user guide](docs/USER-GUIDE.txt) for transport and scope details, and [external-μ integration](docs/EXTERNAL-MU.txt) for the executable protocol and certificate-only token identity setup.

## YubiKey integration status

The external signer receives an ML-DSA-65 public key and a 64-byte μ, and returns a raw signature. It must sign μ directly, without hashing it again. A token's PIN/touch interaction belongs in the adapter. The included `TestMuAdapter` is **software-only** and is not a hardware driver.

The supplied Yubico .NET PIV documentation does not expose ML-DSA external-μ signing. The public `Yubico/yubikey-manager` PIV implementation was also inspected at commit `4ca60f706af930459138d8dc0f0f953480e1c7a4`: its key-type enum has no ML-DSA entry, and conventional `Prehashed` support is not external-μ ML-DSA. It provides useful smart-card transport, but connecting the assumed ML-DSA-capable device still requires its algorithm identifier, APDU format and signing semantics. See [source inspection notes](docs/YUBIKEY-MANAGER.txt).

## Validation and limits

50 local checks passed on macOS/Java 25: all four signing/encryption combinations; Unicode MIME bodies; AES-GCM tampering and wrong-recipient rejection; pure and composite external-μ signing; corruption of each composite signature component; PKCS#12 reload and wrong-password rejection; address mismatch handling; and an executable-adapter round trip. [Recorded results](docs/TEST-RESULTS.txt).

No mail was sent and no hardware signing was performed. Live SMTP/IMAP, third-party mail client interoperability and a production security audit remain outstanding. SMTP requires STARTTLS (default 587); IMAP uses TLS (default 993). No OAuth account setup. The reader supports signed text/plain messages, optionally inside AuthEnvelopedData; it does not display ordinary unsigned mail, legacy EnvelopedData, HTML or attachments.

Generated certificates are local test identities, not publicly trusted credentials. Trust uses exact certificate pinning, validity and key-usage checks; no CA chain building or revocation checking. Outer From/To/Subject headers are not signed or encrypted. The UI distinguishes signature validity from pin trust and flags a From/certificate mismatch. Passwords are not persisted; loaded keys remain in process memory until exit.

## Source layout

- `MailApp.java`: Swing UI and account dialogs
- `MailEngine.java`: S/MIME and SMTP/IMAP
- `Identity.java`: identity generation, PKCS#12 and signer selection
- `ExternalMu.java`: provider SPI and executable adapter
- `TokenSetup.java`: certificate-only token identity utility
- `SelfTest.java`, `TestMuAdapter.java`: tests and software fixture

All Java sources are under `src/dev/hybridmail/`. Third-party source and binaries are not vendored; their own licenses apply. No project license has been selected yet.
