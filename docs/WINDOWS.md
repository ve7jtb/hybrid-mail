# Windows x64 and ARM64 installers

The Windows installers workflow builds each architecture on its native GitHub Actions runner. Download the matching `PQ-Mail-Windows-x64` or `PQ-Mail-Windows-arm64` artifact ZIP, extract it, and run the Setup EXE. These are unsigned development installers, not production-signed releases. An installer is available only after its workflow succeeds.

Installation is per-user under `%LOCALAPPDATA%\Programs\PQ Mail`, with Start Menu and desktop shortcuts. Java 25, embedded Python, OpenSSL, the patched PR #818 PKCS#11 provider, Yubico PKCS#11 module and empty-key provisioning helper are included. No Java, Python or ykman installation is required on the destination machine. User identities and settings live separately under `%LOCALAPPDATA%\Hybrid Mail`; uninstalling the application does not delete those identities or token keys. Persistent mail credentials and software identity passwords are protected by the PRF vault. Legacy Credential Manager entries are migrated after unlocking; the app can renew OAuth access using the saved refresh token after vault unlock.

Build: the workflow builds the pinned Java dependencies on Linux, then native helpers/provider and the installer separately on Windows x64 and ARM64. Windows native builds require Rust 1.88+, MSVC, MSYS2 compiler/meson/OpenSSL/dlfcn, Azul Zulu JDK 25, and Inno Setup 6.4.3+. See `.github/workflows/windows-installers.yml` for commands and `scripts/package-windows.ps1` / `scripts/windows-installer.iss` for packaging.

CI checks cover software crypto, simulated token operations, native credential-store roundtrip and provider load. Physical YubiKey provisioning/signing/decryption on each Windows architecture remains a separate hardware acceptance test. No CI job resets or provisions a real YubiKey.

## Native passkey vault unlock

The x64 and ARM64 installers include a native `pqmail-passkey.exe`, built for
that architecture with MSVC. It uses the operating system's `webauthn.dll`,
loaded with `LOAD_LIBRARY_SEARCH_SYSTEM32`; no WebAuthn DLL is redistributed.
No separate runtime, browser, RP-domain association file, or administrator
privilege is needed for this helper. WebAuthn API version 4 or newer and a
PRF-capable authenticator are required. Runtime checks reject unsupported APIs.
Windows Hello/provider availability alone does not establish PRF support.

1. Open **Keys → Passkey method**.
2. Choose **Native Windows — security key** for the existing YubiKey passkey,
   or **Native Windows — platform passkey** for a compatible provider.
3. Choose **Unlock / manage passkeys**, select the saved passkey label and
   approve Windows' PIN/touch or platform authentication prompt.
4. Confirm **Passkey vault unlocked**. Lock and repeat; then quit and reopen
   the app to test a fresh unlock.

The RP remains `ve7jtb.github.io`. The request uses the existing credential ID
and raw PRF salt, with user verification required. WebAuthn applies the standard
PRF input hashing itself; the helper does not set the raw-HMAC-salt flag.
**Use existing passkey** performs discovery without creating a credential.
Creating a new credential still requires selecting **Browser** explicitly.
Failure/cancellation never silently switches providers or creates credentials.

Java sends bounded public request metadata over stdin and receives the PRF result
on stdout. The helper does not read a PIN, persist secrets or emit them in logs,
arguments, environment variables or temporary files. Windows owns the credential
prompt. The parent validates the WebAuthn context/UP/UV and authenticates the
vault wrapper before allowing access. The helper supports cancellation and the
parent enforces a timeout. Mutable secret buffers are cleared where possible;
runtime string copies cannot be guaranteed to be erased immediately.

Build with `scripts/build-passkey-windows.ps1` in the target x64/ARM64 MSVC
Developer shell. The Windows installer workflow runs it for both architectures.
Its `--self-test` checks parsing, API options, raw salt preservation, result
encoding, wrong-key/PRF rejection and clearing without requesting a credential.
`--probe` reports only the system API version and API availability, without a
passkey prompt. Each artifact includes `passkey-capabilities-ARCH.json` for the
build runner; this does not certify the destination computer or authenticator.
Packaging checks the PE machine type and runs the staged helper's self-test.

Portable C++ tests and Java bridge/vault tests use synthetic inputs. Physical
YubiKey native unlock, cancellation and restart tests on Windows remain pending.
Neither CI nor these tests creates or changes authenticator credentials.

API references: [Microsoft assertion options](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_get_assertion_options)
and [WebAuthn header/API versions](https://github.com/microsoft/webauthn/blob/master/webauthn.h).
