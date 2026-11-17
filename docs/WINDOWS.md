# Windows x64 and ARM64 installers

The Windows installers workflow builds each architecture on its native GitHub Actions runner. Download the matching `PQ-Mail-Windows-x64` or `PQ-Mail-Windows-arm64` artifact ZIP, extract it, and run the Setup EXE. These are unsigned development installers, not production-signed releases. An installer is available only after its workflow succeeds.

Installation is per-user under `%LOCALAPPDATA%\Programs\PQ Mail`, with Start Menu and desktop shortcuts. Java 25, embedded Python, OpenSSL, the patched PR #818 PKCS#11 provider, Yubico PKCS#11 module and empty-key provisioning helper are included. No Java, Python or ykman installation is required on the destination machine. User identities and settings live separately under `%LOCALAPPDATA%\Hybrid Mail`; uninstalling the application does not delete those identities or token keys. Google client configuration and refresh tokens use Windows Credential Manager; the app renews access when connecting after restart.

Build: the workflow builds the pinned Java dependencies on Linux, then native helpers/provider and the installer separately on Windows x64 and ARM64. Windows native builds require Rust 1.88+, MSVC, MSYS2 compiler/meson/OpenSSL/dlfcn, Azul Zulu JDK 25, and Inno Setup 6.4.3+. See `.github/workflows/windows-installers.yml` for commands and `scripts/package-windows.ps1` / `scripts/windows-installer.iss` for packaging.

CI checks cover software crypto, simulated token operations, native credential-store roundtrip and provider load. Physical YubiKey provisioning/signing/decryption on each Windows architecture remains a separate hardware acceptance test. No CI job resets or provisions a real YubiKey.
