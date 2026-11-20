# Native Linux vault passkeys

The amd64 and ARM64 packages include `native/bin/pqmail-passkey`, built from
Yubico's Rust YubiKit with its **hid** feature enabled. This is a USB FIDO2
backend, separate from the PC/SC PIV backend used for mail signing/decryption.
No browser, localhost listener, ykman installation or PKCS#11 module is involved
in vault unlocking.

## Use an existing YubiKey passkey

1. Install the matching `.deb`, or extract the portable app with its dependencies.
2. Choose **Keys → Passkey method → Native Linux — YubiKey USB**.
3. Connect only the YubiKey holding your existing PQ Mail passkey. It must have
   FIDO2 enabled, a configured FIDO2 PIN, and support hmac-secret/PRF.
4. Choose **Unlock / manage passkeys**, select your saved passkey name, and enter
   the **FIDO2 PIN**, which is distinct from the PIV PIN used for mail operations.
5. Touch the key when prompted. Keep it connected until the operation completes.

An existing encrypted vault retains its credential ID, PRF salt and wrappers.
The same browser-created credential can therefore produce the same wrapping
key. Using the same credential on a new instance alone does not copy the old
vault's contents: import a wrapped transfer bundle to transfer those contents.

For a fresh Linux vault, native setup finds an **existing** discoverable PQ Mail
passkey; it does not create one. In an unlocked vault, **Use existing passkey**
can enroll another credential. Multiple matching credentials are shown by their
credential ID; the app's chosen device label names the saved wrapper. Native
creation and native credential deletion are not implemented. Select **Browser**
explicitly if you need to create a new passkey. A native failure never silently
opens a browser or creates/replaces a credential.

## Linux permissions

The Debian installer declares `libudev1` and `libu2f-udev` dependencies. Ubuntu's
standard FIDO udev rules grant access to the active local desktop user. Replug
the key after installing the rules. For the portable archive on Ubuntu:

```sh
sudo apt install libudev1 libu2f-udev
```

Do not run PQ Mail as root or make all hidraw devices world-writable. SSH/headless
sessions and some VM USB passthrough configurations may not receive the active
seat ACL; use a local desktop session and pass through the YubiKey's FIDO HID
interface. PC/SC-only forwarding is insufficient. The helper reports a missing
or inaccessible device and refuses to choose silently between multiple YubiKeys.
Other vendors, platform/synced providers and NFC are not supported by this backend.

## Security and protocol

The helper is assertion-only and fixes the RP ID to `ve7jtb.github.io`, origin to
`https://ve7jtb.github.io`, and user verification to **required**. It passes the
original vault PRF salt to YubiKit's WebAuthn client, which performs the standard
`SHA-256("WebAuthn PRF" || 0x00 || input)` transformation once. Raw CTAP hmac-secret
salts must not be substituted for the stored WebAuthn input.

This is a trusted native CTAP client, not an OS/browser origin-isolation service.
It only accesses the fixed PQ Mail RP. Only the packaged helper is launched.
PINs and results use anonymous parent/child pipes, not command-line arguments,
environment variables, files, terminal prompts or diagnostic logs. The helper
does not initialize a traffic logger and disables its core dumps. Owned mutable
PIN/PRF buffers are cleared; the process exits after each operation. Managed
runtime and SDK temporary allocations are not a guarantee of forensic erasure.

Cancel closes the prompt and terminates the helper; the outer deadline is five
minutes. Wrong PIN, no PRF output, wrong credential, malformed responses and
missing UP/UV fail closed. A PIN is submitted at most once per operation, with
no automatic retry. Successful unlock still requires authenticated decryption
of the existing vault wrapper. PIV keys, certificates, touch policies and FIDO
credentials are not provisioned or modified by this flow (assertion counters
may advance normally).

## Build and validation

```sh
bash scripts/build-passkey-linux.sh
```

The pinned YubiKit revision is recorded in Cargo.toml and Cargo.lock. CI on
Ubuntu 24.04 amd64 and ARM64 runs Rust protocol/result tests, Java scripted pipe
and vault tests, and package loading checks. It tests the packaged helper's
rejection of credential creation before device access, dependency resolution,
Debian contents, icons, and the bundled Java 25.0.5.1 runtime.

These tests use synthetic credentials and software keys. **A real Linux YubiKey
unlock and restart test is still required**; CI does not establish USB hardware
interoperability or validate a provider's browser-to-native PRF output on a key.
For that test: unlock an existing vault natively, lock it, unlock again, restart
PQ Mail, and confirm the same credential still unlocks without opening a browser.
Never include PINs or PRF values in a test report.
