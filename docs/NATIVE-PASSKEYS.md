# Native macOS passkey assertions

PQ Mail includes an AuthenticationServices helper for unlocking an existing PRF
vault and enrolling an existing passkey. It does not create credentials. Select
**Keys → Passkey method → Native macOS — security key** for a USB YubiKey, or
**Native macOS — platform passkey** for a compatible platform provider. The
browser method remains available for registration and older systems.

The native implementation requires macOS 26.4 or later because that is the SDK
availability of security-key PRF. A credential must support PRF and belong to
`ve7jtb.github.io`. A passkey already enrolled through Chrome uses the same
credential ID and raw salt. No vault migration or replacement credential is
required. Actual interoperability must be tested on the target authenticator.

## Signing and association

1. Use an active paid Apple Developer team. Personal Teams cannot provision
   Associated Domains.
2. Register explicit App ID `io.github.ve7jtb.pqmail.passkey`, enabling Associated
   Domains. Its signed entitlement is `webcredentials:ve7jtb.github.io`.
3. Host `.well-known/apple-app-site-association` over HTTPS at that domain:

   ```json
   { "webcredentials": { "apps": ["TEAMID.io.github.ve7jtb.pqmail.passkey"] } }
   ```

   Substitute the actual provisioning team's ID. Preserve other intentionally
   authorized applications if the domain already has an association file.
   Confirm Apple's CDN at
   `https://app-site-association.cdn-apple.com/a/v1/ve7jtb.github.io` serves it.
4. Set `PQ_MAIL_APPLE_TEAM` and run `bash scripts/build-passkey-helper.sh`.
   Automatic signing requests a development profile. Developer ID distribution
   additionally requires `PQ_MAIL_SIGNING_IDENTITY`, `PQ_MAIL_DISTRIBUTION=1`
   and `PQ_MAIL_PASSKEY_PROFILE` naming the helper's Developer ID profile.
   This is separate from `PQ_MAIL_HELPER_PROFILE` for the Keychain helper.
5. Set `PQ_MAIL_NATIVE_PASSKEYS=1` when running `package.sh`. Packaging validates
   the signed App ID, team, associated domain, embedded profile and expiry.
   Preserve the helper's own signature when signing the surrounding app.

The native option refuses to activate when this helper is absent. An error or
cancellation never starts a browser or creates a credential automatically.

## Request and secret handling

The Java process sends a bounded JSON assertion request to the helper's stdin.
The helper fixes the RP ID, requires user verification and uses the enrolled
credential ID for unlock. Discovery omits that allowlist. AuthenticationServices
receives the original 32-byte PRF input, without application prehashing.

The result returns only through stdout to the parent. No callback server is
started and no PRF output is written to a file, argument, environment variable,
clipboard or log. Java validates challenge, origin, RP hash, user presence,
user verification, credential ID and PRF output length, then authenticates the
existing encrypted vault wrapper. Cancellation/timeout terminates the helper.
Mutable secret buffers are cleared where possible; JSON/Swift runtime copies
cannot be guaranteed to be erased immediately.

## Validation and remaining hardware check

`build.sh test` includes `NativePasskeyTest`, which checks the OS gate, assertion
request, discovery, unchanged wrapper/salt, wrong challenge/key/UV rejection,
cancellation, and unlocking an unchanged synthetic browser-created vault.
The Swift helper's `--self-test` validates bounded request input without
contacting an authenticator. An unsigned build is suitable for that self-test
only, not for proving native passkey access.

The helper compiles against the installed AuthenticationServices SDK. The
domain association was published and accepted by Apple's CDN. Live native
YubiKey unlocking is **not yet verified**: the configured developer membership
remains pending and Xcode rejects the Associated Domains profile.

Once the profile is issued and the signed helper is installed:

1. Select native security-key mode; lock the existing vault.
2. Choose the existing passkey label and approve macOS's PIN/touch prompt.
3. Confirm **Passkey vault unlocked** with no browser opened.
4. Quit and reopen PQ Mail, then repeat the unlock.
5. Confirm the enrolled credential IDs and vault wrappers are unchanged.

Do not substitute new registration for a failed unlock. Report the native error
code without including PINs or PRF responses.

References: [Apple passkey integration](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys/),
[security-key assertion API](https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialassertionrequest).

## Linux USB FIDO2

Linux packages include a separate YubiKit HID assertion helper. See [Linux setup, security boundary and validation](LINUX-PASSKEYS.md). It reuses the same PRF wrappers as the browser and the other native backends. Live Linux hardware validation remains pending.
