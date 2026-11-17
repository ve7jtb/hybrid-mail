# macOS app, inbox and Google setup

Launch **Hybrid Mail.app** from Finder. Java, OpenSSL and the patched native PKCS#11 libraries are bundled. Python 3 uses `/usr/bin/python3` by default; change its absolute path under **Keys & token → YubiKey configuration → Advanced** if necessary. The package is ad-hoc signed for local testing, not notarized.

## Saved identities and configuration

Settings live in `~/Library/Application Support/Hybrid Mail/`. **Show saved identity files** opens the directory. Token identities contain public signing/encryption certificates in DER and PEM, without private keys or an identity-file password. Imported software identities retain the original encrypted PKCS#12 and prompt for their password when opened. Original identity files are not moved or deleted.

The app remembers the selected identity, recipient certificate, pinned signer, sender/recipient addresses, server host/port/username, and YubiKey serial/slots. Before a PKCS#11 operation, the app checks for the configured device serial without logging in. If it is missing, **Connect your YubiKey** offers Retry/Cancel before asking for a PIN. Retry only repeats read-only enumeration; failed PIN/private operations are never retried automatically. The YubiKey operation dialog names the algorithm for the current component (ML-DSA, RSA-PSS/ECDSA, ML-KEM or ECDH). Each token operation prompts for a PIN; a composite operation reuses the PIN for its two components and clears it afterward. PINs, mailbox passwords and OAuth tokens are not saved. The imported Google Desktop client JSON is stored with owner-only access as `google-client.json` and is excluded from source control.

Use **Update token certificate email** to issue new local test certificates for your saved token profiles without replacing their keys. Both the subject CN and email (`rfc822Name`) SAN use the entered address. Each profile requires a signing-certificate signature and an encryption-certificate signature, with one PIN prompt each. Existing identities are retained. The new selected profile is also set as your self-test recipient and pinned signer. Export certificates with a `.pem` filename for PEM or `.cer` for DER. Certificate reissuance does not write certificates to the token or publish them online.

## Optional encryption and contact certificates

Outgoing mail is always signed. In Compose, **Sign with** selects your saved signing identity (pure or hybrid). **Encrypt to** selects a saved recipient encryption certificate when optional encryption is enabled; its label includes the mailbox, algorithm and fingerprint prefix. These two choices are independent. Signing contacts in the certificate manager are verification pins, not your outgoing private-key identities. **Also encrypt for recipient (optional)** is off by default. Signed-only mail needs no recipient certificate. Turning encryption on requires a supported encryption certificate whose email SAN matches the To address. Address mismatches are reported before requesting a PIN or SMTP credentials; the app never silently downgrades an encrypted send.

The **Certificates** tab saves contacts' signing and encryption certificates separately. Import `.pem` or `.cer`, inspect the email/algorithm/fingerprint and confirm trust. The import checks validity, email SAN and key usage; encryption certificates must use a supported ML-KEM profile. If a certificate has several email SANs, choose the contact address. Multiple certificates for one mailbox can coexist.

**Use selected certificate** makes an encryption certificate the current recipient, fills the To address and enables encryption. For a signing certificate it selects the exact certificate pin used by the reader; it does not change your own signing identity. There is one active signer pin at a time. **Details** shows subject, issuer, SANs, validity and full SHA-256 fingerprint. **Export** writes PEM or DER according to the filename extension. **Remove** removes it from active contacts and clears a matching active pin/recipient; the public files are retained under `removed-contacts` for recovery by reimport. Removing a contact never deletes a token key or your own identity.

## Ten-message inbox

Select **Inbox → Connect IMAP** for a TLS server (usually port 993). The app opens `INBOX` read-only and lists up to ten newest arrivals by IMAP sequence, newest first. This is arrival order, not a global sort by the sender-controlled Date header. Only headers are initially loaded. Double-click or select **Open selected message** to retrieve the selected body (20 MiB limit). Refresh updates the list. A disconnected/stale session requires reconnecting. No delete, move, flag changes, or background polling is implemented.

Plain-text unsigned mail is explicitly marked unverified. HTML is not rendered and attachments are not displayed. Supported S/MIME mail goes through the existing signature verification and authenticated decryption pipeline; the YubiKey PIN is requested when needed. Outer headers are unprotected. Select the matching saved encryption identity before opening encrypted mail.

## Google OAuth client setup

1. Open [Google Auth Platform](https://console.cloud.google.com/auth/overview) and choose/create a Google Cloud project.
2. Configure **Branding** with an app name and support/developer email.
3. For a personal account, choose an **External** audience. Keep the app in testing and add the intended Gmail account as a test user.
4. Add `https://mail.google.com/` under **Data Access**. Google requires this full-mail scope for IMAP/SMTP; review its broad permissions at consent. Workspace policies may restrict access.
5. Under **Clients**, create an OAuth client of type **Desktop app** and download its JSON. A Web application client is not accepted. No deployed web redirect is needed: the app uses a temporary loopback IP port.
6. In **Inbox**, import the JSON with **Import Google OAuth client**. If JSON download is unavailable, choose **Enter Google client credentials** and paste the full Client ID plus Client secret into its masked field. Both methods save the same local client configuration. Then choose **Sign in with Google**. Enter the test email and complete Google's consent in the system browser. Cancel is available in the app.
7. Choose **Connect Gmail**. This uses `imap.gmail.com:993` over TLS with XOAUTH2. For sending, choose **Compose → Send via SMTP → Google OAuth**; this uses `smtp.gmail.com:587` with required STARTTLS and XOAUTH2.

Tokens stay in memory. Sign in again after expiration or restarting the app. **Sign out of Google** clears the local token and disconnects the inbox; it does not revoke the grant at Google. You can revoke it through your Google account's third-party connections. Never commit the downloaded client JSON, access tokens or account passwords.

Signing certificates must contain the actual From mailbox in their email SAN. Encryption recipients must match the To mailbox. The original `beta0@example.test` certificates cannot sign mail with a Gmail From address; reissue local test certificates first, retaining the same keys.

Google setup and permission policies may vary by project/account. Live Gmail OAuth sign-in and IMAP inbox listing were observed in the packaged app. SMTP submission remains separately dependent on account policy and user confirmation; software tests do not establish live delivery. Sending still requires an explicit app confirmation.

References: [Google desktop OAuth](https://developers.google.com/identity/protocols/oauth2/native-app), [Gmail XOAUTH2](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol), [Angus OAuth2](https://eclipse-ee4j.github.io/angus-mail/docs/api/org.eclipse.angus.mail/org/eclipse/angus/mail/imap/package-summary.html).
