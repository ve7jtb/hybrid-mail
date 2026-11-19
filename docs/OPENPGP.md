# OpenPGP preview

PQ Mail supports signed and optionally encrypted PGP/MIME. Experimental NIST/Brainpool draft Level 3 hybrid OpenPGP is available on desktop (macOS, Windows, Linux), Android and iOS. Level 5 classical P-384 OpenPGP is available on desktop and Android only. This bounded preview does not claim compatibility with every OpenPGP client.

## Supported profiles

| Identity selected in PQ Mail | OpenPGP profile | Token operations |
|---|---|---|
| Level 3 hybrid | Experimental [draft-05](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-nist-bp-comp-05): ML-DSA-65 + ECDSA P-384 (41), ML-KEM-768 + ECDH P-384 (37) | 9c + 83 signing, 9d + 82 decryption for newly provisioned keys |
| Level 5 hybrid | [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) v6 ECDSA P-384 (19), ECDH P-384 (18); **classical, not post-quantum** | 83 signing, 82 decryption; no ML-DSA or ML-KEM private operations |

Explicit saved legacy slot mappings remain honored. Level 5 pure/hybrid **S/MIME** remains unchanged; selecting classical OpenPGP does not change or replace keys. Pure-only certificates lack the classical public keys needed for this profile. Level 2 and pure-only identities remain S/MIME-only. The draft's PQ Level 5 profile needs P-521 and is not implemented by this P-384 option.

Both supported profiles use authenticated SEIPDv2 message encryption with AES-256; GCM and OCB are supported. Classical v6 P-384 ECDH uses the RFC-required SHA-384 KDF and AES-192 key wrap. S/MIME composite signatures and OpenPGP signatures use different encodings and domain separation.

## Getting started

1. Select a Level 3 hybrid identity, or a Level 5 hybrid identity on desktop/Android, with its software keys or matching public YubiKey certificates.
2. Open **OpenPGP** on desktop or **OpenPGP public identities** on Android.
   On iOS use the OpenPGP public-identity controls in local mail.
3. Create your OpenPGP public identity, or import its existing `.asc` file.
   Creation signs its key bindings with the selected OpenPGP profile. New desktop YubiKey provisioning and Android issuance for existing keys offer this by default, with an opt-out. Level 5 clearly labels the choice as classical P-384.
4. Export the public `.asc` file. Exchange it with correspondents and compare
   fingerprints through a trusted channel. Import recipient and signer public
   identities before encrypting or verifying their messages.
5. Select **OpenPGP** in Compose. Encryption is optional. Save/open `.eml`
   files; desktop and Android can also use their existing send/receive paths.
   iOS currently works with local files only.

For a self-test, choose your own public identity as recipient and verifier.
For another installation, transfer the same public `.asc` identity together
with the matching password-protected software `.p12` or public YubiKey
credential bundle. A new OpenPGP identity can have a different fingerprint
even when backed by the same keys. Importing your own public identity checks
that its keys and email match the selected credential.

## Certificate changes and on-key backups

After creating an OpenPGP identity, choose **Back up certificate bundle to YubiKey…**. Desktop credential creation and email/SAN updates offer **Back up now / Not now**; Android certificate issuance offers a backup or later choice. Backup rebuilds the signed public bundle from the selected email/SAN profile set and includes both S/MIME profiles, the saved OpenPGP public identity, serial and slot mappings. It does not generate new private keys.

On another installation use **Restore certificate bundle from YubiKey…** (Android adds **— no PIN**). File-based `.pqcert` import is separately named **Import certificate bundle from file…**. That older file-sharing format carries X.509 certificates and mappings; use the on-key bundle or transfer `.asc` separately for OpenPGP.

When the primary email stays the same, desktop SAN updates preserve the existing OpenPGP public identity and its fingerprints. Changing the primary email creates new OpenPGP certifications if enabled. Additional S/MIME SAN addresses are not automatically added as OpenPGP user IDs; this preview uses one email user ID.

An iOS build cannot currently restore a Level 5 bundle containing classical P-384 OpenPGP. Level 3 hybrid bundles remain supported. See [on-key storage and recovery](ON-KEY-CERTIFICATES.md).

## Private keys and trust

Software private keys remain in the password-protected `.p12`. Hardware
operations use the existing PIV keys: bundled PKCS#11 on desktop, YubiKit on
Android, and YubiKit transport/raw PIV on iOS. No OpenPGP applet provisioning
is required. The host performs public-key encryption and the hybrid combiner;
the YubiKey performs private-key signing, decapsulation and ECDH.

An operation reuses its entered PIN across its components, then clears the
operation cache. PINs are not saved. Public `.asc` files contain no private keys.
Import verifies the public identity's self-signatures and key bindings, but
does **not** establish ownership or trust. S/MIME certificate fingerprint trust
does not automatically transfer to OpenPGP identities.

## Current limits and validation

Only plain-text mail, one recipient, one email user ID and the profiles above are supported. Attachments remain available through S/MIME. There is
no OpenPGP secret-key import/export, compression, general legacy-key support or
general-purpose OpenPGP keyring/trust-management implementation.

Validation includes published draft vectors, signature/ciphertext tampering,
software and simulated hardware round trips, JavaMail serialization, Android
emulator instrumentation and bidirectional Java/OpenSSL message exchange.
A Level 3 hybrid USB round trip was reported successful by the tester, without a persisted hardware report. Classical P-384 hardware testing, OpenPGP NFC testing and Windows runtime testing remain pending. S/MIME hardware passes are not OpenPGP validation.

Run `./build.sh test` for Java tests. Android's
`OpenPgpAndroidTest` and `YubiBackendTest` run through
`./android/gradlew -p android :app:connectedDebugAndroidTest` with an emulator
or device. See [the iOS guide](../ios/README.md) for OpenSSL framework setup and
Swift tests. Cross-platform fixtures must be generated locally: they contain
temporary software private keys and must not be published as user credentials.

Independent classical interoperability checks are in `tests/java/dev/hybridmail/ClassicalOpenPgpTest.java`. After building the app classes, run `BCPG_JAR=/path/to/bcpg-jdk18on-1.81.jar bash scripts/test-classical-openpgp.sh`. The routine OpenPGP regression also checks classical software/token-adapter round trips and confirms that classical mode makes no ML-DSA/ML-KEM calls.

## RFC 9980 certificates with extra YubiKey keys

The desktop OpenPGP tab now offers **Create RFC 9980 OpenPGP identity from YubiKey…**
for the Level 3 (middle parameter set) hybrid identity. It reuses ML-DSA-65 in
9c and ML-KEM-768 in 9d, plus separately provisioned Ed25519 in 84 and X25519
in 85. It creates a v6 ML-DSA-65+Ed25519 primary key (algorithm 30), certified
email UID, and bound ML-KEM-768+X25519 encryption subkey (algorithm 35).
The three certificate signatures require both signing components. Private keys
never leave the device. The previous local OpenPGP certificate is retained as a
fingerprint-named `.backup` file; it remains a different identity/fingerprint.

After creation, choose **Back up now** to store the new public certificate with
both S/MIME profiles in the signed on-key bundle. For RFC 9980 records, the
bundle mapping fixes the additional signing/decryption slots to 84/85; backup
and restore check their public keys against the card. The S/MIME mappings in
82/83 are unchanged. Restoring over a previous local OpenPGP identity preserves
that previous certificate as a backup. Older builds that do not understand
algorithms 30/35 reject the bundle; update the receiving app before restoring.
Android now restores these bundles and uses the extra keys through YubiKit over USB/NFC. iOS support for these extra keys remains pending.

Validation includes RFC 9980 Appendix A.3 public certificate and detached
signature vectors, simulated-token PGP/MIME round trips, and bundle restoration
with wrong/missing extra-slot rejection. Desktop hardware certificate signing, encrypted-message round trip, bundle backup and fresh restoration passed on the test YubiKey. Android emulator protocol tests passed; physical Android NFC validation remains pending.

## V4 recipients and incoming signatures

Compose signs outgoing mail only with a supported hybrid PQ identity. Selecting OpenPGP uses the To mailbox to find recipient certificates on keys.openpgp.org. The lookup is visible in Compose, is read-only, and does not mark a key trusted. Encryption stays unavailable without a matching current encryption key; the recipient-key selector shows only that mailbox’s usable keys and their actual classical algorithm or hybrid KEM. Changing To invalidates in-flight results and disables encryption until a new key is available and the user enables it. Imported keys can be used offline.

V4 certificates are receive/encrypt-to identities, never outgoing signers. Supported verification algorithms are legacy Ed25519, ECDSA and RSA 2048+ with SHA-2. Multiple self-certified email UIDs and subkeys are supported; revoked, expired, unbound, future-dated and unsupported critical signatures are rejected. Signing subkeys require a valid back-signature. Designated revocation keys are currently unsupported and such certificates are rejected. SHA-1 document/certification signatures, cleartext-signed messages and DSA/ElGamal are unsupported. Key validity is checked at use; historical signatures under an expired key are conservatively rejected.

PGP/MIME detached signatures and bounded compressed one-pass signed payloads can be verified. Classical encryption uses the current bound RSA/ECDH subkey, AES-256 (or AES-128 according to preferences), v3 PKESK and v1 SEIPD/MDC. It does not downgrade outgoing signing: the inner signature remains hybrid. A legacy-only recipient can decrypt the envelope but needs hybrid support to verify that signature. Confirm fingerprints independently; successful cryptographic verification does not establish identity trust.

Classical-only encryption requires an **Encrypt anyway** confirmation, and valid classical-only signatures carry a **not post-quantum resistant** warning. These warnings also apply to conventional S/MIME. A hybrid signature containing ML-DSA or a hybrid KEM containing ML-KEM does **not** get the corresponding warning. Signing and encryption are assessed independently; a hybrid signature does not upgrade classical ciphertext protection. Trust and post-quantum algorithm status are separate.

### Saved OpenPGP contacts and trust (desktop)

Imported sender/recipient keys and successful Compose keyserver lookups are saved as **untrusted OpenPGP contacts** in Certificates. They survive app restarts and can be used offline. Choose **Details**, **Use selected certificate**, **Export**, or **Remove** just as for S/MIME contacts. Earlier session-only imports must be imported or looked up once again. Your own identity certificates remain in their existing identity storage.

**Mark trusted** requires explicit confirmation of the contact email and **entire primary-key fingerprint**, checked independently with its owner. Trust is scoped to that email/fingerprint pair, including valid bound subkeys; it does not transfer to another email or replacement primary key. A refreshed valid certificate with the same primary fingerprint retains that pair’s trust. **Remove trust** persists across restarts. Removing the contact also removes its trust and retains its public certificate in `removed-contacts`. Trust does not bypass certificate validation or suppress classical-only algorithm warnings.

Read & verify reports the saved trust decision for the actual From mailbox only after signature validation and a matching certified email. Saved contacts can supply incoming verification keys after restart; if an encrypted message has multiple matching signer certificates, select one explicitly before decrypting to avoid repeated token operations.

**Choosing trusted OpenPGP email addresses:** In Certificates, select an OpenPGP contact and choose **Mark trusted…**. The dialog lists every currently validated, self-certified email address, shows the full primary-key fingerprint, and provides **Select all email addresses**. Existing trust choices and the selected contact are checked initially. **Save trust choices** trusts checked addresses and removes trust from unchecked addresses for this primary key; selected aliases are added to Certificates. **Cancel** saves nothing. This covers valid signing and encryption subkeys bound to that primary key, while retaining expiry, revocation, usage checks and classical-algorithm warnings.
