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

When the primary email stays the same, desktop SAN updates preserve the existing OpenPGP public identity and its fingerprints. Changing the primary email creates new OpenPGP certifications if enabled. Complete initial Level 3 desktop setup includes all supplied email addresses as certified user IDs in its v6 and v4 views. Updating SANs on an existing identity does not automatically rewrite its OpenPGP certificates.

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

Desktop composition supports plain text or signed plain-text/HTML alternatives, with one recipient and the profiles above. The safe desktop viewer blocks images and active content. Attachments remain available through S/MIME. There is
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
with wrong/missing extra-slot rejection. Desktop hardware certificate signing, encrypted-message round trip, bundle backup and fresh restoration passed on a Level 3 Beta0 key. Android emulator protocol tests passed; physical Android NFC validation remains pending.

## V4 recipients and incoming signatures

Desktop Compose uses v6 hybrid signing unless the preferred recipient certificate is v4. That explicit compatibility mode uses the separated Level 3 identity’s dedicated Ed25519 key in slot 88, prompts about classical signing, and includes both public certificates. Other identities must first provision the required Ed25519/X25519 keys; no empty primary or substitute key is created. Selecting OpenPGP uses the To mailbox to find recipient certificates on keys.openpgp.org. The lookup is visible in Compose, is read-only, and does not mark a key trusted. Encryption stays unavailable without a matching current encryption key; the recipient-key selector shows only that mailbox’s usable keys and their actual classical algorithm or hybrid KEM. Changing To invalidates in-flight results and disables encryption until a new key is available and the user enables it. Imported keys can be used offline.

Imported v4 certificates remain public recipient/verification credentials. Desktop compatibility signing creates a separate v4 public certificate from the existing RFC 9980 Ed25519 and ML-KEM-768 + X25519 keys. Supported verification algorithms are legacy Ed25519, ECDSA and RSA 2048+ with SHA-2. Multiple self-certified email UIDs and subkeys are supported; revoked, expired, unbound, future-dated and unsupported critical signatures are rejected. Signing subkeys require a valid back-signature. Designated revocation keys are currently unsupported and such certificates are rejected. SHA-1 document/certification signatures, cleartext-signed messages and DSA/ElGamal are unsupported. Key validity is checked at use; historical signatures under an expired key are conservatively rejected.

PGP/MIME detached signatures and bounded compressed one-pass signed payloads can be verified. Classical encryption uses the current bound RSA/ECDH subkey, AES-256 (or AES-128 according to preferences), v3 PKESK and v1 SEIPD/MDC. Desktop compatibility signatures use Ed25519 only for v4 recipients. Algorithm-35 v4 subkeys use hybrid encryption with v3 PKESK; replies to the compatibility subkey can be decrypted with the existing RFC 9980 identity. Confirm fingerprints independently; successful cryptographic verification does not establish identity trust.

Classical-only encryption requires an **Encrypt anyway** confirmation, and valid classical-only signatures carry a **not post-quantum resistant** warning. These warnings also apply to conventional S/MIME. A hybrid signature containing ML-DSA or a hybrid KEM containing ML-KEM does **not** get the corresponding warning. Signing and encryption are assessed independently; a hybrid signature does not upgrade classical ciphertext protection. Trust and post-quantum algorithm status are separate.

### Saved OpenPGP contacts and trust (desktop)

Imported sender/recipient keys and successful Compose keyserver lookups are saved as **untrusted OpenPGP contacts** in Certificates. They survive app restarts and can be used offline. Choose **Details**, **Use selected certificate**, **Export**, or **Remove** just as for S/MIME contacts. Earlier session-only imports must be imported or looked up once again. Your own identity certificates remain in their existing identity storage.

**Mark trusted** requires explicit confirmation of the contact email and **entire primary-key fingerprint**, checked independently with its owner. Trust is scoped to that email/fingerprint pair, including valid bound subkeys; it does not transfer to another email or replacement primary key. A refreshed valid certificate with the same primary fingerprint retains that pair’s trust. **Remove trust** persists across restarts. Removing the contact also removes its trust and retains its public certificate in `removed-contacts`. Trust does not bypass certificate validation or suppress classical-only algorithm warnings.

Read & verify reports the saved trust decision for the actual From mailbox only after signature validation and a matching certified email. Saved contacts can supply incoming verification keys after restart; if an encrypted message has multiple matching signer certificates, select one explicitly before decrypting to avoid repeated token operations.

**Choosing trusted OpenPGP email addresses:** In Certificates, select an OpenPGP contact and choose **Mark trusted…**. The dialog lists every currently validated, self-certified email address, shows the full primary-key fingerprint, and provides **Select all email addresses**. Existing trust choices and the selected contact are checked initially. **Save trust choices** trusts checked addresses and removes trust from unchecked addresses for this primary key; selected aliases are added to Certificates. **Cancel** saves nothing. This covers valid signing and encryption subkeys bound to that primary key, while retaining expiry, revocation, usage checks and classical-algorithm warnings.

### Desktop recipient preference and compatibility

PQ Mail prefers a matching v6 certificate over v4, then prefers a usable supported hybrid encryption subkey within that certificate. Classical encryption requires confirmation; no usable subkey means encryption is unavailable. V6 does not itself mean post-quantum: a classical v6 certificate still outranks a hybrid v4 certificate under this policy. Certificate import or receipt never grants trust automatically.

For v4 recipients, the desktop RFC 9980 YubiKey identity signs with its existing Ed25519 key and attaches `public-key-v4.asc` (Ed25519 primary, ML-KEM-768 + X25519 subkey) and `public-key-v6.asc` (hybrid signing/encryption). Both attachments are covered by the message signature and are inside encryption when enabled. Their fingerprints remain stable because the compatibility certificate reuses the original key creation timestamps. Public certificates are generated during composition; this does not generate token keys or write an updated on-key backup. A receiving client must support algorithm 35 to use the hybrid subkey. Proton/Thunderbird interoperability for this new outbound mode is not yet established.

Local regression tests cover v6-first selection (including classical v6 over hybrid v4), hybrid subkey preference and revocation fallback, Ed25519 certificate/message validation, both attached certificates, v3 hybrid encryption/decryption and tamper rejection, and continued v6 hybrid signing for v6 or unknown recipients. Hardware calls were simulated in these tests; no email was sent.

### Compatibility certificate views

Migrated identities attach exactly three public certificates for v4 recipients: v6, full v4 hybrid-capable, and v4 classical-only. The v4 variants share one primary fingerprint. The diagnostic signing-only attachment has been removed.

### Sequoia v6 interoperability

The desktop parser accepts RFC 9980 v6 ML-DSA-65 + Ed25519 certificates with multiple certified email user IDs, certification-only primaries, separate cross-certified signing subkeys, authentication subkeys and ML-KEM-768 + X25519 encryption subkeys. It verifies bindings, expiry and revocation before use; importing does not grant trust. Unsupported algorithms and critical extensions remain rejected. Existing PQ Mail identity generation and fingerprints are unchanged.

Local tests against Sequoia sq 1.5.0 / sequoia-openpgp 2.4.1 verified detached signatures and signed/encrypted payloads in both directions using disposable software keys. Sequoia default encrypted-message padding is accepted. RFC 9980 PQ certificates use the implicit AES-256/OCB preference when no explicit AEAD preferences are present. This tests OpenPGP cryptography and MIME payload handling, not delivery through another mail service or a new hardware run. Public regression fixtures are in `tests/fixtures/sequoia`; no private test keys are included.

### Complete Level 3 setup and recovery (desktop)

Choose **Keys → Create identity on empty YubiKey… → Level 3**. The app checks every user PIV slot and creates all ten keys in one operation. It then issues pure/hybrid S/MIME certificates and, by default, the separated v6 OpenPGP certificate plus v4 hybrid-capable and classical-only views. Uncheck the OpenPGP certificate option to defer issuance; the complete key layout is still generated. The regular OpenPGP creation action can issue the certificates later without generating keys.

| Purpose | Slots | Algorithms |
|---|---|---|
| Certification-only v6 primary | 86 / 87 | ML-DSA-65 + Ed25519 |
| Hybrid signing subkey | 9c / 84 | ML-DSA-65 + Ed25519 |
| Hybrid encryption subkey | 9d / 85 | ML-KEM-768 + X25519 |
| Classical compatibility signing | 88 | Ed25519 |
| Classical compatibility encryption | 89 | X25519 |
| Additional S/MIME hybrid components | 83 / 82 | ECDSA P-384 / ECDH P-384 |

All keys require PIN verification. Slots 9c, 9d, 86, 88 and 89 require touch; 82, 83, 84, 85 and 87 do not. The signing subkeys are cross-certified. The certification primary binds hybrid and classical subkeys. Outgoing v6 signatures remain hybrid; v4 compatibility signatures use only slot 88. V4 classical encryption uses slot 89, never the hybrid X25519 component in 85. New certificates include the primary email and additional email addresses.

After creation, choose **Back up now** to save the signed compressed certificate bundle, or **Not now** to defer. It contains the pure/hybrid S/MIME certificates, v6 and full v4 OpenPGP certificates, serial and slot mappings. The classical-only v4 view is derived without private-key access. No PINs, management keys, private keys or trust decisions are written to the bundle. Restoring does not grant trust.

**Resume interrupted setup…** replaces the old pending-certificates action. Select `setup.properties` from the saved `token-setups` directory; the failure dialog shows its path. The manifest is written before key generation, and each generated public key is saved. Recovery verifies device serial, key material, algorithms and PIN/touch policies. It reuses completed certificates, preserving fingerprints. If keys are missing, explicit provisioning authorization allows only empty target slots to be generated; an occupied slot without a recorded public key, a changed key/policy, or an unreadable slot stops recovery for inspection. Initial creation never overwrites a nonempty key.

The separate **Create / migrate v6 identity** button is removed. An unfinished older OpenPGP migration is still detected for the selected saved identity by **Resume interrupted setup…**. This recovery path checks its existing public-key journal, completes certificates/trust changes and backs up/restores the bundle without generating keys. An incomplete old key-generation journal requires inspection. Only previously trusted email/fingerprint pairs are transferred; no additional trust is granted. The previous bundle bank is retained on a failed write.

Automated tests use software keys and simulated cards: complete ten-key provisioning plans, partial-generation recovery, stable fingerprints across interrupted issuance, multiple email user IDs, v6/v4 signing and encryption, compressed bundle restoration, existing migration recovery, and rejection of unknown occupied slots and mismatched public keys. No physical provisioning was performed for this update. Earlier Sequoia tests validate the separated primary/signing structure and classical X25519 exchange.
