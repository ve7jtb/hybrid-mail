# Level 3 OpenPGP software-PQ companion

The desktop and Sequoia development implementations support **hardware Ed25519/X25519 with software ML-DSA-65/ML-KEM-768**. A dedicated PIN-protected P-384 key unwraps the companion without touch. Message signing and decryption still require touch through their separate hardware keys.

Status: software and physical-card interoperability tests pass.

On November 21, 2026, YubiKey 5.8 test device **40814807** passed Level 3 polyfill signing and authenticated decryption in PQ Mail and Sequoia, including signature verification and encrypted-message exchange in both directions. Fresh on-key restore matched the staged companion and recovery backup byte for byte. The companion is **34,382 bytes**, occupying **34,630 bytes** across 18 card objects. Before/after snapshots confirmed that all four existing keys and their PIN/touch policies were unchanged during the successful resume/test run; other slots and ordinary PIV certificates were unchanged. Slots 82/9c (Ed25519) and 9d (X25519) retain PIN Always/Touch Always; wrapping slot 83 (P-384) retains PIN Always/Touch Never. Restore persisted only public material and encrypted companion data and did not grant contact trust.

## Key layout and authorization

| Slot | Hardware key | Role | PIN policy | Touch policy |
| --- | --- | --- | --- | --- |
| 82 | Ed25519 | Classical component of certification primary | Always | Always |
| 9c | Ed25519 | Classical component of signing subkey | Always | Always |
| 9d | X25519 | Classical component of encryption subkey | Always | Always |
| 83 | P-384 | Dedicated companion wrapping key | Always | Never |

The companion holds three independent private seeds: ML-DSA-65 certification (32 bytes), ML-DSA-65 signing (32 bytes), and ML-KEM-768 (64 bytes). It contains no software Edwards keys. The OpenPGP certificate has a certification-only v6 primary, a separate signing subkey and an encryption subkey. Their algorithms are ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519. This profile does not issue S/MIME or v4 compatibility identities.

Initial certificate issuance requires several touches. A normal signing operation performs one no-touch P-384 unwrap followed by one touch-required Ed25519 signature; decryption performs one no-touch unwrap followed by one touch-required X25519 agreement. The PIN is requested once per logical operation, reused for its components, then cleared. There are no automatic retries of private operations.

Creation checks all ordinary PIV key slots and certificates before generating anything, records public keys durably, and refuses to overwrite occupied slots. Resume validates the journal, serial, public keys, algorithms and policies before continuing. Other applications, including FIDO, are unchanged. New-profile provisioning currently requires the Unix journal durability implementation; Windows can restore/use the profile but does not yet provision it.

## Desktop use

In **Keys**:

- **Create Level 3 software-PQ identity on empty YubiKey…** detects an empty compatible card, collects up to three email addresses, provisions the four keys, creates the companion, tests it and writes its single bank.
- **Resume Level 3 software-PQ setup…** uses the original setup directory after an interrupted operation. Preserve its journal and staged ciphertext; do not reset the card or restart creation.
- **Restore Level 3 software-PQ companion from YubiKey…** reads and validates public data without a PIN, displays the identity and security tradeoff for review, then saves public data and encrypted companion bytes locally. It does not grant contact trust.

Select the restored identity in Compose with **OpenPGP**. It uses v6 hybrid signatures and supports v6 recipients. Export the actual OpenPGP public certificate for contacts. The two X.509 records inside the companion are local catalog metadata only; the app refuses them as S/MIME signing/encryption credentials or trusted S/MIME contacts.

**Forget YubiKey identity** deletes the selected local catalog records and companion ciphertext. It does not erase card keys or data.

## Sequoia use

The `sequoia-pqmail-piv` adapter has a separate Level 3 companion backend. `piv-companion-restore` detects `PQMCP003` and performs full profile-specific validation; `piv-level3-companion-restore` explicitly requires this profile. Both receive the trusted local object-helper executable, device serial and a new output directory. Card metadata never selects executable paths.

```sh
piv-level3-companion-restore /path/to/hybrid-mail-provision SERIAL restored
```

Restore compares all four live public keys, validates certificate signatures, the outer hybrid signature, role manifest and catalog metadata. It writes only public keys/certificates, encrypted companion bytes and a public restore manifest. The adapter unwraps the PQ seeds in memory for each operation using the same PKCS#11 backend as PQ Mail. The standalone browser app has not been updated to offer this new profile.

## Storage encoding

`PQMCP003` is a distinct profile: it never reinterprets the existing Level 5 `PQMCP001` or `PQMCP002` formats. Normal lossless compression is mandatory for newly written companions. Ultra-compact reconstruction is not implemented for this profile.

The existing `PQMCZ001` wrapper contains a four-byte big-endian expanded length and one bounded zlib stream. Stored and expanded envelopes are each limited to 65,536 bytes; trailing, nested or oversized encodings are rejected. The decompressed envelope is `BLOB(body) || BLOB(signature)`, where each BLOB has a four-byte big-endian length.

The body fields, in order, are:

1. Eight ASCII bytes `PQMCP003`, then a four-byte big-endian device serial.
2. Four BLOBs of DER SubjectPublicKeyInfo, ordered slots 82, 9c, 9d, 83.
3. BLOB containing the complete public OpenPGP certificate.
4. Two BLOBs containing the signing and encryption X.509 catalog records.
5. BLOB containing the exact canonical role manifest.
6. Ephemeral uncompressed P-384 point (97 bytes), random HKDF salt (32 bytes), random GCM nonce (12 bytes).
7. BLOB containing AES-256-GCM ciphertext and its 16-byte authentication tag.

The AAD is the complete body prefix through the nonce, excluding the ciphertext-length field. The wrapping key is HKDF-SHA-256 of the P-384 ECDH result, with the stored salt and info `ASCII("PQMail companion L3 P384 v1") || SHA256(AAD)`, producing 32 bytes. The plaintext is one BLOB containing the empty-password PKCS#12. It has exactly three DER key bags, friendly names `cert-pq`, `sign-pq`, `kem-pq`, and seed-only PKCS#8 private keys; there are no certificate bags, inner encryption, password or MAC. The outer AEAD is its confidentiality/integrity boundary.

The outer signature is `Ed25519-signature || ML-DSA-65-signature` (64 + 3309 bytes), using the certification primary components over `SHA512(ASCII("PQMail Level3 companion signature v1") || body)`. Both signatures must validate. The canonical JSON manifest identifies version 1, the serial and profile `LEVEL3_POLYFILL`, plus ordered roles, algorithm names, storage kinds, slot references and SHA-256 public-key hashes. Readers compare it to the expected manifest derived from the validated certificate and hardware keys.

The single companion bank uses manifest object `5f5200` and chunk objects `5f5201`–`5f5220`, with 2,048-byte data chunks. The existing `PQCIDX01`/`PQCCHK01` framing commits the manifest last. Before writing, the application saves and flushes a local ciphertext recovery copy. An interrupted first write resumes only against identical staged ciphertext and matching existing chunks. The ordinary PIV certificate slots and separate public-bundle namespace are not used for duplicate copies of this profile's certificates.

## Space

Synthetic measurements with normal compression:

| Email addresses | Companion bytes (approximately) | Card objects including framing (approximately) |
| --- | ---: | ---: |
| 1 | 34,400 | 34,650 |
| 2 | 37,800 | 38,100 |
| 3 | 41,200 | 41,520 |

Exact size varies with certificate encodings and signatures and is measured before writing. The three private seeds occupy only 128 bytes; their seed-only PKCS#12 is 438 bytes. Public keys and signatures account for most storage. Setup allows at most three emails and caps card objects at 43,008 bytes, retaining an 8 KiB reserve within the documented 51,200-byte PIV data allocation.

On YubiKey 5.8, PIV storage is separate from FIDO storage. Saving PIV bytes does not free discoverable-passkey capacity. See [Yubico's PIV storage documentation](https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html).

## Security boundary

**Level 3 describes the hybrid algorithms applied to messages, not the protection of stored private keys.** This is a compatibility option for classical-only cards, not native hardware PQ custody. Breaking the classical P-384 wrapping scheme would expose the software PQ seeds in a copied companion; a future quantum attacker is therefore a material storage threat. A compromised host can capture the seeds while they are unwrapped. PIN protection and touch on the message components do not remove either limitation.

The app never intentionally saves a plaintext PKCS#12, private seed, wrapping secret or password. Implementations clear operation buffers and release/destroy provider keys on success and failure. Managed-runtime copies, provider allocations, swap and crash dumps remain possible exposure paths. Hardware quality also varies: physical protection, side-channel resistance and device random-number generation require separate assessment, including applicable FIPS 140/Common Criteria evaluations. This profile does not claim such validation.

PRF remains available for PQ Mail's settings/account vault. It is not used to wrap this companion, so no extra FIDO touch is needed for each message operation. Resetting PIV or losing the slot 83 key prevents unwrapping this companion; a copied encrypted bundle alone cannot recover it on another card.

## Validation

Automated tests cover seed-only encoding, canonical framing, wrong-key/serial and tampering rejection before PIN/private use, exact operation routing, secret cleanup, desktop restart/restore/forget, HTML PGP/MIME, and refusal of metadata carriers as S/MIME credentials. Synthetic Java and Sequoia tests verify detached and embedded signatures and signed/encrypted messages in both directions. Native fake-card tests cover slot policies, empty-card requirements and interrupted provisioning. The physical-card results above are recorded separately from these synthetic tests. Earlier attempts stopped during unwrap and management-key validation; the successful resume reused the original keys and staged ciphertext. The earlier unwrap failure was not reproduced and its cause remains unconfirmed; safe failure-stage reporting was added, and malformed management keys are now rejected before private test operations.
