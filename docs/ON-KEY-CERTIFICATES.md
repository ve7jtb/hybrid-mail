# Portable YubiKey identities

PQ Mail can save its public identity material on the YubiKey and import it on
macOS, Windows, Linux, Android and iOS. Private keys remain in PIV. This is an
application-specific format, not a PIV, S/MIME or OpenPGP standard storage format.

## Keys and compatibility

New desktop provisioning creates four keys in `9c` (ML-DSA), `83` (ECDSA), `9d`
(ML-KEM) and `82` (ECDH), for any of the three security profiles. Pure and hybrid
certificates share these keys. Existing saved credentials retain their explicit
slot mappings; legacy records without mappings still mean `9a`, not `83`.
Android/iOS do not gain key generation from this feature. They import/use existing
keys. Android certificate issuance detects `83`, falling back to an existing
`9a` only when `83` has no key. Slot `81` is the PUK reference, not a key slot.

## Back up, restore, or import from file

Desktop **Keys** and Android **Identities & certificates** offer:

- **Back up certificate bundle to YubiKey…**: rebuild and sign the current public bundle, write it to custom PIV data objects, and verify read-back.
- **Restore certificate bundle from YubiKey…** (Android adds **— no PIN**): read, validate, review and restore local identities and slot mappings.
- **Import certificate bundle from file…**: choose an existing `.pqcert` file; this is separate from reading a key.
- **Forget YubiKey identity…**: remove one local identity, its certificate files, slot mappings and saved OpenPGP identity. No token connection is made. Other profiles, software `.p12` files and contact trust remain; on-key data is not erased.

iOS has backup/restore controls under **YubiKey credentials**, requiring the appropriate NFC or smart-card entitlements. The migration action has been removed from all interfaces. Saved mappings and recovery checks remain supported.

After desktop credential creation or email/SAN updates, a **Back up now / Not now** prompt lets the user back up the new certificates or defer. Android certificate issuance offers the same backup choice. The review identifies the certificates, serial, slot mappings and saved OpenPGP content. Backup is a separate authenticated operation; choosing Not now leaves the previous on-key bundle unchanged.

Select a saved YubiKey identity before saving. The bundle includes both pure and
hybrid signing/encryption X.509 certificates, serial and role-to-slot mappings,
and any existing supported OpenPGP public identity. OpenPGP packets are preserved,
including timestamps, self-signatures and subkey bindings; fingerprints do not
change. Create/import the OpenPGP identity first if it should be portable. Desktop/Android support the Level 3 hybrid draft and Level 5 classical P-384 OpenPGP profiles. iOS supports Level 3 only and rejects Level 5 bundles containing classical OpenPGP. SAN email addresses remain in
the certificates. Current demo certificates are self-signed; arbitrary CA chains
and mail-server preferences are not included.

Saving signs the bundle (preferring the hybrid signing profile), verifies that
signature, checks the card serial and all component public keys, then requires
management-key authentication to write public PIV objects. The signing PIN and
management key are different credentials. Android/iOS may require removing and
re-tapping the NFC key between signing and writing; follow the prompts and keep
contact during each operation. Public reads need no PIN.

Import validates the signature and OpenPGP bindings and checks all public keys
against the connected card before offering review. Confirm the displayed serial,
algorithms, emails and fingerprints, then import. It never automatically trusts
incoming senders. No PIN, PUK, management key, private key, password, OAuth refresh
token, executable adapter path or imported trust decision is in the bundle.
Anyone with access to the key can read the public certificates and email addresses.

## Completed migration and legacy recovery

The test keys have completed the 9a-to-83 migration, so there is no longer a migration button. The earlier guarded migration moved the existing ECDSA key internally, preserving its public key and PIN/touch policies; it required an empty destination and management authentication. No migration happens when installing an update or restoring a normal bundle.

A transport failure after MOVE has an uncertain outcome. Do not provision or
replace keys to recover. The retained recovery code recognizes matching public keys in `83` when `9a` is absent. On-key restore can review/recover an old signed `9a` map
when that exact key is now in `83`; the review explicitly identifies this change.
If certificate copying failed after the move, a standard slot certificate may
still need administrator repair. Existing S/MIME certificates and OpenPGP public
identities retain their keys and fingerprints.

## Binary format and interruption handling

All integers are unsigned big-endian. All blobs have a four-byte byte length.
The maximum signed bundle is 65,536 bytes, with 1–16 profiles; both pure and hybrid
must be present and share a consistent key/slot set.

* Payload: eight ASCII bytes `PQMAILB1`, profile count (u32), then each profile:
  serial (u32), four one-byte slots (ML-DSA, ECDSA, ML-KEM, ECDH), signing DER blob,
  encryption DER blob, binary OpenPGP public-packet blob (zero length if absent).
* Signed envelope: `PQMAILS1`, payload blob, signer profile index (u32), signature
  blob. Signature algorithm comes from that profile's signing public key and signs
  the entire payload, including its domain marker. Readers reject unknown profiles,
  trailing bytes, conflicting mappings, malformed lengths and invalid signatures.
* Application-private object banks: manifest at `0x5F5000` / `0x5F5100`, chunks
  at base+1 through base+32. These tags are a PQ Mail convention, not registered
  Yubico assignments. Unexpected existing objects cause refusal, not overwrite.
* Manifest: `PQMIDX01`, generation (u64), envelope length (u32), SHA-256 (32 bytes).
* Chunk: `PQMCHK01`, generation (u64), zero-based index (u32), up to 2,048 bytes.
  An object is at most 2,068 bytes. Reads validate length, generation, digest and
  signature. Transport errors are not treated as missing objects. Android NFC
  bounds GET DATA and its GET RESPONSE continuations to 240 response-data bytes,
  below the observed Pixel 10 truncation boundary; USB behavior is unchanged.

Updates write/read-back the inactive bank and commit its manifest last. Previous-bank and unused chunk contents can remain publicly readable; saving is
not a secure-erase operation. The older
bank remains available after a failed write, including a torn new manifest. The
signature provides integrity/key binding, not external trust or rollback
protection. Shared device capacity can still reject a write; no claim of an atomic
PIV PUT DATA operation or fixed available capacity is made. Test bundles with four
certificates occupy about 19 KiB (Level 2), 38 KiB (Level 3 including OpenPGP) and
33 KiB (Level 5); retaining two banks needs approximately twice that plus other
objects on the key. Actual certificate sizes and free capacity vary.

## Validation

Tests cover all three profiles, Java/Swift signed-bundle interoperability,
OpenPGP preservation, tampering, namespace collisions, wrong keys/serials,
interruption at every chunk/commit write, and occupied-destination refusal.
On November 18, 2026, a physical Beta0 key passed macOS backup/read-back of a 24,434-byte Level 3 bundle, clean-state import/restart/duplicate import, and a guarded 9a-to-83 move. Public-key metadata and certificates were compared before/after: only the requested key location changed. Pixel 10 restored the refreshed bundle over NFC, updating both saved profiles to 9c/83/9d/82, then passed pure and hybrid NFC S/MIME signing/decryption. One pre-PIN metadata-read retry during hybrid decryption recovered. This does not establish that Pixel 10 NFC reliability issues are resolved.

That physical bundle had no saved OpenPGP identity. Classical P-384 OpenPGP bundle preservation is software/emulator-tested; physical transfer and iOS storage testing remain pending. Java/Swift interoperability results cover the earlier shared formats, not the new Level 5 classical OpenPGP payload.

## Compressed on-key storage

New backups on desktop (macOS, Windows and Linux), Android and iOS store the signed envelope in `PQMZIP01`: eight ASCII magic bytes, a big-endian u32 uncompressed length, and exactly one RFC 1950 zlib stream. The manifest size and SHA-256 cover the stored compressed representation. After decompression, the original bundle signature and all supported certificate/key bindings are still verified. Both stored and expanded data are limited to 65,536 bytes; malformed, truncated, trailing and oversized compressed streams are rejected. Compression does not change certificate fingerprints or trust. File sharing/export formats are unchanged.

New writes always use compression. Uncompressed banks remain readable temporarily so the two test keys can migrate safely; remove that migration reader only after both compressed backups have passed restore verification. An interrupted write never triggers automatic key generation or deletion of the previous committed bank. The desktop recovery tool can reclaim obsolete PQ Mail tail chunks only after verifying a complete committed bundle.

The compression format is shared across clients, independently of their supported certificate profiles. iOS also restores B2 bundles with separated RFC 9980 certification keys and both v4 compatibility views. It verifies certificate signatures, signing-subkey cross-certifications, PQ message-key bindings and the additional public keys in slots 84–89, persists all three public certificate views, and preserves them on backup. This supports certificate restore/export and S/MIME; RFC 9980 OpenPGP message signing/decryption is not yet enabled on iOS. Physical iPhone restore testing remains pending.

Validation includes Java/Swift compression exchange in both directions, all three security profiles, interrupted writes, bounded decompression and malformed streams, plus Android emulator storage tests. Level 5 macOS backup, read-back verification and fresh-state restore passed on November 19, 2026, including the v4 P-384 compatibility certificate and hybrid/classical encryption paths. All nine existing public keys and their policies were unchanged. This does not establish physical Android/iOS compatibility with that Level 5 profile or completion of the separate Level 3 certification-key migration.
