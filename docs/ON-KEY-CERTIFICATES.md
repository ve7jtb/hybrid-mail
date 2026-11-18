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

## Save and import

Desktop: **Keys → Save certificates on YubiKey… / Import certificates from
YubiKey… / Migrate signing key 9a → 83…**.
Android: the same actions are under **Identities & certificates**.
iOS: **YubiKey credentials**. Hardware actions require a build with the relevant
NFC or smart-card entitlements; the software-only iOS preview cannot use them.

Select a saved YubiKey identity before saving. The bundle includes both pure and
hybrid signing/encryption X.509 certificates, serial and role-to-slot mappings,
and any existing supported OpenPGP public identity. OpenPGP packets are preserved,
including timestamps, self-signatures and subkey bindings; fingerprints do not
change. Create/import the OpenPGP identity first if it should be portable. Current
OpenPGP support is the Level 3 hybrid draft profile. SAN email addresses remain in
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

## Migration and recovery

Migration moves the existing ECDSA key internally from `9a` to **empty `83`**;
both a key and a certificate in the destination cause refusal. It requires
management-key authentication, verifies the destination public key and PIN/touch
policies, copies any standard slot certificate and removes its old copy only
after verification. It does not generate, export or replace a private key.
A public local backup is saved before attempting the move. PQ Mail updates its
local mappings; **save the on-key bundle again afterward** to persist the new map.
No hardware migration is performed merely by installing the update.

A transport failure after MOVE has an uncertain outcome. Do not provision or
replace keys to recover. The migration action can recover local mappings if `9a`
is absent and all expected public keys match the map using `83`, without sending
another MOVE. Likewise, on-key import can review/recover an old signed `9a` map
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

Updates write/read-back the inactive bank and commit its manifest last. The older
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
Physical Beta0 writes/migration and NFC capacity/latency still require a user-run
hardware test. Do not describe software/emulator results as hardware validation.
