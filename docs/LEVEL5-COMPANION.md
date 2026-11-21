# Level 5 software companion (development)

The companion supplies **new** software Ed448 certification and message-signing
keys, and an X448 decryption key, for RFC 9980 Level 5 OpenPGP. Existing hardware
ML-DSA-87 keys in 86/9c and ML-KEM-1024 in 9d remain on the device. The private
software keys are in an empty-password PKCS#12, entirely encrypted using
P-384 ECDH through slot 82, HKDF-SHA256 and AES-256-GCM. There is no separately
saved password or vault entry. The public envelope is signed by slot 86 and
binds the serial, all four hardware SPKIs, the OpenPGP certificate or reconstruction template, and a component
manifest. Each application checks the certificate's cross-certification and
live device bindings before activation.

PQ Mail and Sequoia restore the same envelope. Sequoia uses its own Rust/OpenSSL
reader and crypto, not PQ Mail's Java implementation. OpenSSL converts the
inner PFX through anonymous pipes; it never receives a plaintext-key filename.
PINs are local prompts and anonymous-pipe inputs only. Each logical operation
clears its authorization and releases unwrapped software keys. Existing PIN
Always and touch policies remain enforced by the card; slot 82 avoids an extra
touch when it already has touch Never.

This is not equivalent to native Ed448/X448 hardware custody. Process memory,
provider/runtime copies, CPU caches and side channels, swap, hibernation, crash
dumps or host compromise may expose software components. Buffer clearing is
best effort, not guaranteed erasure. P-384 wrapping is classical protection at
rest; message algorithms retain their ML-DSA-87/ML-KEM-1024 components. See the
[draft's custody comparison](internet-drafts/draft-bradley-pqmail-certificate-bundle-00.html#custody-tradeoffs).

## Storage and recovery

The public certificate bundle stays unchanged. The companion has one separate
bank: manifest `5f5200`, chunks `5f5201`–`5f5220`. The manifest is `PQCIDX01`,
a 32-bit big-endian length, and SHA-256 of the complete stored representation.
Each chunk is `PQCCHK01`, a 32-bit index, and at most 2048 bytes. These are local
application conventions, not assigned PIV object identifiers.

The stored representation is `PQMCZ001`, a 32-bit big-endian expanded length,
and exactly one zlib stream containing the signed encrypted envelope. The
stored and expanded lengths are each limited to 65,536 bytes; the expanded
length must be nonzero and match exactly. Readers reject truncated streams,
trailing data, concatenated streams and nested wrappers before parsing the
inner envelope. The storage digest covers the wrapper and compressed bytes,
not the expanded envelope. Compression settings are not part of the format.

Lossless compression of a full companion preserves **every byte of the existing inner envelope**. It
removes repeated public material from the stored representation without
changing the certificate, fingerprints, component keys, signature, ciphertext,
AES-GCM AAD or key derivation. No private-key unwrap, certificate reissuance or
new signature is needed to compact an existing companion. Readers can also
accept the unwrapped envelope during local recovery and explicit compaction.

The inner envelope has two bounded u32-length-prefixed fields: signed body and
ML-DSA-87 signature. The signed body contains `PQMCP001` for a complete certificate or `PQMCP002` for an ultra-compact template, u32 serial, four DER
SPKI fields in 86/9c/9d/82 order, the binary OpenPGP certificate/template field, a UTF-8
component-manifest field, 97-byte ephemeral P-384 point, 32-byte salt, 12-byte
nonce, and the ciphertext field. Everything before the ciphertext length is
AES-GCM AAD. HKDF-SHA256 info is ASCII `PQMail companion P384 v1` followed by
SHA-256(AAD); output is a 32-byte AES key. Plaintext contains one bounded P12
field. The PFX has three named unencrypted key/certificate bag pairs, no inner
MAC, and is never deliberately persisted outside the encrypted envelope.

Normal creation accepts only an empty namespace or an exact, staged-ciphertext
resume. A different existing identity is not overwritten. Explicit compaction
must verify that expansion reproduces the existing envelope byte for byte and
save durable local copies of both representations before replacing stored
objects. Every object is read back, and the manifest commits last. Interrupted
creation or compaction retains the same software identity for explicit recovery.
The test launcher measures exact bytes and keeps a 16 KiB reserve before a first
write. No key generation/reset/policy/certificate commands occur in this flow.

## Ultra-compact storage

The optional `PQMCP002` representation retains the certificate packets and
signature metadata, but zeroes the self-issued signature values and their
2-byte digest-check prefixes and 32-byte signature salts before compression.
Salt lengths, timestamps, User IDs, preferences, restrictions, and exact
public-key packet bodies remain. Each reconstructed signature gets a fresh
random salt, following RFC 9580 Section 13.2; the zero salt is never used for signing.
The embedded signing-subkey cross-certification is treated the same way. The
outer hardware ML-DSA-87 envelope signature remains complete, so the template is
authenticated and checked against live keys before requesting private operations.

Full-certificate `PQMCP001` storage remains the default. A user can start there
and explicitly convert later if device space becomes constrained. Conversion
first validates the old certificate, unwraps the existing software components,
and re-encrypts **the same keys** with fresh wrapping randomness because the
new template changes AES-GCM AAD. It creates a new envelope signature; it does
not create replacement identity keys, alter fingerprints, or change PIN/touch
policy. This differs from lossless recompression, which needs no private
operation and preserves the original ciphertext and envelope signature exactly.

The initial ultra-compact profile supports one Level 5 algorithm-31 v6
certification primary, 1–5 self-certified email User IDs, one separately bound
algorithm-31 signing subkey with its cross-certification, and one algorithm-36
encryption subkey. It uses strict metadata allowlists, SHA-512 and fresh
32-byte signature salts at reconstruction. Unsupported packets, revocations, third-party
certifications and unknown metadata cause conversion to stop; they are not
silently removed. CA-issued S/MIME certificates and other immutable signatures
remain in full storage. This is not a general-purpose OpenPGP re-signing API.

On first restore to a host:

1. Verify the envelope, complete template structure, component mappings and
   actual card public keys before requesting a PIN.
2. Use an existing full public certificate only if its signatures validate and
   normalizing its signature values, digest prefixes and salts produces the
   exact authenticated template.
3. Otherwise, obtain PIN authorization, unwrap the software components in
   memory, and reconstruct the allowed certificate signatures. The embedded
   signing-subkey cross-certification is signed first; its enclosing binding is
   signed afterward because the regenerated embedded bytes change that digest.
4. Verify the complete result, confirm matching fingerprints and template, then
   cache only the public certificate. Clear the PIN and unwrapped private keys.

The signing subkey's existing touch policy applies during reconstruction.
Subsequent operations on that host reuse the validated public certificate;
reconstruction is needed again only if that cache is missing or no longer
matches the authenticated template. Normal message signing/decryption still
unwraps the encrypted private components for the individual operation. No
plaintext `.p12`, Ed448/X448 private key, wrapping secret or PIN is cached.

An ultra-compact template is **not a usable transferable OpenPGP certificate**
until reconstruction and verification complete. Only the reconstructed public
certificate may be exported or attached to messages. Certificate signatures
may have different bytes, although key fingerprints remain identical; a pin on
the entire certificate's hash needs separate handling. Trust is never granted
by conversion or restore.

The [Internet-Draft](internet-drafts/draft-bradley-pqmail-certificate-bundle-00.md#ultra-template)
specifies framing, placeholder positions, metadata restrictions, reconstruction
order, cache validation and recovery requirements. Actual savings are measured
for each certificate; no fixed count of additional passkeys is promised.

## Status

Software checks pass for restore, signing, decryption, tampering/wrong-card/key
rejection, every interrupted storage write, and namespace collisions. Sequoia
signed and decrypted using the synthetic fixture; PQ Mail independently verified
its signature, and Sequoia decrypted PQ Mail ciphertext.

The original companion passed a physical YubiKey 6 Beta0 test:
PQ Mail restored, signed and decrypted; the companion was backed up and freshly
restored by Sequoia; Sequoia signed and decrypted both implementations' test
ciphertexts, with independent signature verification. Before/after snapshots
matched all 24 ordinary PIV slot states, public keys and PIN/touch policies,
as well as the existing PIV certificates and public-bundle objects. Only the
separate companion objects were added.

Lossless compaction of that exact companion reduces 46,412 bytes to **39,163
bytes**, including the 12-byte compression wrapper: a saving of **7,249 bytes
(15.6%)**, and 20 data chunks instead of 23. The 31,268-byte public certificate
and all inner-envelope bytes remain identical after expansion. These are
encoded sizes. The physical lossless replacement test passed:
free storage increased from **18.0 to 25.8 KiB**, and the object count fell from
57 to 54. PQ Mail and Sequoia independently restored the smaller on-card bank,
signed and decrypted successfully, and verified each other's signatures or
ciphertexts. Expansion reproduced the complete original signed envelope exactly.
All nine hardware keys, PIN/touch policies, 24 PIV slot states, ordinary
certificates and original public-bundle objects matched their before snapshots.

Software checks include malformed/oversized/nested compression rejection,
166 injected replacement/recovery interruption points, and independent
Java/Sequoia signing and decryption. The Sequoia adapter suite passed 18 tests.
The signed macOS app was updated with the compressed reader and companion
restore flow. The lossless hardware result does not validate ultra-compact
signature reconstruction.

The ultra-compact Java suites pass reconstruction with fresh salts, preservation
of component keys and metadata, validated public-cache reuse, signing/decryption,
12 malformed authenticated-template rejection cases and 60 injected storage and
recovery interruption points. A synthetic one-User-ID fixture measured **39,134
bytes full → 15,421 bytes ultra-compact** (about 60.6% smaller); the
final two-User-ID interoperability fixture measured **43,918 → 15,431 bytes**. Randomized keys and signatures mean
individual fixture runs vary slightly. These are encoded software-fixture sizes,
not physical-device free-space measurements. **No physical ultra-compact
conversion has been performed or claimed.**

Independent Java/Sequoia ultra-compact interoperability also passed. The Rust
reader reconstructed Java's two-User-ID template through a simulated card
backend using one P-384 unwrap, five certification-key ML-DSA calls and one
signing-key ML-DSA call. A subsequent validated public-cache restore succeeded
with the private backend unavailable and no new private calls. Java validated
the Rust certificate's normalized template and fresh salts; each implementation
verified the other's signature and decrypted the other's ciphertext. These
checks do not measure physical-card timing or touch behavior.

The profile registry also names Level 3/5 NIST and native Level 5 Ed448/X448
options. Their generalized signed-manifest routing and complete selection UI
are still being implemented. No unsupported profile is silently replaced with
the companion. NIST S/MIME and experimental NIST OpenPGP encodings must not be
presented as RFC 9980 message algorithms.
