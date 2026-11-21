# Proposed Level 3 PRF-protected companion for YubiKey 5.8

**Design proposal — not implemented or provisioned.** This profile would let a
YubiKey 5.8 participate in RFC 9980 Level 3 OpenPGP using hardware classical
components and software post-quantum components. It does not turn the device
into an ML-DSA/ML-KEM implementation. No keys, passkeys, policies, or card objects
have been created or changed for this proposal.

## Components

| Role | Algorithm | Custody |
| --- | --- | --- |
| Certification primary, PQ component | ML-DSA-65 | Independent 32-byte seed in encrypted companion |
| Certification primary, classical component | Ed25519 | Generated on device; PIN Always, Touch Always |
| Message signing, PQ component | ML-DSA-65 | Different independent 32-byte seed in encrypted companion |
| Message signing, classical component | Ed25519 | Separate device key; PIN Always, Touch Always |
| Message decryption, PQ component | ML-KEM-768 | Independent 64-byte seed in encrypted companion |
| Message decryption, classical component | X25519 | Generated on device; PIN Always, Touch Always |

The resulting v6 certification and signing keys use ML-DSA-65 + Ed25519, and
the encryption subkey uses ML-KEM-768 + X25519. Certification and message signing
remain separate logical keys. Each seed is generated with a cryptographically
secure host random generator; storage of a seed does not reduce the entropy
required by the algorithm. Expanded PQ private material exists only during use.

Hardware slots must be explicit references in a versioned, authenticated role
manifest. This proposal deliberately assigns no slot numbers: the selected
layout must accommodate the card's capabilities and confirm each selected slot
is empty before generation. Existing keys must never be moved or overwritten
implicitly. Optional v4 compatibility credentials would require separately
specified classical keys and certificate views; they are not implied here.

Yubico documents Ed25519/X25519 support in firmware 5.8 and describes PIN/touch
policies as properties set at generation/import, not settings that can later be
changed in place. [PIV capabilities](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html),
[PIN and touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html).

## Encrypted seed container

The proposed inner container is an **empty-password PKCS#12** carrying only the
three PQ private seeds and the public material needed to validate their roles.
The final profile must specify exact private-key encodings, seed lengths,
algorithm identifiers and bag names; provider-specific defaults are not an
interoperability contract. The empty password is not a security boundary.

1. Generate an independent random 32-byte content-encryption key (DEK).
2. Encrypt the PKCS#12 with AES-256-GCM under that DEK, using a fresh nonce and
   authenticated metadata binding the envelope, profile, roles and public keys.
3. Obtain a 32-byte WebAuthn PRF output from a registered credential with user
   verification and user presence. Derive a wrapping key (KEK) using HKDF-SHA256
   with a fresh salt and an explicit companion/key-wrap domain separator.
4. Wrap the DEK with AES-256-GCM under the KEK using a separate fresh nonce and
   authenticated credential/envelope metadata. Persist only the encrypted
   PKCS#12, wrapped DEK, authentication tags and public restore metadata.

There is no saved PKCS#12 password, plaintext seed file, persisted PRF output,
or plaintext DEK/KEK cache. Domain separation must distinguish companion
wrapping from PQ Mail vault access even if the same passkey is enrolled for
both purposes. Multiple explicitly enrolled authenticators could have separate
DEK wraps; they must not cause copies of the private seed material in plaintext.

The exact domain strings, canonical encoding, nonce rules, size bounds and
signature coverage remain to be finalized and tested before implementation.

## Portable restore and authorization

A portable bundle needs the RP ID, credential ID, credential public key,
PRF input salt, HKDF salt, wrapped DEK, algorithm/profile identifiers, hardware
key references, component public-key hashes and authenticated envelope bindings.
These fields are public metadata, not substitutes for the authenticator secret.
Device serial numbers may help selection but are not cryptographic proof that
the correct card or FIDO credential is present.

A receiving client would validate the envelope and public component bindings,
select the registered credential, request a fresh challenge-bound assertion,
and verify the expected RP/credential plus UP and UV results before deriving
the KEK. Native CTAP and browser WebAuthn clients must agree on the exact PRF
input transformation; the WebAuthn PRF input cannot simply be treated as a raw
CTAP hmac-secret salt. The final profile must fix this transformation so the
same credential yields the same wrapping key across implementations.
[WebAuthn PRF processing](https://www.w3.org/TR/webauthn-3/#prf-extension).

Registration should first offer discovery and enrollment of an existing
eligible credential. Creating a new credential must use a distinct user handle
and must not overwrite another instance's credential. Firmware 5.8 supports
`hmac-secret-mc`, allowing derivation during credential creation where the client
supports it; existing credentials use an assertion. [Yubico PRF support](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Pseudo-Random_Function_PRF_Support.html).

After unwrap, the client must derive and compare all PQ public keys, verify the
certificate/component mappings and perform the requested operation. Seeds,
expanded private keys, DEK/KEK and authorization state remain operation-scoped
and are cleared on completion or failure. Public certificates can be cached;
private material cannot. Runtime copies, swap and crash dumps remain residual
host-exposure risks despite best-effort clearing.

FIDO authorization and PIV signing/decryption are separate operations. Requiring
Touch Always for the hardware keys may entail another touch after the PRF
unlock; this design does not promise a single touch or weaken card policy.
Deleting the FIDO credential or resetting FIDO would destroy access to its DEK
wrap. Recovery therefore requires another explicitly enrolled authenticator or
an independently protected backup, not a hidden password fallback.

## Security boundary

The **message algorithms** are the Level 3 hybrid combinations. That label does
not assert Category 3 protection for storage, transport, firmware, host memory
or the complete system.

PRF-derived symmetric wrapping avoids making the PQ seeds recoverable solely
by breaking a public classical wrapping key. Wrapping these seeds only with
P-384 or X25519 would allow a future quantum attacker with the encrypted
companion and public wrapping metadata to recover the PQ private components as
well as attack the classical message components. This is why the proposed
profile uses PRF wrapping instead of the existing Level 5 companion's
classical-only wrapping arrangement.

PRF does not remove every quantum exposure: CTAP hmac-secret transports its
output under a secret established using P-256 ECDH. A captured
host–authenticator exchange therefore does not have post-quantum transport
protection. The persistent PRF secret is symmetric, but that fact alone does
not establish end-to-end quantum-safe custody. A compromised host can also
capture the unwrapped seeds during legitimate use. These are design inferences
from the specified mechanisms, not claims of a demonstrated device exploit.
[CTAP 2.3, PIN/UV protocol and hmac-secret](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

## Storage budget and format version

Yubico documents 24 ordinary PIV key slots, a **51,200-byte PIV data allocation**,
and approximately 3,052 bytes per certificate on YubiKey 5 Series. Keys have a
separate fixed layout. These are documented limits, not a measurement of free
space on the attached device. The encrypted container and public certificate
bundle must be measured before any write, including object framing and recovery
requirements. [PIV storage limits](https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html).

On this firmware, PIV data allocation is **separate from FIDO credential
storage**. Compacting a PIV bundle frees PIV data space; it does not create more
passkey slots. The YubiKey 6 Beta0 shared-storage observations do not apply to
this YubiKey 5.8 model. The documented FIDO limits are 100 discoverable
credentials and a separate 4 KiB large-blob array; neither is general PIV
companion capacity. [Firmware capabilities](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-overview.html),
[FIDO storage](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html).

This is a different custody and wrapping profile from the current Level 5
`PQMCP001` full and `PQMCP002` ultra-compact companions. It requires a **new
versioned envelope/profile and role manifest**; those existing magic values,
fixed mappings and reader semantics must not be reused or silently reinterpreted.
The public certificate format remains standard OpenPGP, while the storage
profile needs independent PQ Mail/Sequoia implementation and interoperability
tests before it can be advertised as supported.

## Storage policy

Normal losslessly compressed storage is the default. Measure the complete encrypted companion, public certificate bundle and object overhead before any card write, and retain headroom for other PIV data. Offer ultra-compact self-signature reconstruction only as an explicit space-saving conversion when supported and useful. On YubiKey 5.8, this saves PIV allocation, not FIDO credential capacity; other card families can have different shared-storage rules.
