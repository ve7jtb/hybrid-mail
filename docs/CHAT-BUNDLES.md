# Portable OpenPGP Chat bundles

PQ Mail's experimental Chat payload is a single binary `message.pgp` file
(`application/octet-stream`), not an `.eml` wrapper around a `.pgp` file.
It uses standard OpenPGP packets and ordinary MIME. No proprietary archive or
compression algorithm is required. The transport-independent Java core is shared
by desktop and Android. The desktop app now has an experimental Google Chat connector and compose/view UI; Android does not yet have that live Chat interface.

## Wire structure

```
Optional public-key encryption (PKESK + integrity-protected SEIPD)
  OpenPGP Compressed Data packet (ZIP or ZLIB, when permitted)
    One-pass signature
    Literal Data containing the complete MIME message
    Document signature
```

The literal data includes signed From, To and Subject headers. Plain text and HTML
are `multipart/alternative`; file attachments add an outer `multipart/mixed`.
Without HTML or attachments, the MIME message is simply `text/plain`.
All alternatives, filenames and attachment bytes are inside the signature and,
when enabled, encryption. Captions and sender display names supplied by a chat
provider are outside this protection. A normal chat client shows a downloadable
file, while an OpenPGP tool can recover the MIME message without PQ Mail.

ZIP here means raw DEFLATE in an OpenPGP Compressed Data packet, not a ZIP archive.
New RFC 9980 certificates advertise ZLIB, ZIP and uncompressed support. For an
existing recipient certificate advertising only uncompressed data, PQ Mail omits
compression rather than overriding that preference. This does not change keys,
fingerprints, saved certificates or on-key backups. Signed-only bundles use ZIP.

The packet format is defined by [RFC 9580 §5.6](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.6).
The use of that file as a chat message, identity mapping and UI are PQ Mail's
integration, not a standardized chat protocol. Email continues to use PGP/MIME.

## Identity and trust boundary

`ChatBundle.create/open` implement the portable encoding and verification layer.
`GoogleChatBundles` adds the desktop experiment gate, unlocked-vault identity pin,
recipient email/full-fingerprint trust requirement for encryption, and comparison
of signed addresses with the authenticated transport account/sender mapping.
A valid incoming signature is returned separately from its local trust status;
opening a bundle does not import or trust a certificate. The receiving caller
must supply the sender's public certificate. The desktop transport can retrieve a separately attached certificate from a linked message in the same conversation by the same Google sender. It uses it as a verification candidate, never as an automatic trust grant.

Outgoing Chat currently requires hybrid v6 signing and, when encrypted, a matching
hybrid v6 recipient. Level 3 uses ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519.
Level 5 software uses ML-DSA-87 + Ed448 and ML-KEM-1024 + X448. The same external
signing/decryption interfaces support provisioned YubiKeys. The offline tests below use software-backed adapters; the live Level 3 test additionally used a real YubiKey. This implementation has one recipient. Group recipient selection, cryptographic room binding and replay detection are not implemented.

## Limits and display

- 20 MiB maximum encoded file and each decompressed OpenPGP packet stream.
- At most three compression layers; appended packets are rejected.
- Up to 20 attachments, totaling at most 10 MiB decoded.
- MIME traversal is bounded to 12 nesting levels and 100 parts.
- Plain/HTML alternatives and attachments are returned only after signature and,
  if applicable, encryption-integrity verification succeeds.
- Attachment names are reduced to safe basenames; no files are saved automatically.
- Verified HTML remains untrusted markup. A viewer must use PQ Mail's safe HTML
  renderer, not a browser with scripts or remote resources enabled.

Compression is optional confidentiality-neutral processing. For encrypted bundles,
lengths remain visible; this format should not become an automatic compression
oracle combining attacker-controlled content with hidden application secrets.

## Live Google Chat interoperability, 2026-11-20

Two-way signed/encrypted Level 3 messages passed between the installed Mac app
(personal Gmail, YubiKey PIV/PKCS#11) and the standalone gws + Sequoia tool
(Workspace, password-encrypted software identity). The incoming Mac result was
“Signature valid · Hybrid PQ · Decrypted”, with the trusted sender fingerprint
and formatted HTML. The return Sequoia result required a valid signature from
the independently selected signer before saving plaintext; signed From/To,
Subject and body matched. Both used ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519.

Google Chat permits only one non-media attachment per message. The transport
uploads the public certificate first, then sends the encrypted bundle with a
`Certificate message: spaces/.../messages/...` reference. Google may flatten
caption line breaks; both clients handle this. References must stay in the same
space and match the bundle's Google sender. OpenPGP trust remains a separate
email/full-fingerprint decision. Sends are not retried automatically; if the
second post fails, the public certificate may already be present.

Raw account-specific evidence and key material are not committed. The standalone
project is [gws-sequoia-chat](https://github.com/ve7jtb/gws-sequoia-chat).

## Offline Sequoia interoperability, 2026-11-20

Tested with `sq 1.5.0`, `sequoia-openpgp 2.4.1`, OpenSSL backend 3.5.9, using the
existing local test executable. That executable is not bundled or redistributed
by this change. Fresh synthetic software identities were used and temporary
Sequoia private-key files were removed after the test. No account stores, email,
chat servers or real YubiKeys were accessed.

| Direction | Level 3 | Level 5 software |
| --- | --- | --- |
| PQ Mail compressed signed `.pgp` → Sequoia verification | Passed | Passed |
| PQ Mail signed/encrypted `.pgp` → Sequoia decryption + verification | Passed | Passed |
| Sequoia signed message → PQ Mail verification | Passed | Passed |
| Sequoia ZIP/ZLIB signed/encrypted message → PQ Mail decryption + verification | Passed | Passed |

Both text and HTML alternatives, signed headers and binary attachments were
checked. Exact MIME bytes were compared for signed-only PQ Mail output and both
incoming encryption compression modes. Sequoia's uncompressed signed-only output
was also tested inside a standard ZLIB wrapper made by the test harness.
`--signer-file` explicitly selects the synthetic expected signer for these tests;
this does not assert any real-world trust in the fixture identity.

Local regression tests additionally reject altered ciphertext/signatures,
wrong signer/recipient keys, sender-address mismatches, appended packets,
excessive compression nesting, decompression bombs and attachment limits.

After `./build.sh`, run the local test with:

```sh
java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.ChatBundleTest
```

Run the real Sequoia test with an executable supporting the above RFC 9980 suites
and a result directory that does not already exist:

```sh
scripts/test-chat-sequoia.sh /path/to/sq /tmp/pq-mail-chat-interop-new
```

For independently downloaded bundles, supply an authenticated sender certificate:

```sh
sq verify --message --signer-file sender.asc --output message.eml message.pgp
sq decrypt --recipient-file recipient-secret.pgp --signer-file sender.asc --signatures 1 --output message.eml message.pgp
```

The second command applies to encrypted bundles and assumes a software private
key. Hardware-held PIV keys need a compatible Sequoia adapter. The recovered MIME
message can be viewed or extracted by a MIME-aware application. Verify the sender
fingerprint independently before treating the content as trusted.
