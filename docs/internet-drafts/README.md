# Certificate bundle and encrypted companion Internet-Draft

**Working draft intended for the Independent Submission Stream, Informational.**
It is not an IETF consensus standard and has not been submitted to the IETF
Datatracker or the Independent Submissions Editor.

- [Readable Internet-Draft](draft-bradley-pqmail-certificate-bundle-00.txt)
- [GitHub Markdown reading copy](draft-bradley-pqmail-certificate-bundle-00.md)
- [RFCXML source](draft-bradley-pqmail-certificate-bundle-00.xml)
- [Rendered HTML](draft-bradley-pqmail-certificate-bundle-00.html) — download/open locally
- [Synthetic public interoperability fixture](fixture-level3-public.json)
- [Framing and negative-case validator](check-fixture.py)
- [Validation and nits report](validation-report.md)

The draft documents **one on-card bank**, bounded zlib compression, the signed
envelope, the deployed `PQMAILB2` certificate payload, public-key matching,
review/import, and verified local recovery before overwrite. No historical
format or two-bank storage specification is included. It also specifies a
**separate encrypted companion bank**, with full-certificate and opt-in
ultra-compact representations. The latter keeps the certificate's key packets
and metadata but replaces eligible self-issued signature values with compressed
zero placeholders. First restore reconstructs and verifies the certificate;
subsequent use relies on a verified public-only cache. Hardware keys and
fingerprints do not change. CA-issued and third-party-signed certificates are
not eligible for this initial reconstruction profile and stay in full storage.

S/MIME certificates are already part of the deployed payload. The proposed
`PQMAILB3` payload adds explicit, signed extensions for additional X.509 and
OpenPGP certificates, other documented public certificate types, and
component-to-key-slot mappings. Unknown critical extensions fail closed.
This is a **design proposal**, not a claim that existing clients support B3.
Existing B2 readers reject it. The companion has its own authenticated layout;
implementing it does not imply B3 support. Publishing this draft does not
rewrite a hardware bundle or change any device key or policy.

The Level 3 layout distinguishes certification (86/87), hybrid signing (9c/84),
hybrid decryption (9d/85), standalone classical signing/decryption (88/89), and
S/MIME classical components (83/82). Classical-only v4 export retains already
signed packets; it does not create a signature or change the primary fingerprint.

## Rebuild and validate

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python render-draft.py --xml2rfc .venv/bin/xml2rfc \
  --cache .xml2rfc-cache
python3 render-draft.py --check
python3 check-fixture.py
```

`render-draft.py` generates Markdown from RFCXML and calls `xml2rfc` for text
and HTML, using the date declared in the draft. Markdown is not hand-maintained
and is not Internet-Draft submission text. `xml2rfc` validates the RFCXML and
generates the required boilerplate. The Python
checker verifies exact lengths, zlib boundaries, field framing, single-bank
chunk reconstruction, and malformed input rejection. **It does not verify
cryptographic signatures or certificate trust.**

The fixture uses random software-generated public keys, `example.test` mailboxes,
and synthetic serial `123456`. It contains no private keys, actual hardware
backup, PINs, account credentials, or contact trust. Both pure and hybrid
envelopes are included; their signatures and public-key bindings are also
exercised by `piv-adapter/tests/restore.rs` in the separate Sequoia adapter work.
No deterministic compression output is required for interoperability.

For the independent IETF nits checker, install `@ietf-tools/idnits` in an
isolated tooling directory and run both the XML and text checks:

```sh
idnits --mode submission --output json draft-bradley-pqmail-certificate-bundle-00.xml
idnits --mode submission --output json draft-bradley-pqmail-certificate-bundle-00.txt
```

These are local checks, not an Internet-Draft submission or an ISE review.
The [validation report](validation-report.md) records tool versions, results,
limitations, and fixed findings for the generated artifacts.

## Review before formal submission

- Confirm author contact information and the chosen draft name.
- Review the proposed extension encoding and obtain independent implementation
  feedback. There is no extension conformance claim yet.
- Resolve algorithm-reference revisions, including the composite KEM draft,
  before claiming compatibility with any later version of that specification.
- Reconcile implementation details with the stronger writer/reader requirements:
  complete namespace recheck including previously absent objects, manifest
  re-read, directory durability where available, and explicit interrupted-write
  recovery metadata. The tested writer flushes and reads back files; that is not
  a universal filesystem power-loss guarantee.
- Perform normal Internet-Draft checks and author review of applicable IPR terms.
  After posting an Internet-Draft, request Independent Submissions Editor review
  with the required submission information. Publishing this repository does not
  perform either step or make legal acknowledgements on the author's behalf.

See the [Independent Submissions checklist](https://www.rfc-editor.org/authors/ise/ise-checklist/).

## Algorithm and custody choices

The Security Considerations now compare hardware-backed Level 3 and Level 5
NIST composites, native Level 5 Ed448/X448, and the Level 5 software companion.
The comparison separates ML parameter categories from certificate compatibility
and private-key custody. NIST S/MIME composites are not RFC 9980 OpenPGP profiles.

The software companion uses an empty-password `.p12` entirely inside
an authenticated P-384-wrapped envelope. Only ciphertext is deliberately saved,
but unwrapped Edwards keys can be exposed through process memory, caches,
swap/page files, hibernation, crash dumps, or host compromise. Per-operation
cleanup reduces exposure without promising guaranteed erasure. The draft now
specifies the companion wire format in its own section and storage namespace;
the ordinary certificate bundle remains **public-only**. Implementation and
test status distinguish the tested lossless format from ultra-compact software
validation and any still-pending physical-device conversion.

The draft also separates message security categories from hardware assurance.
It covers FIPS 140-3 and Common Criteria evaluation scope, physical and
side-channel protection, and on-device randomness (SP 800-90A/B/C). A device's
certification label does not automatically cover its PQ firmware or all key
operations. Companion keys rely on host entropy; token key generation relies
on the token's evaluated generator. No test-device certification is claimed.
