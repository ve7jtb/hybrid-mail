# Public certificate bundle Internet-Draft

**Working draft intended for the Independent Submission Stream, Informational.**
It is not an IETF consensus standard and has not been submitted to the IETF
Datatracker or the Independent Submissions Editor.

- [Readable Internet-Draft](draft-bradley-pqmail-certificate-bundle-00.txt)
- [RFCXML source](draft-bradley-pqmail-certificate-bundle-00.xml)
- [Rendered HTML](draft-bradley-pqmail-certificate-bundle-00.html) — download/open locally
- [Synthetic public interoperability fixture](fixture-level3-public.json)
- [Framing and negative-case validator](check-fixture.py)

The draft documents **one on-card bank**, bounded zlib compression, the signed
envelope, the deployed `PQMAILB2` certificate payload, public-key matching,
review/import, and verified local recovery before overwrite. No historical
format or two-bank storage specification is included.

S/MIME certificates are already part of the deployed payload. The proposed
`PQMAILB3` payload adds explicit, signed extensions for additional X.509 and
OpenPGP certificates, other documented public certificate types, and
component-to-key-slot mappings. Unknown critical extensions fail closed.
This is a **design proposal**, not a claim that existing clients support B3.
Existing B2 readers reject it. This documentation change does not update apps,
rewrite the hardware bundle, or change any device key or policy.

The Level 3 layout distinguishes certification (86/87), hybrid signing (9c/84),
hybrid decryption (9d/85), standalone classical signing/decryption (88/89), and
S/MIME classical components (83/82). Classical-only v4 export retains already
signed packets; it does not create a signature or change the primary fingerprint.

## Rebuild and validate

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/xml2rfc --cache .xml2rfc-cache --text --html --path . \
  draft-bradley-pqmail-certificate-bundle-00.xml
python3 check-fixture.py
```

`xml2rfc` validates the RFCXML and generates the required boilerplate. The Python
checker verifies exact lengths, zlib boundaries, field framing, single-bank
chunk reconstruction, and malformed input rejection. **It does not verify
cryptographic signatures or certificate trust.**

The fixture uses random software-generated public keys, `example.test` mailboxes,
and synthetic serial `123456`. It contains no private keys, actual hardware
backup, PINs, account credentials, or contact trust. Both pure and hybrid
envelopes are included; their signatures and public-key bindings are also
exercised by `piv-adapter/tests/restore.rs` in the separate Sequoia adapter work.
No deterministic compression output is required for interoperability.

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
