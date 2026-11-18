# Published OpenPGP test vectors

The three ASCII-armored, **public test-data** fixtures are extracted without
modification (apart from removing document indentation and pagination) from
Appendix A.1.2–A.1.4 of:

- Dang et al., *PQ/T Composite Schemes for OpenPGP using NIST and Brainpool
  Elliptic Curve Domain Parameters*, draft-ietf-openpgp-nist-bp-comp-05,
  24 September 2026.
- https://www.ietf.org/archive/id/draft-ietf-openpgp-nist-bp-comp-05.txt
- https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-nist-bp-comp-05

Copyright (c) 2026 IETF Trust and the persons identified as the document authors.
The source document is subject to the IETF Trust's Legal Provisions:
https://trustee.ietf.org/license-info

No private-key fixture is included. These examples test public-key bindings,
hybrid signatures, the published KEM-combiner inputs and result, session-key
unwrap, AES-256-OCB authenticated decryption, and verification of the resulting
signed message. The known session/key shares come from the same published
example and are not user credentials.
