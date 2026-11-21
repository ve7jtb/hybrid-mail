# Level 3 companion design update

The PRF-wrapped proposal has been superseded by the accepted [Level 3 software-PQ companion](LEVEL3-POLYFILL.md): a dedicated PIN-protected, no-touch P-384 key in slot 83 unwraps the software ML-DSA-65/ML-KEM-768 seeds. Hardware Ed25519 certification/signing and X25519 decryption remain touch-required. PRF still protects the settings vault.

The implementation and its security tradeoff are documented in the linked profile. In particular, P-384 provides classical protection at rest; the Level 3 label describes the message algorithms. Software and physical YubiKey 5.8 tests now pass for signing, decryption and fresh on-card restore in PQ Mail and Sequoia; see the linked report.
