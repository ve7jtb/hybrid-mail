# YubiKey PKCS#11 S/MIME encryption and decryption

The app supports pure **ML-KEM-768** and composite **MLKEM768-ECDH-P256-SHA3-256** recipients in CMS KEMRecipientInfo. Signed content is encrypted with AES-256-GCM inside S/MIME AuthEnvelopedData. The KEM-derived key-encryption key uses HKDF-SHA256 and AES-256 key wrap, matching the existing Bouncy Castle software path.

Encryption uses the recipient's public certificate on the host; the sender does not need the recipient's YubiKey. Decryption uses `CKM_ML_KEM` decapsulation and, for the composite profile, `CKM_ECDH1_DERIVE` through OpenSSL and the Yubico PKCS#11 module. Both private keys stay on the token. The hybrid combiner, CMS KDF, AES key unwrap and message decryption run on the host, so shared secrets and message keys are transiently present in host memory.

## Build and configure

Build the Java app and native dependencies using [PKCS11.md](PKCS11.md). The native build applies the reproducible `ykcs11-ec-metadata.patch` to the pinned Yubico source. It derives EC parameters from the device key, enabling keys with no token-stored certificate, and advertises private EC/X25519 derivation capability. A focused, non-hardware Rust unit test covers the parameter and capability attributes. The signing PIN patch is retained.

Set the common `OPENSSL_BIN`, `PKCS11_PROVIDER`, `PKCS11_MODULE`, and `PKCS11_SERIAL` configuration. Then select separate encryption slots:

```sh
export PKCS11_KEM_SLOT=9d
export PKCS11_ECDH_SLOT=82
export PKCS11_TRADITIONAL_SLOT=9a  # existing RSA signing component
```

The KEM adapter accepts slot 9d or retired slots 82–95 and rejects signing slots 9a/9c. Public keys are exported through PKCS#11 and checked against the local recipient certificate before private operations. The same ML-KEM key may be used in the pure and hybrid recipient certificates.

## Optional provisioning

`provision-kem.py` checks both target slots before changing anything. It generates ML-KEM-768 in empty 9d and ECDH P-256 in empty 82 with PIN policy `always` and touch policy `never`. It reuses matching existing keys and refuses to replace an occupied slot with different metadata. Signing slots are untouched. Provisioning is separate from the signing/decryption adapter and requires the user's intent to create these keys.

```sh
export YKMAN_BIN=/absolute/path/ykman
python3 scripts/provision-kem.py /absolute/path/new-public-metadata-directory
```

Management credentials and provisioning PINs are entered only at ykman's Terminal prompts. No PIN, PUK or management key is changed. No certificate is written to the token.

## Hardware demo

Use the pure and RSA composite signing identities from the dual-key signing demo:

```sh
./scripts/test-kem-pkcs11.sh /absolute/path/rsa-signing-identities /absolute/path/new-output
```

The script exports the encryption public keys through PKCS#11, prompts for the existing local identity-file password, and creates local encryption certificates signed by the corresponding existing signing keys. Both output PKCS#12 identities contain public certificates only, with no signing or encryption private keys.

For each pure/hybrid profile it signs and encrypts a message, saves the `.eml`, reopens it from disk, decrypts through the token, checks the AES-GCM authentication tag, and verifies the inner S/MIME signature and sender binding. Expected test plaintext is also saved locally. Nothing is sent over SMTP or IMAP. Expect six app PIN prompts: certificate signing, message signing and decryption for each profile. Each hybrid operation shares its PIN across its two components and clears its cache afterward.

On success the UI opens with the hybrid identity, signing adapter, KEM adapter and own recipient certificate selected. For manual use, load the new identity and select `adapters/pkcs11-kem.py` in **Keys & token → Token decryption**. Import another user's encryption certificate to send to that user. Reopening an encrypted message requests one decryption PIN. A missing/failing token backend never falls back to software private keys.

## Recovery details and validation

The fixed hybrid profile splits the encapsulation into 1088 ML-KEM ciphertext bytes and a 65-byte uncompressed P-256 ephemeral point. It validates the point before token access. The host combines the two 32-byte secrets using the pinned BC profile's SHA3-256 combiner and domain-separation label, including the traditional ciphertext and recipient public key. Tests compare this recovery against BC-generated encapsulations through full CMS round trips.

The app validates the KEM OID, ciphertext length, HKDF algorithm, 32-byte KEK length, AES-256 wrap, AES-256-GCM and a minimum 128-bit tag before releasing plaintext. Invalid wrapping/KDF parameters and malformed ciphertext fail closed. Optional user keying material is limited to 1024 bytes for this demo.

`pkcs11-kem.py` receives an algorithm, base64 public SPKI and base64 ciphertext/peer SPKI over stdin, followed by the app PIN in pipe mode. It passes the PIN through an anonymous descriptor to OpenSSL. The 32-byte shared secret is returned through stdout as raw binary; it is never written to a temporary file or log. Temporary files contain only public data and configuration. App-owned secret/PIN buffers are cleared on completion/failure; each native subprocess exits after its operation. No automatic PIN retries are performed.

Software validation passes for both complete S/MIME profiles, identity persistence without decryption keys, wrong recipients, malformed ciphertext, modified GCM tags, backend failures, PIN scope cleanup, anonymous-pipe handling and temporary-file cleanup. Hardware validation passed on 2026-11-16 with the Beta0 YubiKey. Both pure ML-KEM-768 and composite MLKEM768-ECDH-P256-SHA3-256 messages were saved, reopened, token-decrypted, AES-256-GCM authenticated and signature-verified. Pure mail used ML-DSA-65 signing; hybrid mail used MLDSA65-RSA3072-PSS-SHA512 signing. Separate inspection confirmed valid encryption-certificate signatures, the expected on-wire KEM identifiers and ciphertext lengths, AES-256-GCM, and the expected recovered test bodies. Both encryption keys reported PIN Always / touch Never. Signing keys remained unchanged and no email was sent. Hardware artifacts remain local and are excluded from GitHub.
