package dev.hybridmail;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public record Identity(X509Certificate signingCert, PrivateKey signingKey,
                       X509Certificate encryptionCert, PrivateKey encryptionKey, PrivateKey traditionalKey) {
    public static final String PURE_SIGN = "ML-DSA-65";
    public static final String HYBRID_SIGN = "MLDSA65-ECDSA-P256-SHA512";
    public static final String PURE_KEM = "ML-KEM-768";
    public static final String HYBRID_KEM = "MLKEM768-ECDH-P256-SHA3-256";
    public String signatureAlgorithm() {
        return signingCert.getPublicKey() instanceof CompositePublicKey ? HYBRID_SIGN : PURE_SIGN;
    }
    public static Identity generate(String email, boolean hybrid) throws Exception {
        new jakarta.mail.internet.InternetAddress(email, true).validate();
        KeyPair s = KeyPairGenerator.getInstance(hybrid ? HYBRID_SIGN : PURE_SIGN, "BC").generateKeyPair();
        KeyPair k = KeyPairGenerator.getInstance(hybrid ? HYBRID_KEM : PURE_KEM, "BC").generateKeyPair();
        String alg = hybrid ? HYBRID_SIGN : PURE_SIGN;
        X509Certificate sc = cert(email, s.getPublic(), s.getPrivate(), alg, true);
        X509Certificate kc = cert(email, k.getPublic(), s.getPrivate(), alg, false);
        return new Identity(sc, s.getPrivate(), kc, k.getPrivate(), null);
    }
    private static X509Certificate cert(String email, PublicKey key, PrivateKey signer, String alg, boolean signing) throws Exception {
        X500Name name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, email).build();
        Instant now = Instant.now();
        var b = new JcaX509v3CertificateBuilder(name, new BigInteger(159, new SecureRandom()).add(BigInteger.ONE),
            Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(365L*86400)), name, key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(signing ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(new JcaContentSignerBuilder(alg).setProvider("BC").build(signer)));
    }
    public ContentSigner signer(ExternalMu.Backend backend) throws Exception {
        signingCert.checkValidity();
        if (backend == null) {
            if (signingKey == null) throw new GeneralSecurityException("No software signing key; configure external adapter");
            return new JcaContentSignerBuilder(signatureAlgorithm()).setProvider("BC").build(signingKey);
        }
        PublicKey pub = signingCert.getPublicKey();
        if (pub instanceof CompositePublicKey c) {
            PrivateKey traditional = traditionalKey;
            if (traditional == null && signingKey instanceof CompositePrivateKey s) traditional = s.getPrivateKeys().get(1);
            if (traditional == null) throw new GeneralSecurityException("Composite token identity needs traditional private key alias 'traditional'");
            var key = CompositePrivateKey.builder(c.getAlgorithmIdentifier().getAlgorithm())
                .addPrivateKey(new ExternalMu.TokenKey(c.getPublicKeys().get(0), backend), ExternalMu.PROVIDER)
                .addPrivateKey(traditional, Security.getProvider("BC")).build();
            return new JcaContentSignerBuilder(signatureAlgorithm()).setProvider("BC").build(key);
        }
        return new JcaContentSignerBuilder(PURE_SIGN).setProvider(ExternalMu.PROVIDER)
            .build(new ExternalMu.TokenKey(pub, backend));
    }
    public void save(Path file, char[] password) throws Exception {
        if (password.length < 12) throw new IllegalArgumentException("Use at least 12 characters for the identity password");
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC"); ks.load(null, password);
        ks.setKeyEntry("sign", signingKey, password, new java.security.cert.Certificate[]{signingCert});
        ks.setKeyEntry("encrypt", encryptionKey, password, new java.security.cert.Certificate[]{encryptionCert});
        Files.createFile(file, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
        try (OutputStream out = Files.newOutputStream(file)) { ks.store(out, password); }
    }
    public static Identity load(Path file, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (InputStream in = Files.newInputStream(file)) { ks.load(in, password); }
        var sc = (X509Certificate)ks.getCertificate("sign");
        if (sc == null) throw new GeneralSecurityException("Missing certificate alias 'sign'");
        String a = sc.getPublicKey().getAlgorithm();
        if (!a.equalsIgnoreCase(PURE_SIGN) && !a.equalsIgnoreCase(HYBRID_SIGN))
            throw new GeneralSecurityException("Unsupported signing key: " + a);
        return new Identity(sc, (PrivateKey)ks.getKey("sign", password), (X509Certificate)ks.getCertificate("encrypt"),
            (PrivateKey)ks.getKey("encrypt", password), (PrivateKey)ks.getKey("traditional", password));
    }
    public static X509Certificate readCertificate(Path file) throws Exception {
        try (InputStream in = Files.newInputStream(file)) {
            return (X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);
        }
    }
    public static String fingerprint(X509Certificate cert) throws Exception {
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
    }
    public static boolean matchesEmail(X509Certificate cert, String email) throws Exception {
        var names = cert.getSubjectAlternativeNames();
        if (names != null) for (var n : names) if (Integer.valueOf(1).equals(n.get(0)) && email.equalsIgnoreCase(n.get(1).toString())) return true;
        return false;
    }
}
