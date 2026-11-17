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
    public static final String HYBRID_RSA_SIGN = "MLDSA65-RSA3072-PSS-SHA512";
    public static final String PURE_44_SIGN = "ML-DSA-44";
    public static final String HYBRID_44_SIGN = "MLDSA44-ECDSA-P256-SHA256";
    public static final String HYBRID_65_P384_SIGN = "MLDSA65-ECDSA-P384-SHA512";
    public static final String HYBRID_768_P384_KEM = "MLKEM768-ECDH-P384-SHA3-256";
    public static final String PURE_87_SIGN = "ML-DSA-87";
    public static final String HYBRID_87_SIGN = "MLDSA87-ECDSA-P384-SHA512";
    public static final String PURE_1024_KEM = "ML-KEM-1024";
    public static final String HYBRID_1024_KEM = "MLKEM1024-ECDH-P384-SHA3-256";
    public static final String PURE_KEM = "ML-KEM-768";
    public static final String HYBRID_KEM = "MLKEM768-ECDH-P256-SHA3-256";
    public String signatureAlgorithm() {
        return signingCert.getPublicKey().getAlgorithm();
    }
    public static Identity generate(String email, boolean hybrid) throws Exception {
        return generate(email,hybrid?HYBRID_SIGN:PURE_SIGN);
    }
    public static Identity generate(String email,String alg)throws Exception{return generate(email,alg,List.of());}
    static List<String> additionalEmails(String primary,String text)throws Exception{
        new jakarta.mail.internet.InternetAddress(primary,true).validate();
        var emails=new ArrayList<String>();var seen=new HashSet<String>();seen.add(primary.toLowerCase(Locale.ROOT));
        if(!text.isBlank())for(String raw:text.split(",",-1)){
            String address=raw.trim();var parsed=new jakarta.mail.internet.InternetAddress(address,true);parsed.validate();
            if(!address.equals(parsed.getAddress())||parsed.getPersonal()!=null)throw new IllegalArgumentException("Enter plain email addresses separated by commas");
            if(!seen.add(address.toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("Duplicate certificate email address");emails.add(address);
        }
        if(emails.size()>4)throw new IllegalArgumentException("Use at most four additional email addresses");return List.copyOf(emails);
    }
    static Identity generate(String email,String alg,List<String> extra)throws Exception{
        new jakarta.mail.internet.InternetAddress(email,true).validate();
        if(!Set.of(PURE_SIGN,HYBRID_SIGN,HYBRID_RSA_SIGN,PURE_87_SIGN,HYBRID_87_SIGN,PURE_44_SIGN,HYBRID_44_SIGN,HYBRID_65_P384_SIGN).contains(alg))throw new GeneralSecurityException("Unsupported signing profile");
        boolean hybrid=alg.startsWith("MLDSA");
        KeyPair s=KeyPairGenerator.getInstance(alg,"BC").generateKeyPair();
        String kem=alg.equals(HYBRID_65_P384_SIGN)?HYBRID_768_P384_KEM:alg.equals(PURE_87_SIGN)?PURE_1024_KEM:alg.equals(HYBRID_87_SIGN)?HYBRID_1024_KEM:hybrid?HYBRID_KEM:PURE_KEM;
        KeyPair k=KeyPairGenerator.getInstance(kem,"BC").generateKeyPair();
        X509Certificate sc = cert(email, s.getPublic(), s.getPrivate(), alg, true,extra);
        X509Certificate kc = cert(email, k.getPublic(), s.getPrivate(), alg, false,extra);
        return new Identity(sc, s.getPrivate(), kc, k.getPrivate(), null);
    }
    /** Exactly four generated keys, shared by pure and hybrid certificate views. */
    static List<Identity> generateSoftwareProfile(String email,TokenProfile profile)throws Exception{return generateSoftwareProfile(email,profile,List.of());}
    static List<Identity> generateSoftwareProfile(String email,TokenProfile profile,List<String> extra)throws Exception{
        String algorithm=switch(profile){case LEVEL2->HYBRID_44_SIGN;case LEVEL3->HYBRID_65_P384_SIGN;case LEVEL5->HYBRID_87_SIGN;};
        var hybrid=generate(email,algorithm,extra);
        var signing=(CompositePrivateKey)hybrid.signingKey();var encryption=(CompositePrivateKey)hybrid.encryptionKey();
        var ml=((CompositePublicKey)hybrid.signingCert().getPublicKey()).getPublicKeys().get(0);
        var kem=((CompositePublicKey)hybrid.encryptionCert().getPublicKey()).getPublicKeys().get(0);
        var sc=cert(email,ml,signing.getPrivateKeys().get(0),profile.ml,true,extra);
        var kc=cert(email,kem,signing.getPrivateKeys().get(0),profile.ml,false,extra);
        return List.of(new Identity(sc,signing.getPrivateKeys().get(0),kc,encryption.getPrivateKeys().get(0),null),hybrid);
    }
    private static X509Certificate cert(String email, PublicKey key, PrivateKey signer, String alg, boolean signing) throws Exception {
        return cert(email,key,signer,alg,signing,List.of());
    }
    private static X509Certificate cert(String email,PublicKey key,PrivateKey signer,String alg,boolean signing,List<String> extra)throws Exception{
        return cert(email, key, new JcaContentSignerBuilder(alg).setProvider("BC").build(signer), signing,extra);
    }
    private static X509Certificate cert(String email, PublicKey key, ContentSigner signer, boolean signing) throws Exception {return cert(email,key,signer,signing,List.of());}
    private static X509Certificate cert(String email,PublicKey key,ContentSigner signer,boolean signing,List<String> extra)throws Exception{
        var names=new ArrayList<GeneralName>();names.add(new GeneralName(GeneralName.rfc822Name,email));
        for(String address:additionalEmails(email,String.join(",",extra)))names.add(new GeneralName(GeneralName.rfc822Name,address));
        X500Name name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, email).build();
        Instant now = Instant.now();
        var b = new JcaX509v3CertificateBuilder(name, new BigInteger(159, new SecureRandom()).add(BigInteger.ONE),
            Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(365L*86400)), name, key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(signing ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names.toArray(GeneralName[]::new)));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }
    /** Create a local test certificate for an EXISTING token key; never generates token keys. */
    public static Identity forToken(String email, PublicKey tokenPublic, boolean hybrid, ExternalMu.Backend backend) throws Exception {
        new jakarta.mail.internet.InternetAddress(email, true).validate();
        if (!PURE_SIGN.equalsIgnoreCase(tokenPublic.getAlgorithm())) throw new GeneralSecurityException("Expected ML-DSA-65 public key");
        PublicKey publicKey = tokenPublic;
        PrivateKey conventional = null;
        if (hybrid) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            KeyPair ec = generator.generateKeyPair();
            publicKey = new CompositePublicKey(org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,
                tokenPublic, ec.getPublic());
            conventional = ec.getPrivate();
        }
        X509Certificate certificate = cert(email, publicKey, externalSigner(publicKey, conventional, backend), true);
        certificate.verify(publicKey, "BC");
        return new Identity(certificate, null, null, null, conventional);
    }
    /** Both signing components remain on the token; only a public certificate is stored. */
    public static Identity forDualToken(String email, PublicKey ml, PublicKey ec, ExternalMu.Backend backend) throws Exception {
        new jakarta.mail.internet.InternetAddress(email,true).validate();
        if (!PURE_SIGN.equalsIgnoreCase(ml.getAlgorithm())) throw new GeneralSecurityException("Expected ML-DSA-65");
        boolean rsa=ec instanceof java.security.interfaces.RSAPublicKey;
        if(rsa && ((java.security.interfaces.RSAPublicKey)ec).getModulus().bitLength()!=3072)throw new GeneralSecurityException("Expected RSA-3072");
        var expected=java.security.AlgorithmParameters.getInstance("EC","BC");
        expected.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var curve=expected.getParameterSpec(java.security.spec.ECParameterSpec.class);
        if (!rsa && (!(ec instanceof java.security.interfaces.ECPublicKey e) || !e.getParams().getCurve().equals(curve.getCurve())
            || !e.getParams().getGenerator().equals(curve.getGenerator()) || !e.getParams().getOrder().equals(curve.getOrder())
            || e.getParams().getCofactor()!=curve.getCofactor())) throw new GeneralSecurityException("Expected ECDSA P-256");
        PublicKey pub=new CompositePublicKey(rsa?org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512:org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,ml,ec);
        X509Certificate certificate=cert(email,pub,externalSigner(pub,null,backend),true);
        certificate.verify(pub,"BC");
        return new Identity(certificate,null,null,null,null);
    }
    public static Identity forToken87(String email,PublicKey ml,PublicKey ec,PublicKey kem,PublicKey ecdh,ExternalMu.Backend backend)throws Exception{
        return forTokenProfile(email,TokenProfile.LEVEL5,ml,ec,kem,ecdh,backend);
    }
    static Identity forTokenProfile(String email,TokenProfile profile,PublicKey ml,PublicKey ec,PublicKey kem,PublicKey ecdh,ExternalMu.Backend backend)throws Exception{return forTokenProfile(email,profile,ml,ec,kem,ecdh,backend,List.of());}
    static Identity forTokenProfile(String email,TokenProfile profile,PublicKey ml,PublicKey ec,PublicKey kem,PublicKey ecdh,ExternalMu.Backend backend,List<String> extra)throws Exception{
        new jakarta.mail.internet.InternetAddress(email,true).validate();
        if(!profile.ml.equals(ml.getAlgorithm())||!profile.kem.equals(kem.getAlgorithm()))throw new GeneralSecurityException("Token keys do not match selected profile");
        PublicKey signing=ml,encryption=kem;
        if(ec!=null){
            var params=AlgorithmParameters.getInstance("EC","BC");params.init(new java.security.spec.ECGenParameterSpec(profile.curve));
            var expected=params.getParameterSpec(java.security.spec.ECParameterSpec.class);
            if(!(ec instanceof java.security.interfaces.ECPublicKey e)||!e.getParams().getCurve().equals(expected.getCurve())||!e.getParams().getOrder().equals(expected.getOrder())||!e.getParams().getGenerator().equals(expected.getGenerator())||e.getParams().getCofactor()!=expected.getCofactor())throw new GeneralSecurityException("Wrong ECDSA curve for selected profile");
            signing=new CompositePublicKey(profile.signingOid,ml,ec);
            encryption=new CompositePublicKey(profile.kemOid,kem,ecdh);
        }else if(ecdh!=null)throw new GeneralSecurityException("Both classical components are required for hybrid mode");
        validateEncryptionKey(encryption);
        var sc=cert(email,signing,externalSigner(signing,null,backend),true,extra);sc.verify(signing,"BC");
        var kc=cert(email,encryption,externalSigner(signing,null,backend),false,extra);kc.verify(signing,"BC");
        return new Identity(sc,null,kc,null,null);
    }
    public ContentSigner signer(ExternalMu.Backend backend) throws Exception {
        signingCert.checkValidity();
        if (backend == null) {
            if (signingKey == null) throw new GeneralSecurityException("No software signing key; configure external adapter");
            return new JcaContentSignerBuilder(signatureAlgorithm()).setProvider("BC").build(signingKey);
        }
        PrivateKey traditional = traditionalKey;
        if (traditional == null && signingKey instanceof CompositePrivateKey s) traditional = s.getPrivateKeys().get(1);
        return externalSigner(signingCert.getPublicKey(), traditional, backend);
    }
    private static ContentSigner externalSigner(PublicKey pub, PrivateKey traditional, ExternalMu.Backend backend) throws Exception {
        backend=backend.newOperation();
        if (pub instanceof CompositePublicKey c) {
            PrivateKey ecKey = traditional == null ? (c.getPublicKeys().get(1) instanceof java.security.interfaces.RSAPublicKey ? new ExternalMu.RsaTokenKey(c.getPublicKeys().get(1),backend) : new ExternalMu.EcTokenKey(c.getPublicKeys().get(1), backend)) : traditional;
            Provider ecProvider = traditional == null ? ExternalMu.PROVIDER : Security.getProvider("BC");
            var key = CompositePrivateKey.builder(c.getAlgorithmIdentifier().getAlgorithm())
                .addPrivateKey(new ExternalMu.TokenKey(c.getPublicKeys().get(0), backend), ExternalMu.PROVIDER)
                .addPrivateKey(ecKey, ecProvider).build();
            return clearAfterSignature(new JcaContentSignerBuilder(pub.getAlgorithm()).setProvider("BC").build(key),backend);
        }
        return clearAfterSignature(new JcaContentSignerBuilder(pub.getAlgorithm()).setProvider(ExternalMu.PROVIDER)
            .build(new ExternalMu.TokenKey(pub, backend)),backend);
    }
    private static ContentSigner clearAfterSignature(ContentSigner signer,ExternalMu.Backend backend){
        return new ContentSigner(){
            public AlgorithmIdentifier getAlgorithmIdentifier(){return signer.getAlgorithmIdentifier();}
            public OutputStream getOutputStream(){return signer.getOutputStream();}
            public byte[] getSignature(){try{return signer.getSignature();}finally{backend.clearSecrets();}}
        };
    }
    /** Reissue local demo certificates for the same keys and a new mailbox address. */
    public Identity reissue(String email,ExternalMu.Backend backend)throws Exception{return reissue(email,backend,List.of());}
    public Identity reissue(String email,ExternalMu.Backend backend,List<String> extra)throws Exception{
        extra=additionalEmails(email,String.join(",",extra));
        X509Certificate signing=cert(email,signingCert.getPublicKey(),signer(backend),true,extra);
        signing.verify(signingCert.getPublicKey(),"BC");
        X509Certificate encryption=encryptionCert==null?null:cert(email,encryptionCert.getPublicKey(),signer(backend),false,extra);
        if(encryption!=null)encryption.verify(signing.getPublicKey(),"BC");
        return new Identity(signing,signingKey,encryption,encryptionKey,traditionalKey);
    }
    public Identity withTokenEncryption(String email,PublicKey key,ExternalMu.Backend signingBackend)throws Exception{
        ExternalKem.validatePublicKey(key);
        X509Certificate certificate=cert(email,key,signer(signingBackend),false);
        certificate.verify(signingCert.getPublicKey(),"BC");
        return new Identity(signingCert,signingKey,certificate,null,traditionalKey);
    }
    public void save(Path file, char[] password) throws Exception {save(file,password,null);}
    void save(Path file,char[] password,Identity pure)throws Exception {
        if (password.length < 12) throw new IllegalArgumentException("Use at least 12 characters for the identity password");
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC"); ks.load(null, password);
        if (signingKey != null) ks.setKeyEntry("sign", signingKey, password, new java.security.cert.Certificate[]{signingCert});
        else ks.setCertificateEntry("sign", signingCert);
        if (encryptionKey != null) ks.setKeyEntry("encrypt", encryptionKey, password, new java.security.cert.Certificate[]{encryptionCert});
        if(encryptionKey==null&&encryptionCert!=null)ks.setCertificateEntry("encrypt",encryptionCert);
        if (traditionalKey != null) {
            PublicKey ec = ((CompositePublicKey)signingCert.getPublicKey()).getPublicKeys().get(1);
            X509Certificate storageCert = cert("conventional-component@example.test", ec, traditionalKey, "SHA256withECDSA", true);
            ks.setKeyEntry("traditional", traditionalKey, password, new java.security.cert.Certificate[]{storageCert});
        }
        if(pure!=null){
            ks.setKeyEntry("pure-sign",pure.signingKey(),password,new java.security.cert.Certificate[]{pure.signingCert()});
            ks.setKeyEntry("pure-encrypt",pure.encryptionKey(),password,new java.security.cert.Certificate[]{pure.encryptionCert()});
        }
        PrivateFiles.create(file);
        try (OutputStream out = Files.newOutputStream(file)) { ks.store(out, password); }
    }
    public static Identity load(Path file, char[] password) throws Exception {return load(file,password,false);}
    static List<Identity> loadProfiles(Path file,char[] password)throws Exception{
        var hybrid=load(file,password);KeyStore ks=KeyStore.getInstance("PKCS12","BC");
        try(var in=Files.newInputStream(file)){ks.load(in,password);}
        return ks.containsAlias("pure-sign")?List.of(load(file,password,true),hybrid):List.of(hybrid);
    }
    static Identity load(Path file,char[] password,boolean pure)throws Exception {
        String prefix=pure?"pure-":"";
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (InputStream in = Files.newInputStream(file)) { ks.load(in, password); }
        var sc = (X509Certificate)ks.getCertificate(prefix+"sign");
        if (sc == null) throw new GeneralSecurityException("Missing certificate alias 'sign'");
        String a = sc.getPublicKey().getAlgorithm();
        if (!a.equalsIgnoreCase(PURE_SIGN) && !a.equalsIgnoreCase(HYBRID_SIGN) && !a.equalsIgnoreCase(HYBRID_RSA_SIGN) && !a.equalsIgnoreCase(PURE_87_SIGN) && !a.equalsIgnoreCase(HYBRID_87_SIGN) && !a.equalsIgnoreCase(PURE_44_SIGN) && !a.equalsIgnoreCase(HYBRID_44_SIGN) && !a.equalsIgnoreCase(HYBRID_65_P384_SIGN))
            throw new GeneralSecurityException("Unsupported signing key: " + a);
        return new Identity(sc, (PrivateKey)ks.getKey(prefix+"sign", password), (X509Certificate)ks.getCertificate(prefix+"encrypt"),
            (PrivateKey)ks.getKey(prefix+"encrypt", password), (PrivateKey)ks.getKey("traditional", password));
    }
    /** Supported software/public recipient profiles; token recovery keeps its narrower validation. */
    public static void validateEncryptionKey(PublicKey key)throws Exception{
        var spki=SubjectPublicKeyInfo.getInstance(key.getEncoded());
        if(spki.getAlgorithm().getAlgorithm().equals(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_alg_ml_kem_1024))return;
        if(key instanceof CompositePublicKey c && (c.getAlgorithmIdentifier().getAlgorithm().equals(org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256)||c.getAlgorithmIdentifier().getAlgorithm().equals(org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256))){
            var expectedMl=c.getAlgorithmIdentifier().getAlgorithm().equals(org.bouncycastle.asn1.iana.IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256)?org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_alg_ml_kem_768:org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_alg_ml_kem_1024;
            if(c.getPublicKeys().size()!=2 || !SubjectPublicKeyInfo.getInstance(c.getPublicKeys().get(0).getEncoded()).getAlgorithm().getAlgorithm().equals(expectedMl))throw new GeneralSecurityException("Incorrect ML-KEM component");
            var ec=SubjectPublicKeyInfo.getInstance(c.getPublicKeys().get(1).getEncoded());
            if(!ec.getAlgorithm().getAlgorithm().equals(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey)||!org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1.equals(ec.getAlgorithm().getParameters()))throw new GeneralSecurityException("Expected named P-384 component");
            var point=org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp384r1").getCurve().decodePoint(ec.getPublicKeyData().getBytes());
            if(point.isInfinity()||!point.isValid())throw new GeneralSecurityException("Invalid P-384 point");return;
        }
        ExternalKem.validatePublicKey(key);
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
