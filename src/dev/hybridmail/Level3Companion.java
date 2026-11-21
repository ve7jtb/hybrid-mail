package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import com.google.gson.Gson;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.pkcs.*;

/**
 * Level 3 OpenPGP with software PQ seeds and hardware classical components.
 * The normal compressed PQMCP003 envelope is authenticated by BOTH primary
 * components. Its empty-password P12 is protected by AES-GCM and a dedicated
 * P-384 ECDH key in slot 83. This is classical protection of private material
 * at rest, not hardware custody of the software ML-DSA/ML-KEM keys.
 *
 * Every instance is operation-scoped. Public inspect performs no hardware
 * private operation; restore requires one no-touch P-384 unwrap. A message
 * then uses its touch-required Ed25519 or X25519 component exactly once.
 */
public final class Level3Companion implements AutoCloseable {
    static final int MAX=65536;
    static final byte[] MAGIC=bytes("PQMCP003");
    static final String[] SLOTS={"82","9c","9d","83"};
    static final String[] ROLES={"cert-pq","sign-pq","kem-pq"};
    private static final byte[] SIGN_DOMAIN=bytes("PQMail Level3 companion signature v1");
    private static final byte[] KDF_DOMAIN=bytes("PQMail companion L3 P384 v1");
    private final Map<String,KeyPair> software;
    final int serial;
    final Map<String,PublicKey> hardware;
    final PublicIdentity own;
    private final Identity anchors;
    static final String ANCHOR_URI="https://github.com/ve7jtb/pq-mail/profile/level3-polyfill/v1/";
    private boolean closed;

    private Level3Companion(int serial,Map<String,PublicKey> hardware,Map<String,KeyPair> software,PublicIdentity own,Identity anchors)throws Exception {
        validateHardware(serial,hardware);validateCertificate(own,hardware);
        validateSoftware(software,own);validateAnchors(anchors,own);
        this.serial=serial;this.hardware=Map.copyOf(hardware);
        this.software=new LinkedHashMap<>(software);this.own=own;this.anchors=anchors;
    }
    static void same(PublicKey a,PublicKey b)throws Exception{Level5Companion.same(a,b);}
    static PublicKey decodePublic(byte[] der)throws Exception{return Level5Companion.decodePublic(der);}
    static void validateHardware(int serial,Map<String,PublicKey> hardware)throws Exception{
        check(serial>0&&hardware.keySet().equals(Set.of(SLOTS)),"Invalid Level 3 companion serial or key layout");
        for(String slot:List.of("82","9c"))same(curve25519(raw(hardware.get(slot)),true),hardware.get(slot));
        same(curve25519(raw(hardware.get("9d")),false),hardware.get("9d"));
        same(ec(raw(hardware.get("83"))),hardware.get("83"));
        check(!Arrays.equals(hardware.get("82").getEncoded(),hardware.get("9c").getEncoded()),"Certification and message signing keys must be separate");
    }
    private static void validateCertificate(PublicIdentity own,Map<String,PublicKey> hardware)throws Exception{
        check(own.separated()&&algorithm(own.signing,true)==30&&algorithm(own.encryption,false)==35,"Expected separated Level 3 RFC 9980 certificate");
        Keys primary=parseKey(own.primary,true);
        check(algorithm(primary,true)==30,"Expected Level 3 certification key");
        same(primary.ec(),hardware.get("82"));same(own.signing.ec(),hardware.get("9c"));same(own.encryption.ec(),hardware.get("9d"));
        check(!Arrays.equals(primary.pq().getEncoded(),own.signing.pq().getEncoded()),"PQ certification and message signing keys must be separate");
    }
    private static void validateSoftware(Map<String,KeyPair> software,PublicIdentity own)throws Exception{
        check(software.keySet().equals(Set.of(ROLES)),"Incomplete Level 3 software key roles");
        same(software.get("cert-pq").getPublic(),parseKey(own.primary,true).pq());
        same(software.get("sign-pq").getPublic(),own.signing.pq());same(software.get("kem-pq").getPublic(),own.encryption.pq());
        // Public keys are derived again from each private seed, not merely read
        // from a bag certificate. This catches swapped or inconsistent seeds.
        for(String role:ROLES){PrivateKey key=software.get(role).getPrivate();same(publicFromPrivate(key,role),software.get(role).getPublic());}
    }
    private static PublicKey publicFromPrivate(PrivateKey key,String role)throws Exception{
        if(role.equals("kem-pq")){check(key instanceof MLKEMPrivateKey&&key.getAlgorithm().equals("ML-KEM-768"),"Expected ML-KEM-768 seed");return ((MLKEMPrivateKey)key).getPublicKey();}
        check(key instanceof MLDSAPrivateKey&&key.getAlgorithm().equals("ML-DSA-65"),"Expected ML-DSA-65 seed");return ((MLDSAPrivateKey)key).getPublicKey();
    }
    /** The interoperable private encoding contains only a tagged seed; no
     * provider-specific expanded representation or duplicate public material. */
    private static PrivateKeyInfo seedInfo(String role,byte[] seed)throws Exception{
        boolean kem=role.equals("kem-pq");check(seed.length==(kem?64:32),"Wrong PQ seed length");
        return new PrivateKeyInfo(new AlgorithmIdentifier(kem?NISTObjectIdentifiers.id_alg_ml_kem_768:NISTObjectIdentifiers.id_ml_dsa_65),new DERTaggedObject(false,0,new DEROctetString(seed)));
    }
    private static KeyPair generateSeed(String role)throws Exception{
        byte[] seed=random(role.equals("kem-pq")?64:32),der=null;
        try{der=seedInfo(role,seed).getEncoded();PrivateKey key=KeyFactory.getInstance(role.equals("kem-pq")?"ML-KEM":"ML-DSA","BC").generatePrivate(new PKCS8EncodedKeySpec(der));return new KeyPair(publicFromPrivate(key,role),key);}
        finally{wipe(seed);wipe(der);}
    }
    private static byte[] seed(PrivateKey key,String role)throws Exception{return role.equals("kem-pq")?((MLKEMPrivateKey)key).getSeed():((MLDSAPrivateKey)key).getSeed();}
    private static byte[] ml(PrivateKey key,byte[] message)throws Exception{
        var signer=Signature.getInstance("ML-DSA-65","BC");signer.initSign(key,RANDOM);signer.update(message);return signer.sign();
    }
    private static OpenPgp.Signer composite(Keys keys,PrivateKey pq,ExternalMu.Backend hardware){
        return digest->{byte[] ed=hardware.signEd25519(keys.ec(),digest),signature=cat(ed,ml(pq,digest));verifyDigest(signature,digest,keys);return signature;};
    }
    /** Generates software seeds only. Hardware generation and policy checks
     * belong to the separate, serial-bound empty-card provisioning workflow. */
    static Level3Companion create(int serial,Map<String,PublicKey> hardware,List<String> emails,ExternalMu.Backend certification,ExternalMu.Backend signing)throws Exception{
        validateHardware(serial,hardware);check(!emails.isEmpty()&&emails.size()<=5,"Expected 1–5 email addresses");
        var seen=new HashSet<String>();for(String email:emails){validateEmail(email);check(seen.add(email.toLowerCase(Locale.ROOT)),"Duplicate email address");}
        var keys=new LinkedHashMap<String,KeyPair>();
        try{
            for(String role:ROLES)keys.put(role,generateSeed(role));
            Keys cert=new Keys(keys.get("cert-pq").getPublic(),hardware.get("82")),sign=new Keys(keys.get("sign-pq").getPublic(),hardware.get("9c")),kem=new Keys(keys.get("kem-pq").getPublic(),hardware.get("9d"));
            OpenPgp.Signer certify=composite(cert,keys.get("cert-pq").getPrivate(),certification),message=composite(sign,keys.get("sign-pq").getPrivate(),signing);
            long created=now();byte[] primary=keyBody(cert,true,created),signBody=keyBody(sign,true,created),encBody=keyBody(kem,false,created),fp=fingerprint(primary);
            var out=new Buffer();out.put(frame(6,primary));
            byte[] prefs=cat(sub(27,b(1)),sub(11,b(9)),sub(21,b(9)),sub(22,b(2,1,0)),sub(30,b(9)),sub(39,b(9,3,9,2)));
            Request direct=request(keyHash(primary),31,fp,prefs,30);out.put(frame(2,direct.finish(certify.sign(direct.digest()))));
            for(String email:emails){byte[] uid=bytes(email);Request claim=request(cat(keyHash(primary),b(0xb4),n(uid.length,4),uid),19,fp,b(),30);out.put(frame(13,uid));out.put(frame(2,claim.finish(certify.sign(claim.digest()))));}
            byte[] pair=cat(keyHash(primary),keyHash(signBody));Request cross=request(pair,25,fingerprint(signBody),b(),30);byte[] proof=cross.finish(message.sign(cross.digest()));
            Request binding=request(pair,24,fp,cat(sub(27,b(2)),sub(32,proof)),30);out.put(frame(14,signBody));out.put(frame(2,binding.finish(certify.sign(binding.digest()))));
            Request encryption=request(cat(keyHash(primary),keyHash(encBody)),24,fp,sub(27,b(12)),30);out.put(frame(14,encBody));out.put(frame(2,encryption.finish(certify.sign(encryption.digest()))));
            PublicIdentity own=new PublicIdentity(out.toByteArray());
            return new Level3Companion(serial,hardware,keys,own,createAnchors(own,keys.get("sign-pq").getPrivate()));
        }catch(Exception e){destroyKeys(keys);throw e;}
    }
    /** Stable public-only carriers for the existing desktop identity selector.
     * They are marked OpenPGP-only and are not authorizations to send S/MIME.
     * Their exact bytes travel in the authenticated companion so importing on
     * another host does not synthesize a different local identity identifier. */
    Identity anchors(){return anchors;}
    private static Identity createAnchors(PublicIdentity own,PrivateKey signer)throws Exception{
        var name=new org.bouncycastle.asn1.x500.X500NameBuilder(org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN,own.email)
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.OU,"OpenPGP-only companion").build();
        var names=new ArrayList<org.bouncycastle.asn1.x509.GeneralName>();
        for(String email:own.certifiedEmails())names.add(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.rfc822Name,email));
        names.add(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier,ANCHOR_URI+own.fingerprint().toLowerCase(Locale.ROOT)));
        var certs=new ArrayList<java.security.cert.X509Certificate>();
        for(boolean signing:new boolean[]{true,false}){
            var builder=new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name,new java.math.BigInteger(159,RANDOM).add(java.math.BigInteger.ONE),new Date(0),new Date(4102444800000L),name,signing?own.signing.pq():own.encryption.pq());
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,true,new org.bouncycastle.asn1.x509.BasicConstraints(false));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,true,new org.bouncycastle.asn1.x509.KeyUsage(signing?org.bouncycastle.asn1.x509.KeyUsage.digitalSignature:org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName,false,new org.bouncycastle.asn1.x509.GeneralNames(names.toArray(org.bouncycastle.asn1.x509.GeneralName[]::new)));
            var certificate=builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("ML-DSA-65").setProvider("BC").build(signer));
            certs.add(new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC").getCertificate(certificate));
        }
        return new Identity(certs.get(0),null,certs.get(1),null,null);
    }
    static void validateAnchors(Identity anchors,PublicIdentity own)throws Exception{
        check(anchors!=null&&anchors.signingKey()==null&&anchors.encryptionKey()==null&&anchors.traditionalKey()==null,"Public-only companion anchors required");
        same(anchors.signingCert().getPublicKey(),own.signing.pq());same(anchors.encryptionCert().getPublicKey(),own.encryption.pq());
        var expectedEmails=new HashSet<String>();for(String email:own.certifiedEmails())expectedEmails.add(email.toLowerCase(Locale.ROOT));
        String uri=ANCHOR_URI+own.fingerprint().toLowerCase(Locale.ROOT);
        for(var certificate:List.of(anchors.signingCert(),anchors.encryptionCert())){
            check(certificate.getVersion()==3&&certificate.getBasicConstraints()==-1&&certificate.getSigAlgOID().equals(NISTObjectIdentifiers.id_ml_dsa_65.getId()),"Invalid companion anchor profile");
            // Match the explicit carrier purpose across implementations; an
            // ordinary ML-DSA S/MIME certificate is not a companion anchor.
            var subject=org.bouncycastle.asn1.x500.X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            var units=subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.OU);
            check(units.length==1&&units[0].size()==1&&org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(units[0].getFirst().getValue()).equals("OpenPGP-only companion"),"Invalid companion anchor purpose");
            certificate.verify(own.signing.pq(),"BC");certificate.checkValidity();
            check(certificate.getIssuerX500Principal().equals(anchors.signingCert().getSubjectX500Principal()),"Companion anchor issuer mismatch");
            var emails=new HashSet<String>();int markers=0;var sans=certificate.getSubjectAlternativeNames();check(sans!=null,"Missing companion anchor metadata");
            for(var entry:sans){int tag=(Integer)entry.get(0);String value=String.valueOf(entry.get(1));if(tag==1)check(emails.add(value.toLowerCase(Locale.ROOT)),"Duplicate anchor email");else {check(tag==6&&value.equals(uri),"Unexpected companion anchor SAN");markers++;}}
            check(markers==1&&emails.equals(expectedEmails),"Anchor email/fingerprint mismatch");
        }
    }
    private void available()throws Exception{check(!closed,"Companion operation has ended");}
    byte[] sign(byte[] plain,ExternalMu.Backend signing)throws Exception{available();return signed(plain,own,composite(own.signing,software.get("sign-pq").getPrivate(),signing));}
    /** External-μ entry point used by the desktop's existing OpenPGP signer.
     * Only the message-signing key is exposed; certification uses create/seal. */
    byte[] signComponent(PublicKey expected,byte[] mu)throws Exception{
        available();same(expected,own.signing.pq());check(mu.length==64,"Expected ML-DSA external mu");
        byte[] encoded=null;MLDSAPrivateKeyParameters parameters=null;
        try{encoded=software.get("sign-pq").getPrivate().getEncoded();parameters=(MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(encoded);var signer=new MLDSASigner();signer.init(true,new ParametersWithRandom(parameters,RANDOM));return signer.generateMuSignature(mu);}
        finally{wipe(encoded);if(parameters!=null)parameters.destroy();}
    }
    byte[] decapsulate(PublicKey expected,byte[] ciphertext)throws Exception{
        available();same(expected,own.encryption.pq());check(ciphertext.length==1088,"Expected ML-KEM-768 ciphertext");
        byte[] encoded=null;MLKEMPrivateKeyParameters parameters=null;
        try{encoded=software.get("kem-pq").getPrivate().getEncoded();parameters=(MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(encoded);return new org.bouncycastle.crypto.kems.MLKEMExtractor(parameters).extractSecret(ciphertext);}
        finally{wipe(encoded);if(parameters!=null)parameters.destroy();}
    }
    byte[] decrypt(byte[] encoded,ExternalKem.Backend hardware)throws Exception{
        available();var env=envelope(encoded,own);byte[] ct=env.ct(),point=slice(ct,0,32),ml=null,x=null,key=null;
        PublicKey peer=curve25519(point,false);
        try{ml=decapsulate(own.encryption.pq(),slice(ct,32,ct.length));x=hardware.derive(this.hardware.get("9d"),peer);key=combine(ml,x,point,raw(own.encryption.ec()));return env.open(key);}
        finally{wipe(ml);wipe(x);wipe(key);}
    }
    record Component(String role,String algorithm,String storage,String slot,String sha256){}
    record Manifest(int version,int serial,String profile,List<Component> components){}
    private static Component component(String role,String algorithm,String storage,String slot,PublicKey key)throws Exception{return new Component(role,algorithm,storage,slot,hex(hash("SHA-256",key.getEncoded())).toLowerCase(Locale.ROOT));}
    static byte[] manifest(int serial,Map<String,PublicKey> hardware,PublicIdentity own)throws Exception{
        var c=new ArrayList<Component>();
        c.add(component("certification-classical","Ed25519","piv","82",hardware.get("82")));
        c.add(component("signing-classical","Ed25519","piv","9c",hardware.get("9c")));
        c.add(component("decryption-classical","X25519","piv","9d",hardware.get("9d")));
        c.add(component("companion-wrap","P-384","piv","83",hardware.get("83")));
        c.add(component("certification-pq","ML-DSA-65","companion","",parseKey(own.primary,true).pq()));
        c.add(component("signing-pq","ML-DSA-65","companion","",own.signing.pq()));
        c.add(component("decryption-pq","ML-KEM-768","companion","",own.encryption.pq()));
        return bytes(new Gson().toJson(new Manifest(1,serial,"LEVEL3_POLYFILL",List.copyOf(c))));
    }
    record Encoded(int serial,Map<String,PublicKey> hardware,PublicIdentity own,Identity anchors,PublicKey ephemeral,byte[] salt,byte[] nonce,byte[] aad,byte[] ciphertext){}
    /** Authenticate against the supplied live hardware key before interpreting
     * certificate/manifest contents; all checks precede private operations. */
    static Encoded inspect(byte[] stored,int serial,Map<String,PublicKey> expected)throws Exception{
        validateHardware(serial,expected);byte[] expanded=CompanionEncoding.unpack(stored);check(expanded.length<=MAX,"Companion exceeds limit");
        var outer=new DataInputStream(new ByteArrayInputStream(expanded));byte[] body=Level5Companion.field(outer),signature=Level5Companion.field(outer);check(outer.available()==0&&signature.length==3373,"Invalid Level 3 companion signature framing");
        byte[] digest=hash("SHA-512",cat(SIGN_DOMAIN,body));var ed=Signature.getInstance("Ed25519","BC");ed.initVerify(expected.get("82"));ed.update(digest);check(ed.verify(slice(signature,0,64)),"Companion hardware certification signature rejected");
        var in=new DataInputStream(new ByteArrayInputStream(body));check(Arrays.equals(in.readNBytes(8),MAGIC)&&in.readInt()==serial,"Wrong companion format or card");
        var hardware=new LinkedHashMap<String,PublicKey>();for(String slot:SLOTS){PublicKey key=decodePublic(Level5Companion.field(in));same(key,expected.get(slot));hardware.put(slot,key);}
        var own=new PublicIdentity(Level5Companion.field(in));validateCertificate(own,hardware);verifyDigest(signature,digest,parseKey(own.primary,true));
        var converter=new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC");
        var anchors=new Identity(converter.getCertificate(new org.bouncycastle.cert.X509CertificateHolder(Level5Companion.field(in))),null,converter.getCertificate(new org.bouncycastle.cert.X509CertificateHolder(Level5Companion.field(in))),null,null);validateAnchors(anchors,own);
        check(Arrays.equals(Level5Companion.field(in),manifest(serial,hardware,own)),"Companion manifest mismatch");
        PublicKey ephemeral=ec(in.readNBytes(97));byte[] salt=in.readNBytes(32),nonce=in.readNBytes(12);check(salt.length==32&&nonce.length==12,"Truncated wrapping metadata");
        byte[] aad=slice(body,0,body.length-in.available()),cipher=Level5Companion.field(in);check(in.available()==0&&cipher.length>=16&&cipher.length<=8192,"Invalid companion ciphertext framing");
        return new Encoded(serial,Map.copyOf(hardware),own,anchors,ephemeral,salt,nonce,aad,cipher);
    }
    /** PFX contains exactly three named seed-only key bags. Certificate public
     * material already lives in the signed outer envelope, so it is not copied. */
    private byte[] p12()throws Exception{
        available();var contents=new ArrayList<ContentInfo>();
        for(String role:ROLES){byte[] seed=seed(software.get(role).getPrivate(),role);
            try{var bag=new PKCS12SafeBagBuilder(seedInfo(role,seed));bag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,new DERBMPString(role));
                // PKCS12PfxPduBuilder defaults to BER-indefinite wrapping. Use
                // explicit DER at every encapsulated layer so strict native
                // implementations need no BER or streaming ASN.1 decoder.
                byte[] safe=new DERSequence(bag.build().toASN1Structure()).getEncoded(ASN1Encoding.DER);
                contents.add(new ContentInfo(PKCSObjectIdentifiers.data,new DEROctetString(safe.clone())));wipe(safe);
            }
            finally{wipe(seed);}
        }
        byte[] authenticated=new AuthenticatedSafe(contents.toArray(ContentInfo[]::new)).getEncoded(ASN1Encoding.DER);
        try{byte[] encoded=new Pfx(new ContentInfo(PKCSObjectIdentifiers.data,new DEROctetString(authenticated)),null).getEncoded(ASN1Encoding.DER);check(encoded.length<=4096,"Unexpected seed container size");return encoded;}
        finally{wipe(authenticated);}
    }
    /** Rewraps the same seeds using fresh ephemeral ECDH, salt and AEAD nonce. */
    byte[] seal(ExternalMu.Backend certification)throws Exception{
        available();byte[] p12=null,plain=null,secret=null,key=null;
        var generator=KeyPairGenerator.getInstance("EC","BC");generator.initialize(new ECGenParameterSpec("secp384r1"));var ephemeral=generator.generateKeyPair();
        try{
            p12=p12();var payload=new WipeBuffer();try{Level5Companion.field(new DataOutputStream(payload),p12);plain=payload.toByteArray();}finally{payload.clear();}
            var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.write(MAGIC);out.writeInt(serial);
            for(String slot:SLOTS)Level5Companion.field(out,hardware.get(slot).getEncoded());Level5Companion.field(out,own.encoded);Level5Companion.field(out,anchors.signingCert().getEncoded());Level5Companion.field(out,anchors.encryptionCert().getEncoded());Level5Companion.field(out,manifest(serial,hardware,own));out.write(raw(ephemeral.getPublic()));byte[] salt=random(32),nonce=random(12);out.write(salt);out.write(nonce);byte[] aad=bytes.toByteArray();
            secret=derive(ephemeral.getPrivate(),hardware.get("83"));key=kdf(secret,salt,cat(KDF_DOMAIN,hash("SHA-256",aad)),32);Level5Companion.field(out,aead(true,3,key,nonce,aad,plain));
            byte[] body=bytes.toByteArray(),digest=hash("SHA-512",cat(SIGN_DOMAIN,body));byte[] signature=composite(parseKey(own.primary,true),software.get("cert-pq").getPrivate(),certification).sign(digest);
            var result=new ByteArrayOutputStream();var writer=new DataOutputStream(result);Level5Companion.field(writer,body);Level5Companion.field(writer,signature);check(result.size()<=MAX,"Companion exceeds allocation");byte[] packed=CompanionEncoding.pack(result.toByteArray());inspect(packed,serial,hardware);return packed;
        }finally{wipe(p12);wipe(plain);wipe(secret);wipe(key);destroy(ephemeral.getPrivate());}
    }
    /** Decode a seed-only key bag, independently derive its public key, and
     * refuse alternate expanded encodings before constructing an active key. */
    private static KeyPair readSeed(PrivateKeyInfo info,String role)throws Exception{
        boolean kem=role.equals("kem-pq");check(info.getVersion().intValueExact()==0&&info.getAttributes()==null&&!info.hasPublicKey(),"Unexpected seed PKCS8 metadata");
        check(info.getPrivateKeyAlgorithm().getParameters()==null&&info.getPrivateKeyAlgorithm().getAlgorithm().equals(kem?NISTObjectIdentifiers.id_alg_ml_kem_768:NISTObjectIdentifiers.id_ml_dsa_65),"Wrong seed algorithm");
        byte[] encoded=null,seed=null;
        try{
            ASN1Primitive value=info.parsePrivateKey().toASN1Primitive();check(value instanceof ASN1TaggedObject&&((ASN1TaggedObject)value).hasContextTag(0),"Seed-only PKCS8 required");
            seed=ASN1OctetString.getInstance((ASN1TaggedObject)value,false).getOctets();check(seed.length==(kem?64:32),"Wrong private seed length");
            encoded=info.getEncoded();check(Arrays.equals(encoded,seedInfo(role,seed).getEncoded()),"Noncanonical seed PKCS8");
            PrivateKey key=KeyFactory.getInstance(kem?"ML-KEM":"ML-DSA","BC").generatePrivate(new PKCS8EncodedKeySpec(encoded));return new KeyPair(publicFromPrivate(key,role),key);
        }finally{wipe(encoded);wipe(seed);}
    }
    static Level3Companion restore(byte[] encoded,int serial,Map<String,PublicKey> expected,ExternalKem.Backend hardware)throws Exception{
        Encoded env=inspect(encoded,serial,expected);byte[] secret=null,key=null,plain=null,p12=null;var keys=new LinkedHashMap<String,KeyPair>();
        try{
            secret=hardware.derive(expected.get("83"),env.ephemeral);check(secret.length==48&&!Arrays.equals(secret,new byte[48]),"Invalid wrapping secret");key=kdf(secret,env.salt,cat(KDF_DOMAIN,hash("SHA-256",env.aad)),32);plain=aead(false,3,key,env.nonce,env.aad,env.ciphertext);
            var input=new DataInputStream(new ByteArrayInputStream(plain));p12=Level5Companion.field(input);check(input.available()==0&&p12.length<=4096,"Invalid seed container framing");
            var pfx=new PKCS12PfxPdu(p12);check(!pfx.hasMac()&&pfx.getContentInfos().length==3,"Unexpected inner P12 metadata");
            for(var content:pfx.getContentInfos()){
                check(content.getContentType().equals(PKCSObjectIdentifiers.data),"Encrypted inner key bag rejected");var bags=new PKCS12SafeBagFactory(content).getSafeBags();check(bags.length==1,"Expected one key per content record");
                var bag=bags[0];check(bag.getType().equals(PKCSObjectIdentifiers.keyBag),"Only seed key bags are permitted");var attrs=bag.getAttributes();check(attrs.length==1&&attrs[0].getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_friendlyName)&&attrs[0].getAttrValues().size()==1,"Invalid seed bag attributes");
                String role=ASN1BMPString.getInstance(attrs[0].getAttrValues().getObjectAt(0)).getString();check(List.of(ROLES).contains(role)&&!keys.containsKey(role),"Unknown or duplicate seed bag");keys.put(role,readSeed((PrivateKeyInfo)bag.getBagValue(),role));
            }
            return new Level3Companion(serial,expected,keys,env.own,env.anchors);
        }catch(Exception e){destroyKeys(keys);throw e;}
        finally{wipe(secret);wipe(key);wipe(plain);wipe(p12);}
    }
    private static final class WipeBuffer extends ByteArrayOutputStream {void clear(){Arrays.fill(buf,(byte)0);reset();}}
    private static void destroy(PrivateKey key){try{key.destroy();}catch(Exception ignored){/* Runtime/provider copies remain a documented limitation. */}}
    private static void destroyKeys(Map<String,KeyPair> keys){for(KeyPair pair:keys.values())destroy(pair.getPrivate());keys.clear();}
    public void close(){if(!closed){closed=true;destroyKeys(software);}}
}
