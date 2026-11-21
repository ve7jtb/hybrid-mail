package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Operation-scoped software Edwards components for a hardware Level 5 identity.
 * The only persistent private material is an authenticated ciphertext containing
 * an empty-password, three-entry PKCS#12. Slot 82 performs ECDH to open it;
 * slots 86/9c/9d retain their existing certification/signing/decapsulation keys.
 * This is classical protection at rest, NOT post-quantum encryption of the P12.
 */
public final class Level5Companion implements AutoCloseable {
    static final int MAX=65536;
    static final byte[] MAGIC=bytes("PQMCP001");
    static final byte[] ULTRA_MAGIC=bytes("PQMCP002");
    static final String[] SLOTS={"86","9c","9d","82"};
    static final String[] ROLES={"cert-ed","sign-ed","kem-x"};
    private final Map<String,KeyPair> software;
    final int serial;
    final Map<String,PublicKey> hardware;
    final PublicIdentity own;
    private boolean closed;

    private Level5Companion(int serial,Map<String,PublicKey> hardware,Map<String,KeyPair> software,PublicIdentity own)throws Exception {
        this.serial=serial;this.hardware=Map.copyOf(hardware);this.software=new LinkedHashMap<>(software);this.own=own;
        validateHardware(serial,hardware);
        // Reject a certificate or software component from a different identity.
        Keys cert=parseKey(own.primary,true);
        same(cert.pq(),hardware.get("86"));same(own.signing.pq(),hardware.get("9c"));same(own.encryption.pq(),hardware.get("9d"));
        validateSoftware(this.software,cert,own.signing,own.encryption);
        check(own.separated()&&algorithm(own.signing,true)==31&&algorithm(own.encryption,false)==36,"Expected separated Level 5 certificate");
    }
    private static void validateSoftware(Map<String,KeyPair> software,Keys cert,Keys sign,Keys kem)throws Exception{
        check(software.keySet().equals(Set.of(ROLES)),"Incomplete companion software key roles");
        same(cert.ec(),software.get("cert-ed").getPublic());same(sign.ec(),software.get("sign-ed").getPublic());same(kem.ec(),software.get("kem-x").getPublic());
        // A PKCS#12 MAC alone does not prove that each stored private key matches
        // its certificate. Exercise each pair before making the identity usable.
        byte[] challenge=random(32);
        for(String role:List.of("cert-ed","sign-ed")){var signer=Signature.getInstance("Ed448","BC");signer.initSign(software.get(role).getPrivate());signer.update(challenge);byte[] sig=signer.sign();var v=Signature.getInstance("Ed448","BC");v.initVerify(software.get(role).getPublic());v.update(challenge);check(v.verify(sig),"Companion Ed448 private/public mismatch");}
        var peer=SoftwareOpenPgp.generate("X448");byte[] a=null,b=null;
        try{a=derive(software.get("kem-x").getPrivate(),peer.getPublic());b=derive(peer.getPrivate(),software.get("kem-x").getPublic());check(MessageDigest.isEqual(a,b),"Companion X448 private/public mismatch");}finally{wipe(a);wipe(b);destroy(peer.getPrivate());}
    }
    static void same(PublicKey a,PublicKey b)throws Exception{check(a!=null&&b!=null&&MessageDigest.isEqual(a.getEncoded(),b.getEncoded()),"Companion key binding mismatch");}
    static void validateHardware(int serial,Map<String,PublicKey> h)throws Exception{
        check(serial>0&&h.keySet().equals(Set.of(SLOTS)),"Invalid companion serial or slot layout");
        for(String slot:List.of("86","9c"))check(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(h.get(slot).getEncoded()).getAlgorithm().getAlgorithm().getId().equals("2.16.840.1.101.3.4.3.19"),"Expected ML-DSA-87");
        check(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(h.get("9d").getEncoded()).getAlgorithm().getAlgorithm().getId().equals("2.16.840.1.101.3.4.4.3"),"Expected ML-KEM-1024");
        same(ec(raw(h.get("82"))),h.get("82"));
    }
    static PublicKey decodePublic(byte[] der)throws Exception{return new JcaPEMKeyConverterCompat().decode(der);}
    // Keep ASN.1 decoding in BC rather than inferring algorithms from untrusted labels.
    private static final class JcaPEMKeyConverterCompat {
        PublicKey decode(byte[] der)throws Exception{return new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC").getPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(der));}
    }
    static byte[] ml(PublicKey key,byte[] message,ExternalMu.Backend backend)throws Exception{
        var s=Signature.getInstance("ML-DSA-87",ExternalMu.PROVIDER);s.initSign(new ExternalMu.TokenKey(key,backend));s.update(message);return s.sign();
    }
    private static OpenPgp.Signer composite(Keys keys,PrivateKey ed,ExternalMu.Backend backend){return digest->{var s=Signature.getInstance("Ed448","BC");s.initSign(ed);s.update(digest);byte[] signature=cat(s.sign(),ml(keys.pq(),digest,backend));verifyDigest(signature,digest,keys);return signature;};}
    /** Generates software keys only; callers supply already-checked hardware public keys. */
    static Level5Companion create(int serial,Map<String,PublicKey> h,List<String> emails,ExternalMu.Backend certification,ExternalMu.Backend signing)throws Exception{
        validateHardware(serial,h);check(!emails.isEmpty()&&emails.size()<=5,"Expected 1–5 email addresses");for(String email:emails)validateEmail(email);
        var keys=new LinkedHashMap<String,KeyPair>();keys.put("cert-ed",SoftwareOpenPgp.generate("Ed448"));keys.put("sign-ed",SoftwareOpenPgp.generate("Ed448"));keys.put("kem-x",SoftwareOpenPgp.generate("X448"));
        try {
            Keys cert=new Keys(h.get("86"),keys.get("cert-ed").getPublic()),sign=new Keys(h.get("9c"),keys.get("sign-ed").getPublic()),kem=new Keys(h.get("9d"),keys.get("kem-x").getPublic());
            OpenPgp.Signer certify=composite(cert,keys.get("cert-ed").getPrivate(),certification),message=composite(sign,keys.get("sign-ed").getPrivate(),signing);
            byte[] primary=keyBody(cert,true,now()),signBody=keyBody(sign,true,now()),encBody=keyBody(kem,false,now()),fp=fingerprint(primary);
            var out=new Buffer();out.put(frame(6,primary));
            byte[] prefs=cat(sub(27,b(1)),sub(11,b(9)),sub(21,b(10)),sub(22,b(2,1,0)),sub(30,b(9)),sub(39,b(9,3,9,2)));
            Request direct=request(keyHash(primary),31,fp,prefs,31);out.put(frame(2,direct.finish(certify.sign(direct.digest()))));
            for(String email:emails){byte[] uid=bytes(email);Request certReq=request(cat(keyHash(primary),b(0xb4),n(uid.length,4),uid),19,fp,b(),31);out.put(frame(13,uid));out.put(frame(2,certReq.finish(certify.sign(certReq.digest()))));}
            byte[] pair=cat(keyHash(primary),keyHash(signBody));Request cross=request(pair,25,fingerprint(signBody),b(),31);byte[] proof=cross.finish(message.sign(cross.digest()));
            Request binding=request(pair,24,fp,cat(sub(27,b(2)),sub(32,proof)),31);out.put(frame(14,signBody));out.put(frame(2,binding.finish(certify.sign(binding.digest()))));
            Request enc=request(cat(keyHash(primary),keyHash(encBody)),24,fp,sub(27,b(12)),31);out.put(frame(14,encBody));out.put(frame(2,enc.finish(certify.sign(enc.digest()))));
            return new Level5Companion(serial,h,keys,new PublicIdentity(out.toByteArray()));
        }catch(Exception e){for(KeyPair k:keys.values())destroy(k.getPrivate());throw e;}
    }
    private void available()throws Exception{check(!closed,"Companion operation has ended");}
    private byte[] ed(String role,byte[] message)throws Exception{available();var s=Signature.getInstance("Ed448","BC");s.initSign(software.get(role).getPrivate());s.update(message);return s.sign();}
    byte[] signComponent(PublicKey expected,byte[] digest)throws Exception{same(expected,software.get("sign-ed").getPublic());return ed("sign-ed",digest);}
    byte[] deriveComponent(PublicKey expected,PublicKey peer)throws Exception{available();same(expected,software.get("kem-x").getPublic());check(raw(peer).length==56,"Expected X448 peer");byte[] secret=derive(software.get("kem-x").getPrivate(),peer);check(!Arrays.equals(secret,new byte[56]),"Zero X448 shared secret");return secret;}
    byte[] sign(byte[] plain,ExternalMu.Backend backend)throws Exception{available();return signed(plain,own,composite(own.signing,software.get("sign-ed").getPrivate(),backend));}
    byte[] decrypt(byte[] encrypted,ExternalKem.Backend backend)throws Exception{
        available();var envelope=envelope(encrypted,own);byte[] ct=envelope.ct(),point=slice(ct,0,56),ml=null,x=null,kek=null;
        try{PublicKey peer=decodePublic(new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.101.111")),point).getEncoded());x=deriveComponent(own.encryption.ec(),peer);ml=backend.decapsulate(hardware.get("9d"),slice(ct,56,ct.length));kek=combine(ml,x,point,raw(own.encryption.ec()));return envelope.open(kek);}finally{wipe(ml);wipe(x);wipe(kek);}
    }
    /** Length-prefixed canonical fields; bounded before any allocation or private operation. */
    static void field(DataOutputStream out,byte[] value)throws Exception{check(value.length<=MAX,"Companion field too large");out.writeInt(value.length);out.write(value);}
    static byte[] field(DataInputStream in)throws Exception{int n=in.readInt();check(n>=0&&n<=MAX&&n<=in.available(),"Invalid companion field length");return in.readNBytes(n);}
    record Encoded(int serial,Map<String,PublicKey> hardware,PublicIdentity own,PublicKey ephemeral,byte[] salt,byte[] nonce,byte[] aad,byte[] ciphertext,boolean ultra,byte[] template){}
    /** Verify the hardware certification signature before trusting any envelope metadata. */
    static Encoded inspect(byte[] bytes,int serial,Map<String,PublicKey> expected)throws Exception{
        return inspect(bytes,serial,expected,null);
    }
    /** Validate all public inputs before any private operation. An ultra
     * envelope can be inspected without regenerating its certificate; routine
     * operations supply a validated cache, while explicit restore reconstructs.
     */
    static Encoded inspect(byte[] bytes,int serial,Map<String,PublicKey> expected,PublicIdentity cached)throws Exception{
        bytes=CompanionEncoding.unpack(bytes);
        validateHardware(serial,expected);check(bytes.length<=MAX,"Companion exceeds maximum size");var outer=new DataInputStream(new ByteArrayInputStream(bytes));byte[] body=field(outer),signature=field(outer);check(outer.available()==0&&signature.length==4627,"Invalid companion signature framing");
        var verifier=Signature.getInstance("ML-DSA-87","BC");verifier.initVerify(expected.get("86"));verifier.update(body);check(verifier.verify(signature),"Companion hardware signature rejected");
        var in=new DataInputStream(new ByteArrayInputStream(body));byte[] magic=in.readNBytes(8);boolean ultra=Arrays.equals(magic,ULTRA_MAGIC);check((ultra||Arrays.equals(magic,MAGIC))&&in.readInt()==serial,"Wrong companion format or card");
        var h=new LinkedHashMap<String,PublicKey>();for(String slot:SLOTS){PublicKey key=decodePublic(field(in));same(key,expected.get(slot));h.put(slot,key);}
        byte[] certificate=field(in),manifest=field(in),template=null;PublicIdentity own=null;
        if(ultra){
            template=certificate;var plan=UltraCertificate.parse(template);KeyLayout.companion(manifest,serial,h,plan);
            same(plan.certificationKeys().pq(),h.get("86"));same(plan.signingKeys().pq(),h.get("9c"));same(plan.encryptionKeys().pq(),h.get("9d"));
            if(cached!=null){UltraCertificate.validateCached(template,cached);own=new PublicIdentity(cached.encoded);}
        }else{
            own=new PublicIdentity(certificate);KeyLayout.companion(manifest,serial,h,own);Keys primary=parseKey(own.primary,true);same(primary.pq(),h.get("86"));same(own.signing.pq(),h.get("9c"));same(own.encryption.pq(),h.get("9d"));
            check(own.separated()&&algorithm(own.signing,true)==31&&algorithm(own.encryption,false)==36,"Wrong companion OpenPGP profile");
        }
        PublicKey ephemeral=ec(in.readNBytes(97));byte[] salt=in.readNBytes(32),nonce=in.readNBytes(12);int aadSize=body.length-in.available();byte[] aad=slice(body,0,aadSize),cipher=field(in);check(in.available()==0&&cipher.length>=16,"Invalid companion encryption framing");
        return new Encoded(serial,h,own,ephemeral,salt,nonce,aad,cipher,ultra,template);
    }
    /** Encrypt the empty-password P12. The outer AEAD is the confidentiality boundary. */
    byte[] seal(ExternalMu.Backend certification)throws Exception{
        return seal(certification,false);
    }
    /** Convert an unlocked existing identity, keeping every software/hardware
     * key and fingerprint. Only wrapping randomness and envelope signature are
     * fresh; certificate self-signatures are reconstructed during first import.
     */
    byte[] toUltra(ExternalMu.Backend certification)throws Exception{
        return seal(certification,true);
    }
    private byte[] seal(ExternalMu.Backend certification,boolean ultra)throws Exception{
        byte[] certificate=ultra?UltraCertificate.template(own):own.encoded;
        available();byte[] p12=null,plain=null,secret=null,key=null;char[] password=new char[0];
        var ephemeral=KeyPairGenerator.getInstance("EC","BC");ephemeral.initialize(new ECGenParameterSpec("secp384r1"));KeyPair pair=ephemeral.generateKeyPair();
        try{
            // No inner encryption or MAC is needed: the signed AES-GCM envelope
            // authenticates this complete PFX. Unencrypted key bags stay in RAM.
            var pfx=new org.bouncycastle.pkcs.PKCS12PfxPduBuilder();
            for(String role:ROLES){
                KeyPair k=software.get(role);var dn=new X500Name("CN=PQ Mail companion "+role);
                var builder=new JcaX509v3CertificateBuilder(dn,new java.math.BigInteger(128,RANDOM).add(java.math.BigInteger.ONE),new Date(0),new Date(4102444800000L),dn,k.getPublic());
                var cert=builder.build(new JcaContentSignerBuilder("Ed448").setProvider("BC").build(software.get("cert-ed").getPrivate()));
                var id=new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils().createSubjectKeyIdentifier(k.getPublic());
                byte[] privateEncoding=k.getPrivate().getEncoded();
                try{
                    var kb=new org.bouncycastle.pkcs.PKCS12SafeBagBuilder(org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(privateEncoding));
                    var cb=new org.bouncycastle.pkcs.PKCS12SafeBagBuilder(cert);
                    for(var bag:List.of(kb,cb)){bag.addBagAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_friendlyName,new org.bouncycastle.asn1.DERBMPString(role));bag.addBagAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_localKeyId,id);pfx.addData(bag.build());}
                }finally{wipe(privateEncoding);}
            }
            p12=pfx.build(null,password).getEncoded();
            var payload=new WipeBuffer();try{var out=new DataOutputStream(payload);field(out,p12);plain=payload.toByteArray();}finally{payload.clear();}
            var body=new ByteArrayOutputStream();var out=new DataOutputStream(body);out.write(ultra?ULTRA_MAGIC:MAGIC);out.writeInt(serial);for(String slot:SLOTS)field(out,hardware.get(slot).getEncoded());field(out,certificate);field(out,KeyLayout.encode(KeyLayout.companion(serial,hardware,own)));out.write(raw(pair.getPublic()));byte[] salt=random(32),nonce=random(12);out.write(salt);out.write(nonce);byte[] aad=body.toByteArray();
            secret=derive(pair.getPrivate(),hardware.get("82"));key=kdf(secret,salt,cat(bytes("PQMail companion P384 v1"),hash("SHA-256",aad)),32);
            field(out,aead(true,3,key,nonce,aad,plain));byte[] signed=body.toByteArray(),signature=ml(hardware.get("86"),signed,certification);var encoded=new ByteArrayOutputStream();var result=new DataOutputStream(encoded);field(result,signed);field(result,signature);check(encoded.size()<=MAX,"Companion exceeds card allocation");byte[] bytes=CompanionEncoding.pack(encoded.toByteArray());inspect(bytes,serial,hardware);return bytes;
        }finally{Arrays.fill(password,'\0');wipe(p12);wipe(plain);wipe(secret);wipe(key);destroy(pair.getPrivate());}
    }
    /** Unlock once for a single operation. Callers MUST close the result in finally. */
    static Level5Companion restore(byte[] encoded,int serial,Map<String,PublicKey> expected,ExternalKem.Backend backend)throws Exception{
        return restore(encoded,serial,expected,backend,null);
    }
    static Level5Companion restore(byte[] encoded,int serial,Map<String,PublicKey> expected,ExternalKem.Backend backend,PublicIdentity cached)throws Exception{
        Encoded env=inspect(encoded,serial,expected,cached);
        // A missing or bad cache must not trigger a decryption PIN or quietly
        // regenerate signatures. Reconstruction is an explicit import action.
        check(env.own!=null,"Ultra companion requires its matching cached certificate or explicit reconstruction");
        var keys=unlock(env,expected,backend);
        try{return new Level5Companion(serial,expected,keys,env.own);}
        catch(Exception e){destroyKeys(keys);throw e;}
    }
    static Level5Companion reconstruct(byte[] encoded,int serial,Map<String,PublicKey> expected,ExternalKem.Backend backend,ExternalMu.Backend certification,ExternalMu.Backend signing)throws Exception{
        Encoded env=inspect(encoded,serial,expected);check(env.ultra,"Reconstruction requires an ultra companion");
        var plan=UltraCertificate.parse(env.template);var keys=unlock(env,expected,backend);
        try{
            // Confirm the decrypted software pairs match the authenticated key
            // packet bodies before authorizing even the first hardware signer.
            validateSoftware(keys,plan.certificationKeys(),plan.signingKeys(),plan.encryptionKeys());
            PublicIdentity own=plan.reconstruct(composite(plan.certificationKeys(),keys.get("cert-ed").getPrivate(),certification),composite(plan.signingKeys(),keys.get("sign-ed").getPrivate(),signing));
            return new Level5Companion(serial,expected,keys,own);
        }catch(Exception e){destroyKeys(keys);throw e;}
    }
    private static void destroyKeys(Map<String,KeyPair> keys){for(KeyPair pair:keys.values())destroy(pair.getPrivate());keys.clear();}
    private static Map<String,KeyPair> unlock(Encoded env,Map<String,PublicKey> expected,ExternalKem.Backend backend)throws Exception{
        byte[] secret=null,key=null,plain=null,p12=null;char[] password=new char[0];var keys=new LinkedHashMap<String,KeyPair>();var privates=new HashMap<String,PrivateKey>();
        try{
            secret=backend.derive(expected.get("82"),env.ephemeral);check(secret.length==48&&!Arrays.equals(secret,new byte[48]),"Invalid P-384 wrapping secret");key=kdf(secret,env.salt,cat(bytes("PQMail companion P384 v1"),hash("SHA-256",env.aad)),32);plain=aead(false,3,key,env.nonce,env.aad,env.ciphertext);
            var in=new DataInputStream(new ByteArrayInputStream(plain));p12=field(in);check(in.available()==0,"Trailing companion private data");
            var pfx=new org.bouncycastle.pkcs.PKCS12PfxPdu(p12);check(!pfx.hasMac(),"Unexpected inner P12 MAC");
            var publics=new HashMap<String,PublicKey>();
            for(var info:pfx.getContentInfos()){
                check(info.getContentType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data),"Unexpected encrypted P12 bag");
                for(var bag:new org.bouncycastle.pkcs.PKCS12SafeBagFactory(info).getSafeBags()){
                    String role=null;
                    for(var attr:bag.getAttributes())if(attr.getAttrType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_friendlyName)){check(role==null&&attr.getAttrValues().size()==1,"Duplicate bag name");role=org.bouncycastle.asn1.ASN1BMPString.getInstance(attr.getAttrValues().getObjectAt(0)).getString();}
                    check(role!=null&&List.of(ROLES).contains(role),"Unknown companion bag");
                    if(bag.getType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.keyBag)){
                        check(!privates.containsKey(role),"Duplicate private key");privates.put(role,new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC").getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo)bag.getBagValue()));
                    }else{check(bag.getType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.certBag)&&!publics.containsKey(role),"Unexpected P12 bag");publics.put(role,new JcaX509CertificateConverter().setProvider("BC").getCertificate((org.bouncycastle.cert.X509CertificateHolder)bag.getBagValue()).getPublicKey());}
                }
            }
            check(privates.size()==3&&publics.size()==3,"Incomplete companion keys");
            for(String role:ROLES)keys.put(role,new KeyPair(publics.get(role),privates.get(role)));
            return keys;
        }catch(Exception e){for(PrivateKey privateKey:privates.values())destroy(privateKey);throw e;}
        finally{if(password!=null)Arrays.fill(password,'\0');wipe(secret);wipe(key);wipe(plain);wipe(p12);}
    }
    private static final class WipeBuffer extends ByteArrayOutputStream {void clear(){Arrays.fill(buf,(byte)0);reset();}}
    private static void destroy(PrivateKey key){try{key.destroy();}catch(Exception ignored){/* Provider may not implement Destroyable; release references on close. */}}
    public void close(){if(!closed){closed=true;for(KeyPair pair:software.values())destroy(pair.getPrivate());software.clear();}}
}
