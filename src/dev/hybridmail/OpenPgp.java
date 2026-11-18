package dev.hybridmail;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.asn1.sec.*;
import org.bouncycastle.crypto.kems.*;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.*;
import org.bouncycastle.jcajce.*;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import jakarta.mail.internet.*;

/** Bounded RFC 9580 / RFC 9980 codec for draft-nist-bp-comp-05 IDs 41/37.
 * No CMS signature representatives or CMS KEM labels are reused here.
 */
public final class OpenPgp {
    static {MailEngine.init();}
    static final class Buffer extends ByteArrayOutputStream {void put(byte[] value){write(value,0,value.length);}}
    static final int LIMIT=20*1024*1024;
    static final SecureRandom RANDOM=new SecureRandom();
    static void check(boolean value,String message)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException(message);}
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static byte[] cat(byte[]...items){var out=new Buffer();for(byte[] b:items)out.put(b);return out.toByteArray();}
    static byte[] b(int...values){byte[] out=new byte[values.length];for(int i=0;i<values.length;i++)out[i]=(byte)values[i];return out;}
    static byte[] n(long value,int size){byte[] out=new byte[size];for(int i=size-1;i>=0;i--){out[i]=(byte)value;value>>>=8;}return out;}
    static byte[] random(int count){byte[] out=new byte[count];RANDOM.nextBytes(out);return out;}
    static byte[] hash(String algorithm,byte[] value)throws Exception{return MessageDigest.getInstance(algorithm,"BC").digest(value);}
    static byte[] slice(byte[] d,int from,int to){return Arrays.copyOfRange(d,from,to);}
    static long now(){return System.currentTimeMillis()/1000;}
    static byte[] frame(int tag,byte[] body){return cat(b(0xc0|tag,255),n(body.length,4),body);}
    static byte[] sub(int tag,byte[] body){return cat(b(255),n(body.length+1,4),b(tag),body);}
    static byte[] keyHash(byte[] body){return cat(b(0x9b),n(body.length,4),body);}
    static byte[] fingerprint(byte[] body)throws Exception{return hash("SHA-256",keyHash(body));}
    static String hex(byte[] value){StringBuilder s=new StringBuilder();for(byte v:value)s.append(String.format("%02x",v&255));return s.toString();}
    static void wipe(byte[] value){if(value!=null)Arrays.fill(value,(byte)0);}
    public static byte[] armor(byte[] data,String kind){return bytes("-----BEGIN PGP "+kind+"-----\r\n\r\n"+Base64.getMimeEncoder(64,b(13,10)).encodeToString(data)+"\r\n-----END PGP "+kind+"-----\r\n");}
    static byte[] unarmor(byte[] input,String kind)throws Exception {
        check(input.length<=LIMIT,"OpenPGP input exceeds limit");String s=new String(input,StandardCharsets.UTF_8);
        if(!s.startsWith("-----BEGIN"))return input;
        String[] lines=s.replace("\r\n","\n").split("\n");check(lines[0].equals("-----BEGIN PGP "+kind+"-----"),"Wrong armor type");
        boolean body=false,end=false;StringBuilder encoded=new StringBuilder();
        for(int i=1;i<lines.length;i++){String l=lines[i];if(l.equals("-----END PGP "+kind+"-----")){end=true;break;}if(!body){if(l.isEmpty())body=true;else check(l.contains(":"),"Invalid armor header");continue;}if(!l.startsWith("="))encoded.append(l.replaceAll("\\s",""));}
        check(end,"Truncated armor");return Base64.getDecoder().decode(encoded.toString());
    }
    static final class Reader {
        final byte[] data;int at;
        Reader(byte[] data){this.data=data;}
        int left(){return data.length-at;}
        byte[] take(int count)throws Exception{check(count>=0&&count<=left(),"Truncated OpenPGP data");byte[] result=slice(data,at,at+count);at+=count;return result;}
        int one()throws Exception{return take(1)[0]&255;}
        long number(int count)throws Exception{long v=0;for(byte c:take(count))v=v*256+(c&255);return v;}
        int length()throws Exception{int a=one();if(a<192)return a;if(a<224)return(a-192)*256+one()+192;if(a==255){long n=number(4);check(n<=LIMIT,"OpenPGP length exceeds limit");return(int)n;}return -(1<<(a&31));}
    }
    record Packet(int tag,byte[] body){}
    static List<Packet> packets(byte[] data)throws Exception {
        check(data.length<=LIMIT,"OpenPGP message exceeds limit");Reader r=new Reader(data);List<Packet> out=new ArrayList<>();
        while(r.left()>0){check(out.size()<64,"Too many OpenPGP packets");int header=r.one();check((header&0xc0)==0xc0,"Legacy OpenPGP packets are unsupported");int tag=header&63;var body=new Buffer();int count;
            do{count=r.length();check(count!=Integer.MIN_VALUE,"Invalid partial length");int len=Math.abs(count);check(len<=LIMIT-body.size()&&(count>=0||List.of(8,9,11,18).contains(tag)),"Invalid partial packet");body.put(r.take(len));}while(count<0);
            if(tag==21)continue;if(tag==10){check(Arrays.equals(body.toByteArray(),bytes("PGP")),"Invalid marker");continue;}out.add(new Packet(tag,body.toByteArray()));
        }return out;
    }
    static byte[] raw(PublicKey key){return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getOctets();}
    static PublicKey ec(byte[] point)throws Exception {
        check(point.length==97&&point[0]==4,"Expected P-384 uncompressed point");
        var curve=SECNamedCurves.getByName("secp384r1").getCurve();var q=curve.decodePoint(point);check(!q.isInfinity()&&q.isValid(),"Invalid EC point");
        return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,SECObjectIdentifiers.secp384r1),point).getEncoded()));
    }
    static PublicKey pq(byte[] raw,boolean signing)throws Exception {
        var oid=new ASN1ObjectIdentifier(signing?"2.16.840.1.101.3.4.3.18":"2.16.840.1.101.3.4.4.2");
        return KeyFactory.getInstance(signing?"ML-DSA":"ML-KEM","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid),raw).getEncoded()));
    }
    record Keys(PublicKey pq,PublicKey ec){}
    static Keys parseKey(byte[] data,boolean signing)throws Exception {
        Reader r=new Reader(data);check(r.one()==6,"OpenPGP v6 required");check(r.number(4)<=now()+300,"Future OpenPGP key");check(r.one()==(signing?41:37),"Only draft Level 3 hybrid OpenPGP is supported");int size=(int)r.number(4);check(size==(signing?2049:1281)&&size==r.left(),"Invalid key size");PublicKey ec=ec(r.take(97));return new Keys(pq(r.take(r.left()),signing),ec);
    }
    static byte[] keyBody(Keys k,boolean signing,long created){byte[] material=cat(raw(k.ec),raw(k.pq));return cat(b(6),n(created,4),b(signing?41:37),n(material.length,4),material);}
    public static boolean supported(Identity id){return id!=null&&Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm())&&id.encryptionCert()!=null&&Identity.HYBRID_768_P384_KEM.equals(id.encryptionCert().getPublicKey().getAlgorithm());}
    static Keys keys(PublicKey key)throws Exception{check(key instanceof CompositePublicKey,"Composite key required");var list=((CompositePublicKey)key).getPublicKeys();check(list.size()==2,"Invalid composite key");return new Keys(list.get(0),list.get(1));}
    static byte[] fixed(byte[] der)throws Exception {
        ASN1Sequence seq=ASN1Sequence.getInstance(der);check(seq.size()==2,"Invalid ECDSA");byte[] out=new byte[96];
        for(int i=0;i<2;i++){BigInteger v=ASN1Integer.getInstance(seq.getObjectAt(i)).getValue();check(v.signum()>0&&v.bitLength()<=384,"Invalid ECDSA scalar");byte[] x=v.toByteArray();int start=x.length>48?1:0;System.arraycopy(x,start,out,48*i+48-(x.length-start),x.length-start);}return out;
    }
    static byte[] der(byte[] fixed)throws Exception{check(fixed.length==96,"Invalid ECDSA size");return new DERSequence(new ASN1Encodable[]{new ASN1Integer(new BigInteger(1,slice(fixed,0,48))),new ASN1Integer(new BigInteger(1,slice(fixed,48,96)))}).getEncoded();}
    static void verifyDigest(byte[] sig,byte[] digest,Keys keys)throws Exception {
        check(sig.length==3405,"Invalid OpenPGP hybrid signature length");
        Signature ec=Signature.getInstance("NONEwithECDSA","BC");ec.initVerify(keys.ec);ec.update(digest);check(ec.verify(der(slice(sig,0,96))),"Invalid OpenPGP ECDSA signature");
        Signature ml=Signature.getInstance("ML-DSA-65","BC");ml.initVerify(keys.pq);ml.update(digest);check(ml.verify(slice(sig,96,sig.length)),"Invalid OpenPGP ML-DSA signature");
    }
    @FunctionalInterface interface Signer{byte[] sign(byte[] digest)throws Exception;}
    static Signer signer(Identity id,ExternalMu.Backend backend)throws Exception {
        check(supported(id),"Select a Level 3 hybrid identity for OpenPGP");Keys keys=keys(id.signingCert().getPublicKey());
        return digest->{
            byte[] ml,ec;
            if(backend!=null){Signature s=Signature.getInstance("ML-DSA-65",ExternalMu.PROVIDER);s.initSign(new ExternalMu.TokenKey(keys.pq,backend));s.update(digest);ml=s.sign();ec=backend.signEcdsa(keys.ec,digest);}
            else {check(id.signingKey() instanceof CompositePrivateKey,"Unlock software identity or select token backend");var privateKeys=((CompositePrivateKey)id.signingKey()).getPrivateKeys();Signature s=Signature.getInstance("ML-DSA-65","BC");s.initSign(privateKeys.get(0),RANDOM);s.update(digest);ml=s.sign();s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(privateKeys.get(1),RANDOM);s.update(digest);ec=s.sign();}
            byte[] out=cat(fixed(ec),ml);verifyDigest(out,digest,keys);return out;
        };
    }
    record Request(byte[] header,byte[] salt,byte[] digest) {
        byte[] finish(byte[] signature){return cat(header,n(0,4),slice(digest,0,2),b(salt.length),salt,signature);}
    }
    static Request request(byte[] data,int type,byte[] fp,byte[] extra)throws Exception {
        byte[] salt=random(24),subs=cat(sub(2,n(now(),4)),sub(33,cat(b(6),fp)),extra),header=cat(b(6,type,41,9),n(subs.length,4),subs);
        return new Request(header,salt,hash("SHA-384",cat(salt,data,header,b(6,255),n(header.length,4))));
    }
    record Checked(Map<Integer,byte[]> subs,byte[] salt,int hash){}
    static Checked verify(byte[] body,byte[] data,int type,byte[] key)throws Exception {
        Reader r=new Reader(body);check(Arrays.equals(r.take(3),b(6,type,41)),"Unsupported signature profile");int h=r.one();
        String name=switch(h){case 8->"SHA-256";case 9->"SHA-384";case 10->"SHA-512";case 12->"SHA3-256";case 14->"SHA3-512";default->throw new GeneralSecurityException("Unsupported OpenPGP hash");};int saltSize=h==9?24:(h==10||h==14?32:16);
        int count=(int)r.number(4);check(count<=8192,"Signature metadata too large");byte[] hashed=r.take(count),header=slice(body,0,r.at);int un=(int)r.number(4);check(un<=8192,"Signature metadata too large");r.take(un);byte[] prefix=r.take(2);check(r.one()==saltSize,"Invalid salt length");byte[] salt=r.take(saltSize),sig=r.take(r.left()),digest=hash(name,cat(salt,data,header,b(6,255),n(header.length,4)));
        check(Arrays.equals(prefix,slice(digest,0,2)),"OpenPGP signature digest mismatch");Reader subs=new Reader(hashed);Map<Integer,byte[]> map=new HashMap<>();
        while(subs.left()>0){int len=subs.length();check(len>0,"Invalid subpacket");Reader s=new Reader(subs.take(len));int t=s.one(),tag=t&127;check((t&128)==0||List.of(2,3,9,11,21,22,27,30,33,39).contains(tag),"Unknown critical subpacket");check(!map.containsKey(tag),"Duplicate subpacket");map.put(tag,s.take(s.left()));}
        check(Arrays.equals(map.get(33),cat(b(6),fingerprint(key))),"Wrong issuer fingerprint");
        byte[] time=map.get(2);check(time!=null&&time.length==4,"Missing creation time");long created=new Reader(time).number(4);check(created<=now()+300,"Future signature");
        if(map.containsKey(3)){byte[] expiry=map.get(3);check(expiry.length==4,"Invalid expiry");long seconds=new Reader(expiry).number(4);check(seconds==0||created+seconds>=now(),"Expired signature");}
        verifyDigest(sig,digest,parseKey(key,true));return new Checked(map,salt,h);
    }
    public static final class PublicIdentity {
        final byte[] primary,subkey,encoded;final Keys signing,encryption;final String email;final int mode;
        public PublicIdentity(byte[] input)throws Exception {
            encoded=unarmor(input,"PUBLIC KEY BLOCK");List<Packet> p=packets(encoded);check(p.stream().map(Packet::tag).toList().equals(List.of(6,2,13,2,14,2)),"Expected one v6 primary, direct signature, certified email and bound encryption subkey; unsupported/revoked keys are rejected");
            primary=p.get(0).body;subkey=p.get(4).body;signing=parseKey(primary,true);encryption=parseKey(subkey,false);
            String uid=new String(p.get(2).body,StandardCharsets.UTF_8);int l=uid.lastIndexOf('<');email=l>=0&&uid.endsWith(">")?uid.substring(l+1,uid.length()-1):uid;validateEmail(email);
            Checked direct=verify(p.get(1).body,keyHash(primary),31,primary);
            verify(p.get(3).body,cat(keyHash(primary),b(0xb4),n(p.get(2).body.length,4),p.get(2).body),19,primary);
            Checked bind=verify(p.get(5).body,cat(keyHash(primary),keyHash(subkey)),24,primary);
            check((flag(direct,27)&3)==3&&(flag(bind,27)&12)!=0,"OpenPGP key flags reject use");
            expiration(primary,direct);expiration(subkey,bind);
            byte[] pref=direct.subs.getOrDefault(39,new byte[0]);check(pref.length%2==0,"Invalid cipher preferences");int mode=0;
            for(int i=0;i<pref.length;i+=2)if(pref[i]==9&&(pref[i+1]==2||pref[i+1]==3))mode=Math.max(mode,pref[i+1]);this.mode=mode;
        }
        public byte[] export(){return armor(encoded,"PUBLIC KEY BLOCK");}
        public String fingerprint()throws Exception{return hex(OpenPgp.fingerprint(primary));}
        public String description()throws Exception{return email+" · OpenPGP Level 3 hybrid (draft-05)\nFingerprint: "+fingerprint()+"\nSelf-signatures verified. Trust is not established; confirm the fingerprint independently.";}
        static int flag(Checked c,int id){byte[] v=c.subs.get(id);return v==null||v.length==0?0:v[0]&255;}
        static void expiration(byte[] key,Checked c)throws Exception{if(c.subs.containsKey(9)){byte[] v=c.subs.get(9);check(v.length==4,"Invalid expiry");long seconds=new Reader(v).number(4),created=new Reader(slice(key,1,5)).number(4);check(seconds==0||created+seconds>=now(),"Expired key");}}
    }
    static void validateEmail(String s)throws Exception{check(s.length()<=254&&s.matches("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"),"Enter a plain email address");}
    static String email(Identity id)throws Exception{for(var san:id.signingCert().getSubjectAlternativeNames())if(Integer.valueOf(1).equals(san.get(0)))return(String)san.get(1);throw new GeneralSecurityException("Missing email SAN");}
    public static PublicIdentity create(Identity id,ExternalMu.Backend backend)throws Exception {
        check(supported(id),"OpenPGP supports Level 3 hybrid only");id.signingCert().checkValidity();id.encryptionCert().checkValidity();
        ExternalMu.Backend op=backend==null?null:backend.newOperation();
        try {
            Signer sign=signer(id,op);byte[] primary=keyBody(keys(id.signingCert().getPublicKey()),true,now()),subkey=keyBody(keys(id.encryptionCert().getPublicKey()),false,now()),fp=fingerprint(primary),uid=bytes(email(id));
            byte[] prefs=cat(sub(27,b(3)),sub(11,b(9)),sub(21,b(9)),sub(22,b(0)),sub(30,b(8)),sub(39,b(9,3,9,2)));
            Request direct=request(keyHash(primary),31,fp,prefs),cert=request(cat(keyHash(primary),b(0xb4),n(uid.length,4),uid),19,fp,b()),bind=request(cat(keyHash(primary),keyHash(subkey)),24,fp,sub(27,b(12)));
            return new PublicIdentity(cat(frame(6,primary),frame(2,direct.finish(sign.sign(direct.digest))),frame(13,uid),frame(2,cert.finish(sign.sign(cert.digest))),frame(14,subkey),frame(2,bind.finish(sign.sign(bind.digest)))));
        }finally{if(op!=null)op.clearSecrets();}
    }
    static void match(PublicIdentity pgp,Identity id)throws Exception{
        check(supported(id),"Select a Level 3 hybrid identity");Keys s=keys(id.signingCert().getPublicKey()),e=keys(id.encryptionCert().getPublicKey());
        check(pgp.email.equals(email(id))&&Arrays.equals(raw(s.pq),raw(pgp.signing.pq))&&Arrays.equals(raw(s.ec),raw(pgp.signing.ec))&&Arrays.equals(raw(e.pq),raw(pgp.encryption.pq))&&Arrays.equals(raw(e.ec),raw(pgp.encryption.ec)),"OpenPGP identity does not match selected keys/email");
    }
    static Path ownPath(Path root,Identity id)throws Exception{check(supported(id),"OpenPGP supports Level 3 hybrid only");return root.resolve("openpgp").resolve(hex(hash("SHA-256",cat(id.signingCert().getEncoded(),id.encryptionCert().getEncoded())))+".asc");}
    public static PublicIdentity loadOwn(Path root,Identity id)throws Exception{Path p=ownPath(root,id);check(Files.isRegularFile(p),"Create or import your OpenPGP public identity first");check(Files.size(p)<=128*1024,"Public identity too large");PublicIdentity own=new PublicIdentity(Files.readAllBytes(p));match(own,id);return own;}
    public static PublicIdentity saveOwn(Path root,Identity id,byte[] input)throws Exception{PublicIdentity own=new PublicIdentity(input);match(own,id);Path p=ownPath(root,id);if(Files.exists(p)){var previous=loadOwn(root,id);check(Arrays.equals(fingerprint(previous.primary),fingerprint(own.primary))&&Arrays.equals(fingerprint(previous.subkey),fingerprint(own.subkey)),"A different OpenPGP identity is already saved");}Files.createDirectories(p.getParent());Path tmp=Files.createTempFile(p.getParent(),"pgp-",".tmp");try{Files.write(tmp,own.export());Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(tmp);}return own;}
    public static PublicIdentity createOwn(Path root,Identity id,ExternalMu.Backend backend)throws Exception{Path p=ownPath(root,id);return Files.exists(p)?loadOwn(root,id):saveOwn(root,id,create(id,backend).export());}
    static byte[] combine(byte[] pq,byte[] ec,byte[] point,byte[] recipient)throws Exception{check(pq.length==32&&ec.length==48&&point.length==97&&recipient.length==97,"Invalid KEM components");return hash("SHA3-256",cat(pq,ec,point,recipient,b(37),bytes("OpenPGPCompositeKDFv1"),b(21)));}
    record Encapsulation(byte[] ciphertext,byte[] kek){}
    static Encapsulation encapsulate(PublicIdentity recipient)throws Exception{
        var pq=new MLKEMGenerator(RANDOM).generateEncapsulated((MLKEMPublicKeyParameters)PublicKeyFactory.createKey(recipient.encryption.pq.getEncoded()));
        KeyPairGenerator gen=KeyPairGenerator.getInstance("EC","BC");gen.initialize(new ECGenParameterSpec("secp384r1"),RANDOM);KeyPair ephemeral=gen.generateKeyPair();byte[] ec=derive(ephemeral.getPrivate(),recipient.encryption.ec),share=pq.getSecret(),point=raw(ephemeral.getPublic());
        try{return new Encapsulation(cat(point,pq.getEncapsulation()),combine(share,ec,point,raw(recipient.encryption.ec)));}finally{wipe(ec);wipe(share);pq.destroy();}
    }
    static byte[] derive(PrivateKey key,PublicKey peer)throws Exception{KeyAgreement ka=KeyAgreement.getInstance("ECDH","BC");ka.init(key);ka.doPhase(peer,true);return ka.generateSecret();}
    static byte[] recover(byte[] ct,Identity id,ExternalKem.Backend backend)throws Exception {
        check(supported(id)&&ct.length==1185,"Invalid OpenPGP recipient/ciphertext");Keys pub=keys(id.encryptionCert().getPublicKey());byte[] point=slice(ct,0,97);PublicKey peer=ec(point);byte[] pq=null,ec=null;ExternalKem.Backend op=backend==null?null:backend.newOperation();
        try{if(op!=null){pq=op.decapsulate(pub.pq,slice(ct,97,ct.length));ec=op.derive(pub.ec,peer);}else{check(id.encryptionKey() instanceof CompositePrivateKey,"Unlock software identity or select token backend");var priv=((CompositePrivateKey)id.encryptionKey()).getPrivateKeys();pq=new MLKEMExtractor((MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(priv.get(0).getEncoded())).extractSecret(slice(ct,97,ct.length));ec=derive(priv.get(1),peer);}return combine(pq,ec,point,raw(pub.ec));}finally{wipe(pq);wipe(ec);if(op!=null)op.clearSecrets();}
    }
    static byte[] wrap(boolean encrypt,byte[] key,byte[] input)throws Exception{Cipher c=Cipher.getInstance("AESWrap","BC");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"));return c.doFinal(input);}
    static byte[] aead(boolean encrypt,int mode,byte[] key,byte[] nonce,byte[] aad,byte[] input)throws Exception{check((mode==2||mode==3)&&key.length==32&&nonce.length==(mode==2?15:12),"Invalid AEAD parameters");Cipher c=Cipher.getInstance(mode==2?"AES/OCB/NoPadding":"AES/GCM/NoPadding","BC");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new AEADParameterSpec(nonce,128,aad));return c.doFinal(input);}
    static byte[] kdf(byte[] session,byte[] salt,byte[] info,int size){HKDFBytesGenerator k=new HKDFBytesGenerator(new SHA256Digest());k.init(new HKDFParameters(session,salt,info));byte[] out=new byte[size];k.generateBytes(out,0,size);return out;}
    static byte[] seipd(byte[] plain,byte[] session,int mode)throws Exception {
        byte[] salt=random(32),info=b(0xd2,2,9,mode,10),derived=kdf(session,salt,info,mode==2?39:36),key=slice(derived,0,32),iv=slice(derived,32,derived.length);var out=new Buffer();out.put(cat(b(2,9,mode,10),salt));int at=0,index=0;
        try{do{int end=Math.min(at+65536,plain.length);out.put(aead(true,mode,key,cat(iv,n(index++,8)),info,slice(plain,at,end)));at=end;}while(at<plain.length);out.put(aead(true,mode,key,cat(iv,n(index,8)),cat(info,n(plain.length,8)),b()));return frame(18,out.toByteArray());}finally{wipe(derived);wipe(key);}
    }
    static byte[] decryptSeipd(byte[] body,byte[] session)throws Exception {
        Reader r=new Reader(body);check(r.one()==2&&r.one()==9,"Expected v2 SEIPD AES-256");int mode=r.one(),chunk=r.one();check((mode==2||mode==3)&&chunk<=16,"Unsupported AEAD parameters");byte[] salt=r.take(32),info=b(0xd2,2,9,mode,chunk),derived=kdf(session,salt,info,mode==2?39:36),key=slice(derived,0,32),iv=slice(derived,32,derived.length);var out=new Buffer();int index=0,size=1<<(chunk+6);check(r.left()>=32,"Truncated ciphertext");
        try{while(r.left()>16){int len=Math.min(size+16,r.left()-16);check(len>=16,"Truncated chunk");out.put(aead(false,mode,key,cat(iv,n(index++,8)),info,r.take(len)));}aead(false,mode,key,cat(iv,n(index,8)),cat(info,n(out.size(),8)),r.take(16));return out.toByteArray();}finally{wipe(derived);wipe(key);}
    }
    static byte[] encrypt(byte[] signed,PublicIdentity recipient)throws Exception {
        check(recipient.mode!=0,"Recipient must advertise AES-256 OCB or GCM");byte[] session=random(32);Encapsulation kem=encapsulate(recipient);
        try{byte[] wrapped=wrap(true,kem.kek,session),pkesk=cat(b(6,33,6),fingerprint(recipient.subkey),b(37),kem.ciphertext,b(wrapped.length),wrapped);return cat(frame(1,pkesk),seipd(signed,session,recipient.mode));}finally{wipe(session);wipe(kem.kek);}
    }
    record Envelope(byte[] ct,byte[] wrapped,byte[] encrypted) {
        byte[] open(byte[] kek)throws Exception{byte[] session=wrap(false,kek,wrapped);try{check(session.length==32,"Invalid session key");return decryptSeipd(encrypted,session);}finally{wipe(session);}}
    }
    static Envelope envelope(byte[] data,PublicIdentity own)throws Exception {
        List<Packet> p=packets(data);check(p.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one recipient and v2 encrypted payload");Reader r=new Reader(p.get(0).body);check(Arrays.equals(r.take(3),b(6,33,6))&&Arrays.equals(r.take(32),fingerprint(own.subkey))&&r.one()==37,"OpenPGP recipient does not match selected identity");byte[] ct=r.take(1185);ec(slice(ct,0,97));check(r.one()==40&&r.left()==40,"Invalid wrapped session key");byte[] encrypted=p.get(1).body;check(encrypted.length>=68&&encrypted[0]==2&&encrypted[1]==9&&(encrypted[2]==2||encrypted[2]==3)&&(encrypted[3]&255)<=16,"Unsupported encrypted payload");return new Envelope(ct,r.take(40),encrypted);
    }
    static byte[] signed(byte[] plain,PublicIdentity own,Signer signer)throws Exception {
        Request req=request(plain,0,fingerprint(own.primary),b());byte[] sig=signer.sign(req.digest);
        return cat(frame(4,cat(b(6,0,9,41,24),req.salt,fingerprint(own.primary),b(1))),frame(11,cat(b(98,0),n(0,4),plain)),frame(2,req.finish(sig)));
    }
    static byte[] openSigned(byte[] data,PublicIdentity signer)throws Exception {
        List<Packet> p=packets(data);check(p.stream().map(Packet::tag).toList().equals(List.of(4,11,2)),"Unsupported signed message; compression is not supported");Reader r=new Reader(p.get(1).body);check(List.of(98,116,117).contains(r.one()),"Invalid literal packet");r.take(r.one()+4);byte[] plain=r.take(r.left());Checked sig=verify(p.get(2).body,plain,0,signer.primary);check(Arrays.equals(p.get(0).body,cat(b(6,0,sig.hash,41,sig.salt.length),sig.salt,fingerprint(signer.primary),b(1))),"One-pass signature mismatch");return plain;
    }
    record Mime(Map<String,String> headers,byte[] body){}
    static Mime mime(byte[] input)throws Exception {
        check(input.length<=LIMIT,"Message exceeds 20 MiB");String s=new String(input,StandardCharsets.UTF_8);int split=s.indexOf("\r\n\r\n");check(split>=0&&split<65536,"Invalid MIME headers");Map<String,String> h=new HashMap<>();
        String unfolded=s.substring(0,split).replaceAll("\r\n[ \t]+"," ");
        for(String line:unfolded.split("\r\n")){int colon=line.indexOf(':');check(colon>0,"Invalid MIME header");String key=line.substring(0,colon).toLowerCase(Locale.ROOT);check(!h.containsKey(key)||!List.of("content-type","content-transfer-encoding","from").contains(key),"Duplicate MIME header");h.put(key,line.substring(colon+1).trim());}return new Mime(h,bytes(s.substring(split+4)));
    }
    static byte[] decoded(Mime m)throws Exception{String encoding=m.headers.getOrDefault("content-transfer-encoding","7bit").toLowerCase(Locale.ROOT);if(encoding.equals("base64"))return Base64.getDecoder().decode(new String(m.body,StandardCharsets.US_ASCII).replaceAll("\\s",""));check(List.of("7bit","8bit","binary").contains(encoding),"Unsupported MIME transfer encoding");return m.body;}
    public static boolean isOpenPgp(byte[] message){try{String c=mime(message).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT);return c.contains("application/pgp-encrypted")||c.contains("application/pgp-signature");}catch(Exception e){return false;}}
    record Parts(Mime root,byte[] first,byte[] second,boolean encrypted){}
    static Parts parts(byte[] message)throws Exception {
        Mime root=mime(message);String ct=root.headers.getOrDefault("content-type","");boolean encrypted=ct.toLowerCase(Locale.ROOT).contains("application/pgp-encrypted");check(ct.toLowerCase(Locale.ROOT).startsWith(encrypted?"multipart/encrypted;":"multipart/signed;"),"Invalid PGP/MIME type");
        String boundary=null;for(String parameter:ct.split(";")){String p=parameter.trim();if(p.toLowerCase(Locale.ROOT).startsWith("boundary=")){check(boundary==null,"Duplicate MIME boundary");boundary=p.substring(9);if(boundary.startsWith("\"")&&boundary.endsWith("\""))boundary=boundary.substring(1,boundary.length()-1);}}
        check(boundary!=null&&boundary.length()>0&&boundary.length()<=70,"Invalid MIME boundary");
        String[] fields=new String(root.body,StandardCharsets.UTF_8).split(java.util.regex.Pattern.quote("--"+boundary),-1);check(fields.length==4&&fields[3].startsWith("--"),"Expected two MIME parts");byte[][] bodies=new byte[2][];
        for(int i=0;i<2;i++){String s=fields[i+1];check(s.startsWith("\r\n")&&s.endsWith("\r\n"),"Invalid boundary");bodies[i]=bytes(s.substring(2,s.length()-2));}
        if(encrypted){Mime control=mime(bodies[0]);check(control.headers.getOrDefault("content-type","").equalsIgnoreCase("application/pgp-encrypted")&&new String(decoded(control),StandardCharsets.UTF_8).trim().equals("Version: 1"),"Invalid PGP/MIME version");check(mime(bodies[1]).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).startsWith("application/octet-stream"),"Invalid encrypted MIME part");}
        else check(mime(bodies[1]).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).startsWith("application/pgp-signature"),"Invalid signature part");
        return new Parts(root,bodies[0],bodies[1],encrypted);
    }
    static byte[] mimeWrap(byte[] first,byte[] second,boolean encrypted,String from,String to,String subject)throws Exception {
        validateEmail(from);validateEmail(to);check(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid subject");String boundary="pqmail-"+UUID.randomUUID(),type=encrypted?"encrypted":"signed",protocol=encrypted?"application/pgp-encrypted":"application/pgp-signature";
        return cat(bytes("From: "+from+"\r\nTo: "+to+"\r\nSubject: "+subject+"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/"+type+"; protocol=\""+protocol+"\"; "+(encrypted?"":"micalg=pgp-sha384; ")+"boundary=\""+boundary+"\"\r\n\r\n--"+boundary+"\r\n"),first,bytes("\r\n--"+boundary+"\r\n"),second,bytes("\r\n--"+boundary+"--\r\n"));
    }
    public static byte[] compose(Identity id,PublicIdentity own,PublicIdentity recipient,String from,String to,String subject,String text,ExternalMu.Backend backend)throws Exception {
        match(own,id);check(from.equalsIgnoreCase(own.email),"Sender address mismatch");validateEmail(to);check(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid subject");check(text.length()<LIMIT/4,"Message too large");if(recipient!=null)check(to.equalsIgnoreCase(recipient.email),"Recipient address mismatch");
        byte[] plain=cat(bytes("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"),bytes(Base64.getMimeEncoder(64,b(13,10)).encodeToString(bytes(text))));
        ExternalMu.Backend op=backend==null?null:backend.newOperation();
        try{Signer signer=signer(id,op);if(recipient!=null)return mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),armor(encrypt(signed(plain,own,signer),recipient),"MESSAGE")),true,from,to,subject);
            Request req=request(plain,0,fingerprint(own.primary),b());return mimeWrap(plain,cat(bytes("Content-Type: application/pgp-signature\r\n\r\n"),armor(frame(2,req.finish(signer.sign(req.digest))),"SIGNATURE")),false,from,to,subject);
        }finally{if(op!=null)op.clearSecrets();}
    }
    public record Opened(String text,String email,String fingerprint,boolean encrypted,boolean fromMatches) {
        public String display(){return "OpenPGP Level 3 hybrid (draft-05)\nSignature valid; trust not established\nSigner: "+email+"\nFingerprint: "+fingerprint+"\nEncrypted: "+encrypted+"\nUnsigned From matches: "+fromMatches+"\n\n"+text;}
    }
    public static Opened open(byte[] message,PublicIdentity signer,PublicIdentity own,Identity id,ExternalKem.Backend backend)throws Exception {
        check(signer!=null,"Import the sender's OpenPGP public key");Parts p=parts(message);byte[] plain;
        if(p.encrypted){check(own!=null&&id!=null,"Select the decryption identity");match(own,id);Envelope env=envelope(unarmor(decoded(mime(p.second)),"MESSAGE"),own);byte[] kek=recover(env.ct,id,backend);try{plain=openSigned(env.open(kek),signer);}finally{wipe(kek);}}
        else{List<Packet> sig=packets(unarmor(decoded(mime(p.second)),"SIGNATURE"));check(sig.size()==1&&sig.get(0).tag==2,"Expected one detached signature");verify(sig.get(0).body,p.first,0,signer.primary);plain=p.first;}
        Mime content=mime(plain);check(content.headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).startsWith("text/plain"),"This OpenPGP preview supports plain-text messages");return new Opened(new String(decoded(content),StandardCharsets.UTF_8),signer.email,signer.fingerprint(),p.encrypted,signer.email.equalsIgnoreCase(p.root.headers.get("from")));
    }
}
