package dev.hybridmail;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.jcajce.CompositePublicKey;

/** Cross-platform public binary format; signed envelope, no serialized executable settings. */
public final class OnKeyBundle {
    public static final int MAX=65536;
    public record Profile(CertificateBundle.Entry entry,byte[] pgp){}
    public record Bundle(List<Profile> profiles,int signer,byte[] encoded,boolean recoveredMigration){
        public List<CertificateBundle.Entry> entries(){return profiles.stream().map(Profile::entry).toList();}
        public int serial(){return profiles.get(0).entry().serial();}
        public String review()throws Exception{return CertificateBundle.review(entries())+(recoveredMigration?"\nRecovered mapping: signed bundle said 9a; matching key is now in 83. Import updates this mapping; save the bundle again.\n":"")+"\nRFC 9980 OpenPGP profiles use additional slots 84 (Ed25519) and 85 (X25519).\nVerified on-key bundle signature. This does not establish sender trust.\nOpenPGP identities: "+profiles.stream().filter(p->p.pgp().length>0).count();}
        public void savePgp(Path root)throws Exception{for(var p:profiles)if(p.pgp().length>0)OpenPgp.replaceOwn(root,p.entry().identity(),new OpenPgp.PublicIdentity(p.pgp()));}
    }
    static final class InvalidData extends IOException{InvalidData(String message){super(message);}}
    static void require(boolean b,String message)throws IOException{if(!b)throw new InvalidData(message);}
    static void blob(DataOutputStream out,byte[] bytes)throws IOException{out.writeInt(bytes.length);out.write(bytes);}
    static byte[] blob(DataInputStream in)throws IOException{int n=in.readInt();require(n>=0&&n<=MAX&&n<=in.available(),"Invalid on-key field length");return in.readNBytes(n);}
    static void magic(DataInputStream in,String expected)throws IOException{require(Arrays.equals(in.readNBytes(8),expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII)),"Unsupported on-key format");}
    public static List<Profile> collect(List<CertificateBundle.Entry> entries,Path root)throws Exception{
        List<Profile> result=new ArrayList<>();for(var e:entries){byte[] pgp=new byte[0];if(OpenPgp.supported(e.identity())&&Files.exists(OpenPgp.ownPath(root,e.identity())))pgp=OpenPgp.loadOwn(root,e.identity()).encoded;result.add(new Profile(e,pgp));}return result;
    }
    public static byte[] payload(List<Profile> profiles)throws Exception{
        CertificateBundle.decode(CertificateBundle.encode(profiles.stream().map(Profile::entry).toList()));
        require(profiles.stream().anyMatch(p->p.entry().identity().signingCert().getPublicKey() instanceof CompositePublicKey)&&profiles.stream().anyMatch(p->!(p.entry().identity().signingCert().getPublicKey() instanceof CompositePublicKey)),"Save both pure and hybrid certificate profiles");
        var first=profiles.get(0).entry();for(var p:profiles){var e=p.entry();require(CertificateBundle.sameKeys(first.identity(),e.identity())&&List.of(first.signingSlot(),first.traditionalSlot(),first.kemSlot(),first.ecdhSlot()).equals(List.of(e.signingSlot(),e.traditionalSlot(),e.kemSlot(),e.ecdhSlot())),"Profiles must share all four slots and PQ keys");}
        bindings(profiles.stream().map(Profile::entry).toList());
        for(var p:profiles){var sign=p.entry().identity().signingCert().getPublicKey();var enc=p.entry().identity().encryptionCert().getPublicKey();boolean hybrid=sign instanceof CompositePublicKey;TokenProfile level=null;
            for(var candidate:TokenProfile.values())if(hybrid?((CompositePublicKey)sign).getAlgorithmIdentifier().getAlgorithm().equals(candidate.signingOid):sign.getAlgorithm().equals(candidate.ml))level=candidate;
            require(level!=null,"Unsupported on-key signing profile");require(hybrid?enc instanceof CompositePublicKey c&&c.getAlgorithmIdentifier().getAlgorithm().equals(level.kemOid):enc.getAlgorithm().equals(level.kem),"Signing and encryption profiles do not match");
        }
        var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeBytes("PQMAILB1");out.writeInt(profiles.size());
        int serial=profiles.get(0).entry().serial();for(var p:profiles){var e=p.entry();require(e.serial()==serial,"Bundle must describe one YubiKey");out.writeInt(e.serial());for(String s:List.of(e.signingSlot(),e.traditionalSlot(),e.kemSlot(),e.ecdhSlot()))out.writeByte(Integer.parseInt(s,16));blob(out,e.identity().signingCert().getEncoded());blob(out,e.identity().encryptionCert().getEncoded());blob(out,p.pgp());if(p.pgp().length>0)OpenPgp.match(new OpenPgp.PublicIdentity(p.pgp()),e.identity());}
        require(bytes.size()<MAX,"Public bundle exceeds on-key capacity");return bytes.toByteArray();
    }
    public static byte[] sign(List<Profile> profiles,int signer,ExternalMu.Backend backend)throws Exception{
        require(signer>=0&&signer<profiles.size(),"Invalid bundle signer");byte[] payload=payload(profiles);
        var signing=profiles.get(signer).entry().identity().signer(backend);signing.getOutputStream().write(payload);byte[] sig=signing.getSignature();
        var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeBytes("PQMAILS1");blob(out,payload);out.writeInt(signer);blob(out,sig);byte[] result=bytes.toByteArray();decode(result);return result;
    }
    public static Bundle decode(byte[] bytes)throws Exception{
        require(bytes.length<=MAX,"On-key bundle exceeds 64 KiB");var in=new DataInputStream(new ByteArrayInputStream(bytes));magic(in,"PQMAILS1");byte[] payload=blob(in);int signer=in.readInt();byte[] sig=blob(in);require(in.available()==0,"Trailing bundle data");
        var p=new DataInputStream(new ByteArrayInputStream(payload));magic(p,"PQMAILB1");int count=p.readInt();require(count>=1&&count<=16&&signer>=0&&signer<count,"Invalid profile count or signer");
        List<Profile> profiles=new ArrayList<>();var cf=CertificateFactory.getInstance("X.509","BC");
        for(int i=0;i<count;i++){int serial=p.readInt();String[] slots=new String[4];for(int j=0;j<4;j++)slots[j]=String.format("%02x",p.readUnsignedByte());byte[] sc=blob(p),ec=blob(p),pgp=blob(p);
            var s=(X509Certificate)cf.generateCertificate(new ByteArrayInputStream(sc));var e=(X509Certificate)cf.generateCertificate(new ByteArrayInputStream(ec));require(Arrays.equals(sc,s.getEncoded())&&Arrays.equals(ec,e.getEncoded()),"Noncanonical certificate data");
            profiles.add(new Profile(new CertificateBundle.Entry(new Identity(s,null,e,null,null),serial,slots[0],slots[1],slots[2],slots[3]),pgp));}
        require(p.available()==0,"Trailing profile data");payload(profiles); // validates certificates, mappings and OpenPGP bindings
        var id=profiles.get(signer).entry().identity();var verifier=Signature.getInstance(id.signatureAlgorithm(),"BC");verifier.initVerify(id.signingCert().getPublicKey());verifier.update(payload);require(verifier.verify(sig),"Invalid on-key bundle signature");
        return new Bundle(List.copyOf(profiles),signer,bytes.clone(),false);
    }
    public interface Card extends AutoCloseable {
        int serial()throws Exception;
        byte[] publicKey(String slot)throws Exception;
        byte[] get(int tag)throws Exception; // null ONLY for SW=6A82
        void put(int tag,byte[] bytes)throws Exception;
        void authenticate(char[] management)throws Exception;
        void move9aTo83()throws Exception; // must refuse occupied key OR certificate destination
        default void close()throws Exception{}
    }
    public static Map<String,byte[]> bindings(List<CertificateBundle.Entry> entries)throws Exception{
        Map<String,byte[]> result=new LinkedHashMap<>();for(var e:entries){add(result,e.signingSlot(),e.traditionalSlot(),e.identity().signingCert().getPublicKey());add(result,e.kemSlot(),e.ecdhSlot(),e.identity().encryptionCert().getPublicKey());}return result;
    }
    private static void add(Map<String,byte[]> map,String pq,String ec,PublicKey key)throws Exception{
        if(key instanceof CompositePublicKey c){add(map,pq,ec,c.getPublicKeys().get(0));add(map,ec,ec,c.getPublicKeys().get(1));return;}
        byte[] old=map.put(pq,key.getEncoded());require(old==null||Arrays.equals(old,key.getEncoded()),"Conflicting public keys for slot "+pq);
    }
    public static void checkPgp(Card card,List<Profile> profiles)throws Exception{
        for(var profile:profiles)if(profile.pgp().length>0){var pgp=new OpenPgp.PublicIdentity(profile.pgp());if(OpenPgp.rfc9980(pgp)){
            require(MessageDigest.isEqual(pgp.signing.ec().getEncoded(),card.publicKey("84")),"OpenPGP Ed25519 public key mismatch in slot 84");
            require(MessageDigest.isEqual(pgp.encryption.ec().getEncoded(),card.publicKey("85")),"OpenPGP X25519 public key mismatch in slot 85");
        }}
    }
    public static void check(Card card,List<CertificateBundle.Entry> entries)throws Exception{
        int serial=card.serial();for(var e:entries)require(e.serial()==serial,"Wrong YubiKey; expected "+e.serial());
        for(var e:bindings(entries).entrySet())require(MessageDigest.isEqual(e.getValue(),card.publicKey(e.getKey())),"YubiKey public key mismatch in slot "+e.getKey());
    }
    public static List<CertificateBundle.Entry> migrated(List<CertificateBundle.Entry> entries){return entries.stream().map(e->new CertificateBundle.Entry(e.identity(),e.serial(),e.signingSlot(),e.traditionalSlot().equals("9a")?"83":e.traditionalSlot(),e.kemSlot(),e.ecdhSlot())).toList();}
    public static Bundle checkOrRecover(Card card,Bundle bundle)throws Exception{
        if(bundle.entries().stream().allMatch(e->e.traditionalSlot().equals("9a"))&&card.publicKey("9a")==null){
            var mapped=migrated(bundle.entries());check(card,mapped);checkPgp(card,bundle.profiles());List<Profile> profiles=new ArrayList<>();for(int i=0;i<mapped.size();i++)profiles.add(new Profile(mapped.get(i),bundle.profiles().get(i).pgp()));return new Bundle(List.copyOf(profiles),bundle.signer(),bundle.encoded(),true);
        }check(card,bundle.entries());checkPgp(card,bundle.profiles());return bundle;
    }
    public static void migrate(Card card,List<CertificateBundle.Entry> entries,char[] management)throws Exception{
        require(entries.stream().allMatch(e->e.traditionalSlot().equals("9a")),"Migration requires existing 9a mappings");
        require(bindings(entries).containsKey("9a"),"Include the hybrid identity to verify the classical signing key");// Recover a completed move after an interrupted local save, without another MOVE.
        if(card.publicKey("9a")==null){check(card,migrated(entries));return;}
        check(card,entries);card.authenticate(management);card.move9aTo83();check(card,migrated(entries));
    }
}
