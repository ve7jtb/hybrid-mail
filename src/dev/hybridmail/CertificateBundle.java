package dev.hybridmail;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.jcajce.CompositePublicKey;

/** Versioned public-only exchange format. Never stores keys, trust, or executable configuration. */
public final class CertificateBundle {
    public static final int MAX_BYTES=512*1024;
    public static final String MIME="application/vnd.pqmail.certificates";
    public record Entry(Identity identity,int serial,String signingSlot,String traditionalSlot,String kemSlot,String ecdhSlot){
        public Entry {
            identity=new Identity(identity.signingCert(),null,identity.encryptionCert(),null,null);
        }
    }
    public static boolean sameKeys(Identity a,Identity b){
        return Arrays.equals(pq(a.signingCert().getPublicKey()),pq(b.signingCert().getPublicKey()))&&a.encryptionCert()!=null&&b.encryptionCert()!=null&&Arrays.equals(pq(a.encryptionCert().getPublicKey()),pq(b.encryptionCert().getPublicKey()));
    }
    private static byte[] pq(PublicKey key){return (key instanceof CompositePublicKey c?c.getPublicKeys().get(0):key).getEncoded();}
    private static void validate(Entry e)throws Exception{
        if(e.serial()<=0)throw new IOException("Bundle requires a positive YubiKey serial");
        var slots=List.of(e.signingSlot(),e.traditionalSlot(),e.kemSlot(),e.ecdhSlot());
        for(String slot:slots)if(slot==null||!slot.matches("9[acde]|8[2-9a-f]|9[0-5]"))throw new IOException("Invalid PIV slot mapping");
        if(new HashSet<>(slots).size()!=4)throw new IOException("Bundle slots must be distinct");
        if(!e.signingSlot().equals("9c"))throw new IOException("PQ Mail currently requires the ML-DSA signing key in slot 9c");
        String alg=e.identity().signingCert().getPublicKey().getAlgorithm();
        if(!Set.of(Identity.PURE_44_SIGN,Identity.PURE_SIGN,Identity.PURE_87_SIGN,Identity.HYBRID_44_SIGN,Identity.HYBRID_SIGN,Identity.HYBRID_65_P384_SIGN,Identity.HYBRID_87_SIGN).contains(alg))throw new IOException("Unsupported YubiKey certificate profile");
        if(e.identity().encryptionCert()==null)throw new IOException("Missing encryption certificate");
        Identity.validateCertificatePurpose(e.identity().signingCert(),"signing");Identity.validateCertificatePurpose(e.identity().encryptionCert(),"encryption");
        if(emails(e.identity().signingCert()).stream().noneMatch(email->{try{return Identity.matchesEmail(e.identity().encryptionCert(),email);}catch(Exception ex){return false;}}))throw new IOException("Signing and encryption certificate emails do not match");
    }
    public static List<String> emails(X509Certificate cert)throws Exception{
        List<String> result=new ArrayList<>();var sans=cert.getSubjectAlternativeNames();if(sans!=null)for(var san:sans)if(Integer.valueOf(1).equals(san.get(0)))result.add(san.get(1).toString());return result;
    }
    public static byte[] encode(List<Entry> entries)throws Exception{
        if(entries.isEmpty()||entries.size()>16)throw new IOException("Expected 1–16 public certificate profiles");
        Properties p=new Properties();p.setProperty("format","pq-mail-certificates");p.setProperty("version","1");p.setProperty("count",Integer.toString(entries.size()));
        for(int i=0;i<entries.size();i++){Entry e=entries.get(i);validate(e);String k="profile."+i+".";
            p.setProperty(k+"serial",Integer.toString(e.serial()));p.setProperty(k+"signingSlot",e.signingSlot());p.setProperty(k+"traditionalSlot",e.traditionalSlot());p.setProperty(k+"kemSlot",e.kemSlot());p.setProperty(k+"ecdhSlot",e.ecdhSlot());
            p.setProperty(k+"signingCertificate",Base64.getEncoder().encodeToString(e.identity().signingCert().getEncoded()));p.setProperty(k+"encryptionCertificate",Base64.getEncoder().encodeToString(e.identity().encryptionCert().getEncoded()));
        }
        ByteArrayOutputStream out=new ByteArrayOutputStream();p.store(out,"PQ Mail PUBLIC certificates and YubiKey mapping; no private keys or trust");if(out.size()>MAX_BYTES)throw new IOException("Certificate bundle too large");return out.toByteArray();
    }
    public static List<Entry> decode(byte[] bytes)throws Exception{
        if(bytes.length>MAX_BYTES)throw new IOException("Certificate bundle exceeds 512 KiB");
        Properties p=new Properties(){@Override public synchronized Object put(Object key,Object value){if(containsKey(key))throw new IllegalArgumentException("Duplicate bundle field");return super.put(key,value);}};
        p.load(new ByteArrayInputStream(bytes));if(!"pq-mail-certificates".equals(p.getProperty("format"))||!"1".equals(p.getProperty("version")))throw new IOException("Unsupported certificate bundle format/version");
        int count=Integer.parseInt(p.getProperty("count","0"));if(count<1||count>16||p.size()!=3+count*7)throw new IOException("Invalid bundle fields or profile count");
        var factory=java.security.cert.CertificateFactory.getInstance("X.509","BC");List<Entry> entries=new ArrayList<>();Set<String> fingerprints=new HashSet<>();
        for(int i=0;i<count;i++){String k="profile."+i+".";
            X509Certificate sign=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(required(p,k+"signingCertificate"))));
            X509Certificate enc=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(required(p,k+"encryptionCertificate"))));
            Entry e=new Entry(new Identity(sign,null,enc,null,null),Integer.parseInt(required(p,k+"serial")),required(p,k+"signingSlot"),required(p,k+"traditionalSlot"),required(p,k+"kemSlot"),required(p,k+"ecdhSlot"));validate(e);
            if(!fingerprints.add(Identity.fingerprint(sign)+Identity.fingerprint(enc)))throw new IOException("Duplicate certificate profile");entries.add(e);
        }return List.copyOf(entries);
    }
    private static String required(Properties p,String name)throws IOException{String v=p.getProperty(name);if(v==null)throw new IOException("Missing bundle field: "+name);return v;}
    public static String review(List<Entry> entries)throws Exception{
        StringBuilder out=new StringBuilder("PUBLIC certificates only. No private keys, PINs, passwords or trust decisions.\nSerial and slots are sender-supplied; the key is checked when used.\nCompare fingerprints with the owner before trusting.\n");
        for(var e:entries)out.append("\nYubiKey ").append(e.serial()).append(" · ").append(e.identity().signatureAlgorithm()).append("\nEmail: ").append(emails(e.identity().signingCert())).append("\nSlots: ML-DSA ").append(e.signingSlot()).append(", traditional signing ").append(e.traditionalSlot()).append(", ML-KEM ").append(e.kemSlot()).append(", ECDH ").append(e.ecdhSlot()).append("\nSigning SHA-256: ").append(Identity.fingerprint(e.identity().signingCert())).append("\nEncryption: ").append(e.identity().encryptionCert().getPublicKey().getAlgorithm()).append("\nEncryption SHA-256: ").append(Identity.fingerprint(e.identity().encryptionCert())).append("\n");return out.toString();
    }
}
