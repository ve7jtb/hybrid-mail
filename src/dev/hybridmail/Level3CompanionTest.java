package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.pkcs.*;

/** Actual cryptography with synthetic card keys. No PC/SC, PIN UI or network. */
public final class Level3CompanionTest {
    static final class Hardware implements ExternalMu.Backend,ExternalKem.Backend {
        final Map<String,KeyPair> keys;final List<byte[]> secrets=new ArrayList<>();
        int certifications,signatures,wrappings,decryptions;
        Hardware(Map<String,KeyPair> keys){this.keys=keys;}
        public byte[] sign(PublicKey key,byte[] mu)throws Exception{throw new GeneralSecurityException("Hardware cannot sign ML-DSA");}
        public byte[] signEd25519(PublicKey key,byte[] message)throws Exception{
            String slot=Arrays.equals(key.getEncoded(),keys.get("82").getPublic().getEncoded())?"82":"9c";
            Level3Companion.same(key,keys.get(slot).getPublic());if(slot.equals("82"))certifications++;else signatures++;
            var s=Signature.getInstance("Ed25519","BC");s.initSign(keys.get(slot).getPrivate());s.update(message);return s.sign();
        }
        public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{throw new GeneralSecurityException("Hardware cannot decapsulate ML-KEM");}
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            String slot=key instanceof java.security.interfaces.ECPublicKey?"83":"9d";
            Level3Companion.same(key,keys.get(slot).getPublic());if(slot.equals("83"))wrappings++;else decryptions++;
            byte[] value=OpenPgp.derive(keys.get(slot).getPrivate(),peer);secrets.add(value);return value;
        }
        public Hardware newOperation(){return this;}
        public void clearSecrets(){}
        void wiped()throws Exception{for(byte[] secret:secrets)check(Arrays.equals(secret,new byte[secret.length]),"Shared secret was not cleared");}
    }
    static void reject(Level5CompanionTest.Checked action)throws Exception{Level5CompanionTest.rejected(action);}
    static Map<String,KeyPair> hardware()throws Exception{
        var ec=KeyPairGenerator.getInstance("EC","BC");ec.initialize(new ECGenParameterSpec("secp384r1"));
        return Map.of("82",SoftwareOpenPgp.generate("Ed25519"),"9c",SoftwareOpenPgp.generate("Ed25519"),"9d",SoftwareOpenPgp.generate("X25519"),"83",ec.generateKeyPair());
    }
    /** Independently inspect the encrypted P12 using only synthetic wrapping
     * material. This proves seed-only storage, rather than relying on API names. */
    static int checkSeeds(byte[] encoded,Map<String,PublicKey> publicKeys,KeyPair wrapping)throws Exception{
        var e=Level3Companion.inspect(encoded,123456,publicKeys);byte[] shared=null,key=null,plain=null,p12=null;
        try{
            shared=derive(wrapping.getPrivate(),e.ephemeral());key=kdf(shared,e.salt(),cat(bytes("PQMail companion L3 P384 v1"),hash("SHA-256",e.aad())),32);plain=aead(false,3,key,e.nonce(),e.aad(),e.ciphertext());
            var in=new DataInputStream(new ByteArrayInputStream(plain));p12=Level5Companion.field(in);check(in.available()==0,"Private payload trailing data");
            var pfx=new PKCS12PfxPdu(p12);check(!pfx.hasMac()&&pfx.getContentInfos().length==3,"Not a three-key empty-password P12");int total=0;var roles=new HashSet<String>();
            for(var c:pfx.getContentInfos())for(var b:new PKCS12SafeBagFactory(c).getSafeBags()){
                check(b.getType().equals(PKCSObjectIdentifiers.keyBag),"Certificate or extra bag duplicated private container");
                String role=ASN1BMPString.getInstance(b.getAttributes()[0].getAttrValues().getObjectAt(0)).getString();check(roles.add(role),"Duplicate key role");
                var info=(PrivateKeyInfo)b.getBagValue();var tagged=ASN1TaggedObject.getInstance(info.parsePrivateKey());check(tagged.hasContextTag(0),"Expanded key encoding stored");
                byte[] seed=ASN1OctetString.getInstance(tagged,false).getOctets();try{check(seed.length==(role.equals("kem-pq")?64:32),"Wrong seed length");total+=seed.length;}finally{wipe(seed);}
            }
            check(total==128&&roles.equals(Set.of(Level3Companion.ROLES)),"Wrong seed inventory");return p12.length;
        }finally{wipe(shared);wipe(key);wipe(plain);wipe(p12);}
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();var keys=hardware();var publicKeys=new LinkedHashMap<String,PublicKey>();keys.forEach((slot,key)->publicKeys.put(slot,key.getPublic()));var card=new Hardware(keys);
        byte[] stored,publicCert,signed,encrypted;byte[] plain=bytes("Synthetic Level 3 companion Java/Sequoia test\n");
        Identity anchors;PublicIdentity own;
        try(var initial=Level3Companion.create(123456,publicKeys,List.of("polyfill@example.test","alias@example.test"),card,card)){
            own=initial.own;anchors=initial.anchors();stored=initial.seal(card);publicCert=own.encoded;
            int certificationCalls=card.certifications,signCalls=card.signatures;
            signed=initial.sign(plain,card);encrypted=encrypt(signed,own);
            check(card.signatures==signCalls+1&&card.certifications==certificationCalls,"Message signature used more than one hardware signing key");
            check(Arrays.equals(plain,openSigned(initial.decrypt(encrypted,card),own)),"Fresh identity message round trip");
        }
        int p12Size=checkSeeds(stored,publicKeys,keys.get("83"));
        int wrappingCalls=card.wrappings,signCalls=card.signatures,decryptCalls=card.decryptions,certCalls=card.certifications;
        try(var restored=Level3Companion.restore(stored,123456,publicKeys,card)){
            check(card.wrappings==wrappingCalls+1&&card.certifications==certCalls&&card.signatures==signCalls&&card.decryptions==decryptCalls,"Restore should use only the dedicated wrapping key");
            check(Arrays.equals(restored.own.encoded,publicCert),"Public certificate changed on restore");
            check(Arrays.equals(restored.anchors().signingCert().getEncoded(),anchors.signingCert().getEncoded())&&Arrays.equals(restored.anchors().encryptionCert().getEncoded(),anchors.encryptionCert().getEncoded()),"Portable anchors changed");
            check(Arrays.equals(plain,openSigned(restored.sign(plain,card),own)),"Restored signature failed");
            check(Arrays.equals(plain,openSigned(restored.decrypt(encrypted,card),own)),"Restored decryption failed");
            check(card.signatures==signCalls+1&&card.decryptions==decryptCalls+1&&card.wrappings==wrappingCalls+1&&card.certifications==certCalls,"Additional per-message private operation");
            // Existing external-mu API uses the software component; the card
            // must never be asked to implement ML-DSA or ML-KEM algorithms.
            var s=Signature.getInstance("ML-DSA-65",ExternalMu.PROVIDER);s.initSign(new ExternalMu.TokenKey(own.signing.pq(),restored::signComponent));s.update(plain);byte[] signature=s.sign();var verifier=Signature.getInstance("ML-DSA-65","BC");verifier.initVerify(own.signing.pq());verifier.update(plain);check(verifier.verify(signature),"Software external-mu component failed");
        }
        var closed=Level3Companion.restore(stored,123456,publicKeys,card);closed.close();closed.close();reject(()->closed.sign(plain,card));reject(()->closed.decapsulate(own.encryption.pq(),new byte[1088]));
        int before=card.wrappings;
        byte[] tampered=stored.clone();tampered[tampered.length/2]^=1;
        reject(()->Level3Companion.restore(tampered,123456,publicKeys,card));reject(()->Level3Companion.restore(stored,999999,publicKeys,card));reject(()->Level3Companion.restore(Arrays.copyOf(stored,stored.length-1),123456,publicKeys,card));
        var other=hardware();for(String slot:Level3Companion.SLOTS){var wrong=new HashMap<>(publicKeys);wrong.put(slot,other.get(slot).getPublic());reject(()->Level3Companion.restore(stored,123456,wrong,card));}
        check(card.wrappings==before,"Invalid envelope reached private hardware");
        // Changing either envelope signature component is rejected before unwrap.
        byte[] inner=CompanionEncoding.unpack(stored);for(int offset:new int[]{inner.length-1,inner.length-3373}){byte[] bad=inner.clone();bad[offset]^=1;reject(()->Level3Companion.restore(CompanionEncoding.pack(bad),123456,publicKeys,card));}
        check(card.wrappings==before,"Invalid composite envelope signature reached unwrap");card.wiped();
        if(args.length==1){Path out=Path.of(args[0]);Files.createDirectories(out);Files.write(out.resolve("companion.pqcomp"),stored);Files.write(out.resolve("public.pgp"),publicCert);Files.write(out.resolve("java-signed.pgp"),signed);Files.write(out.resolve("java-encrypted.pgp"),encrypted);Files.write(out.resolve("plain.txt"),plain);Files.write(out.resolve("signing-anchor.der"),anchors.signingCert().getEncoded());Files.write(out.resolve("encryption-anchor.der"),anchors.encryptionCert().getEncoded());
            // Fixture export is explicit and uses generated test keys only.
            for(var entry:keys.entrySet()){Files.write(out.resolve(entry.getKey()+".der"),entry.getValue().getPublic().getEncoded());Files.write(out.resolve(entry.getKey()+"-test-private.der"),entry.getValue().getPrivate().getEncoded());}}
        System.out.println("PASS Level 3 companion: seed-only empty-password P12 (128 seed bytes, "+p12Size+" P12 bytes), portable anchors, one wrapping/one signing-or-decryption operation, invalid envelope rejected before private use, shared-secret cleanup");
        System.out.println("Certificate "+publicCert.length+" bytes; normal compressed companion "+stored.length+" bytes");
    }
}
