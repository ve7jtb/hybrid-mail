package dev.hybridmail;

import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import org.bouncycastle.jcajce.*;
import org.bouncycastle.jcajce.spec.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import jakarta.activation.DataHandler;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.util.ByteArrayDataSource;

public final class TokenKemTest {
    @FunctionalInterface interface Action{void run()throws Exception;}
    static void reject(Action action,String label)throws Exception{try{action.run();}catch(Exception expected){System.out.println("PASS "+label);return;}throw new AssertionError(label);}
    static final class Simulator implements ExternalKem.Backend{
        final KeyPair ml,ec;int mlCalls,ecCalls,clears;boolean failEc;
        final List<byte[]> secrets=new ArrayList<>();
        Simulator(KeyPair ml,KeyPair ec){this.ml=ml;this.ec=ec;}
        public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{
            mlCalls++;if(!Arrays.equals(key.getEncoded(),ml.getPublic().getEncoded()))throw new GeneralSecurityException("Wrong ML key");
            KeyGenerator kg=KeyGenerator.getInstance("ML-KEM","BC");
            kg.init(new KEMExtractSpec.Builder(ml.getPrivate(),ct,"AES",256).withKdfAlgorithm(null).build());
            byte[] value=kg.generateKey().getEncoded();secrets.add(value);return value;
        }
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            ecCalls++;if(failEc)throw new GeneralSecurityException("Simulated ECDH failure");
            if(!Arrays.equals(key.getEncoded(),ec.getPublic().getEncoded()))throw new GeneralSecurityException("Wrong EC key");
            KeyAgreement ka=KeyAgreement.getInstance("ECDH","BC");ka.init(ec.getPrivate());ka.doPhase(peer,true);
            byte[] value=ka.generateSecret();secrets.add(value);return value;
        }
        public void clearSecrets(){clears++;}
        void assertWiped(){for(byte[] secret:secrets)if(!Arrays.equals(secret,new byte[secret.length]))throw new AssertionError("Shared secret not wiped");}
    }
    static MimeMessage replaceKem(MimeMessage message,KEMRecipientInfo replacement)throws Exception{
        ContentInfo ci=ContentInfo.getInstance(message.getInputStream().readAllBytes());
        AuthEnvelopedData env=AuthEnvelopedData.getInstance(ci.getContent());
        OtherRecipientInfo original=OtherRecipientInfo.getInstance(RecipientInfo.getInstance(env.getRecipientInfos().getObjectAt(0)).getInfo());
        var recipient=new RecipientInfo(new OtherRecipientInfo(original.getType(),replacement));
        var changed=new AuthEnvelopedData(env.getOriginatorInfo(),new DERSet(recipient),env.getAuthEncryptedContentInfo(),env.getAuthAttrs(),env.getMac(),env.getUnauthAttrs());
        MimeMessage copy=MailEngine.parse(MailEngine.encode(message));
        copy.setDataHandler(new DataHandler(new ByteArrayDataSource(new ContentInfo(ci.getContentType(),changed).getEncoded(),message.getContentType())));copy.saveChanges();return copy;
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();Path dir=Files.createTempDirectory("token-kem-test-");
        try{
            Identity sender=Identity.generate("sender@example.test",false),base=Identity.generate("recipient@example.test",false);
            KeyPair ml=KeyPairGenerator.getInstance("ML-KEM-768","BC").generateKeyPair();
            KeyPairGenerator ecGen=KeyPairGenerator.getInstance("EC","BC");ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));KeyPair ec=ecGen.generateKeyPair();
            PublicKey hybrid=new CompositePublicKey(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256,ml.getPublic(),ec.getPublic());
            for(boolean composite:new boolean[]{false,true}){
                PublicKey pub=composite?hybrid:ml.getPublic();
                Identity id=base.withTokenEncryption("recipient@example.test",pub,null);
                Path file=dir.resolve(composite?"hybrid.p12":"pure.p12");char[] pass="test-only-kem-password".toCharArray();id.save(file,pass);
                Identity recipient=Identity.load(file,pass);
                if(recipient.encryptionKey()!=null||recipient.encryptionCert()==null)throw new AssertionError("Expected certificate-only encryption identity");
                Simulator sim=new Simulator(ml,ec);
                String text="Token KEM test café 日本語\r\n";
                MimeMessage message=MailEngine.compose(sender,"sender@example.test","recipient@example.test","Encrypted",text,recipient.encryptionCert(),null);
                var opened=MailEngine.open(MailEngine.parse(MailEngine.encode(message)),recipient,sender.signingCert(),sim);
                if(!opened.encrypted()||!opened.pinned()||!opened.fromMatches()||!text.equals(opened.text())||sim.mlCalls!=1||sim.ecCalls!=(composite?1:0)||sim.clears!=1)throw new AssertionError("Token KEM roundtrip");
                sim.assertWiped();System.out.println("PASS token "+(composite?Identity.HYBRID_KEM:Identity.PURE_KEM)+" CMS authenticated decrypt + identity reload + secret cleanup");
                int before=sim.mlCalls;
                reject(()->MailEngine.open(message,base,sender.signingCert(),sim),"wrong recipient rejected before token");
                if(sim.mlCalls!=before)throw new AssertionError("Wrong recipient contacted token");
                ContentInfo ci=ContentInfo.getInstance(message.getInputStream().readAllBytes());AuthEnvelopedData env=AuthEnvelopedData.getInstance(ci.getContent());
                var originalKem=KEMRecipientInfo.getInstance(OtherRecipientInfo.getInstance(RecipientInfo.getInstance(env.getRecipientInfos().getObjectAt(0)).getInfo()).getValue());
                var wrongKdf=new KEMRecipientInfo(originalKem.getRecipientIdentifier(),originalKem.getKem(),originalKem.getKemct(),
                    org.bouncycastle.cms.CMSAlgorithm.SHA384_HKDF,new ASN1Integer(32),null,originalKem.getWrap(),originalKem.getEncryptedKey());
                MimeMessage changedKdf=replaceKem(message,wrongKdf);int callsBefore=sim.mlCalls;
                reject(()->MailEngine.open(changedKdf,recipient,null,sim),"KDF substitution rejected before token");
                if(sim.mlCalls!=callsBefore)throw new AssertionError("Bad KDF contacted token");
                byte[] corruptedCt=originalKem.getKemct().getOctets().clone();corruptedCt[0]^=1;
                var badKem=new KEMRecipientInfo(originalKem.getRecipientIdentifier(),originalKem.getKem(),new DEROctetString(corruptedCt),
                    originalKem.getKdf(),new ASN1Integer(32),null,originalKem.getWrap(),originalKem.getEncryptedKey());
                MimeMessage changedCt=replaceKem(message,badKem);
                reject(()->MailEngine.open(changedCt,recipient,null,sim),"corrupted ML-KEM encapsulation cannot recover plaintext");sim.assertWiped();
                byte[] mac=env.getMac().getOctets().clone();mac[0]^=1;
                var broken=new AuthEnvelopedData(env.getOriginatorInfo(),env.getRecipientInfos(),env.getAuthEncryptedContentInfo(),env.getAuthAttrs(),new DEROctetString(mac),env.getUnauthAttrs());
                MimeMessage bad=MailEngine.parse(MailEngine.encode(message));bad.setDataHandler(new DataHandler(new ByteArrayDataSource(new ContentInfo(ci.getContentType(),broken).getEncoded(),message.getContentType())));bad.saveChanges();
                reject(()->MailEngine.open(bad,recipient,null,sim),"bad GCM tag rejected after token recovery");sim.assertWiped();
                byte[] invalid=new byte[composite?1153:1087];int calls=sim.mlCalls;
                reject(()->ExternalKem.recover(pub,invalid,sim),"malformed KEM ciphertext rejected before token");
                if(sim.mlCalls!=calls)throw new AssertionError("Malformed ciphertext contacted token");
                if(composite){
                    sim.failEc=true;int cleanup=sim.clears;
                    reject(()->MailEngine.open(message,recipient,null,sim),"ECDH failure aborts hybrid decryption without fallback");
                    if(sim.clears!=cleanup+1)throw new AssertionError("Failure did not clear PIN scope");sim.assertWiped();
                }
            }
        }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
