package dev.hybridmail;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@RunWith(AndroidJUnit4.class)
public class ProfileTest {
    @Before public void providers(){Security.removeProvider("BC");Security.insertProviderAt(new BouncyCastleProvider(),1);MailEngine.init();}
    @Test public void allSoftwareProfilesAndPkcs12()throws Exception {
        Path root=InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath().resolve("interop");Files.createDirectories(root);
        for(TokenProfile p:TokenProfile.values()){
            var ids=Identity.generateSoftwareProfile("android@example.test",p,List.of("alias@example.test"));
            Path bundle=root.resolve(p.code+".p12");Files.deleteIfExists(bundle);char[] password="test-only-password".toCharArray();ids.get(1).save(bundle,password,ids.get(0));
            var restored=Identity.loadProfiles(bundle,password);assertEquals(2,restored.size());
            try{Identity.loadProfiles(bundle,"incorrect-password".toCharArray());fail("Wrong password accepted");}catch(java.io.IOException expected){}
            for(int mode=0;mode<2;mode++){
                var id=restored.get(mode);assertEquals(2,id.signingCert().getSubjectAlternativeNames().size());
                for(boolean encrypted:new boolean[]{false,true}){
                    var m=MailEngine.composeAttachments(id,"alias@example.test","android@example.test","Android interoperability",p.code+" mode "+mode,encrypted?id.encryptionCert():null,null,java.util.List.of(new MailEngine.Attachment("résumé.bin",new byte[]{0,1,13,10,(byte)255})));
                    byte[] bytes=MailEngine.encode(m);var opened=MailEngine.open(MailEngine.parse(bytes),id,id.signingCert());
                    assertEquals("résumé.bin",opened.attachments().get(0).name());
                    assertArrayEquals(new byte[]{0,1,13,10,(byte)255},opened.attachments().get(0).data());
                    assertEquals(encrypted,opened.encrypted());assertTrue(opened.pinned());assertTrue(opened.fromMatches());assertEquals(p.code+" mode "+mode,opened.text());
                    Files.write(root.resolve(p.code+"-"+mode+"-"+encrypted+".eml"),bytes);
                    if(encrypted){
                        var info=org.bouncycastle.asn1.cms.ContentInfo.getInstance(m.getInputStream().readAllBytes());
                        var env=org.bouncycastle.asn1.cms.AuthEnvelopedData.getInstance(info.getContent());
                        var content=env.getAuthEncryptedContentInfo();byte[] ciphertext=content.getEncryptedContent().getOctets();ciphertext[ciphertext.length/2]^=1;
                        var changed=new org.bouncycastle.asn1.cms.AuthEnvelopedData(env.getOriginatorInfo(),env.getRecipientInfos(),new org.bouncycastle.asn1.cms.EncryptedContentInfo(content.getContentType(),content.getContentEncryptionAlgorithm(),new org.bouncycastle.asn1.DEROctetString(ciphertext)),env.getAuthAttrs(),env.getMac(),env.getUnauthAttrs());
                        var bad=new jakarta.mail.internet.MimeMessage(m);bad.setDataHandler(new jakarta.activation.DataHandler(new jakarta.mail.util.ByteArrayDataSource(new org.bouncycastle.asn1.cms.ContentInfo(info.getContentType(),changed).getEncoded(),m.getContentType())));bad.saveChanges();
                        try{MailEngine.open(bad,id,null);fail("Tampered ciphertext accepted");}catch(Exception expected){}
                    }
                }
            }
            Arrays.fill(password,'\0');
        }
    }
    @Test public void externalInterfacesAllProfiles()throws Exception{
        for(var p:TokenProfile.values()){
            var ml=KeyPairGenerator.getInstance(p.ml,"BC").generateKeyPair();var kem=KeyPairGenerator.getInstance(p.kem,"BC").generateKeyPair();
            var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new java.security.spec.ECGenParameterSpec(p.curve));var ec=g.generateKeyPair();var dh=g.generateKeyPair();
            ExternalMu.Backend signer=new ExternalMu.Backend(){
                public byte[] sign(PublicKey key,byte[] mu)throws Exception{assertEquals(64,mu.length);var s=new org.bouncycastle.crypto.signers.MLDSASigner();s.init(true,org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(ml.getPrivate().getEncoded()));return s.generateMuSignature(mu);}
                public byte[] signEcdsa(PublicKey key,byte[] digest)throws Exception{assertEquals(p.category==2?32:48,digest.length);var s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(ec.getPrivate());s.update(digest);return s.sign();}
            };
            ExternalKem.Backend recovery=new ExternalKem.Backend(){
                public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{var priv=(org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(kem.getPrivate().getEncoded());return new org.bouncycastle.crypto.kems.MLKEMExtractor(priv).extractSecret(ct);}
                public byte[] derive(PublicKey key,PublicKey peer)throws Exception{var a=javax.crypto.KeyAgreement.getInstance("ECDH","BC");a.init(dh.getPrivate());a.doPhase(peer,true);return a.generateSecret();}
            };
            for(boolean hybrid:new boolean[]{false,true}){
                var id=Identity.forTokenProfile("token@example.test",p,ml.getPublic(),hybrid?ec.getPublic():null,kem.getPublic(),hybrid?dh.getPublic():null,signer);
                assertNull(id.signingKey());assertNull(id.encryptionKey());
                var m=MailEngine.compose(id,"token@example.test","token@example.test","External interfaces","test",id.encryptionCert(),signer);
                assertEquals("test",MailEngine.open(m,id,id.signingCert(),recovery).text());
            }
        }
    }
}
