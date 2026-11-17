package dev.hybridmail;
import java.security.*;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
public final class Token87Test {
 public static void main(String[] args)throws Exception{
  MailEngine.init();var ml=KeyPairGenerator.getInstance(Identity.PURE_87_SIGN,"BC").generateKeyPair();var kem=KeyPairGenerator.getInstance(Identity.PURE_1024_KEM,"BC").generateKeyPair();
  var generator=KeyPairGenerator.getInstance("EC","BC");generator.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));var ec=generator.generateKeyPair();var ecdh=generator.generateKeyPair();int[] calls={0,0};
  ExternalMu.Backend signer=new ExternalMu.Backend(){
   public byte[] sign(PublicKey key,byte[] mu)throws Exception{calls[0]++;var s=new MLDSASigner();s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(ml.getPrivate().getEncoded()),new SecureRandom()));return s.generateMuSignature(mu);}
   public byte[] signEcdsa(PublicKey key,byte[] digest)throws Exception{calls[1]++;if(digest.length!=48)throw new AssertionError("P384 SHA384 digest");var s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(ec.getPrivate());s.update(digest);return s.sign();}
  };
  Path dir=Files.createTempDirectory("token87-test-");
  try{
   DesktopState state=new DesktopState(dir);state.set("token.serial","111111");
   for(boolean hybrid:new boolean[]{false,true}){
    var identity=Identity.forToken87("token@example.test",ml.getPublic(),hybrid?ec.getPublic():null,kem.getPublic(),hybrid?ecdh.getPublic():null,signer);
    String id=state.remember(identity,"Token87",null);state.bindToken(id,"111111","9a","9d","82");identity=state.loadIdentity(id,null);
    if(identity.signingKey()!=null||identity.encryptionKey()!=null||identity.traditionalKey()!=null)throw new AssertionError("Private key stored");
    state.set("token.serial","222222");state.activateIdentity(identity);if(!DesktopState.activeTokenSerial().equals("111111"))throw new AssertionError("Device binding replaced by global settings");
    var recovery=new TokenKemTest.Simulator(kem,ecdh);
    var message=MailEngine.compose(identity,"token@example.test","token@example.test","Token87","Hardware interfaces",identity.encryptionCert(),signer);
    var opened=MailEngine.open(message,identity,identity.signingCert(),recovery);
    if(!opened.encrypted()||!opened.pinned()||!opened.text().equals("Hardware interfaces"))throw new AssertionError("Round trip");recovery.assertWiped();
    byte[] malformed=new byte[hybrid?1665:1567];int before=recovery.mlCalls;
    try{ExternalKem.recover(identity.encryptionCert().getPublicKey(),malformed,recovery);throw new AssertionError("Malformed accepted");}catch(GeneralSecurityException expected){}
    if(before!=recovery.mlCalls)throw new AssertionError("Malformed contacted token");
    System.out.println("PASS token87 "+hybrid+": external mu/P384, KEM1024/P384, public-only storage, per-identity serial binding");
   }
   if(calls[1]!=3)throw new AssertionError("Expected 3 hybrid ECDSA calls");
  }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
