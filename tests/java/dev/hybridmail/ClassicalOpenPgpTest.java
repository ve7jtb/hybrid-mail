package dev.hybridmail;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.jcajce.CompositePrivateKey;
public final class ClassicalOpenPgpTest {
 static void check(boolean v)throws Exception{if(!v)throw new Exception("Classical OpenPGP assertion failed");}
 public static void main(String[]args)throws Exception{
  MailEngine.init();var id=Identity.generate("classical@example.com",Identity.HYBRID_87_SIGN);var token=new Identity(id.signingCert(),null,id.encryptionCert(),null,null);var hw=new OpenPgpTest.Hardware(id);
  for(boolean hardware:new boolean[]{false,true}){
   var current=hardware?token:id;var own=OpenPgp.create(current,hardware?hw:null);check(own.description().contains("not post-quantum"));
   var calc=new JcaKeyFingerprintCalculator();var ring=new PGPPublicKeyRing(own.encoded,calc);var primary=ring.getPublicKey();var iter=ring.getPublicKeys();iter.next();var sub=iter.next();check(primary.getAlgorithm()==19&&sub.getAlgorithm()==18);
   for(var it=primary.getSignaturesOfType(31);it.hasNext();){var sig=it.next();sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),primary);check(sig.verifyCertification(primary));}
   for(var it=primary.getSignaturesForID("classical@example.com");it.hasNext();){var sig=it.next();sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),primary);check(sig.verifyCertification("classical@example.com",primary));}
   for(var it=sub.getSignatures();it.hasNext();){var sig=it.next();sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),primary);check(sig.verifyCertification(primary,sub));}
   for(boolean encrypt:new boolean[]{false,true}){
    byte[] message=OpenPgpTest.incomingClassical(current,own,encrypt,"Classical test",hardware?hw:null);
    check(OpenPgp.open(message,own,own,current,hardware?hw:null).text().equals("Classical test"));
    var parts=OpenPgp.parts(message);byte[] data=OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(parts.second())),encrypt?"MESSAGE":"SIGNATURE");
    if(encrypt){var encrypted=(PGPEncryptedDataList)new PGPObjectFactory(data,calc).nextObject();var packet=(PGPPublicKeyEncryptedData)encrypted.get(0);var privateKey=new JcaPGPKeyConverter().setProvider("BC").getPGPPrivateKey(sub,((CompositePrivateKey)id.encryptionKey()).getPrivateKeys().get(1));byte[] plain=packet.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey)).readAllBytes();check(packet.verify());check(OpenPgp.openSigned(plain,own).length>0);}
    else{var sig=((PGPSignatureList)new PGPObjectFactory(data,calc).nextObject()).get(0);sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),primary);sig.update(parts.first());check(sig.verify());}
    data[data.length-1]^=1;try{if(encrypt)OpenPgp.envelope(data,own).open(new byte[24]);else OpenPgp.verify(OpenPgp.packets(data).get(0).body(),parts.first(),0,own.primary);throw new AssertionError("Tamper accepted");}catch(java.security.GeneralSecurityException expected){}
   }
   // Independently generated RFC 9580 ECDH/v2-SEIPD envelope must decrypt here.
   byte[] signed=OpenPgp.signed(OpenPgp.bytes("independent"),own,OpenPgp.signer(id,null));var out=new ByteArrayOutputStream();var gen=new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(9).setProvider("BC").setUseV6AEAD().setWithAEAD(3,10));gen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(sub).setProvider("BC"));try(var enc=gen.open(out,signed.length)){enc.write(signed);}var env=OpenPgp.envelope(out.toByteArray(),own);byte[] kek=OpenPgp.recover(env.ct(),current,hardware?hw:null,own);try{check(Arrays.equals(signed,env.open(kek)));}finally{OpenPgp.wipe(kek);}
  }
  check(hw.ml==0&&hw.kem==0&&hw.ec>0&&hw.dh>0);
  System.out.println("PASS Level 5 classical P-384 software/token-adapter round trips, BC self-signature and message verification, bidirectional ECDH encryption, tampering; zero ML-DSA/ML-KEM calls.");
 }
}
