package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.jcajce.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

/** Temporary synthetic identities only. Never use with real credentials. */
public final class DesktopInterop {
 static void write(Path dir,String name,byte[] data)throws Exception{Files.write(dir.resolve(name),data);}
 static void key(Path dir,String prefix,PrivateKey key)throws Exception{
  if(key instanceof CompositePrivateKey c){write(dir,prefix+"-pq.pk8",c.getPrivateKeys().get(0).getEncoded());write(dir,prefix+"-ec.pk8",c.getPrivateKeys().get(1).getEncoded());}
  else write(dir,prefix+"-pq.pk8",key.getEncoded());
 }
 static PrivateKey readKey(Path dir,String name,String alg)throws Exception{return KeyFactory.getInstance(alg,"BC").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(dir.resolve(name))));}
 static Identity load(Path dir)throws Exception{
  var cf=CertificateFactory.getInstance("X.509","BC");
  X509Certificate s=(X509Certificate)cf.generateCertificate(Files.newInputStream(dir.resolve("sign.cer")));
  X509Certificate e=(X509Certificate)cf.generateCertificate(Files.newInputStream(dir.resolve("kem.cer")));
  PrivateKey sk=readKey(dir,"sign-pq.pk8","ML-DSA"),ek=readKey(dir,"kem-pq.pk8","ML-KEM");
  if(Files.exists(dir.resolve("sign-ec.pk8")))sk=new CompositePrivateKey(SubjectPublicKeyInfo.getInstance(s.getPublicKey().getEncoded()).getAlgorithm().getAlgorithm(),sk,readKey(dir,"sign-ec.pk8","EC"));
  if(Files.exists(dir.resolve("kem-ec.pk8")))ek=new CompositePrivateKey(SubjectPublicKeyInfo.getInstance(e.getPublicKey().getEncoded()).getAlgorithm().getAlgorithm(),ek,readKey(dir,"kem-ec.pk8","EC"));
  return new Identity(s,sk,e,ek,null);
 }
 public static void main(String[]args)throws Exception{
  MailEngine.init();Path root=Path.of(args[1]);String[]levels={"level2","level3","level5"};String[][]algs={{Identity.PURE_44_SIGN,Identity.HYBRID_44_SIGN},{Identity.PURE_SIGN,Identity.HYBRID_65_P384_SIGN},{Identity.PURE_87_SIGN,Identity.HYBRID_87_SIGN}};
  for(int i=0;i<3;i++)for(int h=0;h<2;h++){
   String profile=levels[i]+"-"+(h==1?"hybrid":"pure");Path dir=root.resolve(profile);Files.createDirectories(dir);
   if(args[0].equals("generate")){
    Identity id=Identity.generate("ios-test@example.com",algs[i][h]);
    id.save(dir.resolve("desktop.p12"),"interop-password-only".toCharArray());
    write(dir,"sign.cer",id.signingCert().getEncoded());write(dir,"kem.cer",id.encryptionCert().getEncoded());key(dir,"sign",id.signingKey());key(dir,"kem",id.encryptionKey());
    for(boolean enc:new boolean[]{false,true})write(dir,enc?"encrypted.eml":"signed.eml",MailEngine.encode(MailEngine.compose(id,"ios-test@example.com","ios-test@example.com","Interop","Desktop interoperability test",enc?id.encryptionCert():null,null)));
    System.out.println("GENERATED "+profile);
   }else{
    Identity id=Files.exists(dir.resolve("ios.p12")) ? Identity.load(dir.resolve("ios.p12"),"interop-password-only".toCharArray()) : load(dir);
    // Verify both locally issued certificate signatures as well as the message.
    id.signingCert().verify(id.signingCert().getPublicKey(),"BC");id.encryptionCert().verify(id.signingCert().getPublicKey(),"BC");
    for(String name:List.of("ios-signed.eml","ios-encrypted.eml")){
     var opened=MailEngine.open(MailEngine.parse(Files.readAllBytes(dir.resolve(name))),id,null);
     if(!opened.text().contains("iOS interoperability test"))throw new Exception("Unexpected message body");
     System.out.println("PASS BC verifies/opens "+profile+" "+name);
    }
   }
  }
 }
}
