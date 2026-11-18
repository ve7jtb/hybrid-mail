package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
public final class OpenPgpTest {
 static void ok(boolean v)throws Exception{OpenPgp.check(v,"OpenPGP test failed");}
 static byte[] hex(String value){byte[] out=new byte[value.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(value.substring(2*i,2*i+2),16);return out;}
 static final class Hardware implements ExternalMu.Backend,ExternalKem.Backend {
  final Identity source;int ml,ec,kem,dh,clears;
  Hardware(Identity source){this.source=source;}
  public Hardware newOperation(){return this;}
  public void clearSecrets(){clears++;}
  public byte[] sign(PublicKey pub,byte[] mu)throws Exception{ml++;var p=((CompositePrivateKey)source.signingKey()).getPrivateKeys();var s=new MLDSASigner();s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(p.get(0).getEncoded()),new SecureRandom()));return s.generateMuSignature(mu);}
  public byte[] signEcdsa(PublicKey pub,byte[] hash)throws Exception{ec++;ok(hash.length==48);Signature s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(((CompositePrivateKey)source.signingKey()).getPrivateKeys().get(1));s.update(hash);return s.sign();}
  public byte[] decapsulate(PublicKey pub,byte[] ct)throws Exception{kem++;var p=((CompositePrivateKey)source.encryptionKey()).getPrivateKeys();return new org.bouncycastle.crypto.kems.MLKEMExtractor((org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(p.get(0).getEncoded())).extractSecret(ct);}
  public byte[] derive(PublicKey pub,PublicKey peer)throws Exception{dh++;return OpenPgp.derive(((CompositePrivateKey)source.encryptionKey()).getPrivateKeys().get(1),peer);}
 }
 public static void run(Path fixtures)throws Exception {
  MailEngine.init();
  var pub=new OpenPgp.PublicIdentity(Files.readAllBytes(fixtures.resolve("nist-p384-public.asc")));
  ok(pub.fingerprint().equalsIgnoreCase("44F8AEA123A5BB7B747C714A3749876A84ECC7EFCAC6CB5ACCD1A152F6351DE6"));
  var sig=OpenPgp.packets(OpenPgp.unarmor(Files.readAllBytes(fixtures.resolve("nist-p384-signature.asc")),"SIGNATURE"));
  OpenPgp.verify(sig.get(0).body(),OpenPgp.bytes("Testing\n"),0,pub.primary);
  var env=OpenPgp.envelope(OpenPgp.unarmor(Files.readAllBytes(fixtures.resolve("nist-p384-message.asc")),"MESSAGE"),pub);
  byte[] kek=OpenPgp.combine(hex("6FC2B62C8A99B3ACE887055CEF120E763820D8742373FB9FBED1AE140056F34D"),hex("849DB1550BC587A213684D607C4B2A888FAADBEAC9B86F4D940CEDFF7CC6F2C6FEA19640135D2676E3309F3B496B114C"),OpenPgp.slice(env.ct(),0,97),OpenPgp.raw(pub.encryption.ec()));
  ok(OpenPgp.hex(kek).equalsIgnoreCase("E32208735F54262A792303915B26BD37BE621FC278617CE81EE62FB41C60F3FD"));
  ok(Arrays.equals(OpenPgp.openSigned(env.open(kek),pub),OpenPgp.bytes("Testing\n")));
  System.out.println("PASS published draft-05 public key, hybrid signature, KEM combiner and encrypted message");
  Identity id=Identity.generate("pgp@example.com",Identity.HYBRID_65_P384_SIGN);
  var hardware=new Hardware(id);var token=new Identity(id.signingCert(),null,id.encryptionCert(),null,null);
  for(boolean useToken:new boolean[]{false,true}) {
   var own=OpenPgp.create(useToken?token:id,useToken?hardware:null);
   for(boolean encrypted:new boolean[]{false,true}) {
    byte[] msg=OpenPgp.compose(useToken?token:id,own,encrypted?own:null,"pgp@example.com","pgp@example.com","Test","OpenPGP interoperable",useToken?hardware:null);
    var opened=OpenPgp.open(msg,own,own,useToken?token:id,useToken?hardware:null);ok(opened.text().equals("OpenPGP interoperable")&&opened.encrypted()==encrypted);
    // Check JavaMail serialization (SMTP/Gmail transport) retains signed MIME bytes.
    var serialized=MailEngine.encode(MailEngine.parse(msg));ok(OpenPgp.open(serialized,own,own,useToken?token:id,useToken?hardware:null).text().equals("OpenPGP interoperable"));
    var parts=OpenPgp.parts(msg);
    byte[] encoded=OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(parts.second())),encrypted?"MESSAGE":"SIGNATURE");encoded[encoded.length-1]^=1;
    byte[] changed=OpenPgp.mimeWrap(parts.first(),OpenPgp.cat(OpenPgp.bytes("Content-Type: "+(encrypted?"application/octet-stream":"application/pgp-signature")+"\r\n\r\n"),OpenPgp.armor(encoded,encrypted?"MESSAGE":"SIGNATURE")),encrypted,"pgp@example.com","pgp@example.com","Test");
    try{OpenPgp.open(changed,own,own,useToken?token:id,useToken?hardware:null);throw new AssertionError("Tamper accepted");}catch(GeneralSecurityException expected){}
   }
  }
  ok(hardware.ml==hardware.ec&&hardware.kem==hardware.dh&&hardware.clears>0);
  System.out.println("PASS software and external backend signing/decryption, transport serialization, tampering and cleanup");
 }
 public static void main(String[]args)throws Exception {
  MailEngine.init();
  if(args.length>0&&args[0].equals("generate")) {
   Path dir=Path.of(args[1]);Files.createDirectories(dir);Identity id=Identity.generate("interop@example.com",Identity.HYBRID_65_P384_SIGN);id.save(dir.resolve("identity.p12"),"interop-password-only".toCharArray());var own=OpenPgp.create(id,null);Files.write(dir.resolve("public.asc"),own.export());
   for(boolean enc:new boolean[]{false,true})Files.write(dir.resolve(enc?"java-encrypted.eml":"java-signed.eml"),OpenPgp.compose(id,own,enc?own:null,"interop@example.com","interop@example.com","Interop","Java OpenPGP test",null));
   System.out.println("PASS generated Java OpenPGP exchange fixtures");return;
  }
  if(args.length>0&&args[0].equals("verify")) {
   Path dir=Path.of(args[1]);Identity id=Identity.load(dir.resolve("identity.p12"),"interop-password-only".toCharArray());var own=new OpenPgp.PublicIdentity(Files.readAllBytes(dir.resolve("public.asc")));
   for(String file:List.of("swift-signed.eml","swift-encrypted.eml")){ok(OpenPgp.open(Files.readAllBytes(dir.resolve(file)),own,own,id,null).text().equals("Swift OpenPGP test"));System.out.println("PASS Java verifies/decrypts "+file);}return;
  }
  run(Path.of(args.length>0?args[0]:"ios/Tests/Fixtures"));
 }
}
