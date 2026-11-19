package dev.hybridmail;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
public final class LegacyOpenPgpPolicyTest {
 static final String EMAIL="legacy@example.com";
 static void ok(boolean b)throws Exception{OpenPgp.check(b,"v4 policy assertion failed");}
 static JcaPGPContentSignerBuilder builder(PGPKeyPair pair,int hash){return new JcaPGPContentSignerBuilder(pair.getPublicKey().getAlgorithm(),hash).setProvider("BC");}
 static PGPKeyPair pair(String name,int algorithm)throws Exception{var g=KeyPairGenerator.getInstance(name,"BC");if(name.equals("RSA"))g.initialize(2048);if(name.equals("EC"))g.initialize(new ECGenParameterSpec("secp384r1"));return new JcaPGPKeyPair(4,algorithm,g.generateKeyPair(),new Date(System.currentTimeMillis()-60000));}
 static PGPSignature signature(PGPKeyPair pair,int type,PGPSignatureSubpacketVector metadata)throws Exception{var s=new PGPSignatureGenerator(builder(pair,8),pair.getPublicKey());s.init(type,pair.getPrivateKey());s.setHashedSubpackets(metadata);return s.generateCertification(pair.getPublicKey());}
 static PGPPublicKeyRing ring(PGPKeyPair primary,PGPKeyPair enc,int fault)throws Exception{
  var h=new PGPSignatureSubpacketGenerator();h.setKeyFlags(false,3);h.setPreferredSymmetricAlgorithms(false,new int[]{9,7});h.setFeature(false,(byte)1);
  if(fault==1)h.setKeyExpirationTime(false,1);
  if(fault==2)h.setNotationData(true,true,"unsupported@example.com","reject");
  var gen=new PGPKeyRingGenerator(19,primary,EMAIL,new JcaPGPDigestCalculatorProviderBuilder().build().get(2),h.generate(),null,builder(primary,8),null);
  var sub=new PGPSignatureSubpacketGenerator();sub.setKeyFlags(false,12);if(fault==3)sub.setKeyExpirationTime(false,1);gen.addSubKey(enc,sub.generate(),null);return gen.generatePublicKeyRing();
 }
 public static void main(String[] args)throws Exception{
  MailEngine.init();
  for(String profile:List.of(Identity.HYBRID_65_P384_SIGN,Identity.HYBRID_87_SIGN)){
   var id=Identity.generate("warning@example.com",profile);ok(CryptoWarnings.pq(id.signingCert().getPublicKey(),true));ok(CryptoWarnings.pq(id.encryptionCert().getPublicKey(),false));
   var sign=(org.bouncycastle.jcajce.CompositePublicKey)id.signingCert().getPublicKey();var enc=(org.bouncycastle.jcajce.CompositePublicKey)id.encryptionCert().getPublicKey();ok(CryptoWarnings.pq(sign.getPublicKeys().get(0),true));ok(!CryptoWarnings.pq(sign.getPublicKeys().get(1),true));ok(CryptoWarnings.pq(enc.getPublicKeys().get(0),false));ok(!CryptoWarnings.pq(enc.getPublicKeys().get(1),false));
  }
  System.out.println("PASS hybrid and pure ML-DSA/ML-KEM suppress non-PQ warnings; classical components alone do not");
  byte[] data=OpenPgp.bytes("v4 signature policy");
  for(String algorithm:List.of("Ed25519","EC","RSA")){
   var primary=pair(algorithm,algorithm.equals("Ed25519")?22:algorithm.equals("EC")?19:1);var enc=pair("X25519",18);var ring=ring(primary,enc,0);var cert=new OpenPgp.PublicIdentity(ring.getEncoded());ok(cert.canEncrypt());
   var gen=new PGPSignatureGenerator(builder(primary,8),primary.getPublicKey());gen.init(0,primary.getPrivateKey());gen.update(data);byte[] sig=gen.generate().getEncoded();cert.legacy.verify(sig,data);
   var bad=data.clone();bad[0]^=1;LegacyOpenPgpTest.rejects(()->cert.legacy.verify(sig,bad));
   LegacyOpenPgpTest.rejects(()->new OpenPgp.PublicIdentity(ring(primary,enc,1).getEncoded()));LegacyOpenPgpTest.rejects(()->new OpenPgp.PublicIdentity(ring(primary,enc,2).getEncoded()));
   var expiredSub=new OpenPgp.PublicIdentity(ring(primary,enc,3).getEncoded());ok(!expiredSub.canEncrypt());LegacyOpenPgpTest.rejects(()->OpenPgp.encrypt(data,expiredSub));
   var revokedPrimary=PGPPublicKey.addCertification(ring.getPublicKey(),signature(primary,32,null));var revoked=PGPPublicKeyRing.insertPublicKey(ring,revokedPrimary);LegacyOpenPgpTest.rejects(()->new OpenPgp.PublicIdentity(revoked.getEncoded()));
   var subKey=ring.getPublicKeys();subKey.next();var k=subKey.next();var revoke=new PGPSignatureGenerator(builder(primary,8),primary.getPublicKey());revoke.init(40,primary.getPrivateKey());var rev=PGPPublicKey.addCertification(k,revoke.generateCertification(primary.getPublicKey(),k));var revokedSub=new OpenPgp.PublicIdentity(PGPPublicKeyRing.insertPublicKey(ring,rev).getEncoded());ok(!revokedSub.canEncrypt());
   var wrong=pair(algorithm,primary.getPublicKey().getAlgorithm());var fake=new PGPSignatureGenerator(builder(wrong,8),wrong.getPublicKey());fake.init(0,wrong.getPrivateKey());fake.update(data);LegacyOpenPgpTest.rejects(()->cert.legacy.verify(fake.generate().getEncoded(),data));
   var weak=new PGPSignatureGenerator(builder(primary,2),primary.getPublicKey());weak.init(0,primary.getPrivateKey());weak.update(data);LegacyOpenPgpTest.rejects(()->cert.legacy.verify(weak.generate().getEncoded(),data));
   System.out.println("PASS v4 "+algorithm+": signature, wrong key/tamper rejection, primary/subkey expiration and revocation, critical metadata, SHA-1 signature rejection");
  }
 }
}
