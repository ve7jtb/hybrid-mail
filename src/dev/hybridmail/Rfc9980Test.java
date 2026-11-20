package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;
public final class Rfc9980Test {
 static void ok(boolean b)throws Exception{OpenPgp.check(b,"RFC9980 assertion failed");}
 static final class Hardware implements ExternalMu.Backend,ExternalKem.Backend {
  final OpenPgpTest.Hardware pq;final KeyPair ed,x,compatEd,compatX;int edCalls,xCalls;
  Hardware(Identity id)throws Exception{pq=new OpenPgpTest.Hardware(id);compatEd=KeyPairGenerator.getInstance("Ed25519","BC").generateKeyPair();compatX=KeyPairGenerator.getInstance("X25519","BC").generateKeyPair();ed=KeyPairGenerator.getInstance("Ed25519","BC").generateKeyPair();x=KeyPairGenerator.getInstance("X25519","BC").generateKeyPair();}
  public Hardware newOperation(){return this;}
  public void clearSecrets(){pq.clearSecrets();}
  public byte[] sign(PublicKey pub,byte[] mu)throws Exception{return pq.sign(pub,mu);}
  public byte[] signCompatibilityEd25519(PublicKey pub,byte[] digest)throws Exception{ok(Arrays.equals(pub.getEncoded(),compatEd.getPublic().getEncoded()));Signature s=Signature.getInstance("Ed25519","BC");s.initSign(compatEd.getPrivate());s.update(digest);return s.sign();}
  public byte[] deriveCompatibility(PublicKey pub,PublicKey peer)throws Exception{ok(Arrays.equals(pub.getEncoded(),compatX.getPublic().getEncoded()));return OpenPgp.derive(compatX.getPrivate(),peer);}
  public byte[] signEcdsa(PublicKey pub,byte[] digest)throws Exception{return pq.signEcdsa(pub,digest);}
  public byte[] signEd25519(PublicKey pub,byte[] digest)throws Exception{edCalls++;ok(Arrays.equals(pub.getEncoded(),ed.getPublic().getEncoded()));Signature s=Signature.getInstance("Ed25519","BC");s.initSign(ed.getPrivate());s.update(digest);return s.sign();}
  public byte[] decapsulate(PublicKey pub,byte[] ct)throws Exception{return pq.decapsulate(pub,ct);}
  public byte[] derive(PublicKey pub,PublicKey peer)throws Exception{xCalls++;ok(Arrays.equals(pub.getEncoded(),x.getPublic().getEncoded()));return OpenPgp.derive(x.getPrivate(),peer);}
 }
 public static void main(String[] args)throws Exception{
  MailEngine.init();
  if(args.length>0){Path fixtures=Path.of(args[0]);var published=new OpenPgp.PublicIdentity(Files.readAllBytes(fixtures.resolve("rfc9980-public.asc")));var signature=OpenPgp.packets(OpenPgp.unarmor(Files.readAllBytes(fixtures.resolve("rfc9980-signature.asc")),"SIGNATURE"));OpenPgp.verify(signature.get(0).body(),OpenPgp.bytes("Testing\r\n"),1,published.primary);System.out.println("PASS RFC 9980 published public certificate self-signatures and detached signature");}
  var ids=Identity.generateSoftwareProfile("rfc@example.com",TokenProfile.LEVEL3,List.of());Identity id=ids.get(1);var hw=new Hardware(id);
  var own=OpenPgp.createRfc9980(id,hw,hw.ed.getPublic(),hw.x.getPublic());ok(own.primary[5]==30&&own.subkey[5]==35);
  for(boolean encrypt:new boolean[]{false,true}){byte[] message=OpenPgp.compose(id,own,encrypt?own:null,"rfc@example.com","rfc@example.com","Test","RFC 9980 test",hw);var opened=OpenPgp.open(MailEngine.encode(MailEngine.parse(message)),own,own,id,hw);ok(opened.text().equals("RFC 9980 test")&&opened.encrypted()==encrypt);}
  ok(hw.pq.ml==hw.edCalls&&hw.pq.kem==hw.xCalls&&hw.pq.ec==0&&hw.pq.dh==0&&hw.pq.clears>0);
  byte[] bad=own.encoded.clone();bad[bad.length-1]^=1;ok(!new OpenPgp.PublicIdentity(bad).canEncrypt());OnKeyBundleTest.fails(()->OpenPgp.encrypt(new byte[0],new OpenPgp.PublicIdentity(bad)));
  OnKeyBundleTest.fails(()->OpenPgp.combine(new byte[32],new byte[32],new byte[32],new byte[32]));
  var profiles=List.of(new OnKeyBundle.Profile(new CertificateBundle.Entry(ids.get(0),123456,"9c","83","9d","82"),new byte[0]),new OnKeyBundle.Profile(new CertificateBundle.Entry(id,123456,"9c","83","9d","82"),own.encoded));
  byte[] encoded=OnKeyBundle.sign(profiles,1,hw.pq);var card=new OnKeyBundleTest.Fake();card.keys.putAll(OnKeyBundle.bindings(profiles.stream().map(OnKeyBundle.Profile::entry).toList()));
  OnKeyBundleTest.fails(()->OnKeyStorage.save(card,encoded,new char[]{'x'}));ok(card.writes==0);
  card.keys.put("84",hw.ed.getPublic().getEncoded());card.keys.put("85",hw.x.getPublic().getEncoded());OnKeyStorage.save(card,encoded,new char[]{'x'});var restored=OnKeyStorage.load(card);ok(Arrays.equals(restored.profiles().get(1).pgp(),own.encoded));
  card.keys.put("84",new byte[]{1});OnKeyBundleTest.fails(()->OnKeyStorage.load(card));
  Path root=Files.createTempDirectory("rfc-pgp-test-");try{OpenPgp.createOwn(root,id,null);OpenPgp.replaceOwn(root,id,own);ok(OpenPgp.rfc9980(OpenPgp.loadOwn(root,id)));try(var stream=Files.list(root.resolve("openpgp"))){ok(stream.anyMatch(p->p.toString().endsWith(".backup")));}restored.savePgp(root);}finally{try(var stream=Files.walk(root)){for(Path p:stream.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
  System.out.println("PASS RFC 9980 certificates, signed/encrypted MIME, component routing, tamper and zero-secret rejection, on-key extra-slot validation, restore and preserved previous identity");
 }
}
