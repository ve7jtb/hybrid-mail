package dev.hybridmail;
import java.security.*;import java.security.spec.*;import java.nio.file.*;import java.util.*;
public class Level5CompatibilityTest {
 static class Backend implements ExternalMu.Backend,ExternalKem.Backend {
  final OpenPgpTest.Hardware base;final Map<String,KeyPair> extra=new HashMap<>();int signed,ml,ec,x;
  Backend(Identity id)throws Exception{base=new OpenPgpTest.Hardware(id);for(String slot:List.of("88","89")){var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new ECGenParameterSpec("secp384r1"));extra.put(slot,g.generateKeyPair());}extra.put("84",KeyPairGenerator.getInstance("ML-KEM-768","BC").generateKeyPair());extra.put("85",KeyPairGenerator.getInstance("X25519","BC").generateKeyPair());}
  public Backend newOperation(){return this;}public void clearSecrets(){}
  public byte[] sign(PublicKey k,byte[] d)throws Exception{return base.sign(k,d);}public byte[] signEcdsa(PublicKey k,byte[] d)throws Exception{return base.signEcdsa(k,d);}
  public byte[] decapsulate(PublicKey k,byte[] d)throws Exception{throw new Exception("Must route extra ML-KEM slot");}public byte[] derive(PublicKey k,PublicKey p)throws Exception{throw new Exception("Must route extra ECDH slot");}
  void matches(String slot,PublicKey pub)throws Exception{OpenPgp.check(Arrays.equals(extra.get(slot).getPublic().getEncoded(),pub.getEncoded()),"Wrong key/slot");}
  public byte[] signCompatibilityEcdsa(PublicKey pub,byte[] d)throws Exception{matches("88",pub);signed++;var s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(extra.get("88").getPrivate());s.update(d);return s.sign();}
  public byte[] decapsulateLevel5Compatibility(PublicKey pub,byte[] ct)throws Exception{matches("84",pub);ml++;return new org.bouncycastle.crypto.kems.MLKEMExtractor((org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(extra.get("84").getPrivate().getEncoded())).extractSecret(ct);}
  public byte[] deriveLevel5Compatibility(PublicKey pub,PublicKey peer)throws Exception{String slot=pub instanceof java.security.interfaces.ECPublicKey?"89":"85";matches(slot,pub);if(slot.equals("89"))ec++;else x++;return OpenPgp.derive(extra.get(slot).getPrivate(),peer);}
 }
 public static void main(String[] args)throws Exception{
  MailEngine.init();var ids=Identity.generateSoftwareProfile("level5@example.org",TokenProfile.LEVEL5,List.of());var id=ids.get(1);var backend=new Backend(id);var root=Files.createTempDirectory("level5-compat-");var keys=new HashMap<String,PublicKey>();backend.extra.forEach((s,k)->keys.put(s,k.getPublic()));
  var full=Level5Compatibility.issue(root,id,keys,backend);var own=OpenPgp.loadOwn(root,id);var classic=Level5Compatibility.classical(full);
  OpenPgp.check(full.quantumEncryption()&&!classic.quantumEncryption()&&classic.canEncrypt()&&full.primary[5]==19&&classic.primary[5]==19,"Wrong recipient policy");
  for(var target:List.of(full,classic))for(boolean encrypt:new boolean[]{false,true}){
   byte[] message=OpenPgp.composeForRecipient(id,own,target,encrypt,own.email,own.email,"Compatibility test","Synthetic Level 5 compatibility test","<b>Synthetic Level 5 compatibility test</b>",backend);
   var opened=OpenPgp.open(message,full,own,id,backend);OpenPgp.check(opened.encrypted()==encrypt&&!opened.postQuantum()&&opened.text().contains("Synthetic Level 5 compatibility test")&&opened.html().equals("<b>Synthetic Level 5 compatibility test</b>"),"Round trip failed");
  }
  OpenPgp.check(backend.ml==1&&backend.x==1&&backend.ec==1,"Wrong component routing");
  var profiles=List.of(new OnKeyBundle.Profile(new CertificateBundle.Entry(ids.get(0),123456,"9c","83","9d","82"),new byte[0]),new OnKeyBundle.Profile(new CertificateBundle.Entry(id,123456,"9c","83","9d","82"),own.encoded,full.encoded));
  byte[] bundle=OnKeyBundle.sign(profiles,1,backend);var card=new OnKeyBundleTest.Fake();card.keys.putAll(OnKeyBundle.bindings(profiles.stream().map(OnKeyBundle.Profile::entry).toList()));keys.forEach((s,k)->card.keys.put(s,k.getEncoded()));OnKeyStorage.save(card,bundle,new char[]{'x'});var restored=OnKeyStorage.load(card);var fresh=Files.createTempDirectory("level5-restored-");restored.savePgp(fresh);OpenPgp.check(OpenPgp.loadOwn(fresh,id).compatibility.fingerprint().equals(full.fingerprint()),"Compatibility missing after restore");
  card.keys.put("84",new byte[]{1});OnKeyBundleTest.fails(()->OnKeyStorage.load(card));
  if(args.length>0){var out=Path.of(args[0]);Files.createDirectories(out);Files.write(out.resolve("level5-compatibility.asc"),full.export());Files.write(out.resolve("level5-classical.asc"),classic.export());Files.write(out.resolve("bundle.pqkey"),bundle);}
  System.out.println("PASS P-384 v4 signing; preferred ML-KEM-768/X25519 and P-384 fallback encryption/decryption; dedicated slot routing; compressed bundle restore and wrong-key rejection");
 }
}
