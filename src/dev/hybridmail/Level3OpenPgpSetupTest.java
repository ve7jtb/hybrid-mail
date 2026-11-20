package dev.hybridmail;
import java.nio.file.*;import java.security.*;import java.util.*;
public final class Level3OpenPgpSetupTest {
 public static void main(String[] args)throws Exception{
  MailEngine.init();var ids=Identity.generateSoftwareProfile("setup@example.test",TokenProfile.LEVEL3,List.of("alias@example.test"));var id=ids.get(1);var hw=new Rfc9980Test.Hardware(id);
  var certId=Identity.generateSoftwareProfile("cert@example.test",TokenProfile.LEVEL3,List.of()).get(1);var certHw=new Rfc9980Test.Hardware(certId);
  Map<String,PublicKey> keys=new HashMap<>();keys.put("9c",OpenPgp.identityKeys(id,true).pq());keys.put("9d",OpenPgp.identityKeys(id,false).pq());keys.put("83",OpenPgp.identityKeys(id,true).ec());keys.put("82",OpenPgp.identityKeys(id,false).ec());keys.put("84",hw.ed.getPublic());keys.put("85",hw.x.getPublic());keys.put("86",OpenPgp.identityKeys(certId,true).pq());keys.put("87",certHw.ed.getPublic());keys.put("88",hw.compatEd.getPublic());keys.put("89",hw.compatX.getPublic());
  Path root=Files.createTempDirectory("level3-initial-"),journal=root.resolve("setup");
  ExternalMu.Backend interrupted=new ExternalMu.Backend(){public byte[] sign(PublicKey k,byte[] m)throws Exception{return hw.sign(k,m);}public byte[] signEd25519(PublicKey k,byte[] m)throws Exception{return hw.signEd25519(k,m);}public byte[] signCompatibilityEd25519(PublicKey k,byte[] m)throws Exception{if(Files.exists(journal.resolve("level3-v6.asc")))throw new java.io.IOException("Synthetic cancellation during v4 issuance");return hw.signCompatibilityEd25519(k,m);}};
  OnKeyBundleTest.fails(()->Level3OpenPgpSetup.issue(root,journal,id,keys,interrupted,certHw));
  byte[] saved=Files.readAllBytes(journal.resolve("level3-v6.asc"));int certificationCalls=certHw.edCalls;
  var own=Level3OpenPgpSetup.issue(root,journal,id,keys,hw,certHw);
  OpenPgp.check(Arrays.equals(saved,own.export())&&certificationCalls==certHw.edCalls,"Recovery regenerated the v6 certificate");
  OpenPgp.check(own.separated()&&own.certifiedEmails().size()==2&&own.compatibility.certifiedEmails().size()==2,"Missing key separation or aliases");
  var classic=OpenPgp.classicalOnlyCompatibility(own.compatibility);
  for(var recipient:List.of(own,own.compatibility,classic)){
   byte[] mail=OpenPgp.composeForRecipient(id,own,recipient,true,own.email,own.email,"Synthetic","Level 3","<b>Level 3</b>",hw);
   var opened=OpenPgp.open(mail,recipient.version()==6?own:own.compatibility,own,id,hw);OpenPgp.check(opened.encrypted()&&opened.text().equals("Level 3")&&opened.html().equals("<b>Level 3</b>"),"Initial certificate round trip failed");
  }
  var entries=List.of(new CertificateBundle.Entry(ids.get(0),123456,"9c","83","9d","82"),new CertificateBundle.Entry(id,123456,"9c","83","9d","82"));var card=new OnKeyBundleTest.Fake();for(var e:keys.entrySet())card.keys.put(e.getKey(),e.getValue().getEncoded());
  byte[] bundle=OnKeyBundle.sign(OnKeyBundle.collect(entries,root),1,hw);OnKeyStorage.saveCompact(card,bundle,new char[]{'x'});var restored=OnKeyStorage.load(card);Path target=root.resolve("restored");restored.savePgp(target);var recovered=OpenPgp.loadOwn(target,id);OpenPgp.check(recovered.fingerprint().equals(own.fingerprint())&&recovered.compatibility!=null,"Initial bundle did not restore all certificates");
  int calls=hw.edCalls+certHw.edCalls;Level3OpenPgpSetup.issue(root,journal,id,keys,hw,certHw);OpenPgp.check(hw.edCalls+certHw.edCalls==calls,"Completed setup unexpectedly signed again");
  keys.put("87",hw.ed.getPublic());OnKeyBundleTest.fails(()->Level3OpenPgpSetup.issue(root,journal,id,keys,hw,certHw));
  var json=new com.google.gson.JsonObject();for(var e:keys.entrySet())json.addProperty(e.getKey(),Base64.getEncoder().encodeToString(e.getValue().getEncoded()));OpenPgp.check(TokenProvision.decode(json.toString(),true).size()==10,"Provisioning result lost keys");
  OpenPgp.check(!OpenPgpMigration.recoverable(new DesktopState(root.resolve("empty-state")),id),"Offered migration on a fresh instance");
  System.out.println("PASS complete Level 3 issuance, aliases, distinct roles, v6/v4 signing/decryption, interrupted v4 recovery without v6 regeneration, compressed bundle restore, wrong-key rejection and ten-key decoding; no hardware used");
 }
}
