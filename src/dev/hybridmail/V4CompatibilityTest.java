package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
/** Local software simulation of the existing Ed25519 token adapter; no hardware or mail. */
public final class V4CompatibilityTest {
 static void ok(boolean b)throws Exception{OpenPgp.check(b,"Compatibility policy assertion failed");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();var id=Identity.generate("legacy@example.com",Identity.HYBRID_65_P384_SIGN);var hw=new Rfc9980Test.Hardware(id);
  var own=OpenPgp.createRfc9980(id,hw,hw.ed.getPublic(),hw.x.getPublic());
  OpenPgp.Signer signer=d->hw.signEd25519(hw.ed.getPublic(),d);
  var v4=OpenPgp.compatibilityCertificate(own,signer);ok(v4.version()==4&&v4.quantumEncryption()&&v4.canEncrypt());
  ok(v4.signingAlgorithms().equals("Ed25519")&&v4.encryptionAlgorithm().contains("ML-KEM"));
  var again=OpenPgp.compatibilityCertificate(own,signer);ok(v4.fingerprint().equals(again.fingerprint()));
  // A newer classical subkey must not displace a valid hybrid subkey.
  byte[] ec=OpenPgp.cat(OpenPgp.b(4),OpenPgp.n(OpenPgp.now(),4),OpenPgp.b(18,10,0x2b,6,1,4,1,0x97,0x55,1,5,1),OpenPgp.mpi(OpenPgp.cat(OpenPgp.b(0x40),OpenPgp.raw(hw.x.getPublic()))),OpenPgp.b(3,1,8,7));
  byte[] binding=OpenPgp.v4Signature(OpenPgp.cat(OpenPgp.v4KeyHash(v4.primary),OpenPgp.v4KeyHash(ec)),24,v4.primary,OpenPgp.sub(27,OpenPgp.b(12)),signer);
  var multiple=new OpenPgp.PublicIdentity(OpenPgp.cat(v4.encoded,OpenPgp.frame(14,ec),OpenPgp.frame(2,binding)));ok(multiple.quantumEncryption());
  // A verified revocation makes the hybrid unavailable and permits classical fallback.
  byte[] revoke=OpenPgp.v4Signature(OpenPgp.cat(OpenPgp.v4KeyHash(v4.primary),OpenPgp.v4KeyHash(v4.subkey)),40,v4.primary,OpenPgp.b(),signer);
  var fallback=new OpenPgp.PublicIdentity(OpenPgp.cat(v4.encoded,OpenPgp.frame(2,revoke),OpenPgp.frame(14,ec),OpenPgp.frame(2,binding)));
  ok(!fallback.quantumEncryption()&&fallback.canEncrypt());
  var classical=new OpenPgp.PublicIdentity(Files.readAllBytes(Path.of(args[0])));
  var recipients=new OpenPgpRecipients();recipients.change("legacy@example.com");recipients.remember(classical);recipients.remember(v4);ok(recipients.choices().get(0).quantumEncryption());recipients.remember(own);ok(recipients.choices().get(0).version()==6);
  var classicalV6=OpenPgp.create(Identity.generate("legacy@example.com",Identity.HYBRID_87_SIGN),null);var preference=new OpenPgpRecipients();preference.change("legacy@example.com");preference.remember(v4);preference.remember(classicalV6);ok(preference.choices().get(0).version()==6&&!preference.choices().get(0).quantumEncryption());
  byte[] signed=OpenPgp.composeForRecipient(id,own,v4,false,"legacy@example.com","legacy@example.com","Compatibility","Hello",hw);
  ok(!new String(own.export(),java.nio.charset.StandardCharsets.US_ASCII).contains("\r\n="));
  var parts=OpenPgp.parts(signed);
  var signature=OpenPgp.packets(OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(parts.second())),"SIGNATURE"));ok(signature.get(0).body()[1]==0);var attached=AttachedOpenPgp.find(MailEngine.parse(signed));ok(attached.size()==2&&attached.get(0).version()==4&&attached.get(1).version()==6);
  ok(!new String(v4.export(),java.nio.charset.StandardCharsets.US_ASCII).contains("\r\n="));
  ok(!new String(OpenPgp.decoded(OpenPgp.mime(parts.second())),java.nio.charset.StandardCharsets.US_ASCII).contains("\r\n="));
  var signingOnly=OpenPgp.signingOnlyCompatibility(v4);ok(!signingOnly.canEncrypt()&&signingOnly.fingerprint().equals(v4.fingerprint()));
  var mimeBody=new jakarta.mail.internet.MimeBodyPart(new java.io.ByteArrayInputStream(parts.first()));ok(((jakarta.mail.Multipart)mimeBody.getContent()).getCount()==4);
  var opened=OpenPgp.open(signed,signingOnly,null,null,null);ok(!opened.postQuantum()&&opened.text().equals("Hello"));
  for(var target:List.of(v4,classical)){
   byte[] encrypted=OpenPgp.composeForRecipient(id,own,target,true,"legacy@example.com","legacy@example.com","Compatibility","Hello",hw);
   var mime=OpenPgp.parts(encrypted);var packets=OpenPgp.packets(OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(mime.second())),"MESSAGE"));ok(packets.get(0).tag()==1&&packets.get(0).body()[0]==3);
   ok((packets.get(0).body()[9]&255)==target.legacy.recipient.getAlgorithm());
   if(target==v4){var result=OpenPgp.open(encrypted,v4,own,id,hw);ok(result.encrypted()&&!result.postQuantum()&&result.text().equals("Hello"));byte[] damaged=encrypted.clone();var raw=OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(mime.second())),"MESSAGE");raw[raw.length-1]^=1;OnKeyBundleTest.fails(()->OpenPgp.openCompatibilityEncrypted(raw,own,id,hw));}
  }
  var modern=OpenPgp.composeForRecipient(id,own,own,false,"legacy@example.com","legacy@example.com","Hybrid","Hello",hw);ok(OpenPgp.open(modern,own,null,null,null).postQuantum());
  var unknown=OpenPgp.composeForRecipient(id,own,null,false,"legacy@example.com","other@example.com","Hybrid","Hello",hw);ok(OpenPgp.open(unknown,own,null,null,null).postQuantum());
  System.out.println("PASS v6-first/hybrid-first selection; v4 Ed25519 certification and MIME signatures; attached v4 hybrid certificate; v3 PKESK hybrid/classical recipients; v6 hybrid for v6/unknown recipients");
 }
}
