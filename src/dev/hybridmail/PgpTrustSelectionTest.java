package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
import javax.swing.*;
import org.bouncycastle.openpgp.*;
public class PgpTrustSelectionTest {
 static void ok(boolean b)throws Exception{OpenPgp.check(b,"Multi-email trust assertion failed");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();var pair=LegacyOpenPgpPolicyTest.pair("Ed25519",22);var enc=LegacyOpenPgpPolicyTest.pair("X25519",18);var ring=LegacyOpenPgpPolicyTest.ring(pair,enc,0);
  var generator=new PGPSignatureGenerator(LegacyOpenPgpPolicyTest.builder(pair,8),pair.getPublicKey());generator.init(19,pair.getPrivateKey());var params=new PGPSignatureSubpacketGenerator();params.setKeyFlags(false,3);generator.setHashedSubpackets(params.generate());String alias="alias@example.com";
  var primary=PGPPublicKey.addCertification(ring.getPublicKey(),alias,generator.generateCertification(alias,ring.getPublicKey()));var key=new OpenPgp.PublicIdentity(PGPPublicKeyRing.insertPublicKey(ring,primary).getEncoded());
  Path root=Files.createTempDirectory("multi-pgp-trust-");
  try{
   var state=new DesktopState(root);state.rememberPgp(key,"legacy@example.com");
   SwingUtilities.invokeAndWait(()->{try{
    var panel=new PgpTrustSelectionPanel(state,key,"legacy@example.com");ok(panel.addresses.size()==2&&panel.selectedEmails().equals(Set.of("legacy@example.com")));ok(!panel.selectAll.isSelected());
    panel.selectAll.doClick();ok(panel.selectedEmails().equals(Set.of("legacy@example.com",alias)));
    // Merely editing the dialog, then cancelling/closing it, does not persist anything.
    ok(!new DesktopState(root).isPgpTrusted(alias,key.fingerprint())&&state.pgpContacts().size()==1);
    state.setPgpTrustSelection(key,panel.selectedEmails());var reopened=new DesktopState(root);ok(reopened.pgpContacts().size()==2);for(String email:key.certifiedEmails())ok(reopened.isPgpTrusted(email,key.fingerprint()));
    var restored=new PgpTrustSelectionPanel(reopened,key,"legacy@example.com");ok(restored.selectAll.isSelected());restored.addresses.get(alias).doClick();ok(!restored.selectAll.isSelected());reopened.setPgpTrustSelection(key,restored.selectedEmails());
    var single=new DesktopState(root);ok(single.isPgpTrusted("legacy@example.com",key.fingerprint())&&!single.isPgpTrusted(alias,key.fingerprint()));
    boolean rejected=false;try{single.setPgpTrustSelection(key,Set.of("intruder@example.com"));}catch(Exception expected){rejected=true;}ok(rejected&&new DesktopState(root).isPgpTrusted("legacy@example.com",key.fingerprint()));
    single.setPgpTrustSelection(key,Set.of());for(String email:key.certifiedEmails())ok(!new DesktopState(root).isPgpTrusted(email,key.fingerprint()));
    ok(key.canEncrypt()&&!key.legacy.signers.isEmpty());ok(key.encryptionDescription().equals("v4 classical X25519 (not PQ)"));
    System.out.println("PASS email list, Select all, existing selections, Cancel without writes, atomic invalid-selection rejection, alias creation, persistence, deselection/removal, signing+encryption certificate coverage");
   }catch(Exception e){throw new RuntimeException(e);}});
  }finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
