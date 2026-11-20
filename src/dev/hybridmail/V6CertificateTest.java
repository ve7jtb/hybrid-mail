package dev.hybridmail;
import java.nio.file.*;import java.util.*;import org.bouncycastle.openpgp.*;
public final class V6CertificateTest {
 public static void main(String[] args)throws Exception {
  MailEngine.init();Path dir=Path.of(args[0]);var cert=new OpenPgp.PublicIdentity(Files.readAllBytes(dir.resolve("public.asc")));byte[] content=Files.readAllBytes(dir.resolve("content.mime")),sig=OpenPgp.unarmor(Files.readAllBytes(dir.resolve("signature.asc")),"SIGNATURE");
  OpenPgp.check(cert.version()==6&&cert.certifiedEmails().size()==2&&cert.canEncrypt()&&cert.quantumEncryption(),"Certificate capabilities lost");cert.v6.verify(sig,content);
  byte[] bad=content.clone();bad[0]^=1;LegacyOpenPgpTest.rejects(()->cert.v6.verify(sig,bad));
  var ring=(PGPPublicKeyRing)LegacyOpenPgp.objects(cert.encoded).nextObject();var stripped=new ArrayList<PGPPublicKey>();
  for(var it=ring.getPublicKeys();it.hasNext();){var k=it.next();if(!k.isMasterKey())for(var signatures=k.getSignaturesOfType(24);signatures.hasNext();)k=PGPPublicKey.removeCertification(k,signatures.next());stripped.add(k);}
  var unbound=new OpenPgp.PublicIdentity(new PGPPublicKeyRing(stripped).getEncoded());OpenPgp.check(!unbound.canEncrypt(),"Unbound encryption key accepted");LegacyOpenPgpTest.rejects(()->unbound.v6.verify(sig,content));LegacyOpenPgpTest.rejects(()->OpenPgp.encrypt(content,unbound));
  byte[] rev=OpenPgp.unarmor(Files.readAllBytes(dir.resolve("revocation.asc")),"PUBLIC KEY BLOCK");var revokedRing=(PGPPublicKeyRing)LegacyOpenPgp.objects(rev).nextObject();var primary=PGPPublicKey.addCertification(ring.getPublicKey(),revokedRing.getPublicKey().getSignaturesOfType(PGPSignature.KEY_REVOCATION).next());var revoked=PGPPublicKeyRing.insertPublicKey(ring,primary);LegacyOpenPgpTest.rejects(()->new OpenPgp.PublicIdentity(revoked.getEncoded()));
  System.out.println("PASS Sequoia v6 multi-UID/certification primary/signing and authentication subkeys; signature verification; tamper, unbound keys and revoked primary rejection");
 }
}
