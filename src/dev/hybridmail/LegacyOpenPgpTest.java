package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
import org.bouncycastle.openpgp.*;
public final class LegacyOpenPgpTest {
 static void ok(boolean b)throws Exception{OpenPgp.check(b,"v4 interoperability assertion failed");}
 @FunctionalInterface interface Attempt{void run()throws Exception;}
 static void rejects(Attempt a)throws Exception{try{a.run();}catch(Exception expected){return;}throw new AssertionError("Invalid input accepted");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path dir=Path.of(args[0]);var key=new OpenPgp.PublicIdentity(Files.readAllBytes(dir.resolve("public.asc")));
  ok(key.legacy!=null&&key.matchesEmail("legacy@example.com")&&key.fingerprint().length()==40);
  byte[] content=Files.readAllBytes(dir.resolve("content.mime")),sig=Files.readAllBytes(dir.resolve("signature.asc"));
  byte[] message=OpenPgp.mimeWrap(content,OpenPgp.cat(OpenPgp.bytes("Content-Type: application/pgp-signature\r\n\r\n"),sig),false,"legacy@example.com","pgp@example.com","GnuPG v4");
  var opened=OpenPgp.open(message,key,null,null,null);ok(opened.display().startsWith("WARNING: Valid classical signature"));ok(!key.quantumEncryption());
  ok(opened.text().contains("Independent v4 verification ✓")&&opened.fromMatches()&&opened.profile().contains("not post-quantum"));
  ok(OpenPgp.open(MailEngine.encode(MailEngine.parse(message)),key,null,null,null).text().equals(opened.text()));
  ok(Arrays.equals(OpenPgp.openSigned(Files.readAllBytes(dir.resolve("signed.pgp")),key),content));
  byte[] altered=content.clone();altered[altered.length-3]^=1;rejects(()->key.legacy.verify(OpenPgp.unarmor(sig,"SIGNATURE"),altered));
  // Missing subkey binding must not grant signing capability; unrelated keys must not validate it.
  var ring=(PGPPublicKeyRing)LegacyOpenPgp.objects(key.encoded).nextObject();var stripped=new ArrayList<PGPPublicKey>();
  for(var it=ring.getPublicKeys();it.hasNext();){var k=it.next();if(!k.isMasterKey())for(var signatures=k.getSignaturesOfType(24);signatures.hasNext();)k=PGPPublicKey.removeCertification(k,signatures.next());stripped.add(k);}
  var unbound=new OpenPgp.PublicIdentity(new PGPPublicKeyRing(stripped).getEncoded());rejects(()->unbound.legacy.verify(OpenPgp.unarmor(sig,"SIGNATURE"),content));rejects(()->OpenPgp.encrypt(content,unbound));
  Identity id=Identity.generate("pgp@example.com",Identity.HYBRID_65_P384_SIGN);var own=OpenPgp.create(id,null);byte[] signed=OpenPgp.signed(content,own,OpenPgp.signer(id,null));
  Files.write(dir.resolve("encrypted.pgp"),OpenPgp.encrypt(signed,key));Files.write(dir.resolve("hybrid-public.asc"),own.export());Files.write(dir.resolve("expected-signed.pgp"),signed);
  byte[] outgoing=OpenPgp.compose(id,own,key,"pgp@example.com","legacy@example.com","Hybrid signed / classical encrypted","test",null);ok(OpenPgp.parts(outgoing).encrypted());
  rejects(()->OpenPgp.compose(id,own,key,"pgp@example.com","wrong@example.com","Mismatch","test",null));
  var classical=Identity.generate("classical@example.com",Identity.HYBRID_87_SIGN);var classicOwn=OpenPgp.create(classical,null);rejects(()->OpenPgp.compose(classical,classicOwn,key,"classical@example.com","legacy@example.com","No classical signing","test",null));
  var recipients=new OpenPgpRecipients();var old=recipients.change("legacy@example.com");recipients.change("changed@example.com");ok(!recipients.accept(old,key)&&recipients.choices().isEmpty());
  var current=recipients.change("legacy@example.com");ok(recipients.accept(current,key)&&recipients.choices().size()==1);ok(!recipients.accept(current,own));
  recipients.remember(unbound);ok(recipients.choices().isEmpty());recipients.remember(key);ok(recipients.choices().size()==1);recipients.change("pgp@example.com");recipients.remember(own);ok(recipients.choices().size()==1&&recipients.choices().get(0).legacy==null);
  System.out.println("PASS recipient address matching, unusable keys excluded, stale lookup rejection and v6 KEM selection");
  if(args.length>1){var dkg=new OpenPgp.PublicIdentity(Files.readAllBytes(Path.of(args[1])));ok(dkg.fingerprint().equalsIgnoreCase("D477040C70C2156A5C298549BB7E9101495E6BF7"));ok(OpenPgp.hex(OpenPgp.fingerprint(dkg.subkey)).equalsIgnoreCase("41156BA983637FD98257066CF2018A9C3952C3A3"));ok(dkg.matchesEmail("dkg@fifthhorseman.net")&&dkg.matchesEmail("dkg@debian.org"));OpenPgp.encrypt(signed,dkg);System.out.println("PASS actual DKG certificate: certified aliases and current Curve25519 encryption subkey; encryption generated locally only");}
  System.out.println("PASS GnuPG Ed25519 v4 detached/compressed signatures, MIME serialization, tampering, unbound subkeys, hybrid-only outgoing policy; encrypted hybrid payload ready for independent GnuPG decryption");
 }
}
