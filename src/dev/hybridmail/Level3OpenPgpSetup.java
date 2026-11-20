package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;
/** Initial issuance from existing on-device keys. Journal contains public certificates only. */
final class Level3OpenPgpSetup {
 static void same(PublicKey a,PublicKey b)throws Exception{OpenPgp.check(a!=null&&b!=null&&Arrays.equals(a.getEncoded(),b.getEncoded()),"Saved OpenPGP certificate does not match the setup keys");}
 static void validate(OpenPgp.PublicIdentity own,Identity id,Map<String,PublicKey> keys)throws Exception{
  OpenPgp.match(own,id);OpenPgp.check(own.separated()&&OpenPgp.rfc9980(own),"Expected separate Level 3 certification and signing keys");
  var cert=OpenPgp.parseKey(own.primary,true);same(cert.pq(),keys.get("86"));same(cert.ec(),keys.get("87"));
  same(own.signing.pq(),keys.get("9c"));same(own.signing.ec(),keys.get("84"));same(own.encryption.pq(),keys.get("9d"));same(own.encryption.ec(),keys.get("85"));same(own.classicalKey(true),keys.get("88"));same(own.classicalKey(false),keys.get("89"));
  OpenPgp.check(new HashSet<>(own.certifiedEmails()).equals(new HashSet<>(CertificateBundle.emails(id.signingCert()).stream().map(e->e.toLowerCase(Locale.ROOT)).toList())),"Saved OpenPGP email addresses differ from this setup");
 }
 static OpenPgp.PublicIdentity issue(Path root,Path journal,Identity id,Map<String,PublicKey> keys,ExternalMu.Backend signing,ExternalMu.Backend certification)throws Exception{
  Files.createDirectories(journal);Path v6=journal.resolve("level3-v6.asc"),v4=journal.resolve("level3-v4.asc");
  var own=Files.exists(v6)?new OpenPgp.PublicIdentity(Files.readAllBytes(v6)):OpenPgp.createInitialSeparated(id,keys,certification,signing);
  validate(own,id,keys);if(!Files.exists(v6))OpenPgpMigration.put(v6,own.export());
  OpenPgp.PublicIdentity compat;
  if(Files.exists(v4))compat=new OpenPgp.PublicIdentity(Files.readAllBytes(v4));
  else{var op=signing.newOperation();try{compat=OpenPgp.compatibilityCertificate(own,d->op.signCompatibilityEd25519(keys.get("88"),d));}finally{op.clearSecrets();}OpenPgpMigration.put(v4,compat.export());}
  OpenPgp.checkCompatibility(own,compat);OpenPgp.check(new HashSet<>(own.certifiedEmails()).equals(new HashSet<>(compat.certifiedEmails())),"Pending compatibility certificate email addresses differ");OpenPgp.classicalOnlyCompatibility(compat);
  Path destination=OpenPgp.ownPath(root,id);
  if(Files.exists(destination))OpenPgp.check(OpenPgp.loadOwn(root,id).fingerprint().equals(own.fingerprint()),"A different OpenPGP identity is already saved; restore its bundle instead");
  OpenPgpMigration.put(destination,own.export());OnKeyBundle.saveCompatibility(destination.resolveSibling(destination.getFileName()+".v4"),compat.encoded);
  return OpenPgp.loadOwn(root,id);
 }
}
