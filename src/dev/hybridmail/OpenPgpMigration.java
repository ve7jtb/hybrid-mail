package dev.hybridmail;
import java.nio.file.*;import java.security.*;import java.security.spec.*;import java.util.*;
/** Public-only journal. Token bundle commits before local identity/trust changes. */
final class OpenPgpMigration {
 interface Card extends OnKeyBundle.Card {void checkCertificationEmpty()throws Exception;void generateCertification()throws Exception;}
 interface Cards {Card open(int serial)throws Exception;}
 static void put(Path path,byte[] data)throws Exception{Files.createDirectories(path.getParent());Path temp=Files.createTempFile(path.getParent(),"migration-",".tmp");try{Files.write(temp,data);Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}}
 static String run(DesktopState state,Identity id,List<CertificateBundle.Entry> entries,ExternalMu.Backend signing,ExternalMu.Backend certification,Cards cards,char[] admin)throws Exception {
  int serial=entries.get(0).serial();Path journal=state.directory().resolve("pgp-migration-"+serial+"-"+OpenPgp.hex(OpenPgp.hash("SHA-256",id.signingCert().getEncoded())));
  try{
   Files.createDirectories(journal);Path oldFile=journal.resolve("previous.asc"),newFile=journal.resolve("replacement.asc");
   OpenPgp.PublicIdentity previous;
   if(Files.exists(oldFile))previous=new OpenPgp.PublicIdentity(Files.readAllBytes(oldFile));
   else if(Files.exists(OpenPgp.ownPath(state.directory(),id)))previous=OpenPgp.loadOwn(state.directory(),id);
   else{byte[] ed,x;try(var card=cards.open(serial)){OnKeyBundle.check(card,entries);ed=card.publicKey("84");x=card.publicKey("85");OpenPgp.check(ed!=null&&x!=null,"Provision the RFC 9980 hybrid component keys in 84/85 first");}previous=OpenPgp.createRfc9980(id,signing,KeyFactory.getInstance("Ed25519","BC").generatePublic(new X509EncodedKeySpec(ed)),KeyFactory.getInstance("X25519","BC").generatePublic(new X509EncodedKeySpec(x)));}
   OpenPgp.check(OpenPgp.rfc9980(previous),"Select an existing RFC 9980 Level 3 YubiKey identity");
   if(!Files.exists(oldFile)){OpenPgp.check(!previous.separated(),"This identity already has separate certification keys");put(oldFile,previous.export());}
   Path trusted=journal.resolve("trusted-emails.txt");if(!Files.exists(trusted)){var emails=new ArrayList<String>();for(String email:previous.certifiedEmails())if(state.isPgpTrusted(email,previous.fingerprint()))emails.add(email);put(trusted,String.join("\n",emails).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
   Path mlFile=journal.resolve("86.der"),edFile=journal.resolve("87.der"),started=journal.resolve("generation-started");
   try(var card=cards.open(serial)){
    OnKeyBundle.check(card,entries);OnKeyBundle.checkPgp(card,List.of(new OnKeyBundle.Profile(entries.stream().filter(e->Arrays.equals(e.identity().signingCert().getPublicKey().getEncoded(),id.signingCert().getPublicKey().getEncoded())).findFirst().orElseThrow(),previous.encoded)));
    if(!Files.exists(mlFile)||!Files.exists(edFile)||!Files.exists(journal.resolve("88.der"))||!Files.exists(journal.resolve("89.der"))){
     OpenPgp.check(!Files.exists(started),"Earlier generation did not finish recording all four public keys. Do not retry generation: inspect slots 86–89 and recover the public-key journal first. Existing keys are preserved.");
     card.checkCertificationEmpty();card.authenticate(admin.clone());put(started,new byte[]{1});card.generateCertification();
     put(mlFile,Objects.requireNonNull(card.publicKey("86")));put(edFile,Objects.requireNonNull(card.publicKey("87")));for(String slot:List.of("88","89"))put(journal.resolve(slot+".der"),Objects.requireNonNull(card.publicKey(slot)));
    }
    OpenPgp.check(Arrays.equals(Files.readAllBytes(mlFile),card.publicKey("86"))&&Arrays.equals(Files.readAllBytes(edFile),card.publicKey("87")),"Certification keys differ from the migration journal");
    for(String slot:List.of("88","89"))OpenPgp.check(Arrays.equals(Files.readAllBytes(journal.resolve(slot+".der")),card.publicKey(slot)),"Compatibility key differs from migration journal");
   }
   var keys=new OpenPgp.Keys(KeyFactory.getInstance("ML-DSA","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(mlFile))),KeyFactory.getInstance("Ed25519","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(edFile))));
   var replacement=Files.exists(newFile)?new OpenPgp.PublicIdentity(Files.readAllBytes(newFile)):OpenPgp.createSeparated(id,previous,keys,certification,signing,KeyFactory.getInstance("Ed25519","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(journal.resolve("88.der")))),KeyFactory.getInstance("X25519","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(journal.resolve("89.der")))));
   OpenPgp.match(replacement,id);OpenPgp.check(replacement.separated()&&Arrays.equals(OpenPgp.raw(OpenPgp.parseKey(replacement.primary,true).pq()),OpenPgp.raw(keys.pq()))&&Arrays.equals(OpenPgp.raw(OpenPgp.parseKey(replacement.primary,true).ec()),OpenPgp.raw(keys.ec())),"Invalid replacement certification key");put(newFile,replacement.export());
   Path v4File=journal.resolve("compatibility.asc"),oldV4File=journal.resolve("previous-v4.asc"),v4Trust=journal.resolve("trusted-v4-emails.txt");
   if(!Files.exists(v4Trust)){var trustedV4=new ArrayList<String>();for(var contact:state.pgpContacts()){var known=state.pgpCertificate(contact);if(known.fingerprint().equals(OpenPgp.oldCompatibilityFingerprint(previous))){put(oldV4File,known.export());if(state.isPgpTrusted(contact.email(),known.fingerprint()))trustedV4.add(contact.email());}}put(v4Trust,String.join("\n",trustedV4).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
   OpenPgp.PublicIdentity compatibility;
   if(Files.exists(v4File))compatibility=new OpenPgp.PublicIdentity(Files.readAllBytes(v4File));else{var op=signing.newOperation();try{compatibility=OpenPgp.compatibilityCertificate(replacement,digest->op.signCompatibilityEd25519(replacement.classicalKey(true),digest));put(v4File,compatibility.export());}finally{op.clearSecrets();}}
   OpenPgp.checkCompatibility(replacement,compatibility);
   var profiles=new ArrayList<OnKeyBundle.Profile>();int signer=-1;
   for(var entry:entries){byte[] pgp=new byte[0];if(OpenPgp.supported(entry.identity())){try{var saved=OpenPgp.loadOwn(state.directory(),entry.identity());pgp=saved.encoded;if(saved.fingerprint().equals(previous.fingerprint())||saved.fingerprint().equals(replacement.fingerprint()))pgp=replacement.encoded;}catch(NoSuchFileException e){/* no OpenPGP identity */}}
    if(Arrays.equals(entry.identity().signingCert().getEncoded(),id.signingCert().getEncoded())){pgp=replacement.encoded;signer=profiles.size();}profiles.add(new OnKeyBundle.Profile(entry,pgp,pgp.length>0&&new OpenPgp.PublicIdentity(pgp).fingerprint().equals(replacement.fingerprint())?compatibility.encoded:new byte[0]));}
   OpenPgp.check(signer>=0,"Selected identity missing from bundle");byte[] bundle=OnKeyBundle.sign(profiles,signer,signing);
   try(var card=cards.open(serial)){OnKeyStorage.saveCompact(card,bundle,admin.clone());var restored=OnKeyStorage.load(card);OpenPgp.check(Arrays.equals(restored.encoded(),bundle),"Bundle restore differs after migration");}
   for(var profile:profiles)if(profile.pgp().length>0&&new OpenPgp.PublicIdentity(profile.pgp()).fingerprint().equals(replacement.fingerprint())){OpenPgp.replaceOwn(state.directory(),profile.entry().identity(),replacement);Path saved=OpenPgp.ownPath(state.directory(),profile.entry().identity());put(saved.resolveSibling(saved.getFileName()+".v4"),compatibility.encoded);}
   state.migratePgpTrust(previous,replacement,new HashSet<>(Files.readAllLines(trusted)));state.migratePgpTrust(Files.exists(oldV4File)?new OpenPgp.PublicIdentity(Files.readAllBytes(oldV4File)):previous,compatibility,new HashSet<>(Files.readAllLines(v4Trust)));put(journal.resolve("complete"),new byte[]{1});
   return "Migration complete. Certification: 86/87; signing: 9c/84; encryption: 9d/85; classical compatibility: 88/89.\nNew fingerprint: "+replacement.fingerprint()+"\nExisting private keys preserved. Certificate bundle restored and verified; local trust updated. No email sent.";
  }finally{Arrays.fill(admin,'\0');}
 }
}
