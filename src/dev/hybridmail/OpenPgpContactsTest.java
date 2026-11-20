package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
public class OpenPgpContactsTest {
 static void ok(boolean value)throws Exception{OpenPgp.check(value,"OpenPGP contact persistence assertion failed");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path root=Files.createTempDirectory("pq-pgp-contacts-");
  try{
   var state=new DesktopState(root);var id=Identity.generate("alice@example.com",Identity.HYBRID_65_P384_SIGN);var key=OpenPgp.create(id,null);
   var contact=state.rememberPgp(key,"ALICE@example.com");ok(state.pgpContacts().size()==1&&!state.isPgpTrusted(contact.email(),key.fingerprint()));
   state=new DesktopState(root);ok(Arrays.equals(key.encoded,state.pgpCertificate(contact).encoded));state.setPgpTrusted(contact,true);state=new DesktopState(root);ok(state.isPgpTrusted("ALICE@example.com",key.fingerprint()));ok(!state.isPgpTrusted("other@example.com",key.fingerprint()));
   state.rememberPgp(key,"alice@example.com");ok(state.pgpContacts().size()==1&&state.isPgpTrusted(contact.email(),key.fingerprint()));
   var replacement=OpenPgp.create(Identity.generate("alice@example.com",Identity.HYBRID_65_P384_SIGN),null);state.rememberPgp(replacement,"alice@example.com");ok(state.pgpContacts().size()==2&&!state.isPgpTrusted(contact.email(),replacement.fingerprint()));
   state.setPgpTrusted(contact,false);state=new DesktopState(root);ok(!state.isPgpTrusted(contact.email(),key.fingerprint()));state.setPgpTrusted(contact,true);state.removePgp(contact);state=new DesktopState(root);ok(!state.isPgpTrusted(contact.email(),key.fingerprint()));contact=state.rememberPgp(key,contact.email());ok(!state.isPgpTrusted(contact.email(),key.fingerprint()));
   state.setPgpTrusted(contact,true);Files.write(root.resolve("openpgp-contacts").resolve(contact.id()).resolve("public.asc"),replacement.export());boolean rejected=false;try{state.isPgpTrusted(contact.email(),key.fingerprint());}catch(Exception expected){rejected=true;}ok(rejected);
   if(args.length>0){var v4=new OpenPgp.PublicIdentity(Files.readAllBytes(Path.of(args[0])));var first=state.rememberPgp(v4,"dkg@fifthhorseman.net");var alias=state.rememberPgp(v4,"dkg@debian.org");state.setPgpTrusted(first,true);state=new DesktopState(root);ok(state.isPgpTrusted(first.email(),v4.fingerprint())&&!state.isPgpTrusted(alias.email(),v4.fingerprint()));}
   System.out.println("PASS v4/v6 contact restart persistence, no implicit trust, exact email/full-primary-fingerprint binding, replacement-key isolation, remove/reimport, file substitution rejection");
  }finally{try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
