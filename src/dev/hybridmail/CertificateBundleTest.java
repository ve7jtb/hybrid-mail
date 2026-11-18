package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
import java.io.*;
public final class CertificateBundleTest {
 interface Checked {void run()throws Exception;}
 static void rejects(Checked action)throws Exception{try{action.run();throw new AssertionError("Invalid bundle accepted");}catch(IOException|IllegalArgumentException|java.security.GeneralSecurityException expected){}}
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path root=Files.createTempDirectory("certificate-bundle-");
  try{for(var profile:TokenProfile.values()){
   var identities=Identity.generateSoftwareProfile("share@example.test",profile,List.of());List<CertificateBundle.Entry> entries=new ArrayList<>();
   for(var id:identities)entries.add(new CertificateBundle.Entry(id,12345678,"9c","9a","83","84"));
   byte[] bytes=CertificateBundle.encode(entries);var decoded=CertificateBundle.decode(bytes);
   if(decoded.size()!=2)throw new AssertionError("Missing profile");
   for(int i=0;i<2;i++){var e=decoded.get(i);if(e.identity().signingKey()!=null||e.identity().encryptionKey()!=null||e.identity().traditionalKey()!=null)throw new AssertionError("Private key export");if(!Arrays.equals(e.identity().signingCert().getEncoded(),identities.get(i).signingCert().getEncoded())||!Arrays.equals(e.identity().encryptionCert().getEncoded(),identities.get(i).encryptionCert().getEncoded())||!e.kemSlot().equals("83"))throw new AssertionError("Public bundle mismatch");}
   var state=new DesktopState(root.resolve(profile.code));state.importCertificateBundle(decoded,true);state.importCertificateBundle(decoded,true);
   if(state.identities().size()!=2||!state.get("selected.identity","").isEmpty())throw new AssertionError("Import changed active selection or duplicated profiles");
   for(var saved:state.identities()){var id=state.loadIdentity(saved.id(),new char[0]);state.activateIdentity(id);if(!DesktopState.activeTokenSerial().equals("12345678")||state.isTrusted(id.signingCert(),"signing"))throw new AssertionError("Binding or trust");}
   state.importCertificateBundle(decoded,false);if(state.contacts().size()!=4)throw new AssertionError("Missing contacts");
   for(var contact:state.contacts())if(state.isTrusted(state.contactCertificate(contact),contact.role()))throw new AssertionError("Implicit trust");
   rejects(()->CertificateBundle.decode(Arrays.copyOf(bytes,CertificateBundle.MAX_BYTES+1)));
   rejects(()->CertificateBundle.decode((new String(bytes,java.nio.charset.StandardCharsets.ISO_8859_1)+"\ntrusted=true\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
   rejects(()->CertificateBundle.decode((new String(bytes,java.nio.charset.StandardCharsets.ISO_8859_1)+"\nversion=1\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
   rejects(()->CertificateBundle.encode(List.of(new CertificateBundle.Entry(identities.get(0),12345678,"9c","9a","9a","82"))));
   rejects(()->state.importCertificateBundle(List.of(new CertificateBundle.Entry(identities.get(0),99999999,"9c","9a","83","84")),true));
   System.out.println("PASS "+profile.code+": pure/hybrid public bundle, serial/slots, idempotent identity/contact import, no implicit trust, malformed/conflicting bundle rejection");
  }}finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
