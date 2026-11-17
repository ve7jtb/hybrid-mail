package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.jcajce.*;
public final class SoftwareProfilesTest {
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path dir=Files.createTempDirectory("software-profiles-");char[] password="test-only-bundle-password".toCharArray();
  try{
   for(String invalid:List.of("one@example.test,two@example.test,three@example.test,four@example.test,five@example.test","bundle@example.test","a@example.test,A@example.test","not-an-email")){
    try{Identity.additionalEmails("bundle@example.test",invalid);throw new AssertionError("Accepted invalid SAN input");}catch(IllegalArgumentException|jakarta.mail.internet.AddressException expected){}
   }
   var extra=Identity.additionalEmails("bundle@example.test","one@example.test,two@example.test,three@example.test,four@example.test");
   for(var profile:TokenProfile.values()){
   var profiles=Identity.generateSoftwareProfile("bundle@example.test",profile,extra);var pure=profiles.get(0);var hybrid=profiles.get(1);
   if(!Arrays.equals(pure.signingKey().getEncoded(),((CompositePrivateKey)hybrid.signingKey()).getPrivateKeys().get(0).getEncoded())||!Arrays.equals(pure.encryptionKey().getEncoded(),((CompositePrivateKey)hybrid.encryptionKey()).getPrivateKeys().get(0).getEncoded()))throw new AssertionError("PQ components not shared");
   Path file=dir.resolve(profile.code+".p12");hybrid.save(file,password,pure);
   try{hybrid.save(file,password,pure);throw new AssertionError("Overwrote bundle");}catch(FileAlreadyExistsException expected){}
   try{Identity.loadProfiles(file,"incorrect-password".toCharArray());throw new AssertionError("Accepted wrong password");}catch(java.io.IOException expected){}
   var loaded=Identity.loadProfiles(file,password);if(loaded.size()!=2)throw new AssertionError("Missing profile");
   DesktopState state=new DesktopState(dir.resolve(profile.code));state.rememberSoftwareProfiles(loaded,file,"Bundle");state=new DesktopState(dir.resolve(profile.code));
   if(state.identities().size()!=2)throw new AssertionError("Missing saved selection");
   for(var saved:state.identities()){
    var id=state.loadIdentity(saved.id(),password);
    for(var certificate:List.of(id.signingCert(),id.encryptionCert())){if(certificate.getSubjectAlternativeNames().size()!=5)throw new AssertionError("Missing SANs");for(String address:extra)if(!Identity.matchesEmail(certificate,address))throw new AssertionError("Missing email SAN");}if(!saved.id().equals(DesktopState.identityId(id)))throw new AssertionError("Wrong profile restored");
    for(boolean encrypt:new boolean[]{false,true}){
     var message=MailEngine.compose(id,"one@example.test","four@example.test","Profiles","Shared keys",encrypt?id.encryptionCert():null,null);
     var opened=MailEngine.open(message,id,id.signingCert());if(opened.encrypted()!=encrypt||!opened.pinned()||!opened.text().equals("Shared keys"))throw new AssertionError("Round trip");
    }
   }
   System.out.println("PASS "+profile+": shared four-key bundle, both selections after restart, signed/encrypted round trips, password and overwrite protection");
  }}finally{Arrays.fill(password,'\0');try(var paths=Files.walk(dir)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
