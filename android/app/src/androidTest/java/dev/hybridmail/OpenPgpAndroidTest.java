package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
public final class OpenPgpAndroidTest {
 @Test public void softwarePersistenceAndMail()throws Exception{
  Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();
  Path root=Files.createTempDirectory(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath(),"pgp-test-");
  try{
   Identity id=Identity.generate("android@example.com",Identity.HYBRID_65_P384_SIGN);Path file=root.resolve("identity.p12");id.save(file,"test-only-password".toCharArray());id=Identity.load(file,"test-only-password".toCharArray());
   var own=OpenPgp.createOwn(root,id,null);assertArrayEquals(own.export(),OpenPgp.loadOwn(root,id).export());
   for(boolean encrypted:new boolean[]{false,true}){
    byte[] message=OpenPgp.compose(id,own,encrypted?own:null,"android@example.com","android@example.com","Test","Android OpenPGP",null);
    var opened=OpenPgp.open(MailEngine.encode(MailEngine.parse(message)),own,own,id,null);assertEquals("Android OpenPGP",opened.text());assertEquals(encrypted,opened.encrypted());
   }
   byte[] bad=own.encoded.clone();bad[bad.length-1]^=1;try{new OpenPgp.PublicIdentity(bad);fail("Invalid binding accepted");}catch(GeneralSecurityException expected){}
  }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
