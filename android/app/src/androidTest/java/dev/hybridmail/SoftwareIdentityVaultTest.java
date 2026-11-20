package dev.hybridmail;
import org.junit.*;import static org.junit.Assert.*;
import java.nio.file.*;import java.util.*;import java.security.*;
import androidx.test.platform.app.InstrumentationRegistry;
public class SoftwareIdentityVaultTest {
 @Before public void providers(){Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();}
 @Test public void profilesRoundTripExportAndLock()throws Exception{
  Path root=Files.createTempDirectory(InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath(),"vault-p12-test");
  byte[] prf=PrfVault.random(32);var vault=new PrfVault(root.resolve("vault.json"));vault.create("YWJj",PrfVault.random(32),prf);Set<String> passwords=new HashSet<>();
  try{for(var profile:TokenProfile.values()){
   var ids=Identity.generateSoftwareProfile("test@example.test",profile,List.of("alias@example.test"));Path local=root.resolve(profile.code+".vault.p12");
   SoftwareIdentityVault.save(ids,local,vault);String random=vault.get("software.p12."+local.getFileName());assertEquals(43,random.length());assertTrue(passwords.add(random));assertFalse(new String(Files.readAllBytes(root.resolve("vault.json"))).contains(random));
   vault.close();try{SoftwareIdentityVault.load(local,vault);fail("Locked vault accepted");}catch(IllegalStateException expected){}
   vault=new PrfVault(root.resolve("vault.json"));vault.unlock("YWJj",prf);var loaded=SoftwareIdentityVault.load(local,vault);assertEquals(2,loaded.size());
   for(int n=0;n<2;n++){var id=loaded.get(n);assertArrayEquals(ids.get(n).signingCert().getEncoded(),id.signingCert().getEncoded());assertArrayEquals(ids.get(n).signingKey().getEncoded(),id.signingKey().getEncoded());assertArrayEquals(ids.get(n).encryptionKey().getEncoded(),id.encryptionKey().getEncoded());
    var message=MailEngine.compose(id,"test@example.test","test@example.test","Vault test","synthetic",id.encryptionCert(),null);var result=MailEngine.open(MailEngine.parse(MailEngine.encode(message)),id,id.signingCert());assertTrue(result.encrypted());assertTrue(result.pinned());assertEquals("synthetic",result.text());
   }
   char[] backup="synthetic-export-password".toCharArray();Path exported=root.resolve("backup.p12");Files.write(exported,SoftwareIdentityVault.export(local,vault,backup));var imported=Identity.loadProfiles(exported,backup);assertEquals(2,imported.size());
   Path importedPath=root.resolve(profile.code+"-import.vault.p12");SoftwareIdentityVault.save(imported,importedPath,vault);assertNotEquals(random,vault.get("software.p12."+importedPath.getFileName()));assertEquals(2,SoftwareIdentityVault.load(importedPath,vault).size());
   try{Identity.loadProfiles(local,backup);fail("Portable password must not unlock local file");}catch(java.io.IOException expected){}
   try{SoftwareIdentityVault.save(ids,local,vault);fail("Existing file overwritten");}catch(java.io.IOException expected){}
  }}finally{vault.close();Arrays.fill(prf,(byte)0);try(var paths=Files.list(root)){for(var p:paths.toList())Files.deleteIfExists(p);}Files.delete(root);}
 }
 @Test public void vaultLockDropsSelectedSoftwareIdentity()throws Exception{
  var instrument=InstrumentationRegistry.getInstrumentation();var context=instrument.getTargetContext();var a=(MainActivity)instrument.startActivitySync(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
  try{instrument.runOnMainSync(()->{try{var selected=MainActivity.class.getDeclaredField("selected");selected.setAccessible(true);selected.set(a,new AndroidStore.Entry("synthetic","test","test.vault.p12",0,"",""));var outgoing=MainActivity.class.getDeclaredField("outgoing");outgoing.setAccessible(true);outgoing.set(a,new byte[]{1});var lock=MainActivity.class.getDeclaredMethod("lockVault");lock.setAccessible(true);lock.invoke(a);assertNull(selected.get(a));assertNull(outgoing.get(a));var identity=MainActivity.class.getDeclaredField("identity");identity.setAccessible(true);assertNull(identity.get(a));}catch(Exception e){throw new AssertionError(e);}});}finally{instrument.runOnMainSync(a::finish);}
 }
}
