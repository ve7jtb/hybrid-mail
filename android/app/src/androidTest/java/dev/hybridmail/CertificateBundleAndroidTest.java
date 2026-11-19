package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import android.content.*;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import androidx.test.platform.app.InstrumentationRegistry;
public final class CertificateBundleAndroidTest {
 @Test public void bundleImportsAndRestrictedShare()throws Exception{
  Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();
  var base=InstrumentationRegistry.getInstrumentation().getTargetContext();String scope="bundle-test-"+UUID.randomUUID();Path root=Files.createTempDirectory(base.getCacheDir().toPath(),"bundle-test-");
  var context=new ContextWrapper(base){public java.io.File getFilesDir(){return root.toFile();}public SharedPreferences getSharedPreferences(String name,int mode){return base.getSharedPreferences(scope+name,mode);}};
  try{var profiles=Identity.generateSoftwareProfile("share@example.test",TokenProfile.values()[1],List.of());List<CertificateBundle.Entry> bundle=new ArrayList<>();
   for(var id:profiles)bundle.add(new CertificateBundle.Entry(id,12345678,"9c","9a","83","84"));
   var decoded=CertificateBundle.decode(CertificateBundle.encode(bundle));var store=new AndroidStore(context);store.importCertificateBundle(decoded,true);store.importCertificateBundle(decoded,true);assertEquals(2,store.entries().size());
   for(var entry:store.entries()){assertArrayEquals(new String[]{"9c","9a","83","84"},store.slots(entry));var id=store.loadToken(entry);assertNull(id.signingKey());assertFalse(store.trusted(Identity.fingerprint(id.signingCert())));assertTrue(YubiBackend.keys(id,store.slots(entry)).containsKey(com.yubico.yubikit.piv.Slot.RETIRED2));}
   store.importCertificateBundle(decoded,false);assertEquals(2,store.encryptionContacts().size());
   byte[] bytes=CertificateBundle.encode(decoded);Files.write(base.getCacheDir().toPath().resolve("PQ-Mail-certificates.pqcert"),bytes);Uri uri=Uri.parse("content://"+base.getPackageName()+".certificates/PQ-Mail-certificates.pqcert");
   try(var in=base.getContentResolver().openInputStream(uri)){assertArrayEquals(bytes,in.readAllBytes());}
   try(var out=base.getContentResolver().openOutputStream(uri)){fail("Write access granted");}catch(java.io.FileNotFoundException expected){}
   try(var in=base.getContentResolver().openInputStream(Uri.parse("content://"+base.getPackageName()+".certificates/settings.properties"))){fail("Other files exposed");}catch(java.io.FileNotFoundException expected){}
   var forgotten=store.entries().get(1);var kept=store.entries().get(0);
   OpenPgp.saveOwn(root,profiles.get(1),OpenPgp.create(profiles.get(1),null).encoded);
   Path pgp=OpenPgp.ownPath(root,profiles.get(1));assertTrue(Files.exists(pgp));
   store.forgetYubiKeyIdentity(forgotten.id());
   var restored=new AndroidStore(context);assertEquals(1,restored.entries().size());assertEquals(kept.id(),restored.entries().get(0).id());
   assertFalse(Files.exists(root.resolve(forgotten.sign())));assertFalse(Files.exists(root.resolve(forgotten.encrypt())));assertFalse(Files.exists(pgp));
   assertFalse(context.getSharedPreferences("slots",0).contains(forgotten.id()));assertTrue(Files.exists(root.resolve(kept.sign())));assertEquals(2,restored.encryptionContacts().size());
   Files.write(root.resolve("protected.p12"),new byte[]{1,2,3});store.add(new AndroidStore.Entry("software","software","protected.p12",0,"",""));
   try{store.forgetYubiKeyIdentity("software");fail("software forgotten");}catch(java.io.IOException expected){}
   assertTrue(Files.exists(root.resolve("protected.p12")));
  }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
