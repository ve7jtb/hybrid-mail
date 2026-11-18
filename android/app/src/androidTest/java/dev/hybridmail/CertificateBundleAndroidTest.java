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
  }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
