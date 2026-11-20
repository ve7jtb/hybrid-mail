package dev.hybridmail;
import android.content.Intent;
import android.view.*;
import android.widget.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import java.nio.file.*;
import java.util.Comparator;
import static org.junit.Assert.*;
public class ComposeDefaultTest {
 private static void set(Object o,String name,Object value)throws Exception{var f=o.getClass().getDeclaredField(name);f.setAccessible(true);f.set(o,value);}
 private static Object get(Object o,String name)throws Exception{var f=o.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(o);}
 private static void compose(MainActivity a)throws Exception{var m=MainActivity.class.getDeclaredMethod("compose");m.setAccessible(true);m.invoke(a);}
 private static CheckBox format(View v){if(v instanceof CheckBox c&&c.getText().toString().startsWith("Use hybrid"))return c;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++){var c=format(g.getChildAt(i));if(c!=null)return c;}return null;}
 @Test public void recipientDefaultsAndManualOverride()throws Exception{
  var in=InstrumentationRegistry.getInstrumentation();var a=(MainActivity)in.startActivitySync(new Intent(in.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
  var root=Files.createTempDirectory(in.getTargetContext().getCacheDir().toPath(),"compose-default-");
  try{
   var id=Identity.generate("compose-test@example.invalid",Identity.HYBRID_65_P384_SIGN);var own=OpenPgp.createOwn(root,id,null);
   in.runOnMainSync(()->{try{
    set(a,"identity",id);set(a,"selected",new AndroidStore.Entry("test","test","",0,"",""));set(a,"to","unknown@example.invalid");compose(a);assertTrue(format(a.findViewById(android.R.id.content)).isChecked());
    set(a,"recipient",id.encryptionCert());set(a,"to","compose-test@example.invalid");compose(a);assertFalse(format(a.findViewById(android.R.id.content)).isChecked());
    ((OpenPgpRecipients)get(a,"pgpRecipients")).remember(own);compose(a);assertTrue(format(a.findViewById(android.R.id.content)).isChecked());
    format(a.findViewById(android.R.id.content)).setChecked(false);compose(a);assertFalse(format(a.findViewById(android.R.id.content)).isChecked());
    set(a,"to","another@example.invalid");compose(a);assertTrue(format(a.findViewById(android.R.id.content)).isChecked());
   }catch(Exception e){throw new RuntimeException(e);}});
  }finally{in.runOnMainSync(a::finish);try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
