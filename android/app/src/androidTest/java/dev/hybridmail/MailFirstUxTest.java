package dev.hybridmail;
import android.content.Intent;
import android.view.*;
import android.widget.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import static org.junit.Assert.*;
public class MailFirstUxTest {
 private View find(View v,String label){if(v instanceof TextView t&&label.equals(t.getText().toString()))return v;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++){View r=find(g.getChildAt(i),label);if(r!=null)return r;}return null;}
 private void set(Object a,String name,Object value)throws Exception{var f=MainActivity.class.getDeclaredField(name);f.setAccessible(true);f.set(a,value);}
 private void call(Object a,String name)throws Exception{var m=MainActivity.class.getDeclaredMethod(name);m.setAccessible(true);m.invoke(a);}
 @Test public void inboxNavigationAndIdentityGuidance(){var i=InstrumentationRegistry.getInstrumentation();var a=(MainActivity)i.startActivitySync(new Intent(i.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));try{i.runOnMainSync(()->{try{
  var root=a.findViewById(android.R.id.content);assertNotNull(find(root,"Settings"));
  set(a,"mailboxProvider","gmail");set(a,"gmailEmail","test@example.test");set(a,"gmail",new GmailApi(()->"test".toCharArray(),(r,l)->new GmailApi.Response(200,"{}".getBytes())));
  set(a,"inboxEntries",java.util.List.of(new ImapInbox.Entry(1,"Alice","Synthetic subject",null,10)));call(a,"renderInbox");
  assertNotNull(find(root,"Synthetic subject"));assertNotNull(find(root,"Search"));assertFalse(find(root,"‹ Newer").isEnabled());assertFalse(find(root,"Older ›").isEnabled());
  find(root,"Compose").performClick();assertNotNull(find(root,"Create software .p12 — four keys"));
  var secure=MainActivity.class.getDeclaredMethod("containsSecureMime",jakarta.mail.Part.class,int.class);secure.setAccessible(true);
  var plain=MailEngine.parse("From: a@example.test\r\nContent-Type: text/plain\r\n\r\nHello".getBytes());assertEquals(false,secure.invoke(a,plain,0));
  var signed=MailEngine.parse("Content-Type: multipart/signed; boundary=x\r\n\r\n--x--\r\n".getBytes());assertEquals(true,secure.invoke(a,signed,0));
 }catch(Exception e){throw new AssertionError(e);}});}finally{i.runOnMainSync(a::finish);}}
}
