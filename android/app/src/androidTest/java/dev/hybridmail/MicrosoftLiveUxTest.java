package dev.hybridmail;
import android.content.Intent;
import android.view.*;
import android.widget.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import static org.junit.Assert.*;
import java.util.*;
/** Explicitly opted-in, read-only live UX test. Never sends, saves mail or changes trust. */
public class MicrosoftLiveUxTest {
 MainActivity activity;android.app.Instrumentation instrument;
 Object get(String name)throws Exception{var f=MainActivity.class.getDeclaredField(name);f.setAccessible(true);return f.get(activity);}
 void call(String name)throws Exception{var m=MainActivity.class.getDeclaredMethod(name);m.setAccessible(true);m.invoke(activity);}
 View find(View v,String text){if(v instanceof TextView t&&text.equals(t.getText().toString()))return v;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++){var r=find(g.getChildAt(i),text);if(r!=null)return r;}return null;}
 EditText search(View v){if(v instanceof EditText e&&"Search inbox".contentEquals(e.getHint()))return e;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++){var e=search(g.getChildAt(i));if(e!=null)return e;}return null;}
 interface Checked{void run()throws Exception;}
 void ui(Checked c){instrument.runOnMainSync(()->{try{c.run();}catch(Exception e){throw new AssertionError(e);}});}
 void ready()throws Exception{Thread.sleep(300);for(int n=0;n<600;n++){final boolean[] done={false};ui(()->done[0]=!(Boolean)get("busy")&&!(Boolean)get("microsoftConnecting"));if(done[0]){instrument.waitForIdleSync();return;}Thread.sleep(100);}fail("Mailbox operation timed out");}
 void click(String text){ui(()->{var v=find(activity.findViewById(android.R.id.content),text);assertNotNull("Control exists: "+text,v);assertTrue("Control enabled: "+text,v.isEnabled());v.performClick();});}
 @Test public void searchPageOpenVerify()throws Exception{
  Assume.assumeTrue("true".equals(InstrumentationRegistry.getArguments().getString("pqmailLiveMicrosoft")));
  instrument=InstrumentationRegistry.getInstrumentation();var context=instrument.getTargetContext();StringBuilder report=new StringBuilder();
  activity=(MainActivity)instrument.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
  try{
   ui(()->{var m=MainActivity.class.getDeclaredMethod("authorizeMicrosoft",Runnable.class);m.setAccessible(true);m.invoke(activity,(Runnable)()->{try{var load=MainActivity.class.getDeclaredMethod("loadMicrosoft",int.class);load.setAccessible(true);load.invoke(activity,0);}catch(Exception e){throw new RuntimeException(e);}});});ready();
   assertEquals("microsoft",get("mailboxProvider"));assertEquals(InstrumentationRegistry.getArguments().getString("pqmailExpectedEmail"),get("microsoftEmail"));var api=(MicrosoftGraph)get("microsoft");assertFalse(((List<?>)get("inboxEntries")).isEmpty());report.append("PASS reconnect and inbox load through Activity.\n");
   var originalApi=api;
   if(!api.hasOlder()){
    var tf=MicrosoftGraph.class.getDeclaredField("transport");tf.setAccessible(true);var network=(MicrosoftGraph.Transport)tf.get(api);
    var cf=MicrosoftGraph.class.getDeclaredField("credentials");cf.setAccessible(true);var credentials=(MicrosoftGraph.Credentials)cf.get(api);
    api=new MicrosoftGraph(credentials,(r,l)->network.send(new MicrosoftGraph.Request(java.net.URI.create(r.uri().toString().replace("$top=50","$top=2")),r.body(),r.token()),l));
    final var paged=api;ui(()->{var f=MainActivity.class.getDeclaredField("microsoft");f.setAccessible(true);f.set(activity,paged);});click("Refresh");ready();
    report.append("INFO inbox fits one normal page; live paging uses a diagnostic-only 2-message limit.\n");
   }
   assertTrue("Inbox has a second diagnostic page",api.hasOlder());click("Older ›");ready();assertEquals(2,api.pageNumber());assertTrue(api.hasNewer());click("‹ Newer");ready();assertEquals(1,api.pageNumber());assertFalse(api.hasNewer());report.append("PASS Older to page 2 and Newer to page 1 through inbox controls.\n");
   ui(()->{var f=MainActivity.class.getDeclaredField("microsoft");f.setAccessible(true);f.set(activity,originalApi);});api=originalApi;
   ui(()->search(activity.findViewById(android.R.id.content)).setText("PQ-Mail-NONEXISTENT-849373268"));click("Search");ready();assertTrue(((List<?>)get("inboxEntries")).isEmpty());assertEquals(1,api.pageNumber());report.append("PASS search for nonexistent subject returns empty results and resets page.\n");
   ui(()->search(activity.findViewById(android.R.id.content)).setText("PQ Mail"));click("Search");ready();var entries=(List<ImapInbox.Entry>)get("inboxEntries");assertFalse("Synthetic mail search has results",entries.isEmpty());report.append("PASS synthetic-message subject search returns results.\n");
   ImapInbox.Entry target=null;String expected=null;
   for(int page=0;page<4&&target==null;page++){
    for(var e:entries){var msg=MailEngine.normalizeSmime(api.message(e.uid()));String ct=msg.getContentType().toLowerCase(Locale.ROOT);if(!(ct.contains("pkcs7-signature")||ct.contains("smime-type=signed-data")))continue;var opened=MailEngine.open(msg,null,null,null);if(opened.signerCertificate()==null||opened.encrypted())continue;assertTrue(opened.fromMatches());assertFalse(opened.text().isBlank());target=e;expected="Signature valid • "+opened.signatureAlgorithm();break;}
    if(target==null&&api.hasOlder()){click("Older ›");ready();entries=(List<ImapInbox.Entry>)get("inboxEntries");}else break;
   }
   assertNotNull("Signed synthetic S/MIME message found",target);final var chosen=target;
   ui(()->{var root=activity.findViewById(android.R.id.content);var subject=find(root,chosen.subject());assertNotNull(subject);assertTrue(((View)subject.getParent()).performClick());});ready();
   final String valid=expected;ui(()->{var root=activity.findViewById(android.R.id.content);assertNotNull(find(root,"S/MIME message"));assertTrue("Visible verification status",contains(root,valid));assertTrue("Visible matching sender",contains(root,"Sender address matches certificate"));});
   report.append("PASS opening signed search result through inbox card.\nPASS reader displays ").append(expected).append(" and sender matches certificate; decoded body is nonempty.\n");
   click("Inbox");click("Clear");ready();assertEquals("",get("mailSearch"));assertEquals(1,api.pageNumber());report.append("PASS Inbox return and Clear restore page 1.\nNo email sent, trust changed, or message content/tokens written to disk.\n");
  }catch(Throwable e){report.append("FAIL ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append('\n');throw e;}
  finally{java.nio.file.Files.writeString(context.getFilesDir().toPath().resolve("microsoft-live-ux-result.txt"),report);System.out.println(report);}
 }
 boolean contains(View v,String text){if(v instanceof TextView t&&t.getText().toString().contains(text))return true;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++)if(contains(g.getChildAt(i),text))return true;return false;}
}
