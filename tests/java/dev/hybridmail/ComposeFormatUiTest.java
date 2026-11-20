package dev.hybridmail;
import javax.swing.*;
import java.nio.file.*;
public final class ComposeFormatUiTest {
 static Object field(MailApp a,String n)throws Exception{var f=MailApp.class.getDeclaredField(n);f.setAccessible(true);return f.get(a);}
 static void stop(MailApp a)throws Exception{((Timer)field(a,"pgpLookupTimer")).stop();}
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception{
  MailEngine.init();var root=Files.createTempDirectory("pq-mail-format-ui-");System.setProperty("hybridmail.dataDir",root.toString());
  var state=new DesktopState(root);var id=Identity.generate("smime@example.test",Identity.HYBRID_65_P384_SIGN);state.rememberContact(id.signingCert(),"smime@example.test","signing");
  var both=Identity.generate("both@example.test",Identity.HYBRID_65_P384_SIGN);state.rememberContact(both.signingCert(),"both@example.test","signing");state.rememberPgp(OpenPgp.create(both,null),"both@example.test");
  SwingUtilities.invokeAndWait(()->{MailApp app=new MailApp();try{
   var f=MailApp.class.getDeclaredField("desktopState");f.setAccessible(true);f.set(app,state);
   var format=(JComboBox<?>)field(app,"mailFormat");var to=(JTextField)field(app,"to");var encrypt=(JCheckBox)field(app,"encrypt");
   check(format.getSelectedIndex()==1,"initial OpenPGP");
   to.setText("smime@example.test");stop(app);check(format.getSelectedIndex()==0,"S/MIME-only fallback");check(!encrypt.isSelected(),"no automatic encryption");
   to.setText("both@example.test");stop(app);check(format.getSelectedIndex()==1,"both prefer OpenPGP");
   format.setSelectedIndex(0);stop(app);
   var refresh=MailApp.class.getDeclaredMethod("refreshContacts");refresh.setAccessible(true);refresh.invoke(app);stop(app);check(format.getSelectedIndex()==0,"manual choice survives refresh");
   to.setText("unknown@example.test");stop(app);check(format.getSelectedIndex()==1,"new unknown recipient prefers OpenPGP");
   to.setText("smime@example.test");stop(app);check(format.getSelectedIndex()==0,"fallback reapplied on new recipient");
   state.rememberPgp(OpenPgp.create(id,null),"smime@example.test");refresh.invoke(app);stop(app);check(format.getSelectedIndex()==1,"new OpenPGP contact changes automatic default");
   System.out.println("PASS hidden Compose controls: initial default, S/MIME-only, both, unknown, manual override, contact import; no network or hardware");
  }catch(Exception e){throw new RuntimeException(e);}finally{try{stop(app);}catch(Exception ignored){}app.dispose();}});
 }
}
