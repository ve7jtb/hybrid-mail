package dev.hybridmail;
import javax.swing.*;
import java.nio.file.*;
/** Swing control checks; hidden window, no account access or network lookup. */
public class ComposeOpenPgpUiTest {
 static Object field(MailApp app,String name)throws Exception{var f=MailApp.class.getDeclaredField(name);f.setAccessible(true);return f.get(app);}
 static void stop(MailApp app)throws Exception{((Timer)field(app,"pgpLookupTimer")).stop();}
 static void ok(boolean b){if(!b)throw new AssertionError("Compose control assertion failed");}
 public static void main(String[] args)throws Exception{
  System.setProperty("hybridmail.dataDir",Files.createTempDirectory("compose-contact-test-").toString());
  MailEngine.init();var classical=new OpenPgp.PublicIdentity(Files.readAllBytes(Path.of(args[0])));var id=Identity.generate("legacy@example.com",Identity.HYBRID_65_P384_SIGN);var hybrid=OpenPgp.create(id,null);
  SwingUtilities.invokeAndWait(()->{MailApp app=new MailApp();try{
   var format=(JComboBox<?>)field(app,"mailFormat");var to=(JTextField)field(app,"to");var encrypt=(JCheckBox)field(app,"encrypt");var choices=(JComboBox<?>)field(app,"pgpEncryption");var status=(JLabel)field(app,"pgpLookupStatus");
   format.setSelectedIndex(1);stop(app);app.addNotify();app.validate();ok(to.getHeight()<50);ok(!encrypt.isEnabled());
   var select=MailApp.class.getDeclaredMethod("selectPgpRecipient",OpenPgp.PublicIdentity.class);select.setAccessible(true);select.invoke(app,classical);stop(app);ok(encrypt.isEnabled()&&choices.getItemCount()==1&&status.getText().contains("WARNING"));
   select.invoke(app,hybrid);stop(app);ok(choices.getItemCount()==2&&status.getText().contains("Hybrid PQ")&&!status.getText().contains("WARNING"));
   for(int i=0;i<choices.getItemCount();i++)if(((OpenPgp.PublicIdentity)choices.getItemAt(i)).fingerprint().equals(classical.fingerprint()))choices.setSelectedIndex(i);ok(status.getText().contains("WARNING"));encrypt.setSelected(true);to.setText("unrelated@example.com");stop(app);ok(!encrypt.isEnabled()&&!encrypt.isSelected()&&choices.getItemCount()==0&&field(app,"pgpRecipient")==null);
   format.setSelectedIndex(0);stop(app);ok(encrypt.isEnabled());
   System.out.println("PASS Compose: v4/v6 recipient-only options, hybrid warning exemption, address-change invalidation, encryption gating, S/MIME switch");
  }catch(Exception e){throw new RuntimeException(e);}finally{try{stop(app);}catch(Exception ignored){}app.dispose();}});
 }
}
