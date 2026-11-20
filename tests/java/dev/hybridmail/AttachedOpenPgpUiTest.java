package dev.hybridmail;
import java.nio.file.*;
import javax.swing.*;
public class AttachedOpenPgpUiTest {
 static void ok(boolean b){if(!b)throw new AssertionError();}
 public static void main(String[] args)throws Exception {
  MailEngine.init();Path root=Files.createTempDirectory("pgp-attached-test-");System.setProperty("hybridmail.dataDir",root.toString());
  var id=Identity.generate("attached@example.com",Identity.HYBRID_65_P384_SIGN);var key=OpenPgp.create(id,null);
  String body="Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nAttached certificate test\r\n--b\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=public.asc\r\n\r\n"+new String(key.export(),java.nio.charset.StandardCharsets.UTF_8)+"\r\n--b--\r\n";
  byte[] plain=OpenPgp.bytes(body);var req=OpenPgp.request(plain,0,OpenPgp.fingerprint(key.primary),OpenPgp.b(),key.primary[5]&255);
  byte[] sig=OpenPgp.armor(OpenPgp.frame(2,req.finish(OpenPgp.signer(id,null).sign(req.digest()))),"SIGNATURE");
  byte[] message=OpenPgp.mimeWrap(plain,OpenPgp.cat(OpenPgp.bytes("Content-Type: application/pgp-signature\r\n\r\n"),sig),false,key.email,key.email,"Attached key");
  ok(AttachedOpenPgp.find(MailEngine.parse(message)).size()==1);
  SwingUtilities.invokeAndWait(()->{var app=new MailApp();try{
   Object result=OpenPgpContactsUiTest.call(app,"display",new Class<?>[]{jakarta.mail.internet.MimeMessage.class,Identity.class,java.security.cert.X509Certificate.class},MailEngine.parse(message),null,null);
   String text=(String)OpenPgpContactsUiTest.call(app,"formatRead",new Class<?>[]{result.getClass()},result);ok(text.contains("NOT TRUSTED")&&text.contains("Attached certificate test"));
   ok(new DesktopState(root).pgpContacts().isEmpty());
   OpenPgpContactsUiTest.call(app,"showMessage",new Class<?>[]{result.getClass()},result);ok(((JButton)OpenPgpContactsUiTest.get(app,"saveIncomingPgp")).isEnabled());ok(((JButton)OpenPgpContactsUiTest.get(app,"trustIncoming")).isEnabled());
   byte[] bad=OpenPgp.bytes(new String(message,java.nio.charset.StandardCharsets.UTF_8).replace("Attached certificate test","Altered certificate test"));
   try{OpenPgpContactsUiTest.call(app,"display",new Class<?>[]{jakarta.mail.internet.MimeMessage.class,Identity.class,java.security.cert.X509Certificate.class},MailEngine.parse(bad),null,null);throw new AssertionError("Tamper accepted");}catch(java.lang.reflect.InvocationTargetException expected){}
   ok(new DesktopState(root).pgpContacts().isEmpty());
   System.out.println("PASS attached certificate verification without saved contacts or identity, untrusted result, separate save/trust controls, no automatic persistence, tampering rejected");
  }catch(Exception e){throw new RuntimeException(e);}finally{((Timer)OpenPgpContactsUiTest.safe(app,"pgpLookupTimer")).stop();app.dispose();}});
 }
}
