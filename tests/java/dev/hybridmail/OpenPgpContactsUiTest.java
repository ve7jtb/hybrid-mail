package dev.hybridmail;
import javax.swing.*;
import java.nio.file.*;
public class OpenPgpContactsUiTest {
 static Object get(Object o,String name)throws Exception{var f=o.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(o);}
 static Object call(Object o,String name,Class<?>[] types,Object...args)throws Exception{var m=o.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(o,args);}
 static void ok(boolean b){if(!b)throw new AssertionError("Contact UI assertion failed");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path root=Files.createTempDirectory("pgp-contact-ui-");System.setProperty("hybridmail.dataDir",root.toString());Path fixtures=Path.of(args[0]);
  var key=new OpenPgp.PublicIdentity(Files.readAllBytes(fixtures.resolve("public.asc")));var state=new DesktopState(root);var contact=state.rememberPgp(key,"legacy@example.com");
  var id=Identity.generate("other@example.com",Identity.HYBRID_65_P384_SIGN);state.rememberContact(id.signingCert(),"other@example.com","signing");
  byte[] message=OpenPgp.mimeWrap(Files.readAllBytes(fixtures.resolve("content.mime")),OpenPgp.cat(OpenPgp.bytes("Content-Type: application/pgp-signature\r\n\r\n"),Files.readAllBytes(fixtures.resolve("signature.asc"))),false,"legacy@example.com","other@example.com","Incoming persisted contact");
  SwingUtilities.invokeAndWait(()->{var app=new MailApp();try{
   call(app,"refreshContacts",new Class<?>[0]);var table=(JTable)get(app,"certificateTable");ok(table.getRowCount()==2);int row=-1;for(int n=0;n<table.getRowCount();n++)if(table.getValueAt(n,1).equals("OpenPGP"))row=n;ok(row>=0);ok(table.getValueAt(row,6).equals(key.fingerprint())&&table.getValueAt(row,3).equals("v4")&&table.getValueAt(row,4).equals("Ed25519")&&table.getValueAt(row,5).equals("X25519"));
   Object result=call(app,"display",new Class<?>[]{jakarta.mail.internet.MimeMessage.class,Identity.class,java.security.cert.X509Certificate.class},MailEngine.parse(message),null,null);
   String text=(String)call(app,"formatRead",new Class<?>[]{result.getClass()},result);ok(text.contains("NOT TRUSTED")&&text.contains("WARNING: Valid classical signature"));
   var settings=(DesktopState)get(app,"desktopState");settings.setPgpTrusted(contact,true);call(app,"refreshContacts",new Class<?>[0]);text=(String)call(app,"formatRead",new Class<?>[]{result.getClass()},result);ok(text.contains("TRUSTED email / primary-key fingerprint: legacy@example.com")&&!text.contains("NOT TRUSTED")&&text.contains("WARNING: Valid classical signature"));
   table.setRowSelectionInterval(row,row);call(app,"setContactTrust",new Class<?>[]{boolean.class},false);ok(!new DesktopState(root).isPgpTrusted(contact.email(),key.fingerprint()));text=(String)call(app,"formatRead",new Class<?>[]{result.getClass()},result);ok(text.contains("NOT TRUSTED"));
   System.out.println("PASS mixed Certificates rows/full fingerprint, persisted incoming signer selection, trusted/untrusted read status, Remove trust persistence, classical warning retained");
  }catch(Exception e){throw new RuntimeException(e);}finally{((Timer)safe(app,"pgpLookupTimer")).stop();app.dispose();}});
 }
 static Object safe(Object app,String field){try{return get(app,field);}catch(Exception e){throw new RuntimeException(e);}}
}
