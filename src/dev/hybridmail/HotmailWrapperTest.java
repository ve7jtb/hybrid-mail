package dev.hybridmail;
import jakarta.mail.internet.*;import jakarta.activation.*;import jakarta.mail.util.*;
public class HotmailWrapperTest{
 public static void main(String[] a)throws Exception{
  MailEngine.init();var id=Identity.generate("test@example.test",true);var original=MailEngine.compose(id,"test@example.test","test@example.test","test","Protected body",id.encryptionCert(),null);
  byte[] cms=original.getInputStream().readAllBytes();var attachment=new MimeBodyPart();attachment.setDataHandler(new DataHandler(new ByteArrayDataSource(cms,"application/pkcs7-mime; name=smime.p7m")));attachment.setDisposition("attachment");
  var text=new MimeBodyPart();text.setText("UNTRUSTED WRAPPER");var mixed=new MimeMultipart("mixed");mixed.addBodyPart(text);mixed.addBodyPart(attachment);var wrapped=new MimeMessage(original);wrapped.setContent(mixed);wrapped.saveChanges();
  var opened=MailEngine.open(MailEngine.parse(MailEngine.encode(wrapped)),id,id.signingCert());if(!opened.encrypted()||!opened.pinned()||!opened.text().equals("Protected body"))throw new AssertionError();System.out.println("PASS wrapped hybrid CMS decrypted and verified; wrapper excluded");
  mixed.addBodyPart(attachment);wrapped.setContent(mixed);wrapped.saveChanges();try{MailEngine.normalizeSmime(wrapped);throw new AssertionError();}catch(java.security.GeneralSecurityException ok){System.out.println("PASS ambiguous CMS attachments rejected");}
 }
}
