package dev.hybridmail;
import java.util.*;
import java.nio.file.Path;
import jakarta.mail.internet.*;
/** Reproduce the Gmail transport rewrite with generated software keys only. */
public final class OpenPgpTransportTest {
 static void ok(boolean value){if(!value)throw new AssertionError();}
 static byte[] rewritten(byte[] cipher,String version,String extra)throws Exception{
  MimeMessage m=new MimeMessage((jakarta.mail.Session)null);m.setFrom("transport@example.test");m.setRecipients(jakarta.mail.Message.RecipientType.TO,"transport@example.test");m.setSubject("Unsigned envelope");
  MimeMultipart parts=new MimeMultipart("mixed");
  MimeBodyPart payload=new MimeBodyPart();payload.setText(new String(cipher,java.nio.charset.StandardCharsets.US_ASCII),"US-ASCII");parts.addBodyPart(payload);
  MimeBodyPart control=new MimeBodyPart();control.setContent(version,"application/pgp-encrypted");control.setHeader("Content-Transfer-Encoding","base64");parts.addBodyPart(control);
  if(extra!=null){MimeBodyPart other=new MimeBodyPart();other.setText(extra);parts.addBodyPart(other);}
  m.setContent(parts);m.saveChanges();return MailEngine.encode(m);
 }
 static void rejected(byte[] input,Identity id,OpenPgp.PublicIdentity own)throws Exception {
  try{OpenPgp.open(input,own,own,id,null);throw new AssertionError("Accepted malformed or tampered envelope");}catch(java.security.GeneralSecurityException expected){}
 }
 public static void main(String[] args)throws Exception {
  MailEngine.init();Identity id=Identity.generateSoftwareProfile("transport@example.test",TokenProfile.LEVEL3,List.of()).get(1);
  var own=OpenPgp.create(id,null);
  byte[] standard=OpenPgp.compose(id,own,own,"transport@example.test","transport@example.test","Test","Authenticated inner body",null);
  byte[] cipher=OpenPgp.decoded(OpenPgp.mime(OpenPgp.parts(standard).second()));
  byte[] changed=rewritten(cipher,"Version: 1\r\n",null);
  ok(OpenPgp.isOpenPgp(changed));
  var binaryMime=MailEngine.parse(changed);var multi=(jakarta.mail.Multipart)binaryMime.getContent();
  multi.getBodyPart(0).setHeader("Content-Type","application/octet-stream");
  ok(OpenPgp.open(MailEngine.encode(binaryMime),own,own,id,null).text().contains("Authenticated inner body"));
  var result=OpenPgp.open(changed,own,own,id,null);
  ok(result.encrypted()&&result.postQuantum()&&result.text().contains("Authenticated inner body"));
  rejected(rewritten(cipher,"Version: 2",null),id,own);
  rejected(rewritten(cipher,"Version: 1","Unauthenticated extra text"),id,own);
  rejected(rewritten(OpenPgp.cat(OpenPgp.bytes("Unauthenticated prefix\r\n"),cipher),"Version: 1",null),id,own);
  rejected(rewritten(OpenPgp.cat(cipher,cipher),"Version: 1",null),id,own);
  byte[] binary=OpenPgp.unarmor(cipher,"MESSAGE");binary[binary.length-1]^=1;
  rejected(rewritten(OpenPgp.armor(binary,"MESSAGE"),"Version: 1",null),id,own);
  ok(OpenPgp.open(standard,own,own,id,null).text().contains("Authenticated inner body"));
  System.out.println("PASS standard/rewritten encrypted MIME, hybrid signature, version/extra-part/prefix/multiple-armor/tamper rejection");
 }
}
