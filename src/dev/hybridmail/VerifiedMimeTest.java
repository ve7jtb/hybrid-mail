package dev.hybridmail;
public class VerifiedMimeTest {
 static void ok(boolean b){if(!b)throw new AssertionError();}
 public static void main(String[] args)throws Exception{
  MailEngine.init();var id=Identity.generate("mime@example.com",Identity.HYBRID_65_P384_SIGN);var own=OpenPgp.create(id,null);
  String html="Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>Hello &amp; caf=C3=A9</p><script>BAD</script><img src=\"https://invalid.example/pixel\">";
  String mixed="Content-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\n"+html+"\r\n--a\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nPreferred plain\r\n--a--\r\n--m\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=key.asc\r\n\r\nNOT BODY\r\n--m--\r\n";
  for(String body:new String[]{html,mixed}){byte[] plain=OpenPgp.bytes(body);var req=OpenPgp.request(plain,0,OpenPgp.fingerprint(own.primary),OpenPgp.b(),own.primary[5]&255);byte[] sig=OpenPgp.armor(OpenPgp.frame(2,req.finish(OpenPgp.signer(id,null).sign(req.digest()))),"SIGNATURE");byte[] msg=OpenPgp.mimeWrap(plain,OpenPgp.cat(OpenPgp.bytes("Content-Type: application/pgp-signature\r\n\r\n"),sig),false,own.email,own.email,"MIME test");var read=OpenPgp.open(msg,own,null,null,null);ok(read.text().contains(body==html?"Hello & café":"Preferred plain"));ok(read.html()!=null&&read.html().contains("Hello &amp; café"));ok(!read.text().contains("BAD")&&!read.text().contains("NOT BODY"));byte[] bad=msg.clone();for(int i=0;i<bad.length-5;i++)if(bad[i]=='H'&&bad[i+1]=='e'&&bad[i+2]=='l'){bad[i]='J';break;}try{OpenPgp.open(bad,own,null,null,null);throw new AssertionError("Tampered MIME accepted");}catch(java.security.GeneralSecurityException expected){}
   byte[] enc=OpenPgp.mimeWrap(OpenPgp.bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),OpenPgp.cat(OpenPgp.bytes("Content-Type: application/octet-stream\r\n\r\n"),OpenPgp.armor(OpenPgp.encrypt(OpenPgp.signed(plain,own,OpenPgp.signer(id,null)),own),"MESSAGE")),true,own.email,own.email,"encrypted");var decrypted=OpenPgp.open(enc,own,own,id,null);ok(decrypted.text().equals(read.text())&&decrypted.html().equals(read.html()));
  }
  System.out.println("PASS signed/encrypted HTML, multipart alternative/mixed, UTF-8 transfer decoding, attachment exclusion and tamper rejection");
 }
}
