package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.mail.smime.*;
import jakarta.mail.internet.*;
public class ConventionalAndroidTest {
 @org.junit.Test public void conventionalRoundTrips()throws Exception {
  Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);
  MailEngine.init();Path dir=Files.createTempDirectory(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath(),"classical-mail-");char[] pass="test-only-password".toCharArray();
  try {for(String alg:List.of("RSA","EC")){
   KeyPairGenerator g=KeyPairGenerator.getInstance(alg,"BC");if(alg.equals("RSA"))g.initialize(2048);else g.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));var pair=g.generateKeyPair();
   String sig=alg.equals("RSA")?"SHA256withRSA":"SHA384withECDSA";
   var builder=new JcaX509v3CertificateBuilder(new X500Name("CN=Conventional test"),java.math.BigInteger.valueOf(System.nanoTime()),new Date(System.currentTimeMillis()-60000),new Date(System.currentTimeMillis()+86400000),new X500Name("CN=Conventional test"),pair.getPublic());
   builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.digitalSignature|(alg.equals("RSA")?KeyUsage.keyEncipherment:KeyUsage.keyAgreement)));
   builder.addExtension(Extension.extendedKeyUsage,false,new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));builder.addExtension(Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.rfc822Name,"test@example.test")));
   var cert=new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder(sig).setProvider("BC").build(pair.getPrivate())));
   var id=new Identity(cert,pair.getPrivate(),cert,pair.getPrivate(),null);
   var ks=KeyStore.getInstance("PKCS12","BC");ks.load(null,pass);ks.setKeyEntry("arbitrary-alias",pair.getPrivate(),pass,new java.security.cert.Certificate[]{cert});Path file=dir.resolve(alg+".p12");try(var out=Files.newOutputStream(file)){ks.store(out,pass);}var loaded=Identity.load(file,pass);
   var signed=MailEngine.compose(loaded,"test@example.test","test@example.test","Conventional","hello",null,null);
   var encrypted=MailEngine.compose(loaded,"test@example.test","test@example.test","Conventional","hello",cert,null);
   for(var m:List.of(signed,encrypted)){var opened=MailEngine.open(m,loaded,cert);if(!opened.text().equals("hello")||!opened.pinned())throw new AssertionError("Round trip");}
   var signer=new SMIMESignedGenerator();signer.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(new JcaContentSignerBuilder(sig).setProvider("BC").build(pair.getPrivate()),cert));signer.addCertificates(new JcaCertStore(List.of(cert)));
   var alternatives=new MimeMultipart("alternative");var plain=new MimeBodyPart();plain.setText("conventional plain","UTF-8");alternatives.addBodyPart(plain);var html=new MimeBodyPart();html.setContent("<b>ignored HTML</b>","text/html");alternatives.addBodyPart(html);var body=new MimeBodyPart();body.setContent(alternatives);
   var detached=new MimeMessage(MailEngine.session());detached.setFrom("test@example.test");detached.setContent(signer.generate(body));detached.saveChanges();
   if(!MailEngine.open(MailEngine.parse(MailEngine.encode(detached)),null,cert).text().equals("conventional plain"))throw new AssertionError("Detached multipart alternative");
   var envelope=new SMIMEEnvelopedGenerator();
   if(alg.equals("RSA"))envelope.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
   else {var eph=g.generateKeyPair();envelope.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,eph.getPrivate(),eph.getPublic(),CMSAlgorithm.AES256_WRAP).setProvider("BC").addRecipient(cert));}
   var wrapped=envelope.generate(signed,new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build());var legacy=new MimeMessage(MailEngine.session());legacy.setFrom("test@example.test");legacy.setDataHandler(wrapped.getDataHandler());var headers=wrapped.getAllHeaders();while(headers.hasMoreElements()){var h=headers.nextElement();legacy.setHeader(h.getName(),h.getValue());}legacy.saveChanges();
   if(!MailEngine.open(MailEngine.parse(MailEngine.encode(legacy)),loaded,cert).text().equals("hello"))throw new AssertionError("CBC receive");
   var unsigned=new MimeBodyPart();unsigned.setText("unsigned encrypted body","UTF-8");var unsignedWrapped=envelope.generate(unsigned,new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build());var unsignedMail=new MimeMessage(MailEngine.session());unsignedMail.setDataHandler(unsignedWrapped.getDataHandler());var uh=unsignedWrapped.getAllHeaders();while(uh.hasMoreElements()){var h=uh.nextElement();unsignedMail.setHeader(h.getName(),h.getValue());}unsignedMail.saveChanges();var unsignedResult=MailEngine.open(MailEngine.parse(MailEngine.encode(unsignedMail)),loaded,cert);if(unsignedResult.signerCertificate()!=null||unsignedResult.pinned()||!unsignedResult.text().equals("unsigned encrypted body"))throw new AssertionError("Unsigned encryption misrepresented");
   System.out.println("PASS "+alg+": import arbitrary .p12 alias, signing/encryption trust, signed mail, AES-GCM and legacy AES-CBC receive");
  }}finally{try(var paths=Files.walk(dir)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
