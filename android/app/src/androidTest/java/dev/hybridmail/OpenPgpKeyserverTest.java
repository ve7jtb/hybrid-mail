package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import java.security.*;
public class OpenPgpKeyserverTest {
 @Test public void boundedLookupAndCertificateBinding()throws Exception{
  Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();
  var email=OpenPgpKeyserver.query("test+tag@example.com");assertEquals("https://keys.openpgp.org/vks/v1/by-email/test%2Btag%40example.com",email.url().toString());
  var id=Identity.generate("test+tag@example.com",Identity.HYBRID_87_SIGN);var own=OpenPgp.create(id,null);
  assertEquals(own.fingerprint(),OpenPgpKeyserver.checked(email,own.export()).fingerprint());
  var fp=OpenPgpKeyserver.query(own.fingerprint());assertEquals(own.fingerprint(),OpenPgpKeyserver.checked(fp,own.export()).fingerprint());
  try{OpenPgpKeyserver.checked(OpenPgpKeyserver.query("other@example.com"),own.export());fail();}catch(java.io.IOException expected){}
  try{OpenPgpKeyserver.checked(OpenPgpKeyserver.query("0".repeat(64)),own.export());fail();}catch(java.io.IOException expected){}
  for(String bad:new String[]{"https://evil.example/", "", "0123456789ABCDEF", "x@example.com\r\nInjected: yes"})try{OpenPgpKeyserver.query(bad);fail();}catch(Exception expected){}
 }
}
