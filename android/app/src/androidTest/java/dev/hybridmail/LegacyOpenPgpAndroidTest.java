package dev.hybridmail;
import org.junit.Test;
public class LegacyOpenPgpAndroidTest {
 @Test public void v4CertificatePolicy()throws Exception{java.security.Security.removeProvider("BC");java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);LegacyOpenPgpPolicyTest.main(new String[0]);}
}
