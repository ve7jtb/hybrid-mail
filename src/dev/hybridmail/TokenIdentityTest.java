package dev.hybridmail;

import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public final class TokenIdentityTest {
    public static void main(String[] args) throws Exception {
        MailEngine.init();
        KeyPair token = KeyPairGenerator.getInstance(Identity.PURE_SIGN,"BC").generateKeyPair();
        ExternalMu.Backend simulator=(pub,mu)->{
            MLDSASigner s=new MLDSASigner();
            s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(token.getPrivate().getEncoded()),new SecureRandom()));
            return s.generateMuSignature(mu);
        };
        Path dir=Files.createTempDirectory("token-identity-test-");
        try {
            for(boolean hybrid:new boolean[]{false,true}) {
                Identity id=Identity.forToken("token@example.test",token.getPublic(),hybrid,simulator);
                id.signingCert().verify(id.signingCert().getPublicKey(),"BC");
                Path path=dir.resolve(hybrid?"hybrid.p12":"pure.p12");char[] password="test-only-local-password".toCharArray();
                id.save(path,password); Identity loaded=Identity.load(path,password);
                if(loaded.signingKey()!=null || loaded.encryptionKey()!=null || (hybrid && loaded.traditionalKey()==null))throw new AssertionError("Token identity storage");
                var mail=MailEngine.compose(loaded,"token@example.test","recipient@example.test","Token","A token-backed message",null,simulator);
                var opened=MailEngine.open(mail,null,loaded.signingCert());
                if(!opened.pinned()||!opened.text().contains("token-backed"))throw new AssertionError("Mail verification");
                System.out.println("PASS token certificate, PKCS12, and external signing (hybrid="+hybrid+")");
            }
        }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
