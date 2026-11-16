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
            KeyPairGenerator ecGen=KeyPairGenerator.getInstance("EC","BC");
            ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            KeyPair ec=ecGen.generateKeyPair();
            int[] calls={0,0};
            ExternalMu.Backend dual=new ExternalMu.Backend() {
                public byte[] sign(PublicKey pub,byte[] mu) throws Exception { calls[0]++;return simulator.sign(pub,mu); }
                public byte[] signEcdsa(PublicKey pub,byte[] hash) throws Exception {
                    calls[1]++;if(hash.length!=32)throw new AssertionError("ECDSA digest length");
                    Signature signer=Signature.getInstance("NONEwithECDSA","BC");
                    signer.initSign(ec.getPrivate());signer.update(hash);return signer.sign();
                }
            };
            Identity dualId=Identity.forDualToken("token@example.test",token.getPublic(),ec.getPublic(),dual);
            Path dualPath=dir.resolve("dual.p12");char[] password="test-only-local-password".toCharArray();
            dualId.save(dualPath,password);dualId=Identity.load(dualPath,password);
            if(dualId.signingKey()!=null||dualId.traditionalKey()!=null)throw new AssertionError("Dual identity contains a private key");
            var mail=MailEngine.compose(dualId,"token@example.test","recipient@example.test","Dual","Both signing keys external",null,dual);
            var opened=MailEngine.open(MailEngine.parse(MailEngine.encode(mail)),null,dualId.signingCert());
            if(!opened.pinned()||!opened.fromMatches()||!opened.text().equals("Both signing keys external")||calls[0]!=2||calls[1]!=2)
                throw new AssertionError("Dual component verification/call counts");
            ExternalMu.Backend bad=new ExternalMu.Backend() {
                public byte[] sign(PublicKey pub,byte[] mu)throws Exception{return simulator.sign(pub,mu);}
                public byte[] signEcdsa(PublicKey pub,byte[] hash)throws Exception {
                    hash[0]^=1;return dual.signEcdsa(pub,hash);
                }
            };
            boolean rejected=false;
            try { MailEngine.compose(dualId,"token@example.test","recipient@example.test","Bad","Bad EC",null,bad); }
            catch(Exception expected){rejected=true;}
            if(!rejected)throw new AssertionError("Invalid external EC signature accepted");
            System.out.println("PASS dual external certificate, certificate-only PKCS12, both S/MIME components, and invalid ECDSA rejection");
            KeyPairGenerator rsaGen=KeyPairGenerator.getInstance("RSA","BC");rsaGen.initialize(3072);KeyPair rsa=rsaGen.generateKeyPair();
            int[] rsaCalls={0},clearCalls={0};
            ExternalMu.Backend rsaBackend=new ExternalMu.Backend(){
                public void clearSecrets(){clearCalls[0]++;}
                public byte[] sign(PublicKey pub,byte[] mu)throws Exception{return simulator.sign(pub,mu);}
                public byte[] signRsa(PublicKey pub,byte[] hash)throws Exception{
                    if(hash.length!=32)throw new AssertionError("RSA digest");rsaCalls[0]++;
                    var signer=org.bouncycastle.crypto.signers.PSSSigner.createRawSigner(new org.bouncycastle.crypto.engines.RSABlindedEngine(),new org.bouncycastle.crypto.digests.SHA256Digest());
                    signer.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(rsa.getPrivate().getEncoded()),new SecureRandom()));
                    signer.update(hash,0,hash.length);return signer.generateSignature();
                }
            };
            Identity rsaId=Identity.forDualToken("token@example.test",token.getPublic(),rsa.getPublic(),rsaBackend);
            Path rsaPath=dir.resolve("rsa.p12");rsaId.save(rsaPath,password);rsaId=Identity.load(rsaPath,password);
            if(!rsaId.signatureAlgorithm().equals(Identity.HYBRID_RSA_SIGN)||rsaId.signingKey()!=null||rsaId.traditionalKey()!=null)throw new AssertionError("RSA identity");
            var rsaMail=MailEngine.compose(rsaId,"token@example.test","recipient@example.test","RSA","External RSA-PSS composite",null,rsaBackend);
            var rsaResult=MailEngine.open(MailEngine.parse(MailEngine.encode(rsaMail)),null,rsaId.signingCert());
            if(!rsaResult.pinned()||!rsaResult.fromMatches()||!rsaResult.signatureAlgorithm().equals(Identity.HYBRID_RSA_SIGN)||rsaCalls[0]!=2||clearCalls[0]!=2)throw new AssertionError("RSA S/MIME verification");
            ExternalMu.Backend wrongRsa=new ExternalMu.Backend(){
                public void clearSecrets(){clearCalls[0]++;}
                public byte[] sign(PublicKey pub,byte[] mu)throws Exception{return simulator.sign(pub,mu);}
                public byte[] signRsa(PublicKey pub,byte[] hash)throws Exception{hash[0]^=1;return rsaBackend.signRsa(pub,hash);}
            };
            rejected=false;
            try{MailEngine.compose(rsaId,"token@example.test","recipient@example.test","Bad RSA","Bad RSA",null,wrongRsa);}
            catch(Exception expected){rejected=true;}
            if(!rejected||clearCalls[0]!=3)throw new AssertionError("Bad RSA signature accepted or failure cleanup missing");
            System.out.println("PASS MLDSA65-RSA3072-PSS-SHA512 external components, certificate-only identity, CMS round trip, and wrong RSA digest rejection");
            var cache=new ExternalMu.OperationPinCache();int[] prompts={0};char[] original="654321".toCharArray();
            ExternalMu.PinSource source=()->{prompts[0]++;return original;};
            char[] first=cache.copy(source),second=cache.copy(source);
            if(prompts[0]!=1||first==second||!Arrays.equals(first,second))throw new AssertionError("PIN must be prompted once and reused by copy");
            Arrays.fill(first,'\0');Arrays.fill(second,'\0');cache.clear();
            if(!Arrays.equals(original,new char[6]))throw new AssertionError("Cached PIN was not cleared");
            char[] next=cache.copy(()->{prompts[0]++;return "123456".toCharArray();});cache.clear();Arrays.fill(next,'\0');
            if(prompts[0]!=2)throw new AssertionError("Next signature reused old PIN");
            System.out.println("PASS one PIN per signature, cache overwrite, fresh prompt afterward, and cleanup on signing failure");
        }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
