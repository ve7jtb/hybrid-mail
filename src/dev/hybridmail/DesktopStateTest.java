package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
public final class DesktopStateTest {
    static void check(boolean value,String label){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
    public static void main(String[] args)throws Exception{
        if(DesktopState.linux()) {
            DesktopState defaults=DesktopState.open();
            check(defaults.directory().getFileName().toString().equals("pq-mail"),"Linux data directory");
            check(defaults.configuration().get("PKCS11_PROVIDER").endsWith(".so")&&defaults.configuration().get("PKCS11_MODULE").endsWith(".so"),"Linux PKCS11 shared library paths");
        }
        MailEngine.init();Path dir=Files.createTempDirectory("hybrid-desktop-test-");
        char[] password="test-only-local-password".toCharArray();
        try{
            DesktopState state=new DesktopState(dir.resolve("state"));
            Identity software=Identity.generate("desktop@example.test",true);
            Identity token=new Identity(software.signingCert(),null,software.encryptionCert(),null,null);
            String id=state.remember(token,"Token test",null);
            state.set("token.serial","test-device");state.save();
            DesktopState reopened=new DesktopState(state.directory());Identity loaded=reopened.loadIdentity(id,null);
            check(loaded.signingKey()==null&&loaded.encryptionKey()==null&&Arrays.equals(loaded.signingCert().getEncoded(),token.signingCert().getEncoded()),"certificate-only identity restores without password");
            Path pem=state.directory().resolve("identities").resolve(id).resolve("encryption.pem");
            check(Arrays.equals(Identity.readCertificate(pem).getEncoded(),token.encryptionCert().getEncoded()),"PEM certificate export round trip");
            check(reopened.get("token.serial","").equals("test-device")&&reopened.get("selected.identity","").equals(id),"device configuration and selection persist");
            state.saveCertificate("recipient",token.encryptionCert());state.saveCertificate("pinned",token.signingCert());
            check(state.certificate("recipient").equals(token.encryptionCert())&&state.certificate("pinned").equals(token.signingCert()),"recipient and pinned certificates persist");
            Identity renewed=software.reissue("new-mailbox@example.test",null,List.of("alias1@example.test","alias2@example.test","alias3@example.test","alias4@example.test"));
            check(Identity.matchesEmail(renewed.signingCert(),"new-mailbox@example.test")&&Identity.matchesEmail(renewed.encryptionCert(),"new-mailbox@example.test")&&Arrays.equals(renewed.signingCert().getPublicKey().getEncoded(),software.signingCert().getPublicKey().getEncoded())&&Arrays.equals(renewed.encryptionCert().getPublicKey().getEncoded(),software.encryptionCert().getPublicKey().getEncoded()),"certificate email update preserves both keys and updates both SANs");
            for(var cert:List.of(renewed.signingCert(),renewed.encryptionCert())){
                check(cert.getSubjectAlternativeNames().size()==5,"reissued certificate contains primary and four extra SANs");
                for(int n=1;n<=4;n++)check(Identity.matchesEmail(cert,"alias"+n+"@example.test"),"reissued SAN alias matches");
            }
            try{software.reissue("new@example.test",null,List.of("NEW@example.test"));throw new AssertionError("duplicate SAN accepted");}catch(IllegalArgumentException expected){}
            try{software.reissue("new@example.test",null,List.of("a@example.test","b@example.test","c@example.test","d@example.test","e@example.test"));throw new AssertionError("fifth extra SAN accepted");}catch(IllegalArgumentException expected){}
            renewed.signingCert().verify(renewed.signingCert().getPublicKey(),"BC");renewed.encryptionCert().verify(renewed.signingCert().getPublicKey(),"BC");
            Path original=dir.resolve("software.p12");software.save(original,password);
            state.remember(software,"Software test",original);
            Identity restored=state.loadIdentity(id,password);
            check(restored.signingKey()!=null&&restored.encryptionKey()!=null,"encrypted software identity restores with password");
            check(!Files.readString(state.directory().resolve("settings.properties")).contains(new String(password)),"identity password absent from settings");
            try{state.loadIdentity(id,"wrong".toCharArray());throw new AssertionError("wrong password accepted");}catch(java.io.IOException expected){System.out.println("PASS wrong saved identity password rejected");}
            var signingContact=state.rememberContact(software.signingCert(),"desktop@example.test","signing");
            var encryptionContact=state.rememberContact(software.encryptionCert(),"desktop@example.test","encryption");
            check(new DesktopState(state.directory()).contacts().size()==2&&state.contactCertificate(encryptionContact).equals(software.encryptionCert()),"signing and encryption contacts persist separately");
            state.rememberContact(software.signingCert(),"desktop@example.test","signing");check(state.contacts().size()==2,"duplicate certificate import is idempotent");
            try{state.rememberContact(software.encryptionCert(),"wrong@example.test","encryption");throw new AssertionError("wrong email accepted");}catch(java.io.IOException expected){System.out.println("PASS contact email mismatch rejected");}
            try{state.rememberContact(software.signingCert(),"desktop@example.test","encryption");throw new AssertionError("wrong key usage accepted");}catch(java.io.IOException expected){System.out.println("PASS signing-only certificate rejected for encryption");}
            check(!state.isTrusted(software.signingCert(),"signing"),"import does not implicitly trust a certificate");
            state.migrateTrust();check(state.isTrusted(software.signingCert(),"signing"),"legacy explicit pin migrates once");
            state.setTrusted(software.signingCert(),"signing",false);state.migrateTrust();
            check(!new DesktopState(state.directory()).isTrusted(software.signingCert(),"signing"),"revocation persists and migration does not restore trust");
            for(boolean hybrid:new boolean[]{false,true}){
                Identity incoming=Identity.generate("incoming@example.test",hybrid);
                var message=MailEngine.compose(incoming,"incoming@example.test","desktop@example.test","Trust test","Verified body",null,null);
                var verified=MailEngine.open(message,null,null);
                check(verified.signerCertificate().equals(incoming.signingCert()),"verified incoming certificate exposed for "+(hybrid?"hybrid":"pure")+" signature");
                state.rememberContact(verified.signerCertificate(),"incoming@example.test","signing");
                state.setTrusted(verified.signerCertificate(),"signing",true);
                check(new DesktopState(state.directory()).isTrusted(incoming.signingCert(),"signing"),"incoming fingerprint trust persists");
            }
            state.setTrusted(software.signingCert(),"signing",true);
            state.setTrusted(software.encryptionCert(),"encryption",true);
            check(!state.isTrusted(software.signingCert(),"encryption")&&!state.isTrusted(renewed.signingCert(),"signing"),"trust is role-specific and does not follow reissued certificates with the same key");
            check(state.isTrusted(software.signingCert(),"signing")&&state.isTrusted(software.encryptionCert(),"encryption"),"multiple certificate fingerprints coexist");
            state.removeContact(signingContact);check(state.contacts().size()==3&&!state.isTrusted(software.signingCert(),"signing")&&Files.isDirectory(state.directory().resolve("removed-contacts")),"contact removal preserves recoverable public certificate");
            for(String algorithm:List.of(Identity.PURE_87_SIGN,Identity.HYBRID_87_SIGN)){
                Identity strong=Identity.generate("strong@example.test",algorithm);
                Path strongFile=dir.resolve(algorithm+".p12");strong.save(strongFile,password);strong=Identity.load(strongFile,password);
                check(strong.signatureAlgorithm().equals(algorithm),"ML-DSA-87 profile survives PKCS12 round trip: "+algorithm);
                strong.signingCert().verify(strong.signingCert().getPublicKey(),"BC");
                check(strong.encryptionCert().getPublicKey().getAlgorithm().equals(algorithm.equals(Identity.PURE_87_SIGN)?Identity.PURE_1024_KEM:Identity.HYBRID_1024_KEM),"ML-DSA-87 uses matching ML-KEM-1024 profile");
                var strongContact=state.rememberContact(strong.encryptionCert(),"strong@example.test","encryption");
                check(state.contactCertificate(strongContact).equals(strong.encryptionCert()),"ML-KEM-1024 recipient certificate import");
                for(boolean encrypt:new boolean[]{false,true}){
                    var message=MailEngine.compose(strong,"strong@example.test","strong@example.test","87 test","Strong signature",encrypt?strong.encryptionCert():null,null);
                    var opened=MailEngine.open(message,strong,strong.signingCert());
                    check(opened.text().contains("Strong signature")&&opened.pinned()&&opened.encrypted()==encrypt,"ML-DSA-87 S/MIME round trip "+algorithm+" encrypted="+encrypt);
                }
            }
            var forget=new DesktopState(dir.resolve("forget"));
            String forgotten=forget.remember(token,"Forget me",null);forget.bindToken(forgotten,"123456","83","9d","82");
            Identity otherToken=new Identity(renewed.signingCert(),null,renewed.encryptionCert(),null,null);
            String kept=forget.remember(otherToken,"Keep me",null);
            forget.set("selected.identity",forgotten);forget.save();forget.forgetYubiKeyIdentity(forgotten);
            var restoredForget=new DesktopState(forget.directory());
            check(restoredForget.identities().size()==1&&restoredForget.identities().get(0).id().equals(kept)&&restoredForget.get("selected.identity","").isEmpty(),"forget removes only selected token record and clears selection persistently");
            check(!Files.exists(forget.directory().resolve("identities").resolve(forgotten))&&restoredForget.get("identity."+forgotten+".token.serial","").isEmpty(),"forget deletes public certificate files and slot mappings");
            Path softwareFile=dir.resolve("forget-protected-software.p12");software.save(softwareFile,password);
            String protectedId=forget.remember(software,"Software",softwareFile);
            try{forget.forgetYubiKeyIdentity(protectedId);throw new AssertionError("software identity forgotten");}catch(java.io.IOException expected){}
            check(Files.exists(forget.directory().resolve("identities").resolve(protectedId).resolve("identity.p12")),"forget refuses software private-key bundles");
            var renewalState=new DesktopState(dir.resolve("renewal"));
            String oldRecord=renewalState.remember(token,"Original",null);renewalState.bindToken(oldRecord,"123456","83","9d","82");
            String newRecord=renewalState.remember(otherToken,"Updated SANs",null);renewalState.bindToken(newRecord,"123456","83","9d","82");
            check(renewalState.certificateBundle(otherToken).size()==1&&renewalState.certificateBundle(otherToken).get(0).identity().signingCert().equals(otherToken.signingCert()),"backup selects updated email/SAN set while retaining old local identities");
            state.saveGoogleClient(new GoogleOAuth.Client("test.apps.googleusercontent.com","test-client-secret"));
            var client=GoogleOAuth.Client.read(state.directory().resolve("google-client.json"));
            check(client.id().equals("test.apps.googleusercontent.com")&&client.secret().equals("test-client-secret")&&!Files.readString(state.directory().resolve("settings.properties")).contains("test-client-secret"),"manual OAuth client round trip in separate owner-only config");
            state.activate();ProcessBuilder process=DesktopState.process("/tmp/adapter path.py");
            check(process.command().equals(List.of("/usr/bin/python3","/tmp/adapter path.py"))&&process.environment().get("PYTHONDONTWRITEBYTECODE").equals("1")&&process.environment().get("PKCS11_SERIAL").equals("test-device"),"desktop adapters use explicit interpreter and saved config without shell");
        }finally{Arrays.fill(password,'\0');try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
