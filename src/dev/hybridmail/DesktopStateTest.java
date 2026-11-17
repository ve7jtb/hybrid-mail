package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
public final class DesktopStateTest {
    static void check(boolean value,String label){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
    public static void main(String[] args)throws Exception{
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
            Identity renewed=software.reissue("new-mailbox@example.test",null);
            check(Identity.matchesEmail(renewed.signingCert(),"new-mailbox@example.test")&&Identity.matchesEmail(renewed.encryptionCert(),"new-mailbox@example.test")&&Arrays.equals(renewed.signingCert().getPublicKey().getEncoded(),software.signingCert().getPublicKey().getEncoded())&&Arrays.equals(renewed.encryptionCert().getPublicKey().getEncoded(),software.encryptionCert().getPublicKey().getEncoded()),"certificate email update preserves both keys and updates both SANs");
            renewed.signingCert().verify(renewed.signingCert().getPublicKey(),"BC");renewed.encryptionCert().verify(renewed.signingCert().getPublicKey(),"BC");
            Path original=dir.resolve("software.p12");software.save(original,password);
            state.remember(software,"Software test",original);
            Identity restored=state.loadIdentity(id,password);
            check(restored.signingKey()!=null&&restored.encryptionKey()!=null,"encrypted software identity restores with password");
            check(!Files.readString(state.directory().resolve("settings.properties")).contains(new String(password)),"identity password absent from settings");
            try{state.loadIdentity(id,"wrong".toCharArray());throw new AssertionError("wrong password accepted");}catch(java.io.IOException expected){System.out.println("PASS wrong saved identity password rejected");}
            state.activate();ProcessBuilder process=DesktopState.process("/tmp/adapter path.py");
            check(process.command().equals(List.of("/usr/bin/python3","/tmp/adapter path.py"))&&process.environment().get("PYTHONDONTWRITEBYTECODE").equals("1")&&process.environment().get("PKCS11_SERIAL").equals("test-device"),"desktop adapters use explicit interpreter and saved config without shell");
        }finally{Arrays.fill(password,'\0');try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
