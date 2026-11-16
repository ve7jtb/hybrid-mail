package dev.hybridmail;

import java.io.Console;
import java.nio.file.*;
import java.util.Arrays;
import jakarta.mail.internet.MimeMessage;

/** Reuse existing Beta0 test identities; only two message signatures, no provisioning. */
public final class Pkcs11Test {
    public static void main(String[] args) throws Exception {
        if(args.length<3||args.length>4)throw new IllegalArgumentException("Pkcs11Test identity-directory adapter new-output-directory [--no-ui]");
        MailEngine.init();Console console=System.console();
        if(console==null)throw new IllegalStateException("Run in Terminal for PIN entry");
        Path identities=Path.of(args[0]),out=Path.of(args[2]).toAbsolutePath();
        Files.createDirectory(out);Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        String adapter=Path.of(args[1]).toAbsolutePath().toString();
        System.out.println("PKCS#11 test: reusing existing pure/hybrid identities, no key generation or email sending.");
        char[] password=console.readPassword("Existing local identity-file password (NOT YubiKey PIN): ");
        if(password==null)throw new IllegalStateException("Cancelled");
        StringBuilder report=new StringBuilder("Beta0 PKCS#11 external-mu S/MIME signing test\n");
        Identity pure=null;MimeMessage pureMail=null;
        try {
            for(String label:new String[]{"pure","hybrid"}) {
                Identity id=Identity.load(identities.resolve(label+".p12"),password);
                if(id.signingKey()!=null)throw new IllegalStateException("Expected token identity without ML-DSA private key");
                String text="Beta0 PKCS#11 hardware signing test: "+label+".\r\nExisting slot 9c via CKM_ML_DSA_EXTERNAL_MU.\r\n";
                System.out.println("\nSigning "+label+" S/MIME through OpenSSL/PKCS#11 (PIN + touch)…");
                MimeMessage message=MailEngine.compose(id,"beta0@example.test","recipient@example.test","Beta0 PKCS#11 "+label,text,null,ExternalMu.executable(adapter));
                byte[] bytes=MailEngine.encode(message);
                var checked=MailEngine.open(MailEngine.parse(bytes),null,id.signingCert());
                if(!checked.pinned()||!checked.fromMatches()||!checked.text().equals(text))throw new AssertionError("S/MIME verification");
                Files.write(out.resolve(label+".eml"),bytes,StandardOpenOption.CREATE_NEW);
                Files.write(out.resolve(label+"-signing.cer"),id.signingCert().getEncoded(),StandardOpenOption.CREATE_NEW);
                report.append("PASS ").append(label).append(": PKCS#11 external-mu signature verified by Bouncy Castle\n");
                System.out.println("PASS "+label+" PKCS#11 S/MIME round trip");
                if(label.equals("pure")){pure=id;pureMail=message;}
            }
            report.append("SUCCESS: both signing profiles verified; no mail sent, no token keys changed.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            System.out.println(report+"Artifacts: "+out);
        } catch(Throwable error) {
            report.append("FAILED: ").append(error.getClass().getSimpleName()).append("; inspect local Terminal output. No automatic retry.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            throw error;
        } finally {Arrays.fill(password,'\0');}
        if(args.length==3)MailApp.openTokenSession(pure,adapter,pureMail);
    }
}
