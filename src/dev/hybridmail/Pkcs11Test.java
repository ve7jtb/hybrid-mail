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
        String ecFile=System.getenv("PKCS11_TRADITIONAL_PUBLIC");
        String mlFile=System.getenv("PKCS11_ML_PUBLIC");
        boolean fresh=mlFile!=null&&!mlFile.isBlank();
        boolean dual=ecFile!=null&&!ecFile.isBlank();
        System.out.println(dual ? "PKCS#11 test: both signing keys on token; creating a new local hybrid certificate. No token key generation or email sending."
            : "PKCS#11 test: reusing existing pure/hybrid identities, no key generation or email sending.");
        char[] password=console.readPassword(fresh?"New local identity-file password (12+ characters, NOT YubiKey PIN): ":"Existing local identity-file password (NOT YubiKey PIN): ");
        if(password!=null&&fresh&&password.length<12)throw new IllegalArgumentException("Use 12+ characters for the local identity password");
        if(password==null)throw new IllegalStateException("Cancelled");
        StringBuilder report=new StringBuilder("Beta0 PKCS#11 external-mu S/MIME signing test\n");
        Identity pure=null,demoIdentity=null;MimeMessage pureMail=null;
        try {
            for(String label:new String[]{"pure","hybrid"}) {
                Identity id;
                if(fresh&&label.equals("pure")) {
                    var ml=java.security.KeyFactory.getInstance("ML-DSA","BC").generatePublic(new java.security.spec.X509EncodedKeySpec(Files.readAllBytes(Path.of(mlFile))));
                    System.out.println("Signing the new pure certificate (one PIN dialog)…");
                    id=Identity.forToken("beta0@example.test",ml,false,ExternalMu.executable(adapter));
                    id.save(out.resolve("pure.p12"),password);
                } else if(dual&&label.equals("hybrid")) {
                    var ec=java.security.KeyFactory.getInstance(System.getenv().getOrDefault("PKCS11_TRADITIONAL_ALGORITHM","RSA"),"BC").generatePublic(new java.security.spec.X509EncodedKeySpec(Files.readAllBytes(Path.of(ecFile))));
                    System.out.println("Signing the new RSA composite certificate (one PIN dialog for both components)…");
                    id=Identity.forDualToken("beta0@example.test",pure.signingCert().getPublicKey(),ec,ExternalMu.executable(adapter));
                    id.save(out.resolve("hybrid.p12"),password);
                    id=Identity.load(out.resolve("hybrid.p12"),password);
                    if(id.traditionalKey()!=null)throw new AssertionError("Dual token identity must not store a traditional private key");
                } else id=Identity.load(identities.resolve(label+".p12"),password);
                if(id.signingKey()!=null)throw new IllegalStateException("Expected token identity without ML-DSA private key");
                String text="Beta0 PKCS#11 hardware signing test: "+label+".\r\nExisting slot 9c via CKM_ML_DSA_EXTERNAL_MU.\r\n";
                System.out.println("\nSigning "+label+" S/MIME through OpenSSL/PKCS#11 (one PIN dialog; touch only if key policy requires it)…");
                MimeMessage message=MailEngine.compose(id,"beta0@example.test","recipient@example.test","Beta0 PKCS#11 "+label,text,null,ExternalMu.executable(adapter));
                byte[] bytes=MailEngine.encode(message);
                var checked=MailEngine.open(MailEngine.parse(bytes),null,id.signingCert());
                if(!checked.pinned()||!checked.fromMatches()||!checked.text().equals(text))throw new AssertionError("S/MIME verification");
                Files.write(out.resolve(label+".eml"),bytes,StandardOpenOption.CREATE_NEW);
                Files.write(out.resolve(label+"-signing.cer"),id.signingCert().getEncoded(),StandardOpenOption.CREATE_NEW);
                report.append("PASS ").append(label).append(": PKCS#11 external-mu signature verified by Bouncy Castle\n");
                if(dual&&label.equals("hybrid"))report.append("PASS hybrid: RSA/ECDSA component also signed through PKCS#11; no signing private keys in local identity\n");
                System.out.println("PASS "+label+" PKCS#11 S/MIME round trip");
                if(label.equals("pure")){pure=id;pureMail=message;}
                if(label.equals("hybrid"))demoIdentity=id;
            }
            report.append("SUCCESS: both signing profiles verified; no mail sent, no token keys changed.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            System.out.println(report+"Artifacts: "+out);
        } catch(Throwable error) {
            report.append("FAILED: ").append(error.getClass().getSimpleName()).append("; inspect local Terminal output. No automatic retry.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            throw error;
        } finally {Arrays.fill(password,'\0');}
        if(args.length==3) {
            Identity demo=dual?demoIdentity:pure;
            MailApp.openTokenSession(demo,adapter,dual?MailEngine.parse(Files.readAllBytes(out.resolve("hybrid.eml"))):pureMail);
        }
    }
}
