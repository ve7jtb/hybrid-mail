package dev.hybridmail;

import java.io.Console;
import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import jakarta.mail.internet.MimeMessage;

/** Hardware test: existing signing identities, new local encryption certificates, no email. */
public final class Pkcs11KemTest {
    public static void main(String[] args)throws Exception{
        if(args.length<6||args.length>7)throw new IllegalArgumentException("Pkcs11KemTest signing-identities ml-public ec-public signing-adapter kem-adapter new-output [--no-ui]");
        MailEngine.init();Console console=System.console();if(console==null)throw new IllegalStateException("Run launcher from Terminal for local identity password");
        Path identities=Path.of(args[0]),out=Path.of(args[5]);Files.createDirectory(out);
        Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        PublicKey ml=KeyFactory.getInstance("ML-KEM","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of(args[1]))));
        PublicKey ec=KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of(args[2]))));
        PublicKey composite=new CompositePublicKey(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256,ml,ec);
        ExternalKem.validatePublicKey(ml);ExternalKem.validatePublicKey(composite);
        String signAdapter=Path.of(args[3]).toAbsolutePath().toString(),kemAdapter=Path.of(args[4]).toAbsolutePath().toString();
        char[] password=console.readPassword("Existing RSA-demo local identity-file password (NOT YubiKey PIN): ");
        if(password==null)throw new IllegalStateException("Cancelled");
        StringBuilder report=new StringBuilder("Beta0 PKCS#11 S/MIME encryption and decryption test\n");
        Identity demo=null;MimeMessage demoMail=null;MailEngine.Opened demoOpened=null;
        try{
            for(String label:new String[]{"pure","hybrid"}){
                Identity signing=Identity.load(identities.resolve(label+".p12"),password);
                if(signing.signingKey()!=null||signing.traditionalKey()!=null)throw new IllegalStateException("Expected token-only signing identity");
                System.out.println("\nCreating "+label+" encryption certificate with existing signing keys (one PIN dialog)…");
                Identity id=signing.withTokenEncryption("beta0@example.test",label.equals("pure")?ml:composite,ExternalMu.executable(signAdapter));
                id.save(out.resolve(label+".p12"),password);id=Identity.load(out.resolve(label+".p12"),password);
                if(id.encryptionKey()!=null||id.signingKey()!=null||id.traditionalKey()!=null)throw new AssertionError("No private keys may be stored locally");
                Files.write(out.resolve(label+"-encryption.cer"),id.encryptionCert().getEncoded(),StandardOpenOption.CREATE_NEW);
                Files.write(out.resolve(label+"-signing.cer"),id.signingCert().getEncoded(),StandardOpenOption.CREATE_NEW);
                String text="Beta0 PKCS#11 encrypted S/MIME test: "+label+".\r\nML-KEM token decapsulation"+(label.equals("hybrid")?" plus token ECDH P-256":"")+".\r\n";
                System.out.println("Signing and encrypting "+label+" S/MIME (one signing PIN dialog)…");
                MimeMessage message=MailEngine.compose(id,"beta0@example.test","beta0@example.test","PQC token encryption "+label,text,id.encryptionCert(),ExternalMu.executable(signAdapter));
                Path messageFile=out.resolve(label+"-encrypted.eml");Files.write(messageFile,MailEngine.encode(message),StandardOpenOption.CREATE_NEW);
                System.out.println("Reopening and decrypting saved "+label+" S/MIME (one decryption PIN dialog)…");
                var checked=MailEngine.open(MailEngine.parse(Files.readAllBytes(messageFile)),id,id.signingCert(),ExternalKem.executable(kemAdapter));
                if(!checked.encrypted()||!checked.pinned()||!checked.fromMatches()||!text.equals(checked.text()))throw new AssertionError("Encrypted S/MIME roundtrip");
                report.append("PASS ").append(label).append(": ").append(id.encryptionCert().getPublicKey().getAlgorithm())
                    .append(" token recovery, AES-256-GCM authentication, ").append(checked.signatureAlgorithm()).append(" signature verification\n");
                Files.writeString(out.resolve(label+"-decrypted.txt"),checked.text(),StandardOpenOption.CREATE_NEW);
                System.out.println("PASS "+label+" saved S/MIME decrypted and verified");
                demo=id;demoMail=message;demoOpened=checked;
            }
            report.append("SUCCESS: both encrypted messages reopened, token-decrypted, authenticated and signature-verified. No email sent; signing keys unchanged.\n");
        }catch(Throwable error){
            report.append("FAILED: ").append(error.getClass().getSimpleName()).append("; see local Terminal error. No automatic retry.\n");throw error;
        }finally{Arrays.fill(password,'\0');Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);System.out.println(report);}
        if(args.length==6)MailApp.openKemSession(demo,signAdapter,kemAdapter,demoMail,demoOpened);
    }
}
