package dev.hybridmail;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import jakarta.mail.internet.MimeMessage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/** Interactive integration test. Only uses an existing token key; sends no email. */
public final class Beta0Test {
    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > 4) throw new IllegalArgumentException("Beta0Test public.pem adapter output-directory [--no-ui]");
        MailEngine.init();
        Console console = System.console();
        if (console == null) throw new IllegalStateException("Run this test in Terminal for PIN entry");
        String serial = System.getenv("YKMAN_SERIAL");
        if (serial == null || !serial.matches("[0-9]+")) throw new IllegalStateException("Set YKMAN_SERIAL to your intended device");
        Path out = Path.of(args[2]).toAbsolutePath(); Files.createDirectory(out);
        var permissions = java.nio.file.attribute.PosixFilePermissions.fromString("rwx------");
        Files.setPosixFilePermissions(out, permissions);
        String executable = Path.of(args[1]).toAbsolutePath().toString();
        PublicKey pub;
        try (PEMParser parser = new PEMParser(Files.newBufferedReader(Path.of(args[0]), StandardCharsets.US_ASCII))) {
            Object object = parser.readObject();
            if (!(object instanceof SubjectPublicKeyInfo info)) throw new IOException("Expected PUBLIC KEY PEM");
            pub = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(info);
        }
        if (!Identity.PURE_SIGN.equalsIgnoreCase(pub.getAlgorithm())) throw new GeneralSecurityException("Expected ML-DSA-65");
        System.out.println("Using existing ML-DSA-65 key in slot 9c. No token provisioning or mail sending.");
        System.out.println("Four signatures: pure certificate, pure S/MIME, hybrid certificate, hybrid S/MIME.");
        System.out.println("The following NEW password protects the local identity files, not your YubiKey PIN.");
        char[] password = console.readPassword("Choose a local identity password (12+ characters): ");
        if (password == null || password.length < 12) throw new IllegalArgumentException("Identity password must be at least 12 characters");
        char[] confirm = console.readPassword("Confirm local identity password: ");
        boolean same = Arrays.equals(password, confirm);
        if (confirm != null) Arrays.fill(confirm, '\0');
        if (!same) { Arrays.fill(password, '\0'); throw new IllegalArgumentException("Passwords did not match"); }
        StringBuilder report = new StringBuilder("Beta0 hardware-backed S/MIME signing test\n");
        report.append("Public key SHA-256: ").append(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pub.getEncoded()))).append('\n');
        ExternalMu.Backend backend = ExternalMu.executable(executable);
        Identity pure = null; MimeMessage pureMail = null;
        try {
            for (boolean hybrid : new boolean[]{false,true}) {
                String label = hybrid ? "hybrid" : "pure";
                System.out.println("\nCreating " + label + " local certificate (PIN + touch in ykman)…");
                Identity id = Identity.forToken("beta0@example.test", pub, hybrid, backend);
                Path identityFile = out.resolve(label + ".p12"); id.save(identityFile, password);
                Identity loaded = Identity.load(identityFile, password);
                if (loaded.signingKey() != null) throw new AssertionError("Token identity unexpectedly contains an ML-DSA private key");
                Files.write(out.resolve(label + "-signing.cer"), loaded.signingCert().getEncoded(), StandardOpenOption.CREATE_NEW);
                String text = "Beta0 hardware signing test: " + label + ".\r\nML-DSA key: existing PIV slot 9c.\r\n";
                System.out.println("Signing " + label + " S/MIME message (PIN + touch in ykman)…");
                MimeMessage mail = MailEngine.compose(loaded,"beta0@example.test","recipient@example.test","Beta0 " + label + " test",text,null,backend);
                byte[] wire = MailEngine.encode(mail);
                var checked = MailEngine.open(MailEngine.parse(wire),null,loaded.signingCert());
                if (!checked.pinned() || !checked.fromMatches() || !checked.text().equals(text)) throw new AssertionError("S/MIME verification failed");
                Files.write(out.resolve(label + ".eml"),wire,StandardOpenOption.CREATE_NEW);
                report.append("PASS ").append(label).append(": certificate verified, identity reloaded without ML-DSA private key, S/MIME signature verified by BC\n");
                System.out.println("PASS " + label + " hardware-backed S/MIME round trip");
                if (!hybrid) { pure=loaded; pureMail=mail; }
            }
            report.append("SUCCESS: both signing profiles verified; no mail sent, no token keys changed.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            System.out.println("\n" + report + "Artifacts: " + out);
        } catch (Throwable error) {
            report.append("FAILED: ").append(error.getClass().getSimpleName()).append(". Check local Terminal output; no automatic retry.\n");
            Files.writeString(out.resolve("result.txt"),report.toString(),StandardOpenOption.CREATE_NEW);
            throw error;
        } finally { Arrays.fill(password, '\0'); }
        if (args.length == 3) MailApp.openTokenSession(pure,executable,pureMail);
    }
}
