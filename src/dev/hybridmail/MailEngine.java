package dev.hybridmail;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public final class MailEngine {
    public static final int MAX_MESSAGE = 20 * 1024 * 1024;
    static { Security.addProvider(new BouncyCastleProvider()); }
    public static void init() { }
    public static Session session() { return Session.getInstance(new Properties()); }
    public static MimeMessage compose(Identity id, String from, String to, String subject, String text,
                                      X509Certificate recipient, ExternalMu.Backend external) throws Exception {
        InternetAddress sender = new InternetAddress(from, true); sender.validate();
        InternetAddress receiver = new InternetAddress(to, true); receiver.validate();
        if (!Identity.matchesEmail(id.signingCert(), sender.getAddress())) throw new GeneralSecurityException("From address does not match signing certificate");
        if (text.length() > MAX_MESSAGE / 4) throw new IOException("Message too large");
        MimeBodyPart plain = new MimeBodyPart(); plain.setText(text, "UTF-8");
        SMIMESignedGenerator sg = new SMIMESignedGenerator();
        sg.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
            .build(id.signer(external), id.signingCert()));
        sg.addCertificates(new JcaCertStore(List.of(id.signingCert())));
        MimeBodyPart protectedPart = sg.generateEncapsulated(plain);
        ByteArrayOutputStream signedBytes = new ByteArrayOutputStream();
        protectedPart.writeTo(signedBytes);
        protectedPart = new MimeBodyPart(new ByteArrayInputStream(signedBytes.toByteArray()));
        SMIMESigned outgoing = new SMIMESigned(protectedPart);
        if (!outgoing.getSignerInfos().getSigners().iterator().next().verify(
                new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(id.signingCert())))
            throw new GeneralSecurityException("Signing key does not match the identity certificate");
        if (recipient != null) {
            recipient.checkValidity();
            if (!Identity.matchesEmail(recipient, receiver.getAddress())) throw new GeneralSecurityException("Recipient address does not match encryption certificate");
            boolean[] usage = recipient.getKeyUsage();
            if (usage == null || usage.length <= 2 || !usage[2]) throw new GeneralSecurityException("Certificate lacks keyEncipherment usage");
            String a = recipient.getPublicKey().getAlgorithm();
            if (!a.equalsIgnoreCase(Identity.PURE_KEM) && !a.equalsIgnoreCase(Identity.HYBRID_KEM))
                throw new GeneralSecurityException("Unsupported recipient KEM: " + a);
            SMIMEAuthEnvelopedGenerator eg = new SMIMEAuthEnvelopedGenerator();
            eg.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(recipient, CMSAlgorithm.AES256_WRAP)
                .setKDF(CMSAlgorithm.SHA256_HKDF).setProvider("BC"));
            protectedPart = eg.generate(protectedPart, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider("BC").build());
        }
        MimeMessage m = new MimeMessage(session());
        m.setFrom(sender); m.setRecipient(Message.RecipientType.TO, receiver); m.setSubject(subject, "UTF-8"); m.setSentDate(new Date());
        m.setDataHandler(protectedPart.getDataHandler());
        Enumeration<Header> headers = protectedPart.getAllHeaders();
        while (headers.hasMoreElements()) { Header h = headers.nextElement(); m.setHeader(h.getName(), h.getValue()); }
        m.saveChanges();
        // Force lazy S/MIME generation now so token errors surface before save/send.
        return parse(encode(m));
    }
    public static byte[] encode(MimeMessage message) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); message.writeTo(out);
        if (out.size() > MAX_MESSAGE) throw new IOException("Message exceeds 20 MiB limit");
        return out.toByteArray();
    }
    public static MimeMessage parse(byte[] bytes) throws Exception {
        if (bytes.length > MAX_MESSAGE) throw new IOException("Message exceeds 20 MiB limit");
        return new MimeMessage(session(), new ByteArrayInputStream(bytes));
    }
    public record Opened(String text, boolean encrypted, String signatureAlgorithm, String fingerprint, boolean pinned, boolean fromMatches) { }
    public static Opened open(MimeMessage message, Identity id, X509Certificate pinned) throws Exception {
        return open(message,id,pinned,null);
    }
    @SuppressWarnings("unchecked")
    public static Opened open(MimeMessage message,Identity id,X509Certificate pinned,ExternalKem.Backend token)throws Exception {
        Part part = message;
        boolean encrypted = new ContentType(part.getContentType()).getParameter("smime-type") != null &&
            "authEnveloped-data".equalsIgnoreCase(new ContentType(part.getContentType()).getParameter("smime-type"));
        if (encrypted) {
            if (id == null || id.encryptionCert()==null || (id.encryptionKey() == null && token==null)) throw new GeneralSecurityException("Load recipient identity to decrypt");
            SMIMEAuthEnveloped env = new SMIMEAuthEnveloped(message);
            RecipientInformation r = env.getRecipientInfos().get(new JceKEMRecipientId(id.encryptionCert()));
            if (r == null) throw new GeneralSecurityException("This identity is not a recipient");
            id.encryptionCert().checkValidity();
            byte[] recovered = r.getContent(token!=null?ExternalKem.recipient(id.encryptionCert(),token):new JceKEMAuthEnvelopedRecipient(id.encryptionKey()).setProvider("BC"));
            part = SMIMEUtil.toMimeBodyPart(recovered);
        }
        SMIMESigned signed;
        if (part.isMimeType("multipart/signed")) signed = new SMIMESigned((MimeMultipart)part.getContent());
        else if ("signed-data".equalsIgnoreCase(new ContentType(part.getContentType()).getParameter("smime-type"))) signed = new SMIMESigned(part);
        else throw new GeneralSecurityException("Expected S/MIME signed content; unsigned messages are not verified");
        var signers = signed.getSignerInfos().getSigners();
        if (signers.size() != 1) throw new GeneralSecurityException("Expected exactly one signer");
        SignerInformation si = signers.iterator().next();
        Collection<X509CertificateHolder> certs = signed.getCertificates().getMatches(si.getSID());
        if (certs.size() != 1) throw new GeneralSecurityException("Missing or ambiguous signing certificate");
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certs.iterator().next());
        cert.checkValidity();
        boolean[] usage = cert.getKeyUsage();
        if (usage == null || !usage[0]) throw new GeneralSecurityException("Signing certificate lacks digitalSignature usage");
        if (!si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) throw new GeneralSecurityException("INVALID signature");
        String fp = Identity.fingerprint(cert);
        boolean trusted = pinned != null && MessageDigest.isEqual(pinned.getEncoded(), cert.getEncoded());
        Address[] from = message.getFrom();
        boolean matches = from != null && from.length == 1 && from[0] instanceof InternetAddress a && Identity.matchesEmail(cert, a.getAddress());
        MimeBodyPart body = signed.getContent();
        if (!body.isMimeType("text/plain")) throw new IOException("This simple reader supports text/plain signed bodies only");
        return new Opened((String)body.getContent(), encrypted, cert.getPublicKey().getAlgorithm(), fp, trusted, matches);
    }
    public static void send(MimeMessage m, String host, int port, String user, String password) throws Exception {
        Properties p = networkProperties("smtp");
        p.setProperty("mail.smtp.starttls.enable", "true"); p.setProperty("mail.smtp.starttls.required", "true");
        p.setProperty("mail.smtp.auth", "true");
        Session session = Session.getInstance(p);
        try (Transport t = session.getTransport("smtp")) { t.connect(host, port, user, password); t.sendMessage(m, m.getAllRecipients()); }
    }
    public static MimeMessage fetchLatest(String host, int port, String user, String password) throws Exception {
        Session s = Session.getInstance(networkProperties("imaps"));
        try (Store store = s.getStore("imaps")) {
            store.connect(host, port, user, password);
            Folder inbox = store.getFolder("INBOX"); inbox.open(Folder.READ_ONLY);
            try {
                if (inbox.getMessageCount() == 0) throw new IOException("Inbox is empty");
                Message m = inbox.getMessage(inbox.getMessageCount());
                if (m.getSizeLong() > MAX_MESSAGE) throw new IOException("Message too large");
                ByteArrayOutputStream out = new ByteArrayOutputStream() {
                    public synchronized void write(byte[] b, int o, int l) { if (count + l > MAX_MESSAGE) throw new IllegalStateException("Message too large"); super.write(b,o,l); }
                    public synchronized void write(int b) { if (count >= MAX_MESSAGE) throw new IllegalStateException("Message too large"); super.write(b); }
                };
                m.writeTo(out); return parse(out.toByteArray());
            } finally { inbox.close(false); }
        }
    }
    private static Properties networkProperties(String protocol) {
        Properties p = new Properties(); String prefix = "mail." + protocol + ".";
        p.setProperty(prefix + "ssl.checkserveridentity", "true");
        p.setProperty(prefix + "connectiontimeout", "15000"); p.setProperty(prefix + "timeout", "30000"); p.setProperty(prefix + "writetimeout", "30000");
        return p;
    }
}
