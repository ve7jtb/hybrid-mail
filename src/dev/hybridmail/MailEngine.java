package dev.hybridmail;

import java.io.*;
import java.security.*;
import java.nio.file.*;
import jakarta.activation.DataHandler;
import jakarta.mail.util.ByteArrayDataSource;
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
        return compose(id,from,to,subject,text,recipient,external,List.of());
    }
    public record Attachment(String name, byte[] data) {
        public Attachment { name=safeFilename(name); data=data.clone(); }
        @Override public byte[] data(){return data.clone();}
        @Override public String toString(){return name+" ("+data.length+" bytes)";}
    }
    private static byte[] readBounded(InputStream in,int limit)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] block=new byte[8192];int n;
        while((n=in.read(block))!=-1){if(n>limit-out.size())throw new IOException("Attachment exceeds size limit");out.write(block,0,n);}
        return out.toByteArray();
    }
    public static String safeFilename(String name){
        if(name==null)return "attachment.bin";
        String result=name.replace('\\','/');result=result.substring(result.lastIndexOf('/')+1).replaceAll("[\\p{Cntrl}]","_");
        return result.isBlank()||result.equals(".")||result.equals("..")?"attachment.bin":result;
    }
    public static MimeMessage compose(Identity id,String from,String to,String subject,String text,
            X509Certificate recipient,ExternalMu.Backend external,List<Path> files)throws Exception {
        return composeFormatted(id,from,to,subject,text,null,recipient,external,files);
    }
    /** Formatting lives inside the signed MIME entity, alongside its text alternative. */
    public static MimeMessage composeFormatted(Identity id,String from,String to,String subject,String text,String html,
            X509Certificate recipient,ExternalMu.Backend external,List<Path> files)throws Exception {
        if(files.size()>20)throw new IOException("At most 20 attachments per message");
        List<Attachment> attachments=new ArrayList<>();long total=0;
        for(Path file:files){
            if(!Files.isRegularFile(file))throw new IOException("Attachment is not a regular file");
            byte[] data;try(InputStream in=Files.newInputStream(file)){data=readBounded(in,MAX_MESSAGE/2);}
            total+=data.length;if(total>MAX_MESSAGE/2)throw new IOException("Attachments exceed 10 MiB");
            attachments.add(new Attachment(file.getFileName().toString(),data));
        }
        return composeAttachments(id,from,to,subject,text,recipient,external,attachments,html);
    }
    public static MimeMessage composeAttachments(Identity id,String from,String to,String subject,String text,
            X509Certificate recipient,ExternalMu.Backend external,List<Attachment> files)throws Exception {
        return composeAttachments(id,from,to,subject,text,recipient,external,files,null);
    }
    public static MimeMessage composeAttachments(Identity id,String from,String to,String subject,String text,
            X509Certificate recipient,ExternalMu.Backend external,List<Attachment> files,String html)throws Exception {
        if(id.level3Polyfill())throw new GeneralSecurityException("This companion is OpenPGP-only; select an S/MIME identity");
        InternetAddress sender = new InternetAddress(from, true); sender.validate();
        InternetAddress receiver = new InternetAddress(to, true); receiver.validate();
        if (!Identity.matchesEmail(id.signingCert(), sender.getAddress())) throw new GeneralSecurityException("From address does not match signing certificate");
        if (text.length() > MAX_MESSAGE / 4) throw new IOException("Message too large");
        MimeBodyPart plain;
        if(html==null){plain=new MimeBodyPart();plain.setText(text,"UTF-8");}
        else plain=new MimeBodyPart(new ByteArrayInputStream(messageBody(text,html)));
        if(files.size()>20)throw new IOException("At most 20 attachments per message");
        if(!files.isEmpty()){
            MimeMultipart mixed=new MimeMultipart("mixed");mixed.addBodyPart(plain);
            long total=text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            for(Attachment file:files){
                byte[] data=file.data();
                total+=data.length;
                if(total>MAX_MESSAGE/2)throw new IOException("Body and attachments exceed 10 MiB; encoded S/MIME must fit the 20 MiB message limit");
                MimeBodyPart attachment=new MimeBodyPart();
                attachment.setDataHandler(new DataHandler(new ByteArrayDataSource(data,"application/octet-stream")));
                attachment.setFileName(file.name());attachment.setDisposition(Part.ATTACHMENT);
                mixed.addBodyPart(attachment);
            }
            plain=new MimeBodyPart();plain.setContent(mixed);
        }
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
            Identity.validateCertificatePurpose(recipient,"encryption");
            SMIMEAuthEnvelopedGenerator eg = new SMIMEAuthEnvelopedGenerator();
            if(recipient.getPublicKey() instanceof java.security.interfaces.RSAPublicKey)
                eg.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
            else if(recipient.getPublicKey() instanceof java.security.interfaces.ECPublicKey ec){
                KeyPairGenerator generator=KeyPairGenerator.getInstance("EC","BC");generator.initialize(ec.getParams());KeyPair ephemeral=generator.generateKeyPair();
                eg.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,ephemeral.getPrivate(),ephemeral.getPublic(),CMSAlgorithm.AES256_WRAP).setProvider("BC").addRecipient(recipient));
            }else eg.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(recipient,CMSAlgorithm.AES256_WRAP).setKDF(CMSAlgorithm.SHA256_HKDF).setProvider("BC"));
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
    /** Base64 keeps UTF-8 and CRLF canonicalization identical across both mail formats.
     * The random boundary cannot collide with base64 part data (it includes '-'). */
    static byte[] messageBody(String text,String html)throws IOException {
        if(text.length()>MAX_MESSAGE/4||(html!=null&&html.length()>1024*1024))throw new IOException("Message body is too large");
        String plain=mimeText("plain",text),encoded=plain;
        if(html!=null){String boundary="pqmail-body-"+UUID.randomUUID();encoded="Content-Type: multipart/alternative; boundary=\""+boundary+"\"\r\n\r\n--"+boundary+"\r\n"+plain+"\r\n--"+boundary+"\r\n"+mimeText("html",html)+"\r\n--"+boundary+"--\r\n";}
        return encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    private static String mimeText(String type,String text){return "Content-Type: text/"+type+"; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"+Base64.getMimeEncoder(64,new byte[]{13,10}).encodeToString(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    public static byte[] encode(MimeMessage message) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); message.writeTo(out);
        if (out.size() > MAX_MESSAGE) throw new IOException("Message exceeds 20 MiB limit");
        return out.toByteArray();
    }
    public static MimeMessage parse(byte[] bytes) throws Exception {
        if (bytes.length > MAX_MESSAGE) throw new IOException("Message exceeds 20 MiB limit");
        return new MimeMessage(session(), new ByteArrayInputStream(bytes));
    }
    /** Some mail transports wrap CMS as an attachment and discard smime-type. */
    static MimeMessage normalizeSmime(MimeMessage message)throws Exception {
        Part cms=message;
        if(message.isMimeType("multipart/mixed")){
            Multipart mixed=(Multipart)message.getContent();Part candidate=null;
            for(int i=0;i<mixed.getCount();i++){
                Part child=mixed.getBodyPart(i);
                if(child.isMimeType("application/pkcs7-mime")||child.isMimeType("application/x-pkcs7-mime")){
                    if(candidate!=null)throw new GeneralSecurityException("Multiple S/MIME attachments; select one explicitly");candidate=child;
                }
            }
            if(candidate==null)return message;cms=candidate;
        }
        if(!cms.isMimeType("application/pkcs7-mime")&&!cms.isMimeType("application/x-pkcs7-mime"))return message;
        byte[] bytes;try(var in=cms.getInputStream()){bytes=readBounded(in,MAX_MESSAGE);}
        var info=org.bouncycastle.asn1.cms.ContentInfo.getInstance(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(bytes));
        String type;
        if(info.getContentType().equals(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.authEnvelopedData))type="authEnveloped-data";
        else if(info.getContentType().equals(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.envelopedData))type="enveloped-data";
        else if(info.getContentType().equals(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.signedData))type="signed-data";
        else throw new GeneralSecurityException("Unsupported CMS content type");
        var copy=new MimeMessage(message);
        copy.setDataHandler(new DataHandler(new ByteArrayDataSource(bytes,"application/pkcs7-mime; smime-type="+type)));
        copy.setHeader("Content-Type","application/pkcs7-mime; smime-type="+type);
        copy.setHeader("Content-Transfer-Encoding","base64");return copy;
    }
    public record Opened(String text, boolean encrypted, String signatureAlgorithm, String fingerprint, boolean pinned, boolean fromMatches, X509Certificate signerCertificate, List<Attachment> attachments, String html) {
        public Opened { attachments=List.copyOf(attachments); }
        public Opened(String text,boolean encrypted,String signatureAlgorithm,String fingerprint,boolean pinned,boolean fromMatches,X509Certificate signerCertificate,List<Attachment> attachments){this(text,encrypted,signatureAlgorithm,fingerprint,pinned,fromMatches,signerCertificate,attachments,null);}
    }
    public static Opened open(MimeMessage message, Identity id, X509Certificate pinned) throws Exception {
        return open(message,id,pinned,null);
    }
    @SuppressWarnings("unchecked")
    public static Opened open(MimeMessage message,Identity id,X509Certificate pinned,ExternalKem.Backend token)throws Exception {
        message=normalizeSmime(message);
        Part part = message;
        String smimeType=new ContentType(part.getContentType()).getParameter("smime-type");
        boolean authenticated="authEnveloped-data".equalsIgnoreCase(smimeType);
        boolean encrypted=authenticated||"enveloped-data".equalsIgnoreCase(smimeType);
        if(encrypted){
            if(id==null||id.encryptionCert()==null||(id.encryptionKey()==null&&token==null))throw new GeneralSecurityException("Load recipient identity to decrypt");
            Identity.validateCertificatePurpose(id.encryptionCert(),"encryption");
            RecipientInformationStore recipients=authenticated?new SMIMEAuthEnveloped(message).getRecipientInfos():new SMIMEEnveloped(message).getRecipientInfos();
            RecipientInformation r=recipients.get(new JceKEMRecipientId(id.encryptionCert()));
            if(r==null)r=recipients.get(new JceKeyTransRecipientId(id.encryptionCert()));
            if(r==null)r=recipients.get(new JceKeyAgreeRecipientId(id.encryptionCert()));
            if(r==null)throw new GeneralSecurityException("This identity is not a recipient");
            Recipient recovery;
            if(r instanceof KEMRecipientInformation)recovery=token!=null?ExternalKem.recipient(id.encryptionCert(),token):new JceKEMAuthEnvelopedRecipient(id.encryptionKey()).setProvider("BC");
            else{
                if(id.encryptionKey()==null)throw new GeneralSecurityException("Conventional decryption requires the matching software .p12 private key");
                if(r instanceof KeyTransRecipientInformation)recovery=authenticated?new JceKeyTransAuthEnvelopedRecipient(id.encryptionKey()).setProvider("BC"):new JceKeyTransEnvelopedRecipient(id.encryptionKey()).setProvider("BC");
                else if(r instanceof KeyAgreeRecipientInformation)recovery=authenticated?new JceKeyAgreeAuthEnvelopedRecipient(id.encryptionKey()).setProvider("BC"):new JceKeyAgreeEnvelopedRecipient(id.encryptionKey()).setProvider("BC");
                else throw new GeneralSecurityException("Unsupported S/MIME recipient type");
            }
            part=SMIMEUtil.toMimeBodyPart(r.getContent(recovery));
        }
        SMIMESigned signed;
        if (part.isMimeType("multipart/signed")) signed = new SMIMESigned((MimeMultipart)part.getContent());
        else if ("signed-data".equalsIgnoreCase(new ContentType(part.getContentType()).getParameter("smime-type"))) signed = new SMIMESigned(part);
        else {
            if(!encrypted)throw new GeneralSecurityException("Expected S/MIME signed content; unsigned messages are not verified");
            List<Attachment> files=new ArrayList<>();StringBuilder content=new StringBuilder();collectContent(part,content,files,0,new int[]{0});
            var body=VerifiedMime.body(part);
            return new Opened(body.text(),true,"Unsigned","",false,false,null,files,body.html());
        }
        var signers = signed.getSignerInfos().getSigners();
        if (signers.size() != 1) throw new GeneralSecurityException("Expected exactly one signer");
        SignerInformation si = signers.iterator().next();
        Collection<X509CertificateHolder> certs = signed.getCertificates().getMatches(si.getSID());
        if (certs.size() != 1) throw new GeneralSecurityException("Missing or ambiguous signing certificate");
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certs.iterator().next());
        cert.checkValidity();
        Identity.validateCertificatePurpose(cert,"signing");
        if (!si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) throw new GeneralSecurityException("INVALID signature");
        String fp = Identity.fingerprint(cert);
        boolean trusted = pinned != null && MessageDigest.isEqual(pinned.getEncoded(), cert.getEncoded());
        Address[] from = message.getFrom();
        boolean matches = from != null && from.length == 1 && from[0] instanceof InternetAddress a && Identity.matchesEmail(cert, a.getAddress());
        List<Attachment> attachments=new ArrayList<>();StringBuilder content=new StringBuilder();
        collectContent(signed.getContent(),content,attachments,0,new int[]{0});
        // Extract the display alternatives only AFTER the original signed MIME
        // bytes verify. Sanitizing or rendering must never change what we verify.
        var body=VerifiedMime.body(signed.getContent());
        return new Opened(body.text(),encrypted,cert.getPublicKey().getAlgorithm(),fp,trusted,matches,cert,attachments,body.html());
    }
    private static void collectContent(Part part,StringBuilder text,List<Attachment> files,int depth,int[] count)throws Exception{
        if(depth>12||++count[0]>100)throw new IOException("Signed MIME nesting or part count exceeds limit");
        if(Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())||part.getFileName()!=null){
            if(files.size()>=20)throw new IOException("Too many attachments");byte[] data;
            try(InputStream in=part.getInputStream()){data=readBounded(in,MAX_MESSAGE);}
            long total=data.length;for(Attachment file:files)total+=file.data.length;
            if(total>MAX_MESSAGE)throw new IOException("Attachments exceed message limit");files.add(new Attachment(part.getFileName(),data));return;
        }
        if(part.isMimeType("text/plain")){if(text.length()>0)text.append("\n");text.append((String)part.getContent());return;}
        if(part.isMimeType("multipart/mixed")||part.isMimeType("multipart/alternative")||part.isMimeType("multipart/related")){
            Multipart multipart=(Multipart)part.getContent();for(int i=0;i<multipart.getCount();i++)collectContent(multipart.getBodyPart(i),text,files,depth+1,count);
        }
    }
    public static void send(MimeMessage m, String host, int port, String user, String password) throws Exception {
        send(m,host,port,user,password,false);
    }
    public static void send(MimeMessage m,String host,int port,String user,String credential,boolean oauth)throws Exception {
        Properties p = networkProperties("smtp",oauth);
        p.setProperty("mail.smtp.starttls.enable", "true"); p.setProperty("mail.smtp.starttls.required", "true");
        p.setProperty("mail.smtp.auth", "true");
        Session session = Session.getInstance(p);
        try (Transport t = session.getTransport("smtp")) { t.connect(host, port, user, credential); t.sendMessage(m, m.getAllRecipients()); }
    }
    public static MimeMessage fetchLatest(String host,int port,String user,String password)throws Exception {
        try(ImapInbox inbox=ImapInbox.connect(host,port,user,password,false)){
            var entries=inbox.latest();if(entries.isEmpty())throw new IOException("Inbox is empty");return inbox.message(entries.getFirst().uid());
        }
    }
    static Properties networkProperties(String protocol,boolean oauth) {
        Properties p = new Properties(); String prefix = "mail." + protocol + ".";
        p.setProperty(prefix + "ssl.checkserveridentity", "true");
        p.setProperty(prefix + "connectiontimeout", "15000"); p.setProperty(prefix + "timeout", "30000"); p.setProperty(prefix + "writetimeout", "30000");
        if(protocol.equals("imaps"))p.setProperty(prefix+"peek","true");
        if(oauth){
            p.setProperty(prefix+"auth.mechanisms","XOAUTH2");
            p.setProperty(prefix+"auth.xoauth2.disable","false");
            p.setProperty(prefix+"auth.login.disable","true");
            p.setProperty(prefix+"auth.plain.disable","true");
        }
        return p;
    }
}
