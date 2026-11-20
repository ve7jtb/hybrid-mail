package dev.hybridmail;

import java.io.*;
import java.util.*;
import jakarta.activation.DataHandler;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.*;

/** Transport-independent .pgp attachment. No OAuth, network, disk writes or
 * implicit trust. Google Chat and other file transports carry identical bytes. */
public final class ChatBundle {
    public static final int MAX_BYTES=MailEngine.MAX_MESSAGE;
    public static final int MAX_ATTACHMENT_BYTES=10*1024*1024;
    public static final String FILENAME="message.pgp";
    public static final String CONTENT_TYPE="application/octet-stream";
    private ChatBundle(){}
    private static void require(boolean condition,String message)throws IOException{if(!condition)throw new IOException(message);}

    /** Construct the complete signed payload, including From/To/Subject. MIME
     * encoding belongs inside the signature; transport captions are not trusted. */
    public static byte[] mime(String from,String to,String subject,String text,String html,List<MailEngine.Attachment> files)throws Exception{
        OpenPgp.validateEmail(from);OpenPgp.validateEmail(to);
        require(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid Chat subject");
        require(files.size()<=20,"At most 20 attachments per Chat bundle");
        MimeBodyPart body=new MimeBodyPart(new ByteArrayInputStream(MailEngine.messageBody(text,html)));
        if(!files.isEmpty()){
            MimeMultipart mixed=new MimeMultipart("mixed");mixed.addBodyPart(body);long total=0;
            for(var file:files){
                byte[] data=file.data();total+=data.length;require(total<=MAX_ATTACHMENT_BYTES,"Chat attachments exceed 10 MiB");
                MimeBodyPart part=new MimeBodyPart();part.setDataHandler(new DataHandler(new ByteArrayDataSource(data,"application/octet-stream")));
                part.setFileName(file.name());part.setDisposition(Part.ATTACHMENT);mixed.addBodyPart(part);
            }
            body=new MimeBodyPart();body.setContent(mixed);
        }
        MimeMessage message=new MimeMessage(MailEngine.session());
        message.setFrom(new InternetAddress(from,true));message.setRecipient(Message.RecipientType.TO,new InternetAddress(to,true));
        message.setSubject(subject,"UTF-8");message.setDataHandler(body.getDataHandler());message.saveChanges();
        return MailEngine.encode(message);
    }

    /** Only v6 hybrid signing is emitted. A recipient is optional for signed-only
     * bundles; encrypted Chat requires a usable hybrid v6 recipient certificate.
     * Trust/recipient selection remains an explicit caller policy, never inferred
     * from a self-signature or from Google's display name. */
    public static byte[] create(Identity id,OpenPgp.PublicIdentity own,OpenPgp.PublicIdentity recipient,
            String from,String to,String subject,String text,String html,List<MailEngine.Attachment> files,ExternalMu.Backend backend)throws Exception{
        OpenPgp.match(own,id);require(own.version()==6&&own.signing!=null&&own.signing.pq()!=null,"Chat requires a v6 hybrid signing identity");
        require(own.matchesEmail(from),"Chat sender does not match the signing certificate");
        if(recipient!=null){recipient=new OpenPgp.PublicIdentity(recipient.encoded);require(recipient.version()==6&&recipient.matchesEmail(to)&&recipient.canEncrypt()&&recipient.quantumEncryption(),"Chat recipient requires matching hybrid v6 encryption keys");}
        byte[] plain=mime(from,to,subject,text,html,files),signed;
        ExternalMu.Backend operation=backend==null?null:backend.newOperation();
        try{
            signed=id.softwareOpenPgp()!=null?id.softwareOpenPgp().signPackets(own,plain):OpenPgp.signed(plain,own,OpenPgp.signer(id,operation,own.signing));
            // Verify locally before emitting bytes; catches a wrong hardware key
            // and enforces current certificate signing flags/expiry/revocation.
            require(Arrays.equals(plain,OpenPgp.openSigned(signed,new OpenPgp.PublicIdentity(own.encoded))),"Chat signing verification failed");
        }finally{if(operation!=null)operation.clearSecrets();}
        require(signed.length<=MAX_BYTES,"Signed Chat bundle exceeds 20 MiB");
        int compression=compression(recipient);
        byte[] compressed=compression==0?signed:compress(signed,compression);
        byte[] result=recipient==null?compressed:OpenPgp.encrypt(compressed,recipient);
        require(result.length<=MAX_BYTES,"Encoded Chat bundle exceeds 20 MiB");return result;
    }
    /** Respect the recipient's advertised compression preferences. With no
     * preference, ZIP is the interoperable OpenPGP default (raw DEFLATE, not a
     * .zip archive). Existing no-compression-only certificates remain usable
     * without silently overriding the recipient policy or reissuing certificates. */
    private static int compression(OpenPgp.PublicIdentity recipient)throws Exception{
        if(recipient!=null&&recipient.v6!=null){
            int[] preferred=recipient.v6.primaryPolicy.getHashedSubPackets().getPreferredCompressionAlgorithms();
            if(preferred!=null&&preferred.length>0){for(int algorithm:preferred)if(algorithm==0||algorithm==1||algorithm==2)return algorithm;throw new IOException("Recipient does not advertise supported Chat compression (ZIP/ZLIB)");}
        }
        return CompressionAlgorithmTags.ZIP;
    }
    static byte[] compress(byte[] packets,int algorithm)throws Exception{
        var out=new ByteArrayOutputStream();var generator=new PGPCompressedDataGenerator(algorithm);
        // A buffer selects current-format, bounded partial lengths. The no-buffer
        // overload emits legacy indeterminate framing and can hide appended data.
        try(var compressed=generator.open(out,new byte[65536])){compressed.write(packets);}return out.toByteArray();
    }
    /** Bound every decompression level and reject appended packets. This also
     * supports standard uncompressed signed messages received from other tools. */
    static byte[] expand(byte[] packets)throws Exception{
        require(packets.length<=MAX_BYTES,"Chat bundle exceeds 20 MiB");
        for(int depth=0;;depth++){
            var factory=LegacyOpenPgp.objects(packets);Object first=factory.nextObject();
            if(!(first instanceof PGPCompressedData compressed))return packets;
            require(depth<3,"Chat compression nesting limit exceeded");
            byte[] expanded=LegacyOpenPgp.bounded(compressed.getDataStream());
            require(factory.nextObject()==null,"Trailing data after compressed Chat bundle");packets=expanded;
        }
    }
    public record Opened(String from,String to,String subject,String text,String html,List<MailEngine.Attachment> attachments,
                         String signerFingerprint,boolean encrypted,boolean postQuantum,byte[] mime){
        public Opened{attachments=List.copyOf(attachments);mime=mime.clone();}
        @Override public byte[] mime(){return mime.clone();}
    }
    /** Authenticate before parsing or exposing any MIME content. The caller
     * independently checks trust and the Chat sender/account binding. HTML is
     * untrusted markup even when signed and must use the safe HTML renderer. */
    public static Opened open(byte[] input,OpenPgp.PublicIdentity signer,OpenPgp.PublicIdentity own,Identity id,ExternalKem.Backend backend)throws Exception{
        require(input.length<=MAX_BYTES,"Chat bundle exceeds 20 MiB");require(signer!=null,"Select the sender's certificate");
        signer=new OpenPgp.PublicIdentity(signer.encoded);
        // PGPUtil accepts binary .pgp and standard ASCII armor. No MIME wrapper
        // or proprietary archive is needed to reach the OpenPGP packet stream.
        byte[] encoded=LegacyOpenPgp.bounded(PGPUtil.getDecoderStream(new ByteArrayInputStream(input)));
        Object first=LegacyOpenPgp.objects(encoded).nextObject();boolean encrypted=first instanceof PGPEncryptedDataList;
        byte[] signed=encoded;
        if(encrypted){
            require(own!=null&&id!=null,"Select the recipient decryption identity");OpenPgp.match(own,id);
            if(id.softwareOpenPgp()!=null)signed=id.softwareOpenPgp().decrypt(encoded);
            else{var envelope=OpenPgp.envelope(encoded,own);byte[] kek=OpenPgp.recover(envelope.ct(),id,backend,own);try{signed=envelope.open(kek);}finally{OpenPgp.wipe(kek);}}
        }
        boolean[] pq={false};byte[] plain=OpenPgp.openSigned(expand(signed),signer,pq);
        MimeMessage message=MailEngine.parse(plain);
        require(message.getHeader("From")!=null&&message.getHeader("From").length==1,"Expected one signed From header");
        Address[] from=message.getFrom(),to=message.getRecipients(Message.RecipientType.TO);
        require(from!=null&&from.length==1&&from[0] instanceof InternetAddress,"Expected one Chat sender");
        require(to!=null&&to.length==1&&to[0] instanceof InternetAddress,"Expected one Chat recipient");
        String sender=((InternetAddress)from[0]).getAddress(),receiver=((InternetAddress)to[0]).getAddress();
        OpenPgp.validateEmail(sender);OpenPgp.validateEmail(receiver);require(signer.matchesEmail(sender),"Signed sender email does not match the verified certificate");
        if(encrypted)require(own.matchesEmail(receiver),"Signed recipient email does not match the decryption identity");
        // Use the existing bounded MIME walker on a Part to retain the full
        // 20 MiB envelope limit without its smaller byte-array reader limit.
        var body=VerifiedMime.body(message);var attachments=new ArrayList<MailEngine.Attachment>();
        collect(message,attachments,0,new int[]{0},new long[]{0});
        return new Opened(sender,receiver,message.getSubject(),body.text(),body.html(),attachments,signer.fingerprint(),encrypted,pq[0],plain);
    }
    private static void collect(Part part,List<MailEngine.Attachment> files,int depth,int[] count,long[] total)throws Exception{
        require(depth<=12&&++count[0]<=100,"Chat MIME nesting/part limit exceeded");
        if(Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())||part.getFileName()!=null){
            require(files.size()<20,"Too many Chat attachments");
            byte[] bytes;try(var in=part.getInputStream()){bytes=in.readNBytes((int)(MAX_ATTACHMENT_BYTES-total[0])+1);}
            total[0]+=bytes.length;require(total[0]<=MAX_ATTACHMENT_BYTES,"Chat attachments exceed 10 MiB");
            files.add(new MailEngine.Attachment(part.getFileName(),bytes));return;
        }
        if(part.isMimeType("multipart/*")){var multi=(Multipart)part.getContent();require(multi.getCount()<=100,"Too many MIME parts");for(int i=0;i<multi.getCount();i++)collect(multi.getBodyPart(i),files,depth+1,count,total);}
    }
}
