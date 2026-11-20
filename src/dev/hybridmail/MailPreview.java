package dev.hybridmail;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.io.*;
/** Text-only preview. Never interprets HTML, fetches images, or downgrades S/MIME failures. */
public final class MailPreview {
    public static boolean isOrdinary(Part part)throws Exception{
        return part.isMimeType("text/plain")||part.isMimeType("text/html")||part.isMimeType("multipart/mixed")||part.isMimeType("multipart/alternative")||part.isMimeType("multipart/related");
    }
    public static String display(MimeMessage message)throws Exception{
        String text=plain(message,0);
        return "UNSIGNED MESSAGE · identity and content are not verified\nNot decrypted or authenticated by this app\n\nFrom (unverified): "+java.util.Arrays.toString(message.getFrom())+"\nSubject (unverified): "+message.getSubject()+"\n\n"+(text==null?"No plain-text body available. HTML and attachments are not displayed.":text);
    }
    static String security(MimeMessage message)throws Exception{
        return "UNSIGNED MESSAGE · identity and content are not verified\nNot decrypted or authenticated by this app\n\nFrom (unverified): "+header(java.util.Arrays.toString(message.getFrom()))+"\nSubject (unverified): "+header(message.getSubject());
    }
    static String header(String value){if(value==null)return "";String clean=value.replaceAll("[\\p{Cntrl}\\u202a-\\u202e\\u2066-\\u2069]"," ");return clean.length()>1000?clean.substring(0,1000)+"…":clean;}
    private static String plain(Part part,int depth)throws Exception{
        if(depth>12)throw new IOException("Message nesting exceeds reader limit");
        if(Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition()))return null;
        if(part.isMimeType("text/plain"))return (String)part.getContent();
        if(part.isMimeType("multipart/mixed")||part.isMimeType("multipart/alternative")||part.isMimeType("multipart/related")){
            Multipart multipart=(Multipart)part.getContent();for(int i=0;i<Math.min(multipart.getCount(),100);i++){String text=plain(multipart.getBodyPart(i),depth+1);if(text!=null)return text;}
        }
        return null;
    }
}
