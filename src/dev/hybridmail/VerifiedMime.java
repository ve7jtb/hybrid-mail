package dev.hybridmail;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.io.*;
import java.util.*;

/** Extracts display text only after the caller authenticates the original MIME bytes. */
final class VerifiedMime {
 private static final int LIMIT=8*1024*1024;
 private final int[] count={0};
 static String display(byte[] bytes)throws Exception {
  if(bytes.length>LIMIT)throw new IOException("Signed MIME exceeds reader limit");
  String text=new VerifiedMime().read(new MimeBodyPart(new ByteArrayInputStream(bytes)),0);
  return text==null?"No displayable text body. Attachments are not displayed.":text;
 }
 private String read(Part part,int depth)throws Exception {
  if(depth>12||++count[0]>100)throw new IOException("Signed MIME nesting/part limit exceeded");
  if(Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())||part.getFileName()!=null)return null;
  if(part.isMimeType("text/plain")||part.isMimeType("text/html")){
   Object content=part.getContent();if(!(content instanceof String s))throw new IOException("Invalid text MIME body");
   if(s.length()>LIMIT)throw new IOException("Text body exceeds reader limit");
   return part.isMimeType("text/html")?"[HTML shown as text; remote content is not loaded]\n"+html(s):s;
  }
  if(part.isMimeType("multipart/alternative")||part.isMimeType("multipart/mixed")||part.isMimeType("multipart/related")){
   Multipart m=(Multipart)part.getContent();if(m.getCount()>100)throw new IOException("Too many MIME parts");
   if(part.isMimeType("multipart/related")){
    String start=new ContentType(part.getContentType()).getParameter("start");
    if(start!=null){for(int i=0;i<m.getCount();i++){BodyPart b=m.getBodyPart(i);String[] ids=b.getHeader("Content-ID");if(ids!=null&&Arrays.asList(ids).contains(start))return read(b,depth+1);}throw new IOException("Missing related MIME root");}
    return m.getCount()==0?null:read(m.getBodyPart(0),depth+1);
   }
   String fallback=null;for(int i=0;i<m.getCount();i++){String s=read(m.getBodyPart(i),depth+1);if(s==null)continue;if(!part.isMimeType("multipart/alternative")||!s.startsWith("[HTML shown as text;"))return s;if(fallback==null)fallback=s;}return fallback;
  }
  return null;
 }
 static String html(String s){
  s=s.replaceAll("(?is)<!--.*?-->","").replaceAll("(?is)<(script|style|head)\\b[^>]*>.*?</\\1\\s*>","");
  s=s.replaceAll("(?i)<(?:br\\b[^>]*|/p\\s*|/div\\s*|/li\\s*|/tr\\s*|/h[1-6]\\s*)>","\n").replaceAll("(?s)<[^>]*>","");
  var matcher=java.util.regex.Pattern.compile("&#(x[0-9a-fA-F]+|[0-9]+);").matcher(s);StringBuilder out=new StringBuilder();while(matcher.find()){String n=matcher.group(1),r=matcher.group();try{int cp=Integer.parseInt(n.startsWith("x")?n.substring(1):n,n.startsWith("x")?16:10);if(Character.isValidCodePoint(cp)&&!(cp>=0xd800&&cp<=0xdfff))r=new String(Character.toChars(cp));}catch(Exception ignored){}matcher.appendReplacement(out,java.util.regex.Matcher.quoteReplacement(r));}matcher.appendTail(out);
  return out.toString().replace("&nbsp;"," ").replace("&lt;","<").replace("&gt;",">").replace("&quot;","\"").replace("&apos;","'").replace("&amp;","&").strip();
 }
}
