package dev.hybridmail;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;
/** Explicit read-only VKS lookup; no upload, automatic trust, or redirects. */
final class OpenPgpKeyserver {
 record Query(URL url,String email,String fingerprint){}
 static Query query(String input)throws Exception{
  String value=input.trim();String fp=value.replaceAll("\\s","").toUpperCase(Locale.ROOT);
  if(fp.matches("[0-9A-F]{40}|[0-9A-F]{64}"))return new Query(new URL("https://keys.openpgp.org/vks/v1/by-fingerprint/"+fp),null,fp);
  OpenPgp.validateEmail(value);return new Query(new URL("https://keys.openpgp.org/vks/v1/by-email/"+URLEncoder.encode(value,"UTF-8").replace("+","%20")),value,null);
 }
 static OpenPgp.PublicIdentity checked(Query query,byte[] data)throws Exception{
  OpenPgp.PublicIdentity key;
  try{key=new OpenPgp.PublicIdentity(data);}catch(Exception e){throw new IOException("Downloaded certificate is invalid or outside PQ Mail's supported OpenPGP profiles (RFC 9980 Level 3, experimental P-384 hybrid, v6 classical P-384, or supported v4 classical certificates). Nothing was selected.",e);}
  if(query.email()!=null&&!key.matchesEmail(query.email()))throw new IOException("Returned certificate email does not match the lookup");
  if(query.fingerprint()!=null&&!query.fingerprint().equalsIgnoreCase(key.fingerprint())&&!query.fingerprint().equalsIgnoreCase(OpenPgp.hex(OpenPgp.fingerprint(key.subkey))))throw new IOException("Returned certificate fingerprint does not match the lookup");
  return key;
 }
 static OpenPgp.PublicIdentity lookup(String input)throws Exception{
  Query query=query(input);var connection=(HttpsURLConnection)query.url().openConnection();connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(15000);connection.setReadTimeout(15000);connection.setRequestProperty("Accept","application/pgp-keys");
  try{
   int status=connection.getResponseCode();if(status==404)throw new IOException("No published key found. Email lookup requires the owner to verify and publish that address on keys.openpgp.org.");if(status==429)throw new IOException("Keyserver rate limit reached. Please wait before trying again.");if(status!=200)throw new IOException("Keyserver returned HTTP "+status);
   String type=connection.getContentType();if(type==null||!type.toLowerCase(Locale.ROOT).startsWith("application/pgp-keys"))throw new IOException("Unexpected keyserver response type");
   try(var in=connection.getInputStream();var out=new ByteArrayOutputStream()){byte[] buffer=new byte[4096];int count;while((count=in.read(buffer))!=-1){if(out.size()+count>128*1024)throw new IOException("Certificate exceeds 128 KiB limit");out.write(buffer,0,count);}return checked(query,out.toByteArray());}
  }finally{connection.disconnect();}
 }
}
