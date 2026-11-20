package dev.hybridmail;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.IOException;

/** Portable software identities only. No account settings, OAuth tokens, or local vault key. */
final class IdentityTransfer {
 static final int MAX_BYTES=1024*1024;
 static JsonObject metadata(byte[] bytes)throws Exception{
  if(bytes.length>MAX_BYTES)throw new IOException("Identity transfer exceeds 1 MiB");
  var j=JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();
  if(j.get("version").getAsInt()!=1||!"pq-mail-software-identity".equals(j.get("type").getAsString())||!PrfVault.RP.equals(j.get("rp").getAsString()))throw new IOException("Unsupported identity transfer");
  if(PrfVault.decode(j.get("id").getAsString()).length!=32||PrfVault.decode(j.get("salt").getAsString()).length!=32)throw new IOException("Invalid transfer metadata");
  int n=PrfVault.decode(j.get("credential").getAsString()).length;if(n<1||n>2048)throw new IOException("Invalid transfer credential");return j;
 }
 private static String context(JsonObject j){return "PQ Mail identity transfer v1|"+PrfVault.RP+"|"+j.get("id").getAsString()+"|"+j.get("credential").getAsString()+"|"+j.get("salt").getAsString();}
 static byte[] create(List<Identity> identities,String credential,byte[] salt,byte[] prf,Path temporaryDirectory)throws Exception{
  if(salt.length!=32||prf.length!=32)throw new IOException("Invalid PRF input");
  var j=new JsonObject();j.addProperty("version",1);j.addProperty("type","pq-mail-software-identity");j.addProperty("rp",PrfVault.RP);j.addProperty("id",PrfVault.b64(PrfVault.random(32)));j.addProperty("credential",credential);j.addProperty("salt",PrfVault.b64(salt));
  byte[] key=PrfVault.random(32),random=PrfVault.random(32),wrapping=PrfVault.derive(prf,context(j)+"|wrap"),p12=null,plain=null;
  char[] password=PrfVault.b64(random).toCharArray();Arrays.fill(random,(byte)0);Path temp=temporaryDirectory.resolve("transfer-"+UUID.randomUUID()+".p12");
  try{
   SoftwareIdentityVault.write(identities,temp,password);p12=Files.readAllBytes(temp);if(p12.length>MAX_BYTES/2)throw new IOException("Identity file too large");
   var payload=new JsonObject();payload.addProperty("password",new String(password));payload.addProperty("p12",PrfVault.b64(p12));plain=payload.toString().getBytes(StandardCharsets.UTF_8);
   j.add("wrapped",PrfVault.seal(wrapping,key,context(j)+"|wrap"));j.add("payload",PrfVault.seal(key,plain,context(j)+"|payload"));byte[] bytes=j.toString().getBytes(StandardCharsets.UTF_8);metadata(bytes);return bytes;
  }finally{Arrays.fill(key,(byte)0);Arrays.fill(wrapping,(byte)0);Arrays.fill(password,'\0');if(p12!=null)Arrays.fill(p12,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);Files.deleteIfExists(temp);}
 }
 static List<Identity> open(byte[] bytes,String credential,byte[] prf,Path temporaryDirectory)throws Exception{
  var j=metadata(bytes);if(!credential.equals(j.get("credential").getAsString()))throw new IOException("Wrong transfer passkey");
  byte[] wrapping=PrfVault.derive(prf,context(j)+"|wrap"),key=null,plain=null,p12=null;char[] password=null;Path temp=temporaryDirectory.resolve("transfer-import-"+UUID.randomUUID()+".p12");
  try{
   key=PrfVault.open(wrapping,j.getAsJsonObject("wrapped"),context(j)+"|wrap");if(key.length!=32)throw new IOException("Invalid transfer key");plain=PrfVault.open(key,j.getAsJsonObject("payload"),context(j)+"|payload");
   var payload=JsonParser.parseString(new String(plain,StandardCharsets.UTF_8)).getAsJsonObject();password=payload.get("password").getAsString().toCharArray();p12=PrfVault.decode(payload.get("p12").getAsString());
   Files.write(temp,p12,StandardOpenOption.CREATE_NEW);var identities=Identity.loadProfiles(temp,password);
   if(identities.isEmpty()||identities.size()>2||identities.stream().anyMatch(i->i.signingKey()==null||i.encryptionKey()==null))throw new IOException("Transfer must contain software signing and encryption keys");return identities;
  }finally{Arrays.fill(wrapping,(byte)0);if(key!=null)Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);if(p12!=null)Arrays.fill(p12,(byte)0);if(password!=null)Arrays.fill(password,'\0');Files.deleteIfExists(temp);}
 }
}
