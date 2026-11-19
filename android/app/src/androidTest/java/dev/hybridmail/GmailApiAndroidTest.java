package dev.hybridmail;
import com.google.gson.*;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
public final class GmailApiAndroidTest {
 static void check(boolean ok,String name){if(!ok)throw new AssertionError(name);System.out.println("PASS "+name);}
 interface Action {void run()throws Exception;}
 static void reject(Action a,String name)throws Exception{try{a.run();}catch(java.io.IOException expected){System.out.println("PASS "+name);return;}throw new AssertionError(name);}
 static GmailApi.Response json(String text){return new GmailApi.Response(200,text.getBytes(StandardCharsets.UTF_8));}
 @org.junit.Test public void gmailTransport()throws Exception{
  check(GmailApi.isSmime("application/pkcs7-mime; smime-type=enveloped-data")&&GmailApi.isSmime("multipart/signed; protocol=\"application/pkcs7-signature\"")&&!GmailApi.isSmime("multipart/signed; protocol=\"application/pgp-signature\"")&&!GmailApi.isSmime("text/plain"),"MIME filter recognizes S/MIME, excludes PGP and plain mail");
  java.security.Security.removeProvider("BC");java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();var calls=new ArrayList<GmailApi.Request>();byte[][] wire={null};boolean[] second={false};var secrets=new ArrayList<char[]>();
  GmailApi.Transport transport=(req,limit)->{
   calls.add(req);
   check(req.token().equals("test-access"),"bearer header");
   String[] parts=req.path().split("\\?",2);String p="/"+parts[0],q=parts.length==2?parts[1]:"";
   if(p.endsWith("/profile"))return json("{\"emailAddress\":\"a@example.test\"}");
   if(p.endsWith("/messages/send")){wire[0]=Base64.getUrlDecoder().decode(JsonParser.parseString(req.body()).getAsJsonObject().get("raw").getAsString());return json("{\"id\":\"sent\"}");}
   if(p.endsWith("/messages")){check(q.contains("labelIds=INBOX")&&q.contains("maxResults=50"),"paged inbox only");second[0]=q.contains("pageToken=");return json(second[0]?"{\"messages\":[{\"id\":\"older\"}]}":"{\"messages\":[{\"id\":\"new\"}],\"nextPageToken\":\"cursor/+\"}");}
   if(q.equals("format=raw"))return json("{\"raw\":\""+Base64.getUrlEncoder().withoutPadding().encodeToString(wire[0])+"\"}");
   check(q.contains("format=metadata")&&!q.contains("format=full"),"headers only until opened");
   return json("{\"internalDate\":\"1000\",\"sizeEstimate\":100,\"payload\":{\"headers\":[{\"name\":\"Subject\",\"value\":\"=?UTF-8?B?Y2Fmw6k=?=\"}]}}");
  };
  try(var api=new GmailApi(()->{var v="test-access".toCharArray();secrets.add(v);return v;},transport)){
   api.verifyAccount("a@example.test");reject(()->api.verifyAccount("wrong@example.test"),"wrong Google account rejected");
   api.setSmimeOnly(true);check(api.latest().isEmpty()&&api.hasOlder(),"filtered empty page preserves navigation without body downloads");api.setSmimeOnly(false);var first=api.latest();long uid=first.get(0).uid();check(first.get(0).subject().equals("café")&&api.hasOlder()&&!api.hasNewer(),"decoded headers and first-page controls");
   api.older();check(!api.hasOlder()&&api.hasNewer(),"older page controls");reject(()->api.message(uid),"previous page no longer retained");
   var back=api.newer();check(api.hasOlder()&&!api.hasNewer(),"return to newer page");
   api.setSearch("from:a@example.test subject:hello");api.latest();check(!api.hasNewer()&&api.pageNumber()==1,"search resets cursor");check(calls.stream().anyMatch(r->r.path().contains("q=from%3Aa%40example.test+subject%3Ahello")),"server search encoded");back=api.latest();
   for(var profile:TokenProfile.values())for(var id:Identity.generateSoftwareProfile("a@example.test",profile,List.of()))for(boolean encrypt:new boolean[]{false,true}){
    var m=MailEngine.compose(id,"a@example.test","a@example.test","API","MIME preserved café",encrypt?id.encryptionCert():null,null);
    byte[] original=MailEngine.encode(m);api.send(m);check(Arrays.equals(original,wire[0]),"raw MIME bytes preserved on send");
    var opened=MailEngine.open(api.message(back.get(0).uid()),id,id.signingCert());check(opened.pinned()&&opened.encrypted()==encrypt&&opened.text().equals("MIME preserved café"),"Gmail MIME pure/hybrid S/MIME "+profile+" encrypted="+encrypt);
   }
   check(calls.stream().allMatch(r->r.body()==null||r.path().equals("messages/send")),"no modify/delete API operations");
   check(secrets.stream().allMatch(a->{for(char c:a)if(c!=0)return false;return true;}),"temporary token copies cleared");
  }
  for(int status:new int[]{401,403,404,429,500})try(var api=new GmailApi(()->"test".toCharArray(),(r,l)->new GmailApi.Response(status,"private error content".getBytes()))){reject(api::latest,"HTTP "+status+" handled");}
  var scopes=MainActivity.class.getDeclaredField("GOOGLE_SCOPES");scopes.setAccessible(true);
  check(new HashSet<>((List<String>)scopes.get(null)).equals(Set.of("https://www.googleapis.com/auth/gmail.readonly","https://www.googleapis.com/auth/gmail.send")),"only read and send scopes");
 }
}
