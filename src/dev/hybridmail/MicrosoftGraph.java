package dev.hybridmail;
import com.google.gson.*;
import jakarta.mail.internet.MimeMessage;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
/** Personal Outlook mailbox; raw MIME read/send, metadata pages held only in memory. */
final class MicrosoftGraph implements MailInbox {
 interface Credentials{char[] get()throws Exception;}
 record Response(int status,byte[] body){}
 interface Transport{Response send(HttpRequest request,int limit)throws Exception;}
 static final String BASE="https://graph.microsoft.com/v1.0/";
 private static final String FIRST=BASE+"me/mailFolders/inbox/messages?$top=50&$select=id,subject,from,receivedDateTime&$orderby=receivedDateTime%20desc";
 private final Credentials credentials;private final Transport transport;
 private final Map<Long,String> ids=new HashMap<>();private long nextId;private boolean closed;
 private String page=FIRST,next="";private final Deque<String> previous=new ArrayDeque<>();
 MicrosoftGraph(Credentials credentials){this(credentials,network());}
 MicrosoftGraph(Credentials credentials,Transport transport){this.credentials=credentials;this.transport=transport;}
 private static Transport network(){var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();return (request,limit)->{var r=client.send(request,HttpResponse.BodyHandlers.ofInputStream());try(var in=r.body()){byte[] b=in.readNBytes(limit+1);if(b.length>limit)throw new IOException("Microsoft response exceeds size limit");return new Response(r.statusCode(),b);}};}
 static URI safeUri(String address)throws IOException {
  try{URI u=URI.create(address);if(!"https".equals(u.getScheme())||!"graph.microsoft.com".equals(u.getHost())||u.getPort()!=-1||u.getUserInfo()!=null||u.getFragment()!=null||!u.getPath().startsWith("/v1.0/me/")||u.getPath().contains(".."))throw new IOException("Invalid Microsoft Graph URL");return u;}catch(IllegalArgumentException e){throw new IOException("Invalid Microsoft Graph URL");}
 }
 private byte[] request(String url,byte[] body,int limit)throws Exception {
  if(closed)throw new IOException("Microsoft session is closed");URI uri=safeUri(url);char[] token=credentials.get();HttpRequest request;
  try{var b=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).header("Authorization","Bearer "+new String(token));
   if(body!=null)b.header("Content-Type","text/plain").POST(HttpRequest.BodyPublishers.ofByteArray(body));
   request=b.build();}finally{Arrays.fill(token,'\0');}
  Response result;try{result=transport.send(request,limit);}catch(Exception e){throw new IOException(body==null?"Cannot contact Microsoft Graph. Check your connection.":"Microsoft send was not confirmed. Check Sent mail before retrying to avoid duplicates.");}
  int expected=body==null?200:202;
  if(result.status()!=expected)throw new IOException("Microsoft Graph HTTP "+result.status()+". "+(body!=null?"Check Sent mail before retrying.":result.status()==401?"Sign in with Microsoft again.":"Check consent and mailbox access, then retry."));
  if(result.body().length>limit)throw new IOException("Microsoft response exceeds size limit");return result.body();
 }
 private JsonObject json(String url,int limit)throws Exception{try{return JsonParser.parseString(new String(request(url,null,limit),StandardCharsets.UTF_8)).getAsJsonObject();}catch(JsonParseException|IllegalStateException e){throw new IOException("Invalid Microsoft response");}}
 String account()throws Exception {
  var j=json(BASE+"me/?$select=mail,userPrincipalName",65536);
  String address=j.has("mail")&&!j.get("mail").isJsonNull()?j.get("mail").getAsString():j.get("userPrincipalName").getAsString();
  new jakarta.mail.internet.InternetAddress(address,true).validate();return address;
 }
 void verifyAccount(String email)throws Exception{if(!account().equalsIgnoreCase(email))throw new IOException("Microsoft authorized a different mailbox. Sign in again.");}
 boolean hasOlder(){return !next.isEmpty();}boolean hasNewer(){return !previous.isEmpty();}
 public synchronized List<ImapInbox.Entry> latest()throws Exception{var r=load(FIRST);previous.clear();return r;}
 synchronized List<ImapInbox.Entry> older()throws Exception{if(!hasOlder())return List.of();String old=page;var r=load(next);previous.push(old);return r;}
 synchronized List<ImapInbox.Entry> newer()throws Exception{if(!hasNewer())return List.of();var r=load(previous.peek());previous.pop();return r;}
 private List<ImapInbox.Entry> load(String url)throws Exception {
  var j=json(url,1024*1024);var entries=new ArrayList<ImapInbox.Entry>();var found=new HashMap<Long,String>();
  String newNext=j.has("@odata.nextLink")?j.get("@odata.nextLink").getAsString():"";if(!newNext.isEmpty())safeUri(newNext);
  for(var value:j.getAsJsonArray("value")){
   if(entries.size()>=50)throw new IOException("Unexpected Microsoft page size");var m=value.getAsJsonObject();String id=m.get("id").getAsString();
   if(id.isBlank()||id.length()>2048)throw new IOException("Invalid Microsoft message ID");
   String from="(unknown sender)";if(m.has("from")&&!m.get("from").isJsonNull())from=m.getAsJsonObject("from").getAsJsonObject("emailAddress").get("address").getAsString();
   String subject=m.has("subject")&&!m.get("subject").isJsonNull()?m.get("subject").getAsString():"(no subject)";
   long uid=++nextId;found.put(uid,id);entries.add(new ImapInbox.Entry(uid,from,subject,Instant.parse(m.get("receivedDateTime").getAsString()),0));
  }
  ids.clear();ids.putAll(found);page=url;next=newNext;return List.copyOf(entries);
 }
 public synchronized MimeMessage message(long uid)throws Exception {
  String id=ids.get(uid);if(id==null)throw new IOException("Refresh the inbox; message is no longer listed");
  String encoded=URLEncoder.encode(id,StandardCharsets.UTF_8).replace("+","%20");
  return MailEngine.parse(request(BASE+"me/messages/"+encoded+"/$value",null,(int)MailEngine.MAX_MESSAGE));
 }
 synchronized void send(MimeMessage message)throws Exception{
  byte[] raw=MailEngine.encode(message);if(raw.length>MailEngine.MAX_MESSAGE)throw new IOException("Message exceeds 20 MiB limit");
  request(BASE+"me/sendMail",Base64.getEncoder().encode(raw),65536);
 }
 public synchronized void close(){closed=true;ids.clear();previous.clear();next="";}
}
