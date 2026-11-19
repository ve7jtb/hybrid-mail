package dev.hybridmail;

import com.google.gson.*;
import jakarta.mail.internet.*;
import java.io.*;
import java.net.URI;
import javax.net.ssl.HttpsURLConnection;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Gmail REST transport: metadata-only inbox listing, raw MIME reads and sends. */
final class GmailApi implements MailInbox {
    static final class Unauthorized extends IOException {Unauthorized(){super("Google session expired or revoked. Connect Gmail again.");}}
    interface Credentials { char[] get() throws Exception; }
    record Response(int status, byte[] body) {}
    record Request(String path, String body, String token) {}
    interface Transport { Response send(Request request, int limit) throws Exception; }
    private static final String BASE="https://gmail.googleapis.com/gmail/v1/users/me/";
    private static final int JSON_LIMIT=(int)(MailEngine.MAX_MESSAGE*4/3+65536);
    private final Credentials credentials;
    private final Transport transport;
    private final Map<Long,String> ids=new HashMap<>();
    private long nextId;
    private String page="",nextPage="";
    private final Deque<String> earlierPages=new ArrayDeque<>();
    boolean hasOlder(){return !nextPage.isEmpty();}
    boolean hasNewer(){return !earlierPages.isEmpty();}
    synchronized List<ImapInbox.Entry> older()throws Exception{if(!hasOlder())return List.of();String old=page;var result=loadPage(nextPage);earlierPages.push(old);return result;}
    synchronized List<ImapInbox.Entry> newer()throws Exception{if(!hasNewer())return List.of();var result=loadPage(earlierPages.peek());earlierPages.pop();return result;}
    private boolean closed;
    private boolean smimeOnly;
    private String search="";
    synchronized void setSearch(String value){String next=value.trim();if(!search.equals(next)){search=next;earlierPages.clear();page="";nextPage="";ids.clear();}}
    int pageNumber(){return earlierPages.size()+1;}
    void setSmimeOnly(boolean value){smimeOnly=value;}
    static boolean isSmime(String value){try{var type=new ContentType(value);String base=type.getBaseType().toLowerCase(Locale.ROOT);String protocol=type.getParameter("protocol");return base.equals("application/pkcs7-mime")||base.equals("application/x-pkcs7-mime")||(base.equals("multipart/signed")&&protocol!=null&&(protocol.equalsIgnoreCase("application/pkcs7-signature")||protocol.equalsIgnoreCase("application/x-pkcs7-signature")));}catch(Exception e){return false;}}
    GmailApi(Credentials credentials){this(credentials,network());}
    GmailApi(Credentials credentials,Transport transport){this.credentials=credentials;this.transport=transport;}
    private static Transport network(){return (request,limit)->{
        var c=(HttpsURLConnection)URI.create(BASE+request.path()).toURL().openConnection();
        c.setInstanceFollowRedirects(false);c.setUseCaches(false);c.setConnectTimeout(15000);c.setReadTimeout(60000);
        c.setRequestProperty("Authorization","Bearer "+request.token());c.setRequestProperty("Accept","application/json");
        try{if(request.body()!=null){c.setRequestMethod("POST");c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");try(var out=c.getOutputStream()){out.write(request.body().getBytes(StandardCharsets.UTF_8));}}
            int status=c.getResponseCode();if(status!=200)return new Response(status,new byte[0]);
            try(var in=c.getInputStream();var out=new ByteArrayOutputStream()){byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1){if(out.size()+n>limit)throw new IOException("Gmail response exceeds size limit");out.write(buffer,0,n);}return new Response(status,out.toByteArray());}
        }finally{c.disconnect();}
    };}
    String accountEmail()throws Exception{return request("profile",null,65536).get("emailAddress").getAsString();}
    void verifyAccount(String email)throws Exception{
        if(!request("profile",null,65536).get("emailAddress").getAsString().equalsIgnoreCase(email))
            throw new IOException("Google authorized a different mailbox. Sign in again with the intended account.");
    }
    private JsonObject request(String path,JsonObject body,int limit)throws Exception{
        if(closed)throw new IOException("Gmail session closed. Connect again.");
        char[] token=credentials.get();Request request;
        try{request=new Request(path,body==null?null:body.toString(),new String(token));}finally{Arrays.fill(token,'\0');}
        Response response;
        try{response=transport.send(request,limit);}catch(Exception e){
            if(body!=null)throw new IOException("Gmail send was not confirmed. Check Sent mail before retrying to avoid duplicates.");
            throw new IOException("Could not contact Gmail. Check your connection and retry.");
        }
        if(response.status()==401)throw new Unauthorized();
        if(response.status()!=200){
            String detail=switch(response.status()){case 401->"Sign in with Google again.";case 403->"Check API enablement, test-user registration, and read/send consent.";case 404->"Message is no longer available; refresh the inbox.";case 429->"Rate limit reached; wait before trying again.";default->body==null?"Try again later.":"Check Sent mail before retrying.";};
            throw new IOException("Gmail API HTTP "+response.status()+". "+detail);
        }
        try{return JsonParser.parseString(new String(response.body(),StandardCharsets.UTF_8)).getAsJsonObject();}
        catch(RuntimeException e){throw new IOException(body==null?"Invalid Gmail response":"Gmail send response was invalid. Check Sent mail before retrying.");}
    }
    private static String safeId(String id)throws IOException{if(!id.matches("[A-Za-z0-9_-]{1,256}"))throw new IOException("Invalid Gmail message identifier");return id;}
    public synchronized List<ImapInbox.Entry> latest()throws Exception{
        var result=loadPage("");earlierPages.clear();return result;
    }
    private List<ImapInbox.Entry> loadPage(String cursor)throws Exception{
        String query="messages?labelIds=INBOX&maxResults=50"+(search.isEmpty()?"":"&q="+java.net.URLEncoder.encode(search,StandardCharsets.UTF_8))+(cursor.isEmpty()?"":"&pageToken="+java.net.URLEncoder.encode(cursor,StandardCharsets.UTF_8));
        var data=request(query,null,65536);var result=new ArrayList<ImapInbox.Entry>();var found=new HashMap<Long,String>();
        if(data.has("messages"))for(var item:data.getAsJsonArray("messages")){
            if(result.size()==50)break;String id=safeId(item.getAsJsonObject().get("id").getAsString());
            var metadata=request("messages/"+id+"?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Content-Type",null,65536);
            String from="(unknown sender)",subject="(no subject)",contentType="";
            if(metadata.has("payload")&&metadata.getAsJsonObject("payload").has("headers"))for(var h:metadata.getAsJsonObject("payload").getAsJsonArray("headers")){
                var header=h.getAsJsonObject();String name=header.get("name").getAsString(),value=header.get("value").getAsString();
                try{value=MimeUtility.decodeText(value);}catch(Exception ignored){}
                if(name.equalsIgnoreCase("Content-Type"))contentType=value;
                if(name.equalsIgnoreCase("From"))from=value;if(name.equalsIgnoreCase("Subject"))subject=value;
            }
            if(smimeOnly&&!isSmime(contentType))continue;
            long uid=ids.entrySet().stream().filter(e->e.getValue().equals(id)).map(Map.Entry::getKey).findFirst().orElseGet(()->++nextId);
            found.put(uid,id);result.add(new ImapInbox.Entry(uid,from,subject,Instant.ofEpochMilli(metadata.get("internalDate").getAsLong()),metadata.get("sizeEstimate").getAsLong()));
        }
        result.sort(Comparator.comparing(ImapInbox.Entry::received).reversed());ids.clear();ids.putAll(found);page=cursor;nextPage=data.has("nextPageToken")?data.get("nextPageToken").getAsString():"";return List.copyOf(result);
    }
    public synchronized MimeMessage message(long uid)throws Exception{
        String id=ids.get(uid);if(id==null)throw new IOException("Message is no longer listed. Refresh the inbox.");
        var data=request("messages/"+safeId(id)+"?format=raw",null,JSON_LIMIT);
        if(data.has("sizeEstimate")&&data.get("sizeEstimate").getAsLong()>MailEngine.MAX_MESSAGE)throw new IOException("Message exceeds 20 MiB limit");
        byte[] raw;try{raw=Base64.getUrlDecoder().decode(data.get("raw").getAsString());}catch(RuntimeException e){throw new IOException("Invalid Gmail MIME message");}
        if(raw.length>MailEngine.MAX_MESSAGE)throw new IOException("Message exceeds 20 MiB limit");return MailEngine.parse(raw);
    }
    synchronized void send(MimeMessage message)throws Exception{
        byte[] raw=MailEngine.encode(message);if(raw.length>MailEngine.MAX_MESSAGE)throw new IOException("Message exceeds 20 MiB limit");
        var data=new JsonObject();data.addProperty("raw",Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
        var result=request("messages/send",data,65536);
        if(!result.has("id"))throw new IOException("Gmail send was not confirmed. Check Sent mail before retrying.");
    }
    public synchronized void close(){closed=true;ids.clear();earlierPages.clear();page="";nextPage="";}
}
