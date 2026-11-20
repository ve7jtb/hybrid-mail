package dev.hybridmail;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/** Small, bounded Google Chat transport. No disk cache, redirects or automatic
 * POST retries. Access tokens only go to the two fixed Google API origins. */
final class GoogleChatApi {
    interface Credential {char[] get()throws Exception;}
    interface Wire {byte[] send(String method,URI uri,String type,byte[] body,char[] token,int limit)throws Exception;}
    private final Credential credential;private final Wire wire;
    GoogleChatApi(Credential credential){this(credential,GoogleChatApi::network);}
    GoogleChatApi(Credential credential,Wire wire){this.credential=credential;this.wire=wire;}
    record Page<T>(List<T> items,String next){Page{items=List.copyOf(items);}}
    record Space(String name,String display,String type){public String toString(){return display+" · "+type+" · "+name;}}
    record Attachment(String filename,String resource){}
    record Message(String name,String sender,String display,String time,String text,List<Attachment> attachments){
        Message{attachments=List.copyOf(attachments);}public String toString(){return time+" · "+display+" · "+(attachments.isEmpty()?text:"Attachments: "+attachments.size());}
    }
    record Account(String email,String user){}
    static String str(JsonObject j,String k){return j.has(k)&&!j.get(k).isJsonNull()?j.get(k).getAsString():"";}
    static String segment(String s){return URLEncoder.encode(s,StandardCharsets.UTF_8).replace("+","%20");}
    static String space(String name)throws IOException{if(!name.matches("spaces/[A-Za-z0-9_-]+"))throw new IOException("Invalid Chat space identifier");return name;}
    private byte[] request(String method,URI uri,String type,byte[] body,int limit)throws Exception{
        char[] token=credential.get();try{return wire.send(method,uri,type,body,token,limit);}finally{Arrays.fill(token,'\0');}
    }
    private JsonObject json(String method,String path,String type,byte[] body)throws Exception{
        byte[] bytes=request(method,URI.create("https://chat.googleapis.com"+path),type,body,2*1024*1024);
        try{return JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();}catch(RuntimeException e){throw new IOException("Invalid Google Chat response");}
    }
    Account account()throws Exception{
        byte[] bytes=request("GET",URI.create("https://www.googleapis.com/oauth2/v2/userinfo"),null,null,65536);
        JsonObject j=JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();
        if(!j.has("verified_email")||!j.get("verified_email").getAsBoolean()||!str(j,"id").matches("[0-9]+"))throw new IOException("Google did not return a verified account email");
        return new Account(GoogleChatVault.email(str(j,"email")),"users/"+str(j,"id"));
    }
    Page<Space> spaces(String page)throws Exception{
        var j=json("GET","/v1/spaces?pageSize=50&pageToken="+segment(page),null,null);var items=new ArrayList<Space>();
        if(j.has("spaces"))for(var item:j.getAsJsonArray("spaces")){var o=item.getAsJsonObject();String name=space(str(o,"name"));String title=str(o,"displayName");items.add(new Space(name,title.isEmpty()?name:title,str(o,"spaceType")));}
        return new Page<>(items,str(j,"nextPageToken"));
    }
    Page<Message> messages(String space,String page)throws Exception{
        var j=json("GET","/v1/"+space(space)+"/messages?pageSize=25&orderBy=createTime%20desc&pageToken="+segment(page),null,null);var items=new ArrayList<Message>();
        if(j.has("messages"))for(var item:j.getAsJsonArray("messages"))items.add(message(item.getAsJsonObject()));return new Page<>(items,str(j,"nextPageToken"));
    }
    static Message message(JsonObject j)throws IOException{
        var sender=j.has("sender")?j.getAsJsonObject("sender"):new JsonObject();var files=new ArrayList<Attachment>();
        if(j.has("attachment"))for(var a:j.getAsJsonArray("attachment")){var f=a.getAsJsonObject();if(f.has("attachmentDataRef"))files.add(new Attachment(str(f,"contentName"),str(f.getAsJsonObject("attachmentDataRef"),"resourceName")));}
        return new Message(str(j,"name"),str(sender,"name"),str(sender,"displayName"),str(j,"createTime"),str(j,"text"),files);
    }
    byte[] download(Attachment attachment,int limit)throws Exception{
        // Never use downloadUri: an untrusted URI must not receive OAuth tokens.
        String resource=attachment.resource();if(resource.isBlank()||resource.length()>4096||Arrays.asList(resource.split("/",-1)).stream().anyMatch(p->p.equals("..")||p.equals(".")))throw new IOException("Invalid attachment reference");
        String path=Arrays.stream(resource.split("/",-1)).map(GoogleChatApi::segment).collect(java.util.stream.Collectors.joining("/"));
        return request("GET",URI.create("https://chat.googleapis.com/v1/media/"+path+"?alt=media"),null,null,limit);
    }
    JsonObject upload(String target,String filename,byte[] bytes)throws Exception{
        if(bytes.length>ChatBundle.MAX_BYTES)throw new IOException("Chat attachment exceeds 20 MiB");
        String boundary="pqmail_"+UUID.randomUUID().toString().replace("-","");JsonObject meta=new JsonObject();meta.addProperty("filename",filename);
        var out=new ByteArrayOutputStream();out.write(("--"+boundary+"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"+meta+"\r\n--"+boundary+"\r\nContent-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8));out.write(bytes);out.write(("\r\n--"+boundary+"--\r\n").getBytes(StandardCharsets.US_ASCII));
        var result=json("POST","/upload/v1/"+space(target)+"/attachments:upload?uploadType=multipart","multipart/related; boundary="+boundary,out.toByteArray());
        if(!result.has("attachmentDataRef"))throw new IOException("Google did not return an uploaded attachment reference");JsonObject ref=new JsonObject();ref.add("attachmentDataRef",result.getAsJsonObject("attachmentDataRef").deepCopy());return ref;
    }
    private Message create(String target,String text,JsonObject attachment)throws Exception{
        JsonObject body=new JsonObject();body.addProperty("text",text);JsonArray files=new JsonArray();files.add(attachment);body.add("attachment",files);
        return message(json("POST","/v1/"+space(target)+"/messages?requestId="+UUID.randomUUID(),"application/json",body.toString().getBytes(StandardCharsets.UTF_8)));
    }
    Message send(String target,byte[] bundle,byte[] certificate)throws Exception{
        // Google accepts only one non-media attachment per message. Keep the
        // standard .pgp intact, and link a separate public certificate message.
        var encrypted=upload(target,ChatBundle.FILENAME,bundle);
        var publicKey=upload(target,"pq-mail-sender-key.pgp",certificate);
        var cert=create(target,"PQ Mail public OpenPGP certificate. Verify its fingerprint independently.",publicKey);
        if(!cert.name().matches(java.util.regex.Pattern.quote(space(target))+"/messages/[A-Za-z0-9_.-]+"))throw new IOException("Invalid certificate message reference");
        try{return create(target,"PQ Mail signed OpenPGP bundle.\nCertificate message: "+cert.name(),encrypted);}
        catch(Exception e){throw new IOException("The public certificate was posted as "+cert.name()+". Bundle delivery failed or is uncertain; check the conversation before retrying.",e);}
    }
    List<Attachment> senderCertificates(Message bundle)throws Exception{
        var direct=bundle.attachments().stream().filter(a->a.filename().equals("pq-mail-sender-key.pgp")).toList();
        if(!direct.isEmpty())return direct;
        // Google can flatten caption line breaks; parse the marker independently of lines.
        var links=java.util.regex.Pattern.compile("(?<!\\S)Certificate message:\\s*(\\S+)").matcher(bundle.text()).results().map(m->m.group(1)).toList();
        if(links.size()!=1)throw new IOException("Expected one linked certificate message");
        String parent=bundle.name().split("/messages/",2)[0],name=links.getFirst();
        if(!name.matches(java.util.regex.Pattern.quote(space(parent))+"/messages/[A-Za-z0-9_.-]+")||name.equals(bundle.name()))throw new IOException("Certificate reference must stay in this conversation");
        var cert=message(json("GET","/v1/"+name,null,null));
        if(bundle.sender().isBlank()||!bundle.sender().equals(cert.sender()))throw new IOException("Linked certificate sender differs");
        return cert.attachments().stream().filter(a->a.filename().equals("pq-mail-sender-key.pgp")).toList();
    }
    static byte[] network(String method,URI uri,String type,byte[] body,char[] token,int limit)throws Exception{
        if(!uri.getScheme().equals("https")||!Set.of("chat.googleapis.com","www.googleapis.com").contains(uri.getHost())||uri.getUserInfo()!=null||uri.getPort()!=-1)throw new IOException("Blocked unexpected Google API destination");
        var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();
        var builder=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).header("Authorization","Bearer "+new String(token));if(type!=null)builder.header("Content-Type",type);
        var response=client.send(builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofByteArray(body)).build(),HttpResponse.BodyHandlers.ofInputStream());
        try(var in=response.body()){
            if(response.statusCode()<200||response.statusCode()>=300)throw new IOException("Google Chat request failed (HTTP "+response.statusCode()+"). Check consent, account eligibility and connection. Sends are not retried automatically; check the conversation before retrying.");
            byte[] bytes=in.readNBytes(limit+1);if(bytes.length>limit)throw new IOException("Google response exceeds size limit");return bytes;
        }
    }
}
