package dev.hybridmail;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

/** Synthetic transport and OAuth tests: no Google account, hardware, or mail. */
public final class GoogleChatTransportTest {
    static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
    interface Task{void run()throws Exception;}
    static void reject(Task task)throws Exception{try{task.run();throw new AssertionError("Unexpected success");}catch(AssertionError e){throw e;}catch(Exception expected){}}
    static byte[] json(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static GoogleOAuth.Token token()throws Exception{return GoogleOAuth.token("{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-refresh\",\"expires_in\":3600,\"token_type\":\"Bearer\",\"scope\":\""+String.join(" ",GoogleChatSession.SCOPES)+"\"}",GoogleChatSession.SCOPES,true);}
    public static void main(String[] args)throws Exception{
        var calls=new ArrayList<String>();var credentials=new ArrayList<char[]>();var bodies=new ArrayList<byte[]>();
        var api=new GoogleChatApi(()->"synthetic-access".toCharArray(),(method,uri,type,body,credential,limit)->{
            credentials.add(credential);calls.add(method+" "+uri);bodies.add(body);
            if(uri.getPath().equals("/oauth2/v2/userinfo"))return json("{\"email\":\"chat@example.test\",\"id\":\"12345\",\"verified_email\":true}");
            if(uri.getPath().equals("/v1/spaces"))return json("{\"spaces\":[{\"name\":\"spaces/abc\",\"displayName\":\"Test\",\"spaceType\":\"SPACE\"}],\"nextPageToken\":\"next/+?\"}");
            if(uri.getPath().endsWith("attachments:upload")){check(type.startsWith("multipart/related; boundary="),"Upload encoding");check(new String(body,StandardCharsets.ISO_8859_1).contains("Content-Type: application/json"),"Missing filename metadata");return json("{\"attachmentDataRef\":{\"attachmentUploadToken\":\"opaque-upload\"}}");}
            if(method.equals("POST")){var message=JsonParser.parseString(new String(body,StandardCharsets.UTF_8)).getAsJsonObject();check(message.getAsJsonArray("attachment").size()==1,"One non-media attachment per message required");check(!message.toString().contains("secret-body"),"Plaintext in caption");return json("{\"name\":\"spaces/abc/messages/one\"}");}
            if(uri.getPath().contains("/media/"))return new byte[]{0,1,2,3};
            return json("{\"messages\":[{\"name\":\"spaces/abc/messages/one\",\"sender\":{\"name\":\"users/12345\",\"displayName\":\"Name\"},\"attachment\":[{\"contentName\":\"message.pgp\",\"attachmentDataRef\":{\"resourceName\":\"opaque/ref\"}},{\"contentName\":\"drive\",\"driveDataRef\":{\"driveFileId\":\"ignored\"}}]}]}");
        });
        check(api.account().user().equals("users/12345"),"Account ID");var spaces=api.spaces("");check(spaces.items().size()==1,"Spaces");api.spaces(spaces.next());check(calls.getLast().contains("next%2F%2B%3F"),"Page token not escaped");
        var messages=api.messages("spaces/abc","");check(messages.items().getFirst().attachments().size()==1,"Drive file followed");check(api.download(messages.items().getFirst().attachments().getFirst(),10).length==4,"Download");
        api.send("spaces/abc",new byte[]{4,5},new byte[]{6,7});check(calls.getLast().contains("requestId="),"Missing request deduplication ID");
        check(calls.stream().filter(v->v.startsWith("POST ")&&v.contains("/messages?")).count()==2,"Expected two linked posts");
        reject(()->api.senderCertificates(new GoogleChatApi.Message("spaces/abc/messages/b","users/12345","","","Certificate message: spaces/other/messages/c",List.of())));
        var linkedApi=new GoogleChatApi(()->"synthetic-access".toCharArray(),(method,uri,type,body,c,limit)->json("{\"name\":\"spaces/abc/messages/cert\",\"sender\":{\"name\":\"users/12345\"},\"attachment\":[{\"contentName\":\"pq-mail-sender-key.pgp\",\"attachmentDataRef\":{\"resourceName\":\"opaque/ref\"}}]}"));
        var flattened=new GoogleChatApi.Message("spaces/abc/messages/b","users/12345","","","PQ Mail signed OpenPGP bundle. Certificate message: spaces/abc/messages/cert",List.of());
        check(linkedApi.senderCertificates(flattened).size()==1,"Google flattened caption not recognized");
        reject(()->linkedApi.senderCertificates(new GoogleChatApi.Message(flattened.name(),"users/other","","",flattened.text(),List.of())));
        reject(()->linkedApi.senderCertificates(new GoogleChatApi.Message(flattened.name(),flattened.sender(),"","",flattened.text()+" Certificate message: spaces/abc/messages/second",List.of())));
        int count=calls.size();reject(()->api.messages("spaces/../../outside",""));reject(()->api.download(new GoogleChatApi.Attachment("bad","../other"),10));reject(()->api.upload("spaces/abc","message.pgp",new byte[ChatBundle.MAX_BYTES+1]));check(calls.size()==count,"Invalid input contacted API");
        for(char[] c:credentials)check(Arrays.equals(c,new char[c.length]),"Access token copy retained");
        reject(()->GoogleChatApi.network("GET",java.net.URI.create("https://evil.example/"),null,null,new char[]{'x'},100));
        reject(()->GoogleOAuth.token("{\"access_token\":\"x\",\"token_type\":\"Bearer\",\"expires_in\":3600}",GoogleChatSession.SCOPES,true));
        reject(()->GoogleOAuth.token("{\"access_token\":\"x\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\""+GoogleOAuth.SCOPE+"\"}",GoogleChatSession.SCOPES,true));
        try(var t=token()){check(t.valid(),"Chat token rejected");}
        Path root=Files.createTempDirectory("chat-session-test-");byte[] prf=PrfVault.random(32),salt=PrfVault.random(32);int[] login={0},refresh={0};String[] returnedEmail={"chat@example.test"};
        GoogleChatSession.OAuth oauth=new GoogleChatSession.OAuth(){public GoogleOAuth.Token authorize(GoogleOAuth.Client c,String email,java.util.function.Consumer<java.net.URI> browser,java.util.function.BooleanSupplier cancelled)throws Exception{login[0]++;return token();}public GoogleOAuth.Token refresh(GoogleOAuth.Client c,String r)throws Exception{check(r.equals("synthetic-refresh"),"Wrong refresh token");refresh[0]++;return token();}};
        GoogleChatApi.Wire wire=(method,uri,type,body,c,limit)->json("{\"email\":\""+returnedEmail[0]+"\",\"id\":\"12345\",\"verified_email\":true}");
        try(var vault=new PrfVault(root.resolve("vault.json"))){
            var client=new GoogleOAuth.Client("chat-test.apps.googleusercontent.com","");var session=new GoogleChatSession(vault,client,oauth,wire);
            reject(()->session.connect("chat@example.test",false,u->{}));check(login[0]==0,"Locked vault invoked OAuth");vault.create("YWJj",salt,prf);
            session.connect("chat@example.test",false,u->{});check(login[0]==1,"First connection did not authorize");
            String disk=Files.readString(root.resolve("vault.json"));check(!disk.contains("synthetic-refresh")&&!disk.contains("synthetic-access"),"Plaintext token on disk");session.close();
            var restored=new GoogleChatSession(vault,client,oauth,wire);restored.connect("chat@example.test",false,u->{});check(login[0]==1&&refresh[0]==1,"Reconnect repeated browser login");
            vault.close();reject(restored::credential);vault.unlock("YWJj",prf);reject(restored::credential); // lock must discard access, even after reopening vault
            returnedEmail[0]="wrong@example.test";reject(()->restored.connect("chat@example.test",true,u->{}));reject(restored::credential);
            var storage=new GoogleChatVault(vault);check(!storage.hasRefresh(client.id(),"wrong@example.test"),"Wrong account persisted");restored.forget("chat@example.test");check(!storage.hasRefresh(client.id(),"chat@example.test"),"Forget left refresh token");
        }finally{Arrays.fill(prf,(byte)0);try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
        System.out.println("PASS Chat transport: paging, multipart uploads, separate certificate, media references, POST deduplication, token clearing, origin/size guards; OAuth scope/account checks, encrypted refresh storage, browser-free reconnect, lock and forget");
    }
}
