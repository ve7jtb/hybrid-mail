package dev.hybridmail;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
public final class MicrosoftMailTest {
 static void check(boolean b,String name){if(!b)throw new AssertionError(name);System.out.println("PASS "+name);}
 interface Action{void run()throws Exception;}
 static void reject(Action a,String name)throws Exception{try{a.run();}catch(IOException e){System.out.println("PASS "+name);return;}throw new AssertionError(name);}
 static MicrosoftGraph.Response json(String s){return new MicrosoftGraph.Response(200,s.getBytes(StandardCharsets.UTF_8));}
 public static void main(String[] args)throws Exception {
  var client=MicrosoftOAuth.bundledClient();String verifier=MicrosoftOAuth.random();
  var uri=MicrosoftOAuth.authorization(client,"test@example.test","http://localhost:12345/","state",verifier);
  var q=MicrosoftOAuth.query(uri.getRawQuery());
  check(q.get("code_challenge").equals(MicrosoftOAuth.challenge(verifier))&&q.get("code_challenge_method").equals("S256")&&!q.containsKey("client_secret")&&q.get("scope").contains("offline_access"),"PKCE, offline access, no desktop client secret");
  reject(()->MicrosoftOAuth.code("code=a&state=wrong","state"),"wrong OAuth state rejected");
  reject(()->MicrosoftOAuth.code("code=a&state=state&state=state","state"),"duplicate callback rejected");
  check(MicrosoftOAuth.code("code=a&state=state","state").equals("a"),"valid callback accepted");
  check(MicrosoftOAuth.granted("Mail.Read Mail.Send User.Read")&&MicrosoftOAuth.granted("https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read")&&!MicrosoftOAuth.granted("Mail.Read"),"required granted scopes checked");
  reject(()->MicrosoftOAuth.token("{\"access_token\":\"t\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"Mail.Read\"}"),"partial consent rejected");
  for(String bad:List.of("http://graph.microsoft.com/v1.0/me/messages","https://evil.example/v1.0/me/messages","https://graph.microsoft.com.evil.example/v1.0/me/messages","https://graph.microsoft.com@evil.example/v1.0/me/messages","https://graph.microsoft.com:444/v1.0/me/messages"))reject(()->MicrosoftGraph.safeUri(bad),"untrusted pagination URL rejected");
  MailEngine.init();byte[][] wire={null};int[] sends={0};var credentials=new ArrayList<char[]>();
  MicrosoftGraph.Transport transport=(req,limit)->{
   check(req.headers().firstValue("Authorization").orElse("").equals("Bearer fake"),"bearer auth");String path=req.uri().getPath();
   if(path.equals("/v1.0/me/"))return json("{\"mail\":\"a@example.test\"}");
   if(path.endsWith("/sendMail")){sends[0]++;wire[0]=Base64.getDecoder().decode(GmailApiTest.body(req));check(req.headers().firstValue("Content-Type").orElse("").equals("text/plain"),"MIME send encoding");return new MicrosoftGraph.Response(202,new byte[0]);}
   if(path.endsWith("/$value"))return new MicrosoftGraph.Response(200,wire[0]);
   boolean older=req.uri().getRawQuery().contains("skiptoken");return json("{\"value\":[{\"id\":\"m/+==\",\"subject\":\"test\",\"receivedDateTime\":\"2026-11-19T00:00:00Z\"}]"+(older?"":",\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=2\"")+"}");
  };
  try(var api=new MicrosoftGraph(()->{char[] t="fake".toCharArray();credentials.add(t);return t;},transport)){
   api.verifyAccount("a@example.test");reject(()->api.verifyAccount("wrong@example.test"),"wrong mailbox rejected");
   var first=api.latest();check(api.hasOlder()&&!api.hasNewer(),"first page");api.older();check(!api.hasOlder()&&api.hasNewer(),"older page");reject(()->api.message(first.get(0).uid()),"stale page ID rejected");var back=api.newer();
   for(var profile:TokenProfile.values())for(var id:Identity.generateSoftwareProfile("a@example.test",profile,List.of())){
    var message=MailEngine.compose(id,"a@example.test","a@example.test","Synthetic","Microsoft MIME roundtrip",id.encryptionCert(),null);byte[] raw=MailEngine.encode(message);api.send(message);
    check(Arrays.equals(raw,wire[0]),"MIME send bytes preserved");var opened=MailEngine.open(api.message(back.get(0).uid()),id,id.signingCert());check(opened.encrypted()&&opened.pinned()&&opened.text().equals("Microsoft MIME roundtrip"),"pure/hybrid authenticated MIME roundtrip "+profile);
   }
   check(credentials.stream().allMatch(t->{for(char c:t)if(c!=0)return false;return true;}),"temporary access-token copies cleared");
  }
  int[] calls={0};try(var api=new MicrosoftGraph(()->"fake".toCharArray(),(req,limit)->{calls[0]++;throw new IOException("private server data");})){
   var id=Identity.generate("a@example.test",false);var message=MailEngine.compose(id,"a@example.test","a@example.test","Synthetic","Test",null,null);
   reject(()->api.send(message),"ambiguous send failure surfaced without retry");check(calls[0]==1,"no automatic resend");
  }
 }
}
