package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
public class MicrosoftGraphAndroidTest {
 MicrosoftGraph.Response json(String s){return new MicrosoftGraph.Response(200,s.getBytes(StandardCharsets.UTF_8));}
 @Test public void searchPagingMimeAndSend()throws Exception{
  MailEngine.init();var requests=new ArrayList<MicrosoftGraph.Request>();byte[][] wire={"From: a@example.test\r\nTo: b@example.test\r\nSubject: synthetic\r\n\r\nhello".getBytes()};var copies=new ArrayList<char[]>();
  try(var graph=new MicrosoftGraph(()->{char[] token="synthetic".toCharArray();copies.add(token);return token;},(r,l)->{
   requests.add(r);assertEquals("synthetic",r.token());String path=r.uri().getPath();
   if(path.endsWith("sendMail")){wire[0]=Base64.getDecoder().decode(r.body());return new MicrosoftGraph.Response(202,new byte[0]);}
   if(path.endsWith("$value"))return new MicrosoftGraph.Response(200,wire[0]);
   if(path.endsWith("/me/"))return json("{\"mail\":\"a@example.test\"}");
   return json("{\"value\":[{\"id\":\"id/+==\",\"subject\":\"test\",\"receivedDateTime\":\"2026-11-19T00:00:00Z\"}]"+(r.uri().getQuery().contains("skiptoken")?"":",\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=2\"")+"}");
  })){
   graph.verifyAccount("a@example.test");var first=graph.latest();assertTrue(graph.hasOlder());assertFalse(graph.hasNewer());graph.older();assertEquals(2,graph.pageNumber());assertTrue(graph.hasNewer());assertFalse(graph.hasOlder());graph.newer();assertEquals(1,graph.pageNumber());
   graph.setSearch("John's test");assertFalse(graph.hasNewer());var result=graph.latest();assertTrue(requests.get(requests.size()-1).uri().getQuery().contains("contains(subject,'John''s test')"));
   var msg=graph.message(result.get(0).uid());assertEquals("synthetic",msg.getSubject());byte[] exact=MailEngine.encode(msg);graph.send(msg);assertArrayEquals(exact,wire[0]);assertEquals("hello",graph.message(result.get(0).uid()).getContent().toString().trim());
   assertTrue(copies.stream().allMatch(c->{for(char v:c)if(v!=0)return false;return true;}));
  }
 }
 @Test public void rejectsUntrustedPaginationAndWrongAccount()throws Exception{
  for(String url:List.of("http://graph.microsoft.com/v1.0/me/messages","https://evil.example/v1.0/me/messages","https://graph.microsoft.com:444/v1.0/me/messages"))try{MicrosoftGraph.safeUri(url);fail();}catch(java.io.IOException expected){}
  try(var graph=new MicrosoftGraph(()->"test".toCharArray(),(r,l)->json("{\"mail\":\"wrong@example.test\"}"))){try{graph.verifyAccount("expected@example.test");fail();}catch(java.io.IOException expected){}}
 }
 @Test public void errorsDoNotLeakResponseAndSendsNotRetried()throws Exception{
  for(int code:new int[]{401,403,429,500}){int[] count={0};try(var graph=new MicrosoftGraph(()->"test".toCharArray(),(r,l)->{count[0]++;return new MicrosoftGraph.Response(code,"private response".getBytes());})){try{graph.latest();fail();}catch(java.io.IOException expected){assertFalse(expected.getMessage().contains("private response"));}assertEquals(1,count[0]);}}
 }
}
