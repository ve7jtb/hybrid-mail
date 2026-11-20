package dev.hybridmail;
import com.sun.net.httpserver.*;
import com.google.gson.*;
import java.net.*;
import java.net.http.*;
import java.util.concurrent.*;
public final class PasskeyCallbackTest {
 public static void main(String[] args)throws Exception{
  try(var client=HttpClient.newHttpClient()){
   for(int i=0;i<50;i++){
    var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var done=new CompletableFuture<JsonObject>();
    server.createContext("/test",exchange->DesktopPasskeyPrf.acknowledge(exchange,done,new JsonObject()));server.start();
    var stopped=CompletableFuture.runAsync(()->{done.join();server.stop(0);});
    try{var reply=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/test")).POST(HttpRequest.BodyPublishers.noBody()).build(),HttpResponse.BodyHandlers.discarding());if(reply.statusCode()!=204)throw new AssertionError("Lost callback response");stopped.get(5,TimeUnit.SECONDS);}finally{server.stop(0);}
   }
  }System.out.println("PASS 50 real HTTP callbacks acknowledged before immediate listener shutdown");
 }
}
