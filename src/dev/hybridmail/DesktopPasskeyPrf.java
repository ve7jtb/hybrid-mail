package dev.hybridmail;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.awt.Desktop;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** WebAuthn at the shared RP; only an encrypted response crosses the loopback bridge. */
final class DesktopPasskeyPrf {
 static final String ORIGIN="https://ve7jtb.github.io", PAGE=ORIGIN+"/pq-mail/passkey/?v=callback3";
 record Result(String credential,byte[] salt,byte[] prf,String user) implements AutoCloseable {
  public void close(){Arrays.fill(prf,(byte)0);}
 }
 static Result request(String name,JsonObject wrapper)throws Exception {return request(name,wrapper,false);}
 static Result request(String name,JsonObject wrapper,boolean discover)throws Exception {
  boolean create=wrapper==null&&!discover;byte[] salt=wrapper==null?PrfVault.random(32):PrfVault.decode(wrapper.get("salt").getAsString());
  String challenge=PrfVault.b64(PrfVault.random(32)),nonce=PrfVault.b64(PrfVault.random(32)),user=create?PrfVault.b64(PrfVault.random(32)):"";
  var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));var pair=generator.generateKeyPair();
  var server=HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0),0);
  var executor=Executors.newFixedThreadPool(2);server.setExecutor(executor);var response=new CompletableFuture<JsonObject>();
  String host="127.0.0.1:"+server.getAddress().getPort(),path="/prf/"+nonce;
  var claimed=new java.util.concurrent.atomic.AtomicBoolean();
  server.createContext(path,exchange->{try{
   if(!exchange.getRequestURI().toString().equals(path)||!host.equals(exchange.getRequestHeaders().getFirst("Host"))||!ORIGIN.equals(exchange.getRequestHeaders().getFirst("Origin"))){exchange.sendResponseHeaders(403,-1);return;}
   var headers=exchange.getResponseHeaders();headers.set("Access-Control-Allow-Origin",ORIGIN);headers.set("Cache-Control","no-store");headers.set("Vary","Origin");
   if(exchange.getRequestMethod().equals("OPTIONS")){headers.set("Access-Control-Allow-Methods","GET, POST");headers.set("Access-Control-Allow-Headers","Content-Type");headers.set("Access-Control-Allow-Private-Network","true");exchange.sendResponseHeaders(204,-1);return;}
   if(exchange.getRequestMethod().equals("GET")){exchange.sendResponseHeaders(204,-1);return;}
   if(!exchange.getRequestMethod().equals("POST")||!"application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type"))){exchange.sendResponseHeaders(405,-1);return;}
   byte[] input=exchange.getRequestBody().readNBytes(131073);if(input.length>131072)throw new SecurityException("Passkey reply too large");
   var sealed=JsonParser.parseString(new String(input,StandardCharsets.UTF_8)).getAsJsonObject();
   JsonObject result=decrypt(pair.getPrivate(),sealed,nonce);
   // Invalid context must not consume a pending request.
   Arrays.fill(validate(result,challenge,create,wrapper==null?null:wrapper.get("credential").getAsString()),(byte)0);
   if(!claimed.compareAndSet(false,true)){exchange.sendResponseHeaders(409,-1);return;}
   acknowledge(exchange,response,result);
  }catch(Exception e){exchange.sendResponseHeaders(400,-1);}finally{exchange.close();}});
  try{
   server.start();var request=new JsonObject();request.addProperty("create",create);request.addProperty("discover",discover);request.addProperty("name",name);request.addProperty("user",user);request.addProperty("challenge",challenge);request.addProperty("salt",PrfVault.b64(salt));request.addProperty("nonce",nonce);request.addProperty("callback","http://"+host+path);request.addProperty("publicKey",PrfVault.b64(pair.getPublic().getEncoded()));if(wrapper!=null)request.addProperty("credential",wrapper.get("credential").getAsString());
   openBrowser(URI.create(PAGE+"#"+PrfVault.b64(request.toString().getBytes(StandardCharsets.UTF_8))));
   var result=response.get(300,TimeUnit.SECONDS);if((discover||result.has("registration"))&&result.getAsJsonObject("response").has("userHandle"))user=result.getAsJsonObject("response").get("userHandle").getAsString();return new Result(result.get("rawId").getAsString(),salt,validate(result,challenge,create,wrapper==null?null:wrapper.get("credential").getAsString()),user);
  }catch(TimeoutException e){throw new java.io.IOException("Passkey operation timed out. Return to Keys → Passkey vault to retry. No secrets were saved.");}
  finally{server.stop(0);executor.shutdownNow();}
 }
 static void acknowledge(HttpExchange exchange,CompletableFuture<JsonObject> response,JsonObject result)throws java.io.IOException{
  // Flush and close the HTTP response before waking the waiter that stops the listener.
  exchange.sendResponseHeaders(204,-1);exchange.close();response.complete(result);
 }
 static String saveBrowserChoice(DesktopState settings,int index)throws Exception{
  if(index!=0&&index!=1)return null;
  String selected=index==0?"Google Chrome":"Default browser";
  settings.set("passkey.browser",selected);settings.save();
  if(!new DesktopState(settings.directory()).get("passkey.browser","").equals(selected))throw new java.io.IOException("Browser preference was not saved");
  return selected;
 }
 static String chooseBrowser(java.awt.Component owner,DesktopState settings)throws Exception{
  Object[] choices={"Use Google Chrome","Use default browser","Cancel"};
  int selected=javax.swing.JOptionPane.showOptionDialog(owner,"Saved choice: "+settings.get("passkey.browser","Not selected")+"\nGoogle Chrome is recommended for the security-key comparison.\nThis changes only PQ Mail passkey operations, not your system default.","PQ Mail passkey browser",javax.swing.JOptionPane.DEFAULT_OPTION,javax.swing.JOptionPane.QUESTION_MESSAGE,null,choices,choices[0]);
  return saveBrowserChoice(settings,selected);
 }
 static void openBrowser(URI uri)throws Exception {
  var settings=DesktopVault.settings();String browser=settings.get("passkey.browser","");
  if(System.getProperty("os.name").startsWith("Mac")&&browser.isEmpty()){
   var choice=new java.util.concurrent.FutureTask<String>(()->chooseBrowser(null,settings));
   if(javax.swing.SwingUtilities.isEventDispatchThread())choice.run();else javax.swing.SwingUtilities.invokeAndWait(choice);browser=choice.get();if(browser==null)throw new java.io.IOException("Passkey operation cancelled");
  }
  if(System.getProperty("os.name").startsWith("Mac")&&browser.equals("Google Chrome")){
   var process=new ProcessBuilder("/usr/bin/open","-a","Google Chrome",uri.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
   if(!process.waitFor(10,TimeUnit.SECONDS)||process.exitValue()!=0)throw new java.io.IOException("Cannot open Google Chrome. Change Passkey browser in Keys.");
  }else Desktop.getDesktop().browse(uri);
 }
 static JsonObject decrypt(PrivateKey privateKey,JsonObject sealed,String nonce)throws Exception {
  var peer=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(PrfVault.decode(sealed.get("publicKey").getAsString())));
  if(!(peer instanceof java.security.interfaces.ECPublicKey ec)||ec.getParams().getCurve().getField().getFieldSize()!=256)throw new SecurityException("Invalid bridge key");
  var agreement=KeyAgreement.getInstance("ECDH");agreement.init(privateKey);agreement.doPhase(peer,true);byte[] shared=agreement.generateSecret(),key=MessageDigest.getInstance("SHA-256").digest(shared),plain=null;
  try{plain=PrfVault.open(key,sealed,nonce);return JsonParser.parseString(new String(plain,StandardCharsets.UTF_8)).getAsJsonObject();}
  finally{Arrays.fill(shared,(byte)0);Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
 }
 static byte[] validate(JsonObject reply,String challenge,boolean create,String credential)throws Exception{
  if(!"public-key".equals(reply.get("type").getAsString()))throw new SecurityException("Expected passkey");
  byte[] id=PrfVault.decode(reply.get("rawId").getAsString());if(id.length==0||id.length>2048||(!create&&credential!=null&&!credential.equals(reply.get("rawId").getAsString())))throw new SecurityException("Wrong passkey");
  var body=reply.getAsJsonObject("response");var client=JsonParser.parseString(new String(PrfVault.decode(body.get("clientDataJSON").getAsString()),StandardCharsets.UTF_8)).getAsJsonObject();
  // Creation may require a follow-up assertion on providers without PRF evaluation at creation.
  String type=create&&!reply.has("registration")?"webauthn.create":"webauthn.get";
  if(!challenge.equals(client.get("challenge").getAsString())||!ORIGIN.equals(client.get("origin").getAsString())||!type.equals(client.get("type").getAsString())||(client.has("crossOrigin")&&client.get("crossOrigin").getAsBoolean()))throw new SecurityException("Passkey context mismatch");
  byte[] auth=type.equals("webauthn.create")?RegistrationCbor.authData(PrfVault.decode(body.get("attestationObject").getAsString())):PrfVault.decode(body.get("authenticatorData").getAsString());
  byte[] rp=MessageDigest.getInstance("SHA-256").digest(PrfVault.RP.getBytes(StandardCharsets.UTF_8));
  if(auth.length<37||!MessageDigest.isEqual(rp,Arrays.copyOf(auth,32))||(auth[32]&5)!=5)throw new SecurityException("Passkey user verification required");
  if(type.equals("webauthn.create")){if(auth.length<55||(auth[32]&64)==0)throw new SecurityException("Missing attested credential");int length=((auth[53]&255)<<8)|(auth[54]&255);if(length!=id.length||auth.length<=55+length||!MessageDigest.isEqual(id,Arrays.copyOfRange(auth,55,55+length)))throw new SecurityException("Registration key mismatch");}
  var ext=reply.getAsJsonObject("clientExtensionResults");if(ext==null||!ext.has("prf")||!ext.getAsJsonObject("prf").has("results"))throw new SecurityException("This passkey provider does not support PRF. Vault remains locked.");
  byte[] prf=PrfVault.decode(ext.getAsJsonObject("prf").getAsJsonObject("results").get("first").getAsString());if(prf.length!=32)throw new SecurityException("Invalid PRF output");return prf;
 }
}
