package dev.hybridmail;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Native macOS/Windows/Linux assertion bridge. PRF output stays in process pipes/memory. */
final class NativePasskeyPrf {
 static final String SECURITY_KEY="Native macOS — security key", PLATFORM="Native macOS — platform passkey", BROWSER="Browser";
 static final String WINDOWS_KEY="Native Windows — security key", WINDOWS_PLATFORM="Native Windows — platform passkey";
 static final String LINUX_KEY="Native Linux — YubiKey USB";
 static Path app(){return DesktopState.resources().resolve("../Helpers/PQMailPasskey.app").normalize();}
 static Path helper(){if(DesktopState.linux())return DesktopState.resources().resolve("native/bin/pqmail-passkey");return DesktopState.windows()?DesktopState.resources().resolve("native/bin/pqmail-passkey.exe"):app().resolve("Contents/MacOS/PQMailPasskey");}
 static boolean supportedVersion(String version){
  try{String[] n=version.split("\\.");int major=Integer.parseInt(n[0]),minor=n.length>1?Integer.parseInt(n[1]):0;return major>26||(major==26&&minor>=4);}catch(RuntimeException e){return false;}
 }
 static boolean available(){if(DesktopState.windows()||DesktopState.linux())return Files.isExecutable(helper());return System.getProperty("os.name").startsWith("Mac")&&supportedVersion(System.getProperty("os.version"))&&Files.isExecutable(helper())&&Files.isRegularFile(app().resolve("Contents/embedded.provisionprofile"));}
 static boolean selected(String method){return SECURITY_KEY.equals(method)||PLATFORM.equals(method)||windowsMethod(method)||LINUX_KEY.equals(method);}
 static boolean windowsMethod(String method){return WINDOWS_KEY.equals(method)||WINDOWS_PLATFORM.equals(method);}
 static boolean methodMatchesOs(String method,String os){return os.equals("Linux")?LINUX_KEY.equals(method):os.startsWith("Windows")?windowsMethod(method):os.startsWith("Mac")&&(SECURITY_KEY.equals(method)||PLATFORM.equals(method));}
 static boolean platformMethod(String method){return PLATFORM.equals(method)||WINDOWS_PLATFORM.equals(method);}
 static String[] methods(String os){return os.startsWith("Windows")?new String[]{BROWSER,WINDOWS_KEY,WINDOWS_PLATFORM}:os.startsWith("Mac")?new String[]{BROWSER,SECURITY_KEY,PLATFORM}:os.equals("Linux")?new String[]{BROWSER,LINUX_KEY}:new String[]{BROWSER};}
 static String choose(java.awt.Component owner,DesktopState settings)throws Exception{
  String[] methods=methods(System.getProperty("os.name"));
  String requirements=DesktopState.windows()?"Native Windows unlock uses the system WebAuthn dialog.\nRequires WebAuthn API v4+ and a PRF-capable authenticator.":System.getProperty("os.name").startsWith("Mac")?"Native macOS unlock uses AuthenticationServices.\nRequires macOS 26.4+ and a signed, provisioned helper.":DesktopState.linux()?"Native Linux uses YubiKit over USB HID.\nRequires a PRF-capable YubiKey with a configured FIDO2 PIN.\nConnect one YubiKey; Linux hidraw access is required.":"This platform uses the Browser method.";
  var choice=(String)javax.swing.JOptionPane.showInputDialog(owner,requirements+"\nExisting passkeys can unlock and be enrolled natively.\nCreating a new passkey currently requires the Browser method.\nNative helper: "+(available()?"available":"unavailable in this build"),"Passkey method",javax.swing.JOptionPane.QUESTION_MESSAGE,null,methods,settings.get("passkey.method",BROWSER));
  if(choice==null)return null;
  if(selected(choice)&&!available())throw new IOException(DesktopState.windows()?"The packaged Windows passkey helper is missing. Passkey preference remains unchanged.":DesktopState.linux()?"The packaged Linux passkey helper is missing. Passkey preference remains unchanged.":"Native passkeys require macOS 26.4+ and a helper provisioned for Associated Domains by a paid Apple Developer team. Passkey preference remains unchanged.");
  settings.set("passkey.method",choice);settings.save();return choice;
 }
 static JsonObject requestData(String name,JsonObject wrapper,byte[] salt,String challenge,String method){
  if(!selected(method))throw new IllegalArgumentException("Unknown native passkey method");
  var request=new JsonObject();request.addProperty("operation","assert");request.addProperty("rp",PrfVault.RP);request.addProperty("name",name);request.addProperty("provider",platformMethod(method)?"platform":"security-key");request.addProperty("challenge",challenge);request.addProperty("salt",PrfVault.b64(salt));
  if(wrapper!=null)request.addProperty("credential",wrapper.get("credential").getAsString());return request;
 }
 static DesktopPasskeyPrf.Result request(String name,JsonObject wrapper,String method)throws Exception{
  if(!methodMatchesOs(method,System.getProperty("os.name")))throw new IOException("This native passkey method belongs to another platform. Choose Passkey method in Keys.");
  if(!available())throw new IOException("Native passkey helper is unavailable or not provisioned. Choose Browser in Keys → Passkey method to use Chrome. No browser was opened.");
  byte[] salt=wrapper==null?PrfVault.random(32):PrfVault.decode(wrapper.get("salt").getAsString());String challenge=PrfVault.b64(PrfVault.random(32));
  var request=requestData(name,wrapper,salt,challenge,method);
  byte[] reply=LINUX_KEY.equals(method)?LinuxPasskeyPrf.request(helper(),request):windowsMethod(method)?exchange(helper(),windowsRequest(request),300):exchange(helper(),request,300);
  try{return decodeResult(reply,salt,challenge,wrapper==null?null:wrapper.get("credential").getAsString());}finally{Arrays.fill(reply,(byte)0);}
 }
 static DesktopPasskeyPrf.Result decodeResult(byte[] bytes,byte[] salt,String challenge,String credential)throws Exception{
  var reply=JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();
  if(reply.has("error")){String error=reply.get("error").getAsString().replaceAll("[\\p{Cntrl}]"," ");throw new IOException("Native passkey operation failed: "+error.substring(0,Math.min(400,error.length())));}
  byte[] prf=DesktopPasskeyPrf.validate(reply,challenge,false,credential);
  var body=reply.getAsJsonObject("response");String user=body.has("userHandle")?body.get("userHandle").getAsString():"";
  return new DesktopPasskeyPrf.Result(reply.get("rawId").getAsString(),salt,prf,user);
 }
 static byte[] windowsRequest(JsonObject request)throws IOException{
  if(!"assert".equals(request.get("operation").getAsString())||!PrfVault.RP.equals(request.get("rp").getAsString()))throw new IOException("Invalid Windows passkey context");
  String provider=request.get("provider").getAsString(),name=request.get("name").getAsString();
  if(!Set.of("security-key","platform").contains(provider)||name.isBlank()||name.codePointCount(0,name.length())>80||name.codePoints().anyMatch(Character::isISOControl))throw new IOException("Invalid Windows passkey request");
  byte[] challenge=PrfVault.decode(request.get("challenge").getAsString()),salt=PrfVault.decode(request.get("salt").getAsString()),id=request.has("credential")?PrfVault.decode(request.get("credential").getAsString()):new byte[0],label=name.getBytes(StandardCharsets.UTF_8);
  if(challenge.length!=32||salt.length!=32||id.length>2048||(request.has("credential")&&id.length==0)||label.length>320)throw new IOException("Invalid Windows passkey input lengths");
  var buffer=new ByteArrayOutputStream();try(var out=new DataOutputStream(buffer)){out.writeBytes("PQPRF001");out.writeByte(provider.equals("platform")?2:1);out.write(challenge);out.write(salt);out.writeShort(id.length);out.write(id);out.writeShort(label.length);out.write(label);}return buffer.toByteArray();
 }
 static byte[] exchange(Path executable,JsonObject request,int timeoutSeconds)throws Exception{return exchange(executable,request.toString().getBytes(StandardCharsets.UTF_8),timeoutSeconds);}
 static byte[] exchange(Path executable,byte[] input,int timeoutSeconds)throws Exception{
  Process process=new ProcessBuilder(executable.toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
  var reader=Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
  var read=CompletableFuture.supplyAsync(()->{
   byte[] buffer=new byte[131073];int size=0;
   try{while(size<buffer.length){int n=process.getInputStream().read(buffer,size,buffer.length-size);if(n<0)break;size+=n;}if(size>131072)throw new IOException("Native passkey response too large");return Arrays.copyOf(buffer,size);}catch(IOException e){throw new CompletionException(e);}finally{Arrays.fill(buffer,(byte)0);}
  },reader);
  byte[] response=null;boolean returned=false;
  try{
   try(var out=process.getOutputStream()){out.write(input);}
   if(!process.waitFor(timeoutSeconds,TimeUnit.SECONDS))throw new IOException("Native passkey operation timed out; vault remains locked");
   response=read.get(5,TimeUnit.SECONDS);
   if(response.length==0)throw new IOException("Native passkey helper did not return a result; check that the packaged helper can run");
   if(process.exitValue()!=0){
    // Only our bounded structured error is exposed, never arbitrary helper output.
    JsonObject error;try{error=JsonParser.parseString(new String(response,StandardCharsets.UTF_8)).getAsJsonObject();}catch(Exception e){throw new IOException("Native passkey operation failed");}
    if(!error.has("error"))throw new IOException("Native passkey operation failed");
   }
   returned=true;return response;
  }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Native passkey operation cancelled",e);}
  finally{
   Arrays.fill(input,(byte)0);process.destroyForcibly();
   try{process.getInputStream().close();}catch(IOException ignored){}
   reader.shutdownNow();
   if(!returned){if(response!=null)Arrays.fill(response,(byte)0);read.whenComplete((bytes,error)->{if(bytes!=null)Arrays.fill(bytes,(byte)0);});}
  }
 }
}
