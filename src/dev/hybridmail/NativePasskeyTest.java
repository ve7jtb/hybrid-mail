package dev.hybridmail;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
/** Synthetic results only; never accesses a user's vault or authenticator. */
public final class NativePasskeyTest {
 public static void main(String[] args)throws Exception{
  DesktopVaultTest.check(!NativePasskeyPrf.supportedVersion("26.3.1")&&NativePasskeyPrf.supportedVersion("26.4")&&NativePasskeyPrf.supportedVersion("27.2.1")&&!NativePasskeyPrf.supportedVersion("invalid"),"Security-key PRF OS gate");
  byte[] salt=PrfVault.random(32),prf=PrfVault.random(32);String challenge=PrfVault.b64(PrfVault.random(32));var wrapper=new JsonObject();wrapper.addProperty("credential","YWJj");wrapper.addProperty("salt",PrfVault.b64(salt));
  var request=NativePasskeyPrf.requestData("Existing key",wrapper,salt,challenge,NativePasskeyPrf.SECURITY_KEY);
  DesktopVaultTest.check(request.get("salt").getAsString().equals(wrapper.get("salt").getAsString())&&request.get("credential").getAsString().equals("YWJj")&&request.get("operation").getAsString().equals("assert")&&request.get("provider").getAsString().equals("security-key"),"Existing wrapper and raw salt preserved");
  DesktopVaultTest.check(!NativePasskeyPrf.requestData("Find existing",null,salt,challenge,NativePasskeyPrf.PLATFORM).has("credential"),"Discoverable assertion");
  byte[] reply=DesktopVaultTest.reply(challenge,prf).toString().getBytes(StandardCharsets.UTF_8);
  try(var result=NativePasskeyPrf.decodeResult(reply,salt,challenge,"YWJj")){DesktopVaultTest.check(Arrays.equals(result.prf(),prf)&&Arrays.equals(result.salt(),salt),"Native/browser PRF result compatibility");}
  DesktopVaultTest.reject(()->NativePasskeyPrf.decodeResult(reply,salt,"different","YWJj"));
  DesktopVaultTest.reject(()->NativePasskeyPrf.decodeResult(reply,salt,challenge,"ZGVm"));
  var invalid=DesktopVaultTest.reply(challenge,prf);var body=invalid.getAsJsonObject("response");byte[] auth=PrfVault.decode(body.get("authenticatorData").getAsString());auth[32]=1;body.addProperty("authenticatorData",PrfVault.b64(auth));
  DesktopVaultTest.reject(()->NativePasskeyPrf.decodeResult(invalid.toString().getBytes(StandardCharsets.UTF_8),salt,challenge,"YWJj"));
  DesktopVaultTest.reject(()->NativePasskeyPrf.decodeResult("{\"error\":\"Cancelled\"}".getBytes(StandardCharsets.UTF_8),salt,challenge,"YWJj"));
  // An assertion from either transport unwraps the very same existing vault.
  Path dir=Files.createTempDirectory("native-prf-test-");
  if(!DesktopState.windows()){
   Path fake=dir.resolve("synthetic-helper");
   Files.writeString(fake,"#!/bin/sh\ncat >/dev/null\ncat <<'RESULT'\n"+new String(reply,StandardCharsets.UTF_8)+"\nRESULT\n");fake.toFile().setExecutable(true,true);
   byte[] pipe=NativePasskeyPrf.exchange(fake,request,5);
   try(var result=NativePasskeyPrf.decodeResult(pipe,salt,challenge,"YWJj")){DesktopVaultTest.check(Arrays.equals(result.prf(),prf),"Native pipe round trip");}finally{Arrays.fill(pipe,(byte)0);}
   Files.writeString(fake,"#!/bin/sh\ncat >/dev/null\nexec /bin/sleep 10\n");
   DesktopVaultTest.reject(()->NativePasskeyPrf.exchange(fake,request,1));
   Files.writeString(fake,"#!/bin/sh\ncat >/dev/null\nhead -c 131073 /dev/zero\n");
   DesktopVaultTest.reject(()->NativePasskeyPrf.exchange(fake,request,5));
  }
  try(var vault=new PrfVault(dir.resolve("vault.json"))){vault.create("YWJj",salt,prf);vault.put("test","synthetic");byte[] before=Files.readAllBytes(dir.resolve("vault.json"));vault.close();try(var result=NativePasskeyPrf.decodeResult(reply,salt,challenge,"YWJj")){vault.unlock(result.credential(),result.prf());}DesktopVaultTest.check(vault.get("test").equals("synthetic")&&Arrays.equals(before,Files.readAllBytes(dir.resolve("vault.json"))),"Unlock preserves existing encrypted vault");}
  finally{Arrays.fill(prf,(byte)0);Arrays.fill(reply,(byte)0);try(var paths=Files.walk(dir)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
  System.out.println("PASS native PRF version gate, existing-credential request, assertion discovery, challenge/credential/UV validation, cancellation, bounded pipe round trip/timeout/oversize rejection, browser-compatible PRF and unchanged vault unlock");
 }
}
