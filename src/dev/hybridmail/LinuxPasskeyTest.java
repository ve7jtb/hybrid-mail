package dev.hybridmail;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
/** No authenticator or user's vault is accessed. */
public final class LinuxPasskeyTest {
 static void check(boolean b,String m){DesktopVaultTest.check(b,m);}
 interface Task{void run()throws Exception;}
 static void reject(Task task)throws Exception{try{task.run();}catch(Exception expected){return;}throw new AssertionError("Failure was required");}
 public static void main(String[] args)throws Exception{
  check(Arrays.asList(NativePasskeyPrf.methods("Linux")).contains(NativePasskeyPrf.LINUX_KEY),"Linux native method exposed");
  check(NativePasskeyPrf.methodMatchesOs(NativePasskeyPrf.LINUX_KEY,"Linux")&&!NativePasskeyPrf.methodMatchesOs(NativePasskeyPrf.SECURITY_KEY,"Linux")&&!NativePasskeyPrf.methodMatchesOs(NativePasskeyPrf.LINUX_KEY,"Mac OS X"),"Cross-platform method rejected");
  reject(()->LinuxPasskeyPrf.encodePin("abc".toCharArray()));reject(()->LinuxPasskeyPrf.encodePin("x".repeat(64).toCharArray()));reject(()->LinuxPasskeyPrf.encodePin(new char[]{'a','b','c','d',0}));reject(()->LinuxPasskeyPrf.encodePin(new char[]{'a','b','c','d','\ud800'}));
  byte[] unicode=LinuxPasskeyPrf.encodePin("café".toCharArray());check(Arrays.equals(unicode,"café".getBytes(StandardCharsets.UTF_8)),"FIDO PIN UTF-8 encoding");Arrays.fill(unicode,(byte)0);
  reject(()->LinuxPasskeyPrf.line(new ByteArrayInputStream(new byte[131074])));
  reject(()->LinuxPasskeyPrf.line(new ByteArrayInputStream("unterminated".getBytes(StandardCharsets.UTF_8))));
  if(DesktopState.windows()){System.out.println("PASS Linux request/PIN/frame tests; subprocess tests run on Linux/macOS");return;}
  Path dir=Files.createTempDirectory("pqmail-linux-prf-");byte[] salt=PrfVault.random(32),prf=PrfVault.random(32);String challenge=PrfVault.b64(PrfVault.random(32));var wrapper=new JsonObject();wrapper.addProperty("credential","YWJj");wrapper.addProperty("salt",PrfVault.b64(salt));
  var request=NativePasskeyPrf.requestData("Named YubiKey",wrapper,salt,challenge,NativePasskeyPrf.LINUX_KEY);
  check(request.get("salt").getAsString().equals(wrapper.get("salt").getAsString()),"Original vault salt reused");
  var result=new JsonObject();result.addProperty("event","result");result.add("result",DesktopVaultTest.reply(challenge,prf));
  var calls=new AtomicInteger();char[] pin="1234".toCharArray();
  var ui=new LinuxPasskeyPrf.Interaction(){public char[] pin(){calls.incrementAndGet();return pin;}public void touch(){}public int select(String[] c){return 1;}};
  try{
   Path fake=dir.resolve("fake");Files.writeString(fake,"#!/usr/bin/env python3\nimport sys,json,struct\nr=json.loads(sys.stdin.buffer.readline())\nprint('{\"event\":\"pin\"}',flush=True)\nn=struct.unpack('>H',sys.stdin.buffer.read(2))[0]\nassert sys.stdin.buffer.read(n)==b'1234'\nprint('{\"event\":\"touch\"}',flush=True)\nprint('{\"event\":\"select\",\"choices\":[\"one\",\"two\"]}',flush=True)\nassert sys.stdin.buffer.read(2)==b'\\x00\\x01'\nprint("+new Gson().toJson(result.toString())+",flush=True)\n");fake.toFile().setExecutable(true,true);
   byte[] wire=LinuxPasskeyPrf.exchange(fake,request,ui,10);
   try(var unlocked=NativePasskeyPrf.decodeResult(wire,salt,challenge,"YWJj");var vault=new PrfVault(dir.resolve("vault.json"))){vault.create("YWJj",salt,prf);vault.put("synthetic","retained");byte[] before=Files.readAllBytes(dir.resolve("vault.json"));vault.close();vault.unlock(unlocked.credential(),unlocked.prf());check(vault.get("synthetic").equals("retained")&&Arrays.equals(before,Files.readAllBytes(dir.resolve("vault.json"))),"Native Linux/browser result unlocks unchanged vault");}finally{Arrays.fill(wire,(byte)0);}
   check(calls.get()==1&&Arrays.equals(pin,new char[4]),"One PIN callback and cleared PIN buffer");
   Files.writeString(fake,"#!/bin/sh\nread request\nprintf '%s\\n' '{\"event\":\"pin\"}' '{\"event\":\"pin\"}'\n");
   var again=new LinuxPasskeyPrf.Interaction(){public char[] pin(){calls.incrementAndGet();return "1234".toCharArray();}public void touch(){}public int select(String[] c){return -1;}};
   calls.set(0);reject(()->LinuxPasskeyPrf.exchange(fake,request,again,5));check(calls.get()<=1,"No automatic PIN retry");
   Files.writeString(fake,"#!/bin/sh\nread request\nexec sleep 30\n");long start=System.nanoTime();reject(()->LinuxPasskeyPrf.exchange(fake,request,ui,1));check(System.nanoTime()-start<5_000_000_000L,"Timeout kills helper");
   final Throwable[] cancelled={null};Thread worker=new Thread(()->{try{LinuxPasskeyPrf.exchange(fake,request,ui,30);}catch(Throwable e){cancelled[0]=e;}});worker.start();Thread.sleep(100);worker.interrupt();worker.join(3000);check(!worker.isAlive()&&cancelled[0]!=null,"Cancellation terminates helper");
   if(args.length>0){Path real=Path.of(args[0]);var invalid=new JsonObject();invalid.addProperty("operation","create");reject(()->LinuxPasskeyPrf.exchange(real,invalid,ui,5));System.out.println("PASS packaged Linux helper rejects creation before device access");}
  }finally{Arrays.fill(prf,(byte)0);try(var paths=Files.walk(dir)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
  System.out.println("PASS Linux native PIN/touch/selection pipe, preserved vault unlock, validation, cancellation and timeout; no hardware accessed");
 }
}
