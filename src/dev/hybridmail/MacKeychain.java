package dev.hybridmail;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
/** No secrets in arguments, environment variables, logs or temporary files. */
final class MacKeychain {
    static byte[] call(String operation,String account,byte[] input)throws IOException{
        Path helper=DesktopState.resources().resolve(DesktopState.windows()?"native/bin/hybrid-mail-credentials.exe":"native/bin/hybrid-mail-keychain");
        if(!Files.isExecutable(helper))helper=Path.of("build/native/hybrid-mail-keychain").toAbsolutePath();
        if(!Files.isExecutable(helper))throw new IOException("Credential-store helper is unavailable. Use the packaged desktop app.");
        Process process=new ProcessBuilder(helper.toString(),operation,account).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{
            try(var out=process.getOutputStream()){if(input!=null)out.write(input);}
            var read=CompletableFuture.supplyAsync(()->{try{return process.getInputStream().readNBytes(65537);}catch(IOException e){throw new CompletionException(e);}});
            if(!process.waitFor(90,TimeUnit.SECONDS))throw new IOException("Mac Keychain access timed out");
            byte[] bytes=read.get(5,TimeUnit.SECONDS);
            if(process.exitValue()==2)return null;
            if(process.exitValue()!=0||bytes.length>65536)throw new IOException("Mac Keychain access failed or was cancelled. Unlock your login Keychain and try again.");
            return bytes;
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Keychain access interrupted");}catch(ExecutionException|TimeoutException e){throw new IOException("Cannot read Mac Keychain response");}finally{process.destroyForcibly();}
    }
    static String get(String account)throws IOException{byte[] data=call("get",account,null);if(data==null)return null;try{return new String(data,StandardCharsets.UTF_8);}finally{Arrays.fill(data,(byte)0);}}
    static void put(String account,String value)throws IOException{byte[] data=value.getBytes(StandardCharsets.UTF_8);try{call("put",account,data);}finally{Arrays.fill(data,(byte)0);}}
    static void delete(String account)throws IOException{call("delete",account,null);}
}
