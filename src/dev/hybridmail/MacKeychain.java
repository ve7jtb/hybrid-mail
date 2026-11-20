package dev.hybridmail;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
/** No secrets in arguments, environment variables, logs or temporary files. */
final class MacKeychain {
    static byte[] call(String operation,String account,byte[] input)throws IOException{
        Path helper=DesktopState.resources().resolve(DesktopState.windows()?"native/bin/hybrid-mail-credentials.exe":DesktopState.linux()?"native/bin/hybrid-mail-credentials":"native/bin/hybrid-mail-keychain");
        Path protectedHelper=DesktopState.resources().resolve("../Helpers/PQMailKeychain.app/Contents/MacOS/PQMailKeychain").normalize();
        if(!account.equals("microsoft-session")&&!DesktopState.windows()&&Files.isExecutable(protectedHelper))helper=protectedHelper;
        if(!Files.isExecutable(helper))helper=Path.of("build/native/hybrid-mail-keychain").toAbsolutePath();
        if(!Files.isExecutable(helper))throw new IOException("Credential-store helper is unavailable. Use the packaged desktop app.");
        Process process=new ProcessBuilder(helper.toString(),operation,account).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{
            try(var out=process.getOutputStream()){if(input!=null)out.write(input);}
            var read=CompletableFuture.supplyAsync(()->{try{return process.getInputStream().readNBytes(65537);}catch(IOException e){throw new CompletionException(e);}});
            if(!process.waitFor(90,TimeUnit.SECONDS))throw new IOException("Credential-store access timed out");
            byte[] bytes=read.get(5,TimeUnit.SECONDS);
            if(process.exitValue()==2)return null;
            if(process.exitValue()==4 && operation.equals("probe-protected"))return new byte[]{1};
            if(process.exitValue()==3)throw new IOException("Touch ID or Mac password authentication was cancelled, unavailable, or timed out. No Google session was restored.");
            if(process.exitValue()!=0||bytes.length>65536)throw new IOException("Credential-store access failed or was cancelled. Unlock your desktop keyring and try again.");
            return bytes;
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Keychain access interrupted");}catch(ExecutionException|TimeoutException e){throw new IOException("Cannot read credential-store response");}finally{process.destroyForcibly();}
    }
    static String get(String account)throws IOException{return get(account,false);}
    static String get(String account,boolean authenticate)throws IOException{if(!authenticate&&DesktopVault.configured())return DesktopVault.get(account);byte[] data=call(authenticate?"get-protected":"get",account,null);if(data==null)return null;try{return new String(data,StandardCharsets.UTF_8);}finally{Arrays.fill(data,(byte)0);}}
    static void put(String account,String value)throws IOException{if(DesktopVault.configured()){DesktopVault.put(account,value);return;}byte[] data=value.getBytes(StandardCharsets.UTF_8);try{call("put",account,data);}finally{Arrays.fill(data,(byte)0);}}
    static boolean protectedHelperAvailable(){return !DesktopState.windows()&&Files.isExecutable(DesktopState.resources().resolve("../Helpers/PQMailKeychain.app/Contents/MacOS/PQMailKeychain").normalize());}
    static boolean protectedSession()throws IOException{return protectedHelperAvailable()&&call("probe-protected","google-session",null)!=null;}
    static void protectSession(boolean enable)throws IOException{if(!protectedHelperAvailable())throw new IOException("This build needs a signed, provisioned Keychain helper to protect the Google OAuth refresh token.");call(enable?"protect":"unprotect","google-session",null);}
    static void putProtected(String account,String value)throws IOException{byte[] data=value.getBytes(StandardCharsets.UTF_8);try{call("put-protected",account,data);}finally{Arrays.fill(data,(byte)0);}}
    static void deleteProtectedSession()throws IOException{if(protectedHelperAvailable())call("delete-protected","google-session",null);}
    static void delete(String account)throws IOException{if(DesktopVault.configured()){DesktopVault.delete(account);return;}call("delete",account,null);}
}
