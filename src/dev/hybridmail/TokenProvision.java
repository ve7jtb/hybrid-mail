package dev.hybridmail;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import com.google.gson.*;
/** Native helper owns one exclusive PIV connection for empty check and generation. */
final class TokenProvision {
    static Path helper(){Path p=DesktopState.resources().resolve(DesktopState.windows()?"native/bin/hybrid-mail-provision.exe":"native/bin/hybrid-mail-provision");return Files.isExecutable(p)?p:DesktopState.resources().resolve("native-src/provision/target/release/hybrid-mail-provision");}
    static String run(String serial,String operation,String profile,Path folder,char[] pin,char[] management)throws Exception{
        if(!serial.matches("[0-9]+"))throw new IOException("Enter the intended YubiKey serial");
        boolean create=operation.equals("create");
        List<String> command=new ArrayList<>(List.of(helper().toString(),operation,serial));
        if(!operation.equals("check"))command.addAll(List.of(profile,folder.toString()));
        Process process=new ProcessBuilder(command).start();var pool=Executors.newFixedThreadPool(2);
        try{
            var out=pool.submit(()->process.getInputStream().readNBytes(32769));var err=pool.submit(()->process.getErrorStream().readNBytes(2049));
            try(var input=process.getOutputStream()){if(create){for(char c:pin)input.write((byte)c);input.write('\n');for(char c:management)input.write((byte)c);input.write('\n');}}
            if(!process.waitFor(create?180:30,TimeUnit.SECONDS))throw new IOException("YubiKey provisioning timed out; do not retry generation if any slot was created");
            byte[] output=out.get(1,TimeUnit.SECONDS);if(output.length>32768)throw new IOException("Invalid provisioning output");
            if(process.exitValue()!=0)throw new IOException(new String(err.get(1,TimeUnit.SECONDS),StandardCharsets.UTF_8).trim());return new String(output,StandardCharsets.UTF_8);
        }finally{if(pin!=null)Arrays.fill(pin,'\0');if(management!=null)Arrays.fill(management,'\0');process.destroyForcibly();pool.shutdownNow();}
    }
    static void check(String serial)throws Exception{if(!run(serial,"check","level5",null,null,null).trim().equals("EMPTY"))throw new IOException("Could not establish empty YubiKey state");}
    static Map<String,PublicKey> create(String serial,TokenProfile profile,Path folder,char[] pin,char[] management)throws Exception{
        return decode(run(serial,"create",profile.code,folder,pin,management),true);
    }
    static Map<String,PublicKey> read(String serial,boolean hybrid,Path folder)throws Exception{return decode(run(serial,"read",hybrid?"hybrid":"pure",folder,null,null),hybrid);}
    static Map<String,PublicKey> read(String serial,TokenProfile profile,Path folder)throws Exception{return decode(run(serial,"read",profile.code,folder,null,null),true);}
    private static Map<String,PublicKey> decode(String output,boolean hybrid)throws Exception{var json=JsonParser.parseString(output).getAsJsonObject();Map<String,PublicKey> keys=new HashMap<>();
        for(String slot:hybrid?List.of("9c","9d","9a","82"):List.of("9c","9d")){
            String alg=slot.equals("9c")?"ML-DSA":slot.equals("9d")?"ML-KEM":"EC";
            keys.put(slot,KeyFactory.getInstance(alg,"BC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(json.get(slot).getAsString()))));
        }return keys;
    }
}
