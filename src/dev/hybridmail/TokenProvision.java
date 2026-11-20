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
        if(!operation.equals("detect")&&!serial.matches("[0-9]+"))throw new IOException("Enter the intended YubiKey serial");
        boolean create=operation.equals("create")||operation.equals("resume");
        if(create){
            boolean valid=pin!=null&&pin.length>=6&&pin.length<=8&&management!=null&&(management.length==32||management.length==48||management.length==64);
            if(pin!=null)for(char c:pin)valid&=c>=32&&c<=126;
            if(management!=null)for(char c:management)valid&=c<128&&Character.digit(c,16)>=0;
            if(!valid){if(pin!=null)Arrays.fill(pin,'\0');if(management!=null)Arrays.fill(management,'\0');throw new IOException("Use a 6–8 character ASCII YubiKey PIN and a valid hexadecimal management key");}
        }
        List<String> command=new ArrayList<>(List.of(helper().toString(),operation));
        if(!operation.equals("detect"))command.add(serial);
        if(create||operation.equals("read"))command.addAll(List.of(profile,folder.toString()));
        Process process=new ProcessBuilder(command).start();var pool=Executors.newFixedThreadPool(2);
        try{
            var out=pool.submit(()->process.getInputStream().readNBytes(32769));var err=pool.submit(()->process.getErrorStream().readNBytes(2049));
            try(var input=process.getOutputStream()){if(create){for(char c:pin)input.write((byte)c);input.write('\n');for(char c:management)input.write((byte)c);input.write('\n');}}
            if(!process.waitFor(create?300:60,TimeUnit.SECONDS))throw new IOException("YubiKey provisioning timed out; do not retry generation if any slot was created");
            byte[] output=out.get(1,TimeUnit.SECONDS);if(output.length>32768)throw new IOException("Invalid provisioning output");
            if(process.exitValue()!=0)throw new IOException(new String(err.get(1,TimeUnit.SECONDS),StandardCharsets.UTF_8).trim());return new String(output,StandardCharsets.UTF_8);
        }finally{if(pin!=null)Arrays.fill(pin,'\0');if(management!=null)Arrays.fill(management,'\0');process.destroyForcibly();pool.shutdownNow();}
    }
    static String detectEmpty()throws Exception{
        String serial=run("","detect","",null,null,null).trim();
        if(!serial.matches("[0-9]+"))throw new IOException("Cannot identify the inserted YubiKey");return serial;
    }
    static void check(String serial)throws Exception{if(!run(serial,"check","level5",null,null,null).trim().equals("EMPTY"))throw new IOException("Could not establish empty YubiKey state");}
    static Map<String,PublicKey> create(String serial,TokenProfile profile,Path folder,char[] pin,char[] management)throws Exception{
        return decode(run(serial,"create",nativeProfile(profile),folder,pin,management),true);
    }
    static Map<String,PublicKey> read(String serial,boolean hybrid,Path folder)throws Exception{return decode(run(serial,"read",hybrid?"hybrid":"pure",folder,null,null),hybrid);}
    static Map<String,PublicKey> read(String serial,TokenProfile profile,Path folder)throws Exception{return decode(run(serial,"read",readProfile(profile,folder),folder,null,null),true);}
    static String nativeProfile(TokenProfile profile){return profile==TokenProfile.LEVEL3?"level3-openpgp":profile.code;}
    static String readProfile(TokenProfile profile,Path folder){return profile==TokenProfile.LEVEL3&&(Files.exists(folder.resolve("provisioning.json"))||Files.exists(folder.resolve("86-public.der")))?"level3-openpgp":profile.code;}
    static Map<String,PublicKey> resume(String serial,TokenProfile profile,Path folder,char[] pin,char[] management)throws Exception{
        return decode(run(serial,Files.exists(folder)?"resume":"create",nativeProfile(profile),folder,pin,management),true);
    }
    static boolean allKeysSaved(TokenProfile profile,Path folder){for(String s:profile==TokenProfile.LEVEL3?List.of("9c","9d","83","82","84","85","86","87","88","89"):profile==TokenProfile.LEVEL5?List.of("9c","9d","83","82","84","85","88","89"):List.of("9c","9d","83","82"))if(!Files.isRegularFile(folder.resolve(s+"-public.der")))return false;return true;}
    static Map<String,PublicKey> decode(String output,boolean hybrid)throws Exception{var json=JsonParser.parseString(output).getAsJsonObject();Map<String,PublicKey> keys=new HashMap<>();
        for(String slot:hybrid?List.of("9c","9d",json.has("83")?"83":"9a","82"):List.of("9c","9d")){
            String alg=slot.equals("9c")?"ML-DSA":slot.equals("9d")?"ML-KEM":"EC";
            keys.put(slot,KeyFactory.getInstance(alg,"BC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(json.get(slot).getAsString()))));
        }
        for(String slot:List.of("84","85","86","87","88","89"))if(json.has(slot)){boolean level3=json.has("86");String alg=switch(slot){case "84"->level3?"Ed25519":"ML-KEM";case "85"->"X25519";case "86"->"ML-DSA";case "87"->"Ed25519";case "88"->level3?"Ed25519":"EC";default->level3?"X25519":"EC";};keys.put(slot,KeyFactory.getInstance(alg,"BC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(json.get(slot).getAsString()))));}
        return keys;
    }
}
