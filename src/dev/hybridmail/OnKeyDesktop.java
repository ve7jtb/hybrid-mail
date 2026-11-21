package dev.hybridmail;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import com.google.gson.*;

/** One exclusive PC/SC connection, shared by Windows/macOS/Linux. */
final class OnKeyDesktop implements OpenPgpMigration.Card {
    private final Process process;
    private final BufferedReader reader;
    private final Writer writer;
    private final ExecutorService reads=Executors.newSingleThreadExecutor();
    OnKeyDesktop(int serial)throws Exception{this(serial,TokenProvision.helper());}
    OnKeyDesktop(int serial,java.nio.file.Path helper)throws Exception{
        process=new ProcessBuilder(helper.toString(),"objects",Integer.toString(serial)).start();
        reader=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8));writer=new OutputStreamWriter(process.getOutputStream(),StandardCharsets.UTF_8);
    }
    private JsonElement call(JsonObject request)throws Exception{
        writer.write(request.toString());writer.write('\n');writer.flush();
        String line=reads.submit(()->{StringBuilder s=new StringBuilder();for(int c;(c=reader.read())!=-1&&c!='\n';){if(s.length()>16384)throw new IOException("Card response too large");s.append((char)c);}return s.toString();}).get(45,TimeUnit.SECONDS);
        if(line.isEmpty())throw new IOException("Cannot access YubiKey: "+new String(process.getErrorStream().readNBytes(2048),StandardCharsets.UTF_8));
        var result=JsonParser.parseString(line).getAsJsonObject();if(result.has("error"))throw new IOException(result.get("error").getAsString());return result.get("value");
    }
    private JsonObject request(String op){var r=new JsonObject();r.addProperty("op",op);return r;}
    public int serial()throws Exception{return call(request("serial")).getAsInt();}
    public byte[] publicKey(String slot)throws Exception{var r=request("key");r.addProperty("slot",slot);var v=call(r);return v.isJsonNull()?null:Base64.getDecoder().decode(v.getAsString());}
    public byte[] get(int tag)throws Exception{var r=request("get");r.addProperty("tag",tag);var v=call(r);return v.isJsonNull()?null:Base64.getDecoder().decode(v.getAsString());}
    public void put(int tag,byte[] bytes)throws Exception{var r=request("put");r.addProperty("tag",tag);r.addProperty("data",Base64.getEncoder().encodeToString(bytes));call(r);}
    public void deleteObject(int tag)throws Exception{var r=request("delete");r.addProperty("tag",tag);call(r);}
    public void authenticate(char[] management)throws Exception{try{var r=request("auth");r.addProperty("management",new String(management));call(r);}finally{Arrays.fill(management,'\0');}}
    public void checkCertificationEmpty()throws Exception{call(request("certification-empty"));}
    public void generateCertification()throws Exception{call(request("certification-generate"));}
    public void move9aTo83()throws Exception{call(request("move"));}
    public void close(){try{writer.close();}catch(Exception ignored){}process.destroyForcibly();reads.shutdownNow();}
}
