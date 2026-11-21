package dev.hybridmail;

import static dev.hybridmail.OpenPgp.check;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.util.*;
import java.util.zip.DeflaterOutputStream;

/** Untrusted compression framing must fail before any card private operation. */
public final class CompanionEncodingTest {
    interface Action {void run() throws Exception;}
    static void reject(Action action) throws Exception {
        try {action.run();throw new AssertionError("Expected compressed input rejection");}
        catch(IOException expected) { }
    }
    static byte[] wrap(byte[] inner, int declared) throws Exception {
        var out=new java.io.ByteArrayOutputStream();out.write(CompanionEncoding.MAGIC);
        out.write(ByteBuffer.allocate(4).putInt(declared).array());
        try(var zip=new DeflaterOutputStream(out)){zip.write(inner);}
        return out.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        byte[] raw=new byte[46412];new Random(42).nextBytes(raw);
        System.arraycopy(raw,0,raw,10000,7000); // Repeated public material.
        byte[] packed=CompanionEncoding.pack(raw);
        check(packed.length<raw.length,"Repeated public data did not compress");
        check(Arrays.equals(raw,CompanionEncoding.unpack(packed)),"Compaction changed signed bytes");
        check(Arrays.equals(raw,CompanionEncoding.unpack(raw)),"Original representation changed");
        check(Arrays.equals(packed,CompanionEncoding.pack(packed)),"Double packing changed representation");
        for(int cut: new int[]{1,8,11,12,packed.length-1})
            if(cut>=8) reject(()->CompanionEncoding.unpack(Arrays.copyOf(packed,cut)));
        reject(()->CompanionEncoding.unpack(Arrays.copyOf(packed,packed.length+1)));
        reject(()->CompanionEncoding.unpack(wrap(raw,raw.length-1)));
        reject(()->CompanionEncoding.unpack(wrap(raw,raw.length+1)));
        reject(()->CompanionEncoding.unpack(wrap(raw,-1)));
        reject(()->CompanionEncoding.unpack(wrap(packed,packed.length)));
        reject(()->CompanionEncoding.unpack(wrap(new byte[65537],65536)));
        reject(()->CompanionEncoding.unpack(new byte[65537]));
        byte[] broken=packed.clone();broken[broken.length-1]^=1;
        reject(()->CompanionEncoding.unpack(broken));
        check(CompanionEncoding.unpack(wrap(new byte[65536],65536)).length==65536,"Bounded maximum rejected");
        if(args.length==1){
            Path directory=Path.of(args[0]);byte[] original=Files.readAllBytes(directory.resolve("companion.pqcomp"));
            byte[] compact=CompanionEncoding.pack(original);
            var keys=new LinkedHashMap<String,java.security.PublicKey>();
            MailEngine.init();for(String slot:Level5Companion.SLOTS)keys.put(slot,Level5Companion.decodePublic(Files.readAllBytes(directory.resolve(slot+".der"))));
            int serial=CompanionDesktop.serial(original);
            var before=Level5Companion.inspect(original,serial,keys);var after=Level5Companion.inspect(compact,serial,keys);
            check(Arrays.equals(before.own().encoded,after.own().encoded)&&Arrays.equals(before.ciphertext(),after.ciphertext())&&Arrays.equals(before.aad(),after.aad()),"Compaction altered certificate, ciphertext or AAD");
            check(CompanionDesktop.serial(compact)==serial,"Compressed serial parsing failed");
            System.out.println("PASS existing signed companion offline validation: "+original.length+" -> "+compact.length+" bytes; signature, certificate, ciphertext and AAD preserved");
        }
        System.out.println("PASS bounded compression, exact original preservation, malformed/truncated/trailing/nested/oversized rejection");
    }
}
