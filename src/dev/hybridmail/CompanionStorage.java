package dev.hybridmail;
import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** One bounded companion bank, disjoint from public bundles and PIV certificates.
 * Writes require a durable ciphertext recovery copy first; the manifest commits last.
 * A partial first write is recovered explicitly from that copy, never by regenerating keys.
 */
final class CompanionStorage {
    static final int BASE=0x5f5200,CHUNK=2048,COUNT=32;
    static Map<String,PublicKey> hardware(OnKeyBundle.Card card)throws Exception{
        var keys=new LinkedHashMap<String,PublicKey>();
        for(String slot:Level5Companion.SLOTS){byte[] spki=card.publicKey(slot);check(spki!=null,"Missing companion hardware key in "+slot);keys.put(slot,Level5Companion.decodePublic(spki));}
        Level5Companion.validateHardware(card.serial(),keys);return keys;
    }
    static byte[] load(OnKeyBundle.Card card)throws Exception{
        byte[] manifest=card.get(BASE);check(manifest!=null&&manifest.length==44,"No complete encrypted companion on this key");var in=new DataInputStream(new ByteArrayInputStream(manifest));check(Arrays.equals(in.readNBytes(8),bytes("PQCIDX01")),"Unknown companion manifest");int size=in.readInt();byte[] digest=in.readNBytes(32);check(size>0&&size<=Level5Companion.MAX,"Invalid companion size");var out=new ByteArrayOutputStream();
        for(int i=0;i<(size+CHUNK-1)/CHUNK;i++){byte[] chunk=card.get(BASE+i+1);check(chunk!=null&&chunk.length==12+Math.min(CHUNK,size-i*CHUNK),"Incomplete companion; restore local ciphertext backup");var r=new DataInputStream(new ByteArrayInputStream(chunk));check(Arrays.equals(r.readNBytes(8),bytes("PQCCHK01"))&&r.readInt()==i,"Wrong companion chunk");out.write(r.readAllBytes());}
        byte[] encoded=out.toByteArray();check(MessageDigest.isEqual(hash("SHA-256",encoded),digest),"Companion digest mismatch");check(Arrays.equals(card.get(BASE),manifest),"Companion changed while reading");inspectOnCard(card,encoded);return encoded;
    }
    static int storedSize(byte[] encoded){return encoded.length+44+12*((encoded.length+CHUNK-1)/CHUNK);}
    /** Dispatch only on a bounded format discriminator, then authenticate every
     * field against the live keys. A serial or unverified manifest is not trust. */
    static void inspectOnCard(OnKeyBundle.Card card,byte[] encoded)throws Exception{
        byte[] expanded=CompanionEncoding.unpack(encoded);var in=new DataInputStream(new ByteArrayInputStream(expanded));byte[] body=Level5Companion.field(in);
        check(body.length>=8,"Truncated companion body");
        if(Arrays.equals(Arrays.copyOf(body,8),bytes("PQMCP003")))Level3Companion.inspect(encoded,card.serial(),Level3PolyfillDesktop.hardware(card));
        else Level5Companion.inspect(encoded,card.serial(),hardware(card));
    }

    /** Re-encode the SAME authenticated envelope in the smaller storage format.
     * No private operation, key generation or certificate change is involved.
     * The single bank is briefly unavailable: recovery copies must reach disk
     * before its commit marker is removed, and the new marker is written last.
     */
    static void replaceCompact(OnKeyBundle.Card card,byte[] previous,byte[] replacement,char[] management,Path recoveryDir)throws Exception{
        replace(card,previous,replacement,management,recoveryDir,false);
    }

    /** Ultra conversion changes the signed envelope and AEAD, but must retain
     * the authenticated certificate template and every component public key.
     * Only the explicit conversion entry point permits this stronger change. */
    static void replaceUltra(OnKeyBundle.Card card,byte[] previous,byte[] replacement,char[] management,Path recoveryDir)throws Exception{
        replace(card,previous,replacement,management,recoveryDir,true);
    }

    private static void replace(OnKeyBundle.Card card,byte[] previous,byte[] replacement,char[] management,Path recoveryDir,boolean ultra)throws Exception{
        try{
            int serial=card.serial();validateReplacement(card,serial,previous,replacement,ultra);
            var before=snapshot(card);var oldObjects=objects(previous);
            sameSnapshot(before,oldObjects,"Companion namespace differs from the committed original; no objects changed");
            check(Arrays.equals(load(card),previous),"Current companion differs from the requested original");
            stage(recoveryDir,"previous.pqcomp",previous);
            stage(recoveryDir,"replacement.pqcomp",replacement);
            // Snapshot absence as well as content for ALL 33 reserved objects.
            // It prevents recovery from mistaking an unrelated tail for ours.
            stage(recoveryDir,"namespace.snapshot",snapshotBytes(serial,before));
            syncDirectory(recoveryDir);
            card.authenticate(management);
            sameSnapshot(snapshot(card),before,"Card changed during authentication; no objects changed");
            validateReplacement(card,serial,previous,replacement,ultra);
            rewrite(card,before,replacement);
        }finally{Arrays.fill(management,'\0');}
    }

    /** Explicit recovery after an interrupted compact replacement. A failure
     * while deleting old chunks cannot use save(), because old and new chunk
     * contents differ. This journal authorizes cleanup only of exact old/new
     * objects; unknown content causes a stop, never a speculative overwrite.
     */
    static void resumeCompact(OnKeyBundle.Card card,Path recoveryDir,char[] management)throws Exception{
        resume(card,recoveryDir,management,false);
    }

    /** Recovery reuses the exact staged ciphertext; it never regenerates keys
     * or repeats certificate signing after a partial card write. */
    static void resumeUltra(OnKeyBundle.Card card,Path recoveryDir,char[] management)throws Exception{
        resume(card,recoveryDir,management,true);
    }

    private static void resume(OnKeyBundle.Card card,Path recoveryDir,char[] management,boolean ultra)throws Exception{
        try{
            byte[] previous=readBackup(recoveryDir.resolve("previous.pqcomp"),Level5Companion.MAX);
            byte[] replacement=readBackup(recoveryDir.resolve("replacement.pqcomp"),Level5Companion.MAX);
            int serial=card.serial();validateReplacement(card,serial,previous,replacement,ultra);
            var oldObjects=objects(previous);var newObjects=objects(replacement);
            check(Arrays.equals(readBackup(recoveryDir.resolve("namespace.snapshot"),70000),snapshotBytes(serial,oldObjects)),"Recovery namespace snapshot differs from the original companion");
            var before=snapshot(card);
            for(int tag=BASE;tag<=BASE+COUNT;tag++){
                byte[] value=before.get(tag);
                check(value==null||Arrays.equals(value,oldObjects.get(tag))||Arrays.equals(value,newObjects.get(tag)),"Unknown companion object; recovery stopped without changes");
            }
            // A manifest can only survive before deletion or after a complete
            // write. Refuse a purported committed bank with missing/mixed data.
            if(Arrays.equals(before.get(BASE),newObjects.get(BASE))){sameSnapshot(before,newObjects,"Incomplete committed replacement");check(Arrays.equals(load(card),replacement),"Restored companion mismatch");return;}
            if(before.get(BASE)!=null)sameSnapshot(before,oldObjects,"Incomplete committed original");
            // Re-flush the verified journal on explicit recovery as well: it
            // may have been copied to this directory after the first failure.
            stage(recoveryDir,"previous.pqcomp",previous);stage(recoveryDir,"replacement.pqcomp",replacement);stage(recoveryDir,"namespace.snapshot",snapshotBytes(serial,oldObjects));syncDirectory(recoveryDir);
            card.authenticate(management);
            sameSnapshot(snapshot(card),before,"Card changed during recovery authentication; no objects changed");
            validateReplacement(card,serial,previous,replacement,ultra);
            rewrite(card,before,replacement);
        }finally{Arrays.fill(management,'\0');}
    }

    private static void validateReplacement(OnKeyBundle.Card card,int serial,byte[] previous,byte[] replacement,boolean ultra)throws Exception{
        check(card.serial()==serial,"Companion card changed");
        check(previous.length<=Level5Companion.MAX&&replacement.length<previous.length,"Replacement must be a smaller companion");
        var keys=hardware(card);
        var oldEnvelope=Level5Companion.inspect(previous,serial,keys);var newEnvelope=Level5Companion.inspect(replacement,serial,keys);
        if(ultra){
            check(!oldEnvelope.ultra()&&newEnvelope.ultra(),"Expected full-to-ultra conversion");
            // compare templates only AFTER validating both hardware signatures.
            // A different but valid identity on the same token is not a conversion.
            check(Arrays.equals(UltraCertificate.template(oldEnvelope.own()),newEnvelope.template()),"Ultra conversion changed certificate keys or metadata");
        }else check(Arrays.equals(CompanionEncoding.unpack(previous),CompanionEncoding.unpack(replacement)),"Compaction must preserve the exact signed envelope");
    }
    private static Map<Integer,byte[]> objects(byte[] encoded)throws Exception{
        var result=new LinkedHashMap<Integer,byte[]>();
        for(int i=0;i<(encoded.length+CHUNK-1)/CHUNK;i++){
            var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.write(OpenPgp.bytes("PQCCHK01"));out.writeInt(i);out.write(encoded,i*CHUNK,Math.min(CHUNK,encoded.length-i*CHUNK));result.put(BASE+i+1,bytes.toByteArray());
        }
        var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.write(OpenPgp.bytes("PQCIDX01"));out.writeInt(encoded.length);out.write(hash("SHA-256",encoded));result.put(BASE,bytes.toByteArray());return result;
    }
    private static Map<Integer,byte[]> snapshot(OnKeyBundle.Card card)throws Exception{
        var result=new LinkedHashMap<Integer,byte[]>();for(int tag=BASE;tag<=BASE+COUNT;tag++){byte[] value=card.get(tag);result.put(tag,value==null?null:value.clone());}return result;
    }
    private static void sameSnapshot(Map<Integer,byte[]> actual,Map<Integer,byte[]> expected,String message)throws Exception{
        for(int tag=BASE;tag<=BASE+COUNT;tag++)check(Arrays.equals(actual.get(tag),expected.get(tag)),message);
    }
    private static byte[] snapshotBytes(int serial,Map<Integer,byte[]> snapshot)throws Exception{
        var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.write(OpenPgp.bytes("PQCSNP01"));out.writeInt(serial);out.writeInt(COUNT+1);
        for(int tag=BASE;tag<=BASE+COUNT;tag++){byte[] value=snapshot.get(tag);out.writeInt(tag);out.writeInt(value==null?-1:value.length);if(value!=null)out.write(value);}return bytes.toByteArray();
    }
    private static void stage(Path directory,String name,byte[] value)throws Exception{
        Files.createDirectories(directory);check(!Files.isSymbolicLink(directory),"Recovery directory must not be a symbolic link");Path path=directory.resolve(name);
        if(Files.exists(path,LinkOption.NOFOLLOW_LINKS))check(Arrays.equals(readBackup(path,value.length),value),"Recovery file differs: "+name);
        else try(var channel=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){var buffer=ByteBuffer.wrap(value);while(buffer.hasRemaining())channel.write(buffer);channel.force(true);}
        check(Arrays.equals(readBackup(path,value.length),value),"Recovery file read-back failed: "+name);
        try(var channel=FileChannel.open(path,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)){channel.force(true);}
    }
    private static byte[] readBackup(Path path,int max)throws Exception{
        check(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)>0&&Files.size(path)<=max,"Missing or invalid companion recovery file");
        try(var in=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){byte[] value=in.readNBytes(max+1);check(value.length>0&&value.length<=max&&in.read()==-1,"Companion recovery file exceeds its limit");return value;}
    }
    private static void syncDirectory(Path directory)throws Exception{
        // On systems that cannot flush directories this replacement stops before
        // touching the card, rather than claiming a durable recovery journal.
        try(var channel=FileChannel.open(directory,StandardOpenOption.READ)){channel.force(true);}
        Path parent=directory.toAbsolutePath().getParent();if(parent!=null)try(var channel=FileChannel.open(parent,StandardOpenOption.READ)){channel.force(true);}
    }
    private static void rewrite(OnKeyBundle.Card card,Map<Integer,byte[]> before,byte[] replacement)throws Exception{
        // Invalidate the old commit first. After a lost acknowledgement the
        // explicit recovery path accepts the object as either present or absent.
        for(int tag=BASE;tag<=BASE+COUNT;tag++)if(before.get(tag)!=null){
            check(Arrays.equals(card.get(tag),before.get(tag)),"Companion object changed before removal");card.deleteObject(tag);check(card.get(tag)==null,"Companion object removal failed; retain recovery files");
        }
        sameSnapshot(snapshot(card),Map.of(),"Companion namespace changed during cleanup");
        // objects() deliberately inserts chunks before the manifest. Read back
        // every chunk before publishing a complete, digest-protected bank.
        for(var entry:objects(replacement).entrySet()){
            check(card.get(entry.getKey())==null,"Companion object appeared during replacement");card.put(entry.getKey(),entry.getValue());check(Arrays.equals(card.get(entry.getKey()),entry.getValue()),"Companion replacement read-back failed; retain recovery files");
        }
        sameSnapshot(snapshot(card),objects(replacement),"Unexpected companion tail after replacement");check(Arrays.equals(load(card),replacement),"Committed compact companion restore mismatch");
    }
    /** Only initialize an empty companion namespace, or resume EXACTLY the same
     * locally backed-up ciphertext. Existing different companions are preserved. */
    static void save(OnKeyBundle.Card card,byte[] encoded,char[] management,Path recovery)throws Exception{
        try{
            inspectOnCard(card,encoded);
            var expected=new LinkedHashMap<Integer,byte[]>();
            for(int i=0;i<(encoded.length+CHUNK-1)/CHUNK;i++){var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.write(bytes("PQCCHK01"));o.writeInt(i);o.write(encoded,i*CHUNK,Math.min(CHUNK,encoded.length-i*CHUNK));expected.put(BASE+1+i,b.toByteArray());}
            var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.write(bytes("PQCIDX01"));o.writeInt(encoded.length);o.write(hash("SHA-256",encoded));expected.put(BASE,b.toByteArray());
            // Compare EVERY allocated object, including the unused tail. This
            // prevents namespace collisions and refuses implicit replacement.
            for(int i=0;i<=COUNT;i++){byte[] old=card.get(BASE+i);check(old==null||Arrays.equals(old,expected.get(BASE+i)),"Existing companion differs; no objects changed");}
            Files.createDirectories(recovery.getParent());
            if(Files.exists(recovery))check(Arrays.equals(Files.readAllBytes(recovery),encoded),"Recovery file differs");
            else{try(var channel=FileChannel.open(recovery,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){var bytes=ByteBuffer.wrap(encoded);while(bytes.hasRemaining())channel.write(bytes);channel.force(true);}}
            check(Arrays.equals(Files.readAllBytes(recovery),encoded),"Recovery backup read-back failed");
            syncDirectory(recovery.getParent());
            card.authenticate(management);
            for(var entry:expected.entrySet()){byte[] old=card.get(entry.getKey());check(old==null||Arrays.equals(old,entry.getValue()),"Card changed since preflight");if(old==null)card.put(entry.getKey(),entry.getValue());check(Arrays.equals(card.get(entry.getKey()),entry.getValue()),"Companion write read-back failed; retain local ciphertext for explicit resume");}
            check(Arrays.equals(load(card),encoded),"Committed companion restore mismatch");
        }finally{Arrays.fill(management,'\0');}
    }
}
