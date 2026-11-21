package dev.hybridmail;
import java.io.*;
import java.security.*;
import java.util.*;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;

/** Two independent banks. Commit the manifest last; never retry a mutation automatically. */
public final class OnKeyStorage {
    public static final int CHUNK=2048,COUNT=32;
    private static final int[] BANK={0x5f5000,0x5f5100};
    private record Saved(int bank,long generation,byte[] bytes){}
    private static byte[] hash(byte[] bytes)throws Exception{return MessageDigest.getInstance("SHA-256").digest(bytes);}
    /**
     * Keep one compressed on-card copy, using verified local files for recovery.
     * The caller supplies an application-owned backup directory. A successful
     * return names the retained recovery folder; it contains PUBLIC data only.
     * No card mutation is permitted until all snapshot and replacement files
     * have been flushed and read back. An interrupted write may leave no valid
     * card bundle: use replacement.pqkey in that folder to resume explicitly.
     */
    public static Path saveSingle(OnKeyBundle.Card card,byte[] encoded,char[] management,Path backupRoot)throws Exception{
        Path backup=null;
        try{
            var bundle=OnKeyBundle.decode(encoded);OnKeyBundle.check(card,bundle.entries());OnKeyBundle.checkPgp(card,bundle.profiles());
            byte[] packed=pack(encoded);Saved old=latest(card);long generation=old==null?1:Math.addExact(old.generation,1);
            if(old!=null)OnKeyBundle.checkOrRecover(card,OnKeyBundle.decode(unpack(old.bytes)));
            var snapshot=new LinkedHashMap<Integer,byte[]>();
            // Both namespaces are scanned only for upgrading existing devices.
            // Writers always use bank A; bank B is removed, not replenished.
            for(int base:BANK)for(int i=0;i<=COUNT;i++){
                byte[] data=card.get(base+i);if(data==null)continue;
                var in=new DataInputStream(new ByteArrayInputStream(data));OnKeyBundle.magic(in,i==0?"PQMIDX01":"PQMCHK01");
                if(i==0){OnKeyBundle.require(data.length==52&&in.readLong()>0,"Unknown manifest; no objects removed");int n=in.readInt();OnKeyBundle.require(n>0&&n<=OnKeyBundle.MAX,"Invalid manifest size");}
                else OnKeyBundle.require(data.length>20&&data.length<=CHUNK+20&&in.readLong()>0&&in.readInt()==i-1,"Unknown chunk; no objects removed");
                snapshot.put(base+i,data);
            }
            Files.createDirectories(backupRoot);backup=Files.createDirectory(backupRoot.resolve("yubikey-"+bundle.serial()+"-"+UUID.randomUUID()));
            if(old!=null)durable(backup.resolve("previous.pqkey"),unpack(old.bytes));
            durable(backup.resolve("replacement.pqkey"),encoded);durable(backup.resolve("replacement.pqmzip"),packed);
            for(var object:snapshot.entrySet())durable(backup.resolve(String.format("object-%06x.bin",object.getKey())),object.getValue());
            String notice="PUBLIC certificate recovery backup; no private keys or credentials.\nSerial: "+bundle.serial()+"\nReplacement SHA-256: "+HexFormat.of().formatHex(hash(encoded))+"\nUse replacement.pqkey for an explicit resume if the on-key write is interrupted.\n";
            durable(backup.resolve("recovery.txt"),notice.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // Reparse the files actually read from storage before authorizing
            // deletion. Hashes alone do not establish certificate validity.
            OnKeyBundle.decode(Files.readAllBytes(backup.resolve("replacement.pqkey")));
            if(old!=null)OnKeyBundle.decode(Files.readAllBytes(backup.resolve("previous.pqkey")));
            card.authenticate(management);
            for(var object:snapshot.entrySet())OnKeyBundle.require(Arrays.equals(object.getValue(),card.get(object.getKey())),"Card changed since local backup; no objects removed");
            // Remove the inactive namespace first, then invalidate A's manifest
            // before deleting its chunks. A manifest is committed only after
            // every replacement chunk has been written and read back.
            for(int base:new int[]{BANK[1],BANK[0]})for(int i=0;i<=COUNT;i++)if(snapshot.containsKey(base+i)){
                card.deleteObject(base+i);OnKeyBundle.require(card.get(base+i)==null,"Object deletion not confirmed");
            }
            for(int i=0;i<(packed.length+CHUNK-1)/CHUNK;i++){
                var b=new ByteArrayOutputStream();var out=new DataOutputStream(b);out.writeBytes("PQMCHK01");out.writeLong(generation);out.writeInt(i);out.write(packed,i*CHUNK,Math.min(CHUNK,packed.length-i*CHUNK));
                byte[] chunk=b.toByteArray();card.put(BANK[0]+1+i,chunk);OnKeyBundle.require(Arrays.equals(chunk,card.get(BANK[0]+1+i)),"Chunk read-back mismatch");
            }
            var b=new ByteArrayOutputStream();var out=new DataOutputStream(b);out.writeBytes("PQMIDX01");out.writeLong(generation);out.writeInt(packed.length);out.write(hash(packed));card.put(BANK[0],b.toByteArray());
            Saved result=read(card,0);OnKeyBundle.require(result!=null&&Arrays.equals(result.bytes,packed),"Single-copy commit verification failed");
            OnKeyBundle.check(card,bundle.entries());OnKeyBundle.checkPgp(card,bundle.profiles());
            for(int i=0;i<=COUNT;i++)OnKeyBundle.require(card.get(BANK[1]+i)==null,"Unexpected second bank remains");
            durable(backup.resolve("complete.txt"),"PASS single compressed on-key copy verified\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return backup;
        }catch(Exception e){throw new IOException(backup==null?"Local backup/preflight failed; no on-key update started":"Bundle update stopped. Recovery files: "+backup+". Inspect before retrying; replacement.pqkey is the signed replacement.",e);}
        finally{Arrays.fill(management,'\0');}
    }
    private static void durable(Path file,byte[] data)throws Exception{
        try(var channel=FileChannel.open(file,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
            var buffer=ByteBuffer.wrap(data);while(buffer.hasRemaining())channel.write(buffer);channel.force(true);
        }
        OnKeyBundle.require(Arrays.equals(data,Files.readAllBytes(file)),"Local backup read-back mismatch");
    }
    private static Saved read(OnKeyBundle.Card card,int bank)throws Exception{
        byte[] manifest=card.get(BANK[bank]);if(manifest==null)return null;
        OnKeyBundle.require(manifest.length==52,"Truncated on-key manifest");var in=new DataInputStream(new ByteArrayInputStream(manifest));OnKeyBundle.magic(in,"PQMIDX01");long generation=in.readLong();int size=in.readInt();byte[] digest=in.readNBytes(32);
        OnKeyBundle.require(generation>0&&size>0&&size<=OnKeyBundle.MAX&&digest.length==32&&in.available()==0,"Invalid on-key manifest");
        var out=new ByteArrayOutputStream();for(int i=0;i<(size+CHUNK-1)/CHUNK;i++){
            byte[] bytes=card.get(BANK[bank]+1+i);if(bytes==null)return null;
            OnKeyBundle.require(bytes.length>=20,"Truncated on-key chunk");var chunk=new DataInputStream(new ByteArrayInputStream(bytes));OnKeyBundle.magic(chunk,"PQMCHK01");if(chunk.readLong()!=generation||chunk.readInt()!=i)return null;
            byte[] data=chunk.readAllBytes();if(data.length!=Math.min(CHUNK,size-i*CHUNK))return null;out.write(data);
        }byte[] bytes=out.toByteArray();if(!MessageDigest.isEqual(hash(bytes),digest))return null;try{OnKeyBundle.decode(unpack(bytes));}catch(Exception e){throw new OnKeyBundle.InvalidData("Invalid signed bank");}return new Saved(bank,generation,bytes);
    }
    private static Saved recoverableRead(OnKeyBundle.Card card,int bank)throws Exception{try{return read(card,bank);}catch(OnKeyBundle.InvalidData e){return null;}}
    private static Saved latest(OnKeyBundle.Card card)throws Exception{Saved a=recoverableRead(card,0),b=recoverableRead(card,1);return a==null?b:b==null?a:a.generation>=b.generation?a:b;}
    public static OnKeyBundle.Bundle load(OnKeyBundle.Card card)throws Exception{var found=latest(card);OnKeyBundle.require(found!=null,"No complete PQ Mail bundle found on this YubiKey");var bundle=OnKeyBundle.decode(unpack(found.bytes));return OnKeyBundle.checkOrRecover(card,bundle);}
    static byte[] pack(byte[] bytes)throws Exception{
        OnKeyBundle.require(bytes.length>0&&bytes.length<=OnKeyBundle.MAX,"Invalid bundle size");
        var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.writeBytes("PQMZIP01");o.writeInt(bytes.length);
        try(var z=new java.util.zip.DeflaterOutputStream(b)){z.write(bytes);}OnKeyBundle.require(b.size()<=OnKeyBundle.MAX,"Compressed bundle exceeds on-key capacity");return b.toByteArray();
    }
    static byte[] unpack(byte[] bytes)throws Exception{
        if(bytes.length<8||!Arrays.equals(Arrays.copyOf(bytes,8),"PQMZIP01".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))return bytes;
        OnKeyBundle.require(bytes.length>=12&&bytes.length<=OnKeyBundle.MAX,"Invalid compressed bundle length");
        var in=new DataInputStream(new ByteArrayInputStream(bytes));magicZip(in);int size=in.readInt();OnKeyBundle.require(size>0&&size<=OnKeyBundle.MAX,"Invalid compressed bundle size");
        var inflater=new java.util.zip.Inflater();try{inflater.setInput(in.readAllBytes());byte[] result=new byte[size];int n=0;
            while(n<size&&!inflater.finished()){int got=inflater.inflate(result,n,size-n);OnKeyBundle.require(got>0,"Truncated compressed bundle");n+=got;}
            byte[] extra=new byte[1];int more=inflater.inflate(extra);OnKeyBundle.require(n==size&&more==0&&inflater.finished()&&inflater.getRemaining()==0,"Invalid compressed bundle boundary");return result;
        }catch(java.util.zip.DataFormatException e){throw new OnKeyBundle.InvalidData("Invalid compressed bundle");}finally{inflater.end();}
    }
    private static void magicZip(DataInputStream in)throws Exception{OnKeyBundle.magic(in,"PQMZIP01");}
    public static void saveCompact(OnKeyBundle.Card card,byte[] bytes,char[] management)throws Exception{saveStored(card,pack(bytes),management);}
    /**
     * Explicit recovery for a full card with an interrupted inactive bank.
     * The signed, live-key-matched active bank is never deleted. A valid
     * inactive backup is also retained. Validate the entire target namespace
     * before authenticating: recognizable magic alone is insufficient to
     * authorize deleting an unrelated or malformed object's contents.
     * Keep the inactive manifest (the native helper forbids deleting it);
     * removing its incomplete chunks cannot make it a valid committed bank.
     * Callers should preserve a local public-object snapshot before recovery.
     */
    public static int reclaimIncompleteBank(OnKeyBundle.Card card,char[] management)throws Exception{
        try{return reclaimIncompleteBankAuthenticated(card,management);}finally{Arrays.fill(management,'\0');}
    }
    private static int reclaimIncompleteBankAuthenticated(OnKeyBundle.Card card,char[] management)throws Exception{
        Saved previous=latest(card);OnKeyBundle.require(previous!=null,"No valid backup; automatic reclamation refused");
        OnKeyBundle.checkOrRecover(card,OnKeyBundle.decode(unpack(previous.bytes)));
        int target=1-previous.bank;if(recoverableRead(card,target)!=null)return 0;
        byte[] manifest=card.get(BANK[target]);
        if(manifest!=null){
            OnKeyBundle.require(manifest.length==52,"Unrecognized inactive manifest; reclamation refused");
            var in=new DataInputStream(new ByteArrayInputStream(manifest));OnKeyBundle.magic(in,"PQMIDX01");
            long generation=in.readLong();int size=in.readInt();
            OnKeyBundle.require(generation>0&&size>0&&size<=OnKeyBundle.MAX,"Unrecognized inactive manifest fields");
        }
        var chunks=new LinkedHashMap<Integer,byte[]>();int reclaimed=0;
        for(int i=1;i<=COUNT;i++){
            byte[] bytes=card.get(BANK[target]+i);if(bytes==null)continue;
            OnKeyBundle.require(bytes.length>20&&bytes.length<=20+CHUNK,"Unrecognized inactive chunk size");
            var in=new DataInputStream(new ByteArrayInputStream(bytes));OnKeyBundle.magic(in,"PQMCHK01");
            OnKeyBundle.require(in.readLong()>0&&in.readInt()==i-1,"Unrecognized inactive chunk fields");
            chunks.put(BANK[target]+i,bytes);reclaimed+=bytes.length;
        }
        if(chunks.isEmpty())return 0;
        card.authenticate(management);
        for(var chunk:chunks.entrySet()){
            OnKeyBundle.require(Arrays.equals(chunk.getValue(),card.get(chunk.getKey())),"Inactive object changed; reclamation stopped");
            card.deleteObject(chunk.getKey());
            OnKeyBundle.require(card.get(chunk.getKey())==null,"Inactive chunk cleanup did not complete; inspect before retrying");
        }
        Saved after=read(card,previous.bank);
        OnKeyBundle.require(after!=null&&after.generation==previous.generation&&Arrays.equals(after.bytes,previous.bytes),"Active backup changed during reclamation");
        return reclaimed;
    }
    /** Reclaim only authenticated PQ Mail tail chunks after a fully verified commit. */
    public static void pruneCommittedTail(OnKeyBundle.Card card,char[] management)throws Exception{
        Saved saved=latest(card);OnKeyBundle.require(saved!=null,"No committed bundle to prune");OnKeyBundle.checkOrRecover(card,OnKeyBundle.decode(unpack(saved.bytes)));
        int first=(saved.bytes.length+CHUNK-1)/CHUNK+1;
        for(int i=first;i<=COUNT;i++){byte[] old=card.get(BANK[saved.bank]+i);if(old!=null)OnKeyBundle.magic(new DataInputStream(new ByteArrayInputStream(old)),"PQMCHK01");}
        card.authenticate(management);
        for(int i=first;i<=COUNT;i++)if(card.get(BANK[saved.bank]+i)!=null){card.deleteObject(BANK[saved.bank]+i);OnKeyBundle.require(card.get(BANK[saved.bank]+i)==null,"Tail cleanup did not complete");}
    }
    public static void save(OnKeyBundle.Card card,byte[] bytes,char[] management)throws Exception{
        saveCompact(card,bytes,management);
    }
    private static void saveStored(OnKeyBundle.Card card,byte[] bytes,char[] management)throws Exception{
        var bundle=OnKeyBundle.decode(unpack(bytes));OnKeyBundle.check(card,bundle.entries());OnKeyBundle.checkPgp(card,bundle.profiles());Saved previous=latest(card);int bank=previous==null?0:1-previous.bank;long generation=previous==null?1:Math.addExact(previous.generation,1);
        // Refuse namespace collisions, including unused tail objects. Never delete another app's data.
        for(int i=0;i<=COUNT;i++){byte[] existing=card.get(BANK[bank]+i);if(existing!=null){var in=new DataInputStream(new ByteArrayInputStream(existing));OnKeyBundle.magic(in,i==0?"PQMIDX01":"PQMCHK01");}}
        card.authenticate(management);
        for(int i=0;i<(bytes.length+CHUNK-1)/CHUNK;i++){
            var buffer=new ByteArrayOutputStream();var out=new DataOutputStream(buffer);out.writeBytes("PQMCHK01");out.writeLong(generation);out.writeInt(i);out.write(bytes,i*CHUNK,Math.min(CHUNK,bytes.length-i*CHUNK));byte[] chunk=buffer.toByteArray();card.put(BANK[bank]+1+i,chunk);OnKeyBundle.require(Arrays.equals(chunk,card.get(BANK[bank]+1+i)),"On-key chunk read-back failed; previous bank retained");
        }
        var buffer=new ByteArrayOutputStream();var out=new DataOutputStream(buffer);out.writeBytes("PQMIDX01");out.writeLong(generation);out.writeInt(bytes.length);out.write(hash(bytes));card.put(BANK[bank],buffer.toByteArray());
        Saved saved=read(card,bank);OnKeyBundle.require(saved!=null&&Arrays.equals(saved.bytes,bytes),"Commit verification failed; reconnect and import to inspect recovery state");
    }
}
