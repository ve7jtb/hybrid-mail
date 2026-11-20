package dev.hybridmail;
import java.io.*;
import java.security.*;
import java.util.*;

/** Two independent banks. Commit the manifest last; never retry a mutation automatically. */
public final class OnKeyStorage {
    public static final int CHUNK=2048,COUNT=32;
    private static final int[] BANK={0x5f5000,0x5f5100};
    private record Saved(int bank,long generation,byte[] bytes){}
    private static byte[] hash(byte[] bytes)throws Exception{return MessageDigest.getInstance("SHA-256").digest(bytes);}
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
