package dev.hybridmail;
import java.util.*;import java.io.*;
public class OnKeyCompactTest {
 static class Card implements OnKeyBundle.Card{
  Map<Integer,byte[]> objects=new HashMap<>();Map<String,byte[]> keys;int limit=200000,writes,fail=-1;boolean auth;
  public int serial(){return 123456;}public byte[] publicKey(String s){return keys.get(s);}public byte[] get(int t){return objects.get(t);}
  public void put(int t,byte[] b)throws Exception{if(!auth||writes++==fail)throw new IOException("Interrupted");int used=objects.values().stream().mapToInt(x->x.length).sum()-objects.getOrDefault(t,new byte[0]).length+b.length;if(used>limit)throw new IOException("Full");objects.put(t,b.clone());}
  public void deleteObject(int t)throws Exception{if(!auth||writes++==fail)throw new IOException("Interrupted cleanup");objects.remove(t);}
  public void authenticate(char[] p){auth=true;Arrays.fill(p,'\0');}public void move9aTo83(){throw new UnsupportedOperationException();}
  Card copy(){var c=new Card();c.objects.putAll(objects);c.keys=keys;c.limit=limit;return c;}
 }
 static void check(boolean ok){if(!ok)throw new AssertionError();}
 static void reject(byte[] b)throws Exception{try{OnKeyStorage.unpack(b);}catch(Exception expected){return;}throw new AssertionError("Malformed compression accepted");}
 public static void main(String[] args)throws Exception{
  MailEngine.init();byte[] raw=OnKeyBundleTest.fixture(TokenProfile.LEVEL3,"83",null);byte[] packed=OnKeyStorage.pack(raw);check(Arrays.equals(raw,OnKeyStorage.unpack(packed)));reject(Arrays.copyOf(packed,packed.length-1));reject(Arrays.copyOf(packed,packed.length+1));byte[] bomb=packed.clone();Arrays.fill(bomb,8,12,(byte)0x7f);reject(bomb);bomb=packed.clone();bomb[11]^=1;reject(bomb);
  var c=new Card();c.keys=OnKeyBundle.bindings(OnKeyBundle.decode(raw).entries());// Seed a pre-compression bank to exercise the temporary migration reader.
  for(int i=0;i<(raw.length+2047)/2048;i++){var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.writeBytes("PQMCHK01");o.writeLong(1);o.writeInt(i);o.write(raw,i*2048,Math.min(2048,raw.length-i*2048));c.objects.put(0x5f5001+i,b.toByteArray());}
  var manifest=new ByteArrayOutputStream();var m=new DataOutputStream(manifest);m.writeBytes("PQMIDX01");m.writeLong(1);m.writeInt(raw.length);m.write(java.security.MessageDigest.getInstance("SHA-256").digest(raw));c.objects.put(0x5f5000,manifest.toByteArray());check(Arrays.equals(raw,OnKeyStorage.load(c).encoded()));
  int operations=(packed.length+2047)/2048+1;
  for(int n=0;n<operations;n++){var failed=c.copy();failed.fail=n;try{OnKeyStorage.saveCompact(failed,raw,new char[]{'x'});}catch(IOException expected){}check(Arrays.equals(raw,OnKeyStorage.load(failed).encoded()));}
  // Model a full inactive bank left by an interrupted larger write.
  for(int i=1;i<=32;i++){var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.writeBytes("PQMCHK01");o.writeLong(2);o.writeInt(i-1);o.write(new byte[2048]);c.objects.put(0x5f5100+i,b.toByteArray());}
  c.limit=c.objects.values().stream().mapToInt(x->x.length).sum()+52;
  OnKeyStorage.saveCompact(c,raw,new char[]{'x'});var committed=c.copy();int before=c.objects.values().stream().mapToInt(x->x.length).sum();
  for(int cut=0;cut<32-(packed.length+2047)/2048;cut++){var failed=committed.copy();failed.fail=cut;try{OnKeyStorage.pruneCommittedTail(failed,new char[]{'x'});}catch(IOException expected){}check(Arrays.equals(raw,OnKeyStorage.load(failed).encoded()));}
  OnKeyStorage.pruneCommittedTail(c,new char[]{'x'});check(c.objects.values().stream().mapToInt(x->x.length).sum()<before);check(Arrays.equals(raw,OnKeyStorage.load(c).encoded()));
  OnKeyStorage.saveCompact(c,raw,new char[]{'x'});check(Arrays.equals(raw,OnKeyStorage.load(c).encoded()));
  System.out.println("PASS bounded decompression, malformed/trailing/truncated streams, every interrupted compressed write and cleanup, full-bank recovery and second commit");
 }
}
