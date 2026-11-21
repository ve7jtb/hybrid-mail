package dev.hybridmail;
import java.io.*;import java.util.*;
/** Full-card fault injection: recovery must always leave the signed bank intact. */
public final class OnKeyRecoveryTest {
 static void ok(boolean value){if(!value)throw new AssertionError();}
 static final class Card extends OnKeyCompactTest.Card {
  public void put(int tag,byte[] data)throws Exception {
   // Model storage engines that allocate a replacement before freeing the old object.
   int used=objects.values().stream().mapToInt(b->b.length).sum();
   if(used+data.length>limit)throw new IOException("No replacement allocation space");
   super.put(tag,data);
  }
  Card cloneCard(){var c=new Card();c.objects.putAll(objects);c.keys=keys;c.limit=limit;return c;}
 }
 static byte[] chunk(int index)throws Exception{var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.writeBytes("PQMCHK01");o.writeLong(2);o.writeInt(index);o.write(new byte[2048]);return b.toByteArray();}
 public static void main(String[] args)throws Exception{
  MailEngine.init();byte[] raw=OnKeyBundleTest.fixture(TokenProfile.LEVEL3,"83",null);
  var card=new Card();card.keys=OnKeyBundle.bindings(OnKeyBundle.decode(raw).entries());OnKeyStorage.save(card,raw,new char[]{'x'});
  for(int i=0;i<20;i++)card.objects.put(0x5f5101+i,chunk(i));
  var outside=new byte[]{1,2,3};card.objects.put(0x5fc105,outside);card.limit=card.objects.values().stream().mapToInt(b->b.length).sum()+1024;
  var active=new HashMap<Integer,byte[]>();for(var e:card.objects.entrySet())if(e.getKey()>=0x5f5000&&e.getKey()<=0x5f5020)active.put(e.getKey(),e.getValue());
  OnKeyBundleTest.fails(()->OnKeyStorage.save(card,raw,new char[]{'x'}));
  for(int cut=0;cut<20;cut++){
   var failed=card.cloneCard();failed.fail=cut;
   OnKeyBundleTest.fails(()->OnKeyStorage.reclaimIncompleteBank(failed,new char[]{'x'}));
   ok(Arrays.equals(raw,OnKeyStorage.load(failed).encoded()));
   for(var e:active.entrySet())ok(Arrays.equals(e.getValue(),failed.objects.get(e.getKey())));
   ok(Arrays.equals(outside,failed.objects.get(0x5fc105)));
  }
  var collision=card.cloneCard();collision.objects.put(0x5f5120,new byte[]{1});
  OnKeyBundleTest.fails(()->OnKeyStorage.reclaimIncompleteBank(collision,new char[]{'x'}));ok(collision.writes==0);
  var wrong=card.cloneCard();wrong.objects.put(0x5f5120,chunk(9));
  OnKeyBundleTest.fails(()->OnKeyStorage.reclaimIncompleteBank(wrong,new char[]{'x'}));ok(wrong.writes==0);
  var noBackup=card.cloneCard();noBackup.objects.remove(0x5f5000);
  OnKeyBundleTest.fails(()->OnKeyStorage.reclaimIncompleteBank(noBackup,new char[]{'x'}));ok(noBackup.writes==0);
  int freed=OnKeyStorage.reclaimIncompleteBank(card,new char[]{'x'});ok(freed==20*(2048+20));
  ok(Arrays.equals(raw,OnKeyStorage.load(card).encoded()));OnKeyStorage.save(card,raw,new char[]{'x'});
  int writes=card.writes;ok(OnKeyStorage.reclaimIncompleteBank(card,new char[]{'x'})==0&&card.writes==writes);
  System.out.println("PASS full-card allocation recovery; all 20 interrupted deletions preserve active signed backup; foreign objects, wrong indexes and missing backup rejected; valid inactive bank retained; compressed write succeeds");
 }
}
