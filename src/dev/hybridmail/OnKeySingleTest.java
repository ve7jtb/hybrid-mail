package dev.hybridmail;
import java.nio.file.*;import java.io.*;import java.util.*;
/** Single-copy storage: a durable recovery file must precede every mutation. */
public final class OnKeySingleTest {
 static final class Card extends OnKeyCompactTest.Card {
  final Path backupRoot;Card(Path p){backupRoot=p;}
  void backed()throws Exception{try(var dirs=Files.list(backupRoot)){
   var latest=dirs.filter(Files::isDirectory).max(Comparator.comparing(p->p.getFileName().toString())).orElseThrow();
   // Tests use a separate root per attempt, with exactly one recovery journal.
   OnKeyBundle.decode(Files.readAllBytes(latest.resolve("replacement.pqkey")));if(!Files.exists(latest.resolve("recovery.txt")))throw new IOException("Missing recovery manifest");
  }}
  public void deleteObject(int tag)throws Exception{backed();super.deleteObject(tag);}
  public void put(int tag,byte[] b)throws Exception{backed();super.put(tag,b);}
 }
 static void ok(boolean b){if(!b)throw new AssertionError();}
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path root=Files.createTempDirectory("single-copy-test-");
  try{
   byte[] raw=OnKeyBundleTest.fixture(TokenProfile.LEVEL3,"83",null);var keys=OnKeyBundle.bindings(OnKeyBundle.decode(raw).entries());
   var old=new OnKeyCompactTest.Card();old.keys=keys;OnKeyStorage.save(old,raw,new char[]{'x'});OnKeyStorage.save(old,raw,new char[]{'x'});
   var c=new Card(root.resolve("success"));c.keys=keys;c.objects.putAll(old.objects);c.objects.put(0x5fc105,new byte[]{1,2,3});
   int before=c.objects.values().stream().mapToInt(v->v.length).sum();Path backup=OnKeyStorage.saveSingle(c,raw,new char[]{'x'},c.backupRoot);
   ok(Arrays.equals(raw,Files.readAllBytes(backup.resolve("previous.pqkey"))));ok(Arrays.equals(raw,OnKeyStorage.load(c).encoded()));
   ok(c.objects.keySet().stream().noneMatch(t->t>=0x5f5100&&t<=0x5f5120));ok(c.objects.values().stream().mapToInt(v->v.length).sum()<before);
   int operations=c.writes;
   for(int i=0;i<operations;i++){
    var bad=new Card(root.resolve("failure-"+i));bad.keys=keys;bad.objects.putAll(old.objects);bad.fail=i;
    OnKeyBundleTest.fails(()->OnKeyStorage.saveSingle(bad,raw,new char[]{'x'},bad.backupRoot));
    Path recovery;try(var dirs=Files.list(bad.backupRoot)){recovery=dirs.findFirst().orElseThrow();}
    ok(Arrays.equals(raw,OnKeyBundle.decode(Files.readAllBytes(recovery.resolve("replacement.pqkey"))).encoded()));
    // Explicitly resume from the locally saved signed bundle, even if the
    // active on-card manifest has already been deleted. No signing needed.
    bad.fail=-1;Path resume=root.resolve("resume-"+i);OnKeyStorage.saveSingle(bad,raw,new char[]{'x'},resume);
    ok(Arrays.equals(raw,OnKeyStorage.load(bad).encoded()));
   }
   var failBackup=new Card(root.resolve("not-directory"));failBackup.keys=keys;failBackup.objects.putAll(old.objects);Files.writeString(failBackup.backupRoot,"blocked");
   OnKeyBundleTest.fails(()->OnKeyStorage.saveSingle(failBackup,raw,new char[]{'x'},failBackup.backupRoot));ok(failBackup.writes==0&&!failBackup.auth);
   var collision=new Card(root.resolve("collision"));collision.keys=keys;collision.objects.putAll(old.objects);collision.objects.put(0x5f5120,new byte[]{1});
   OnKeyBundleTest.fails(()->OnKeyStorage.saveSingle(collision,raw,new char[]{'x'},collision.backupRoot));ok(collision.writes==0);
   ok(Arrays.equals(c.objects.get(0x5fc105),new byte[]{1,2,3}));
   System.out.println("PASS single-copy storage, durable local recovery before all mutations, "+operations+" interrupted deletes/writes and explicit resumes, failed local backup, namespace collision, reclaimed second bank and unchanged certificate objects");
  }finally{try(var files=Files.walk(root)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
