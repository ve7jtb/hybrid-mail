package dev.hybridmail;
import java.io.*;
import java.nio.file.*;
import java.util.*;
public final class OnKeyBundleTest {
    static void check(boolean ok)throws Exception{if(!ok)throw new Exception("Assertion failed");}
    interface Action{void run()throws Exception;}
    static void fails(Action action)throws Exception{try{action.run();}catch(Exception expected){return;}throw new Exception("Expected rejection");}
    static final class Fake implements OnKeyBundle.Card {
        Map<Integer,byte[]> objects=new HashMap<>();Map<String,byte[]> keys=new HashMap<>();int writes,failAt=-1,serial=123456;boolean auth,moved;
        public int serial(){return serial;}
        public byte[] publicKey(String s){return keys.get(s);}
        public byte[] get(int tag){return objects.get(tag);}
        public void put(int tag,byte[] data)throws Exception{check(auth);if(writes++==failAt)throw new IOException("Injected full/interrupted write");objects.put(tag,data.clone());}
        public void authenticate(char[] chars){auth=true;Arrays.fill(chars,'\0');}
        public void move9aTo83()throws Exception{check(!keys.containsKey("83"));keys.put("83",keys.remove("9a"));moved=true;}
        Fake copy(){var f=new Fake();f.objects.putAll(objects);f.keys.putAll(keys);return f;}
    }
    public static byte[] fixture(TokenProfile profile,String slot,Path directory)throws Exception{
        var ids=Identity.generateSoftwareProfile("onkey@example.com",profile,List.of("alias@example.com"));List<OnKeyBundle.Profile> profiles=new ArrayList<>();
        for(var id:ids){byte[] pgp=OpenPgp.supported(id)?OpenPgp.create(id,null).encoded:new byte[0];profiles.add(new OnKeyBundle.Profile(new CertificateBundle.Entry(id,123456,"9c",slot,"9d","82"),pgp));}
        byte[] payload=OnKeyBundle.payload(profiles);var signer=ids.get(1).signer(null);signer.getOutputStream().write(payload);var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeBytes("PQMAILS1");OnKeyBundle.blob(out,payload);out.writeInt(1);OnKeyBundle.blob(out,signer.getSignature());byte[] encoded=bytes.toByteArray();OnKeyBundle.decode(encoded);
        if(directory!=null){Files.createDirectories(directory);Files.write(directory.resolve(profile.code+".pqkey"),encoded);Files.write(directory.resolve(profile.code+".pqmzip"),OnKeyStorage.pack(encoded));}return encoded;
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();Path output=args.length==0?null:Path.of(args[0]);
        for(var profile:TokenProfile.values()){
            byte[] bytes=fixture(profile,"83",output);var bundle=OnKeyBundle.decode(bytes);check(bundle.entries().size()==2);check(bundle.profiles().get(1).pgp().length>0==(profile!=TokenProfile.LEVEL2));
            var fake=new Fake();fake.keys.putAll(OnKeyBundle.bindings(bundle.entries()));OnKeyStorage.save(fake,bytes,new char[]{'x'});check(Arrays.equals(bytes,OnKeyStorage.load(fake).encoded()));
            int chunks=(OnKeyStorage.pack(bytes).length+2047)/2048;
            for(int cut=0;cut<=chunks;cut++){var interrupted=fake.copy();interrupted.failAt=cut;fails(()->OnKeyStorage.save(interrupted,bytes,new char[]{'x'}));check(Arrays.equals(bytes,OnKeyStorage.load(interrupted).encoded()));}
            OnKeyStorage.save(fake,bytes,new char[]{'x'});check(Arrays.equals(bytes,OnKeyStorage.load(fake).encoded()));
            var torn=fake.copy();torn.objects.put(0x5f5100,new byte[]{80,81});check(Arrays.equals(bytes,OnKeyStorage.load(torn).encoded()));
            byte[] tampered=bytes.clone();tampered[tampered.length-1]^=1;fails(()->OnKeyBundle.decode(tampered));fails(()->OnKeyBundle.decode(Arrays.copyOf(bytes,bytes.length-1)));
            var collision=new Fake();collision.keys.putAll(fake.keys);collision.objects.put(0x5f5002,new byte[]{1,2,3});fails(()->OnKeyStorage.save(collision,bytes,new char[]{'x'}));check(collision.writes==0);
            fake.serial=999;fails(()->OnKeyStorage.load(fake));
            System.out.println("PASS "+profile.code+": "+bytes.length+" bytes; signatures, PGP, tampering, wrong key, collision and every interrupted write");
        }
        var old=OnKeyBundle.decode(fixture(TokenProfile.LEVEL3,"9a",null));var card=new Fake();card.keys.putAll(OnKeyBundle.bindings(old.entries()));OnKeyStorage.save(card,old.encoded(),new char[]{'x'});OnKeyBundle.migrate(card,old.entries(),new char[]{'x'});check(card.moved&&!card.keys.containsKey("9a"));OnKeyBundle.check(card,OnKeyBundle.migrated(old.entries()));check(OnKeyStorage.load(card).recoveredMigration());
        Path temp=Files.createTempDirectory("onkey-import-");try{var state=new DesktopState(temp);state.importCertificateBundle(old.entries(),true);var recovered=OnKeyStorage.load(card);state.importOnKey(recovered);state.importOnKey(recovered);check(state.identities().size()==2);
            for(var saved:state.identities()){Identity id=state.loadIdentity(saved.id(),new char[0]);state.activateIdentity(id);check(state.get("identity."+saved.id()+".token.rsaSlot","").equals("83"));check(!state.isTrusted(id.signingCert(),"signing"));if(OpenPgp.supported(id))check(Arrays.equals(OpenPgp.loadOwn(temp,id).encoded,old.profiles().get(1).pgp()));}
        }finally{try(var paths=Files.walk(temp)){for(var file:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(file);}}
        OnKeyBundle.migrate(card,old.entries(),new char[]{'x'});
        var occupied=new Fake();occupied.keys.putAll(OnKeyBundle.bindings(old.entries()));occupied.keys.put("83",new byte[]{1});fails(()->OnKeyBundle.migrate(occupied,old.entries(),new char[]{'x'}));check(!occupied.moved);
        if(output!=null)for(var profile:TokenProfile.values()){Path swift=output.resolve("swift-"+profile.code+".pqkey");if(Files.exists(swift)){byte[] raw=Files.readAllBytes(swift);OnKeyBundle.decode(raw);check(Arrays.equals(raw,OnKeyStorage.unpack(Files.readAllBytes(output.resolve("swift-"+profile.code+".pqmzip")))));}}
        System.out.println("PASS migration keeps public keys and rejects occupied 83; on-key bundle suite complete");
    }
}
