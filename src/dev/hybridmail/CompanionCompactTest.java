package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/** Storage fault injection uses synthetic keys only. It never opens a real card. */
public final class CompanionCompactTest {
    static final class Card extends OnKeyCompactTest.Card {
        int failAt=-1,mutations;boolean failAfter;Runnable afterAuth;
        final Map<String,String> policies=new HashMap<>();
        @Override public void authenticate(char[] pin){super.authenticate(pin);if(afterAuth!=null)afterAuth.run();}
        private void before()throws IOException{if(!auth)throw new IOException("Not authenticated");if(mutations==failAt&&!failAfter)throw new IOException("Interrupted before mutation");}
        private void after()throws IOException{int operation=mutations++;if(operation==failAt&&failAfter)throw new IOException("Lost mutation acknowledgement");}
        @Override public void put(int tag,byte[] value)throws Exception{
            before();int used=objects.values().stream().mapToInt(a->a.length).sum()-objects.getOrDefault(tag,new byte[0]).length+value.length;if(used>limit)throw new IOException("Card full");objects.put(tag,value.clone());after();
        }
        @Override public void deleteObject(int tag)throws Exception{before();objects.remove(tag);after();}
        @Override Card copy(){var card=new Card();objects.forEach((tag,value)->card.objects.put(tag,value.clone()));card.keys=new HashMap<>();keys.forEach((slot,value)->card.keys.put(slot,value.clone()));card.policies.putAll(policies);card.limit=limit;return card;}
    }
    static void equal(byte[] a,byte[] b,String message)throws Exception{check(Arrays.equals(a,b),message);}
    static void preserved(Card actual,Card original)throws Exception{
        check(actual.keys.keySet().equals(original.keys.keySet()),"Key slots changed");for(String slot:original.keys.keySet())equal(actual.keys.get(slot),original.keys.get(slot),"Public key changed in "+slot);
        check(actual.policies.equals(original.policies),"Touch/PIN policies changed");
        for(var entry:original.objects.entrySet())if(entry.getKey()<CompanionStorage.BASE||entry.getKey()>CompanionStorage.BASE+CompanionStorage.COUNT)equal(actual.objects.get(entry.getKey()),entry.getValue(),"Unrelated object changed");
        for(int tag:actual.objects.keySet())check(original.objects.containsKey(tag)||(tag>=CompanionStorage.BASE&&tag<=CompanionStorage.BASE+CompanionStorage.COUNT),"Unexpected object outside companion namespace");
    }
    static void reject(Level5CompanionTest.Checked action)throws Exception{Level5CompanionTest.rejected(action);}
    public static void main(String[] args)throws Exception{
        MailEngine.init();var cert=SoftwareOpenPgp.generate("ML-DSA-87");var sign=SoftwareOpenPgp.generate("ML-DSA-87");var kem=SoftwareOpenPgp.generate("ML-KEM-1024");var ec=KeyPairGenerator.getInstance("EC","BC");ec.initialize(new ECGenParameterSpec("secp384r1"));var wrap=ec.generateKeyPair();
        var hardware=Map.of("86",cert.getPublic(),"9c",sign.getPublic(),"9d",kem.getPublic(),"82",wrap.getPublic());byte[] previous;
        try(var created=Level5Companion.create(123456,hardware,List.of("compact@example.test"),Level5CompanionTest.signer(cert),Level5CompanionTest.signer(sign))){previous=CompanionEncoding.unpack(created.seal(Level5CompanionTest.signer(cert)));}
        byte[] replacement=CompanionEncoding.pack(previous);check(replacement.length<previous.length,"Fixture must shrink");
        var original=new Card();original.keys=new HashMap<>();hardware.forEach((slot,key)->original.keys.put(slot,key.getEncoded()));
        // Extra keys/policies and objects model the rest of the real device,
        // including public bundle storage, ordinary PIV certs and other app data.
        for(String slot:List.of("83","84","85","88","89"))original.keys.put(slot,new byte[]{1,2,3});
        original.keys.keySet().forEach(slot->original.policies.put(slot,slot.equals("9c")||slot.equals("9d")?"PIN always; touch always":"PIN always; touch never"));
        original.objects.put(0x5fc10a,new byte[]{7,8,9});original.objects.put(0x5f5000,new byte[]{4,5,6});original.objects.put(0x5f5300,new byte[]{10,11});
        Path root=Files.createTempDirectory("companion-compact-test-");
        try{
            CompanionStorage.save(original,previous,new char[]{'x'},root.resolve("seed.pqcomp"));original.mutations=0;
            // Replacement must fit in the same bank without spare device space.
            original.limit=original.objects.values().stream().mapToInt(a->a.length).sum();
            var complete=original.copy();Path completeDir=root.resolve("complete");char[] management={'s','e','c','r','e','t'};
            CompanionStorage.replaceCompact(complete,previous,replacement,management,completeDir);
            check(Arrays.equals(management,new char[management.length]),"Management credential not wiped");equal(CompanionStorage.load(complete),replacement,"Compacted restore failed");preserved(complete,original);
            int operations=complete.mutations;
            // Every operation can fail before delivery or after the card acted
            // but before the application saw success. Both must be recoverable.
            for(boolean after:new boolean[]{false,true})for(int cut=0;cut<operations;cut++){
                var card=original.copy();card.failAt=cut;card.failAfter=after;Path journal=root.resolve((after?"after-":"before-")+cut);
                reject(()->CompanionStorage.replaceCompact(card,previous,replacement,new char[]{'x'},journal));
                equal(Files.readAllBytes(journal.resolve("previous.pqcomp")),previous,"Original ciphertext recovery missing");equal(Files.readAllBytes(journal.resolve("replacement.pqcomp")),replacement,"Replacement ciphertext recovery missing");check(Files.size(journal.resolve("namespace.snapshot"))>previous.length,"Full namespace snapshot missing");preserved(card,original);
                card.failAt=-1;CompanionStorage.resumeCompact(card,journal,new char[]{'x'});equal(CompanionStorage.load(card),replacement,"Interrupted replacement did not restore");preserved(card,original);
                int count=card.mutations;CompanionStorage.resumeCompact(card,journal,new char[]{'x'});check(card.mutations==count,"Complete recovery was not idempotent");
            }
            // A second interruption during recovery must be just as safe as
            // the initial interruption, without regenerating or rewrapping.
            var incomplete=original.copy();incomplete.failAt=7;Path recovery=root.resolve("repeat-recovery");reject(()->CompanionStorage.replaceCompact(incomplete,previous,replacement,new char[]{'x'},recovery));
            var recovered=incomplete.copy();CompanionStorage.resumeCompact(recovered,recovery,new char[]{'x'});int recoveryOperations=recovered.mutations;
            for(boolean after:new boolean[]{false,true})for(int cut=0;cut<recoveryOperations;cut++){
                var card=incomplete.copy();card.failAt=cut;card.failAfter=after;reject(()->CompanionStorage.resumeCompact(card,recovery,new char[]{'x'}));preserved(card,original);card.failAt=-1;
                CompanionStorage.resumeCompact(card,recovery,new char[]{'x'});equal(CompanionStorage.load(card),replacement,"Interrupted recovery failed");preserved(card,original);
            }
            // Refuse collisions, altered recovery data, different envelopes and
            // objects appearing during management authentication before writes.
            var collision=original.copy();collision.objects.put(CompanionStorage.BASE+32,new byte[]{99});reject(()->CompanionStorage.replaceCompact(collision,previous,replacement,new char[]{'x'},root.resolve("collision")));check(collision.mutations==0,"Unexpected tail was overwritten");
            var race=original.copy();race.afterAuth=()->race.objects.put(CompanionStorage.BASE+32,new byte[]{99});reject(()->CompanionStorage.replaceCompact(race,previous,replacement,new char[]{'x'},root.resolve("race")));check(race.mutations==0,"Post-authentication tail was overwritten");
            var changed=original.copy();changed.objects.put(CompanionStorage.BASE+1,new byte[]{9});reject(()->CompanionStorage.replaceCompact(changed,previous,replacement,new char[]{'x'},root.resolve("changed")));check(changed.mutations==0,"Changed old companion was overwritten");
            var wrongKey=original.copy();wrongKey.keys.put("82",ec.generateKeyPair().getPublic().getEncoded());reject(()->CompanionStorage.replaceCompact(wrongKey,previous,replacement,new char[]{'x'},root.resolve("wrong-key")));check(wrongKey.mutations==0,"Wrong hardware key caused writes");
            byte[] altered=replacement.clone();altered[altered.length/2]^=1;var bad=original.copy();reject(()->CompanionStorage.replaceCompact(bad,previous,altered,new char[]{'x'},root.resolve("altered")));reject(()->CompanionStorage.replaceCompact(bad,previous,previous,new char[]{'x'},root.resolve("not-smaller")));check(bad.mutations==0,"Invalid replacement caused writes");
            var unknown=original.copy();unknown.failAt=1;Path unknownDir=root.resolve("unknown");reject(()->CompanionStorage.replaceCompact(unknown,previous,replacement,new char[]{'x'},unknownDir));unknown.failAt=-1;unknown.objects.put(CompanionStorage.BASE+2,new byte[]{99});int count=unknown.mutations;reject(()->CompanionStorage.resumeCompact(unknown,unknownDir,new char[]{'x'}));check(unknown.mutations==count,"Recovery erased unknown object");
            var stale=original.copy();Path staleDir=root.resolve("stale-journal");Files.createDirectory(staleDir);Files.write(staleDir.resolve("previous.pqcomp"),new byte[]{1});reject(()->CompanionStorage.replaceCompact(stale,previous,replacement,new char[]{'x'},staleDir));check(stale.mutations==0,"Mismatched recovery file caused writes");
            byte[] damagedSnapshot=Files.readAllBytes(completeDir.resolve("namespace.snapshot"));damagedSnapshot[8]^=1;Files.write(completeDir.resolve("namespace.snapshot"),damagedSnapshot);count=complete.mutations;reject(()->CompanionStorage.resumeCompact(complete,completeDir,new char[]{'x'}));check(complete.mutations==count,"Damaged recovery snapshot caused writes");
            // Restore the compact representation through the actual crypto API:
            // storage compression must not alter Ed448/X448 keys or certificates.
            var backend=new TokenKemTest.Simulator(kem,wrap);try(var restored=Level5Companion.restore(replacement,123456,hardware,backend)){
                byte[] plain=bytes("Compacted companion restore test\n"),signed=restored.sign(plain,Level5CompanionTest.signer(sign));equal(openSigned(restored.decrypt(encrypt(signed,restored.own),backend),restored.own),plain,"Compacted sign/decrypt failed");
            }backend.assertWiped();
            System.out.println("PASS compact companion: "+previous.length+" -> "+replacement.length+" bytes; "+((operations+recoveryOperations)*2)+" interrupted replacement/recovery mutations recovered; collisions/auth races rejected; keys, policies and unrelated objects unchanged; fresh signing/decryption passed");
        }finally{try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
