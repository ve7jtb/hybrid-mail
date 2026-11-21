package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/** Every simulated card mutation is interrupted before and after delivery.
 * This test exercises the explicit ultra conversion/recovery entry points;
 * it never opens a token, changes a real policy, or persists real key material. */
public final class CompanionUltraStorageTest {
    public static void main(String[] args)throws Exception{
        MailEngine.init();KeyPair cert=SoftwareOpenPgp.generate("ML-DSA-87"),sign=SoftwareOpenPgp.generate("ML-DSA-87"),kem=SoftwareOpenPgp.generate("ML-KEM-1024");
        var generator=KeyPairGenerator.getInstance("EC","BC");generator.initialize(new ECGenParameterSpec("secp384r1"));var wrap=generator.generateKeyPair();
        var keys=Map.of("86",cert.getPublic(),"9c",sign.getPublic(),"9d",kem.getPublic(),"82",wrap.getPublic());
        byte[] full,ultra;PublicIdentity own;
        try(var identity=Level5Companion.create(123456,keys,List.of("ultra-storage@example.test"),Level5CompanionTest.signer(cert),Level5CompanionTest.signer(sign))){
            full=identity.seal(Level5CompanionTest.signer(cert));ultra=identity.toUltra(Level5CompanionTest.signer(cert));own=identity.own;
        }
        var card=new CompanionCompactTest.Card();card.keys=new HashMap<>();keys.forEach((slot,key)->card.keys.put(slot,key.getEncoded()));
        keys.keySet().forEach(slot->card.policies.put(slot,slot.equals("9c")||slot.equals("9d")?"PIN Always; Touch Always":"PIN Always; Touch Never"));
        card.objects.put(0x5fc10a,new byte[]{1,2,3});card.objects.put(0x5f5000,new byte[]{4,5,6});card.objects.put(0x5f5300,new byte[]{7,8,9});
        Path root=Files.createTempDirectory("ultra-storage-");
        try{
            CompanionStorage.save(card,full,new char[]{'x'},root.resolve("seed.pqcomp"));card.mutations=0;
            card.limit=card.objects.values().stream().mapToInt(a->a.length).sum();
            var complete=card.copy();CompanionStorage.replaceUltra(complete,full,ultra,new char[]{'x'},root.resolve("complete"));int mutations=complete.mutations;
            check(Arrays.equals(CompanionStorage.load(complete),ultra),"Ultra bank restore mismatch");CompanionCompactTest.preserved(complete,card);
            for(boolean after:new boolean[]{false,true})for(int cut=0;cut<mutations;cut++){
                var failed=card.copy();failed.failAt=cut;failed.failAfter=after;Path recovery=root.resolve((after?"after-":"before-")+cut);
                Level5CompanionTest.rejected(()->CompanionStorage.replaceUltra(failed,full,ultra,new char[]{'x'},recovery));
                check(Arrays.equals(Files.readAllBytes(recovery.resolve("previous.pqcomp")),full),"Lost original full certificate backup");
                check(Arrays.equals(Files.readAllBytes(recovery.resolve("replacement.pqcomp")),ultra),"Lost staged ultra ciphertext");
                failed.failAt=-1;CompanionStorage.resumeUltra(failed,recovery,new char[]{'x'});
                check(Arrays.equals(CompanionStorage.load(failed),ultra),"Ultra recovery failed");CompanionCompactTest.preserved(failed,card);
            }
            // Recovery uses authenticated templates, not only an equal serial.
            // A different envelope/metadata or unknown namespace object fails
            // before the first overwrite, even when its signature is valid.
            var collision=card.copy();collision.objects.put(CompanionStorage.BASE+32,new byte[]{99});
            Level5CompanionTest.rejected(()->CompanionStorage.replaceUltra(collision,full,ultra,new char[]{'x'},root.resolve("collision")));
            check(collision.mutations==0,"Ultra conversion erased an unexpected object");
            var wrong=card.copy();wrong.keys.put("82",generator.generateKeyPair().getPublic().getEncoded());
            Level5CompanionTest.rejected(()->CompanionStorage.replaceUltra(wrong,full,ultra,new char[]{'x'},root.resolve("wrong-key")));check(wrong.mutations==0,"Wrong key caused writes");
            var strict=card.copy();Level5CompanionTest.rejected(()->CompanionStorage.replaceCompact(strict,full,ultra,new char[]{'x'},root.resolve("wrong-mode")));check(strict.mutations==0,"Lossless entry point accepted a resealed envelope");
            var privateBackend=new TokenKemTest.Simulator(kem,wrap);
            int calls=privateBackend.ecCalls;
            Level5CompanionTest.rejected(()->Level5Companion.restore(ultra,123456,keys,privateBackend));check(privateBackend.ecCalls==calls,"Missing public cache caused a private operation");
            // Once reconstructed, the public cache avoids all certification and
            // cross-certification work on later signing/decryption operations.
            try(var reconstructed=Level5Companion.reconstruct(ultra,123456,keys,privateBackend,Level5CompanionTest.signer(cert),Level5CompanionTest.signer(sign))){
                check(Arrays.equals(reconstructed.own.primary,own.primary)&&Arrays.equals(reconstructed.own.signingBody(),own.signingBody())&&Arrays.equals(reconstructed.own.subkey,own.subkey),"Fingerprints changed");
                UltraCertificate.validateCached(Level5Companion.inspect(ultra,123456,keys).template(),reconstructed.own);
                try(var cached=Level5Companion.restore(ultra,123456,keys,privateBackend,reconstructed.own)){
                    byte[] plain=bytes("Ultra storage round trip\n"),signed=cached.sign(plain,Level5CompanionTest.signer(sign));
                    check(Arrays.equals(plain,openSigned(cached.decrypt(encrypt(signed,cached.own),privateBackend),cached.own)),"Cached ultra sign/decrypt failed");
                }
            }
            privateBackend.assertWiped();
            System.out.println("PASS ultra conversion/recovery: "+full.length+" -> "+ultra.length+" bytes; "+(2*mutations)+" interrupted mutations; unrelated data and policies preserved; fingerprint/cached sign/decrypt checks passed");
        }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
