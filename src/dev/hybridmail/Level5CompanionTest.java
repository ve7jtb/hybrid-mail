package dev.hybridmail;
import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/** Real-crypto fixtures; synthetic hardware substitutes never contain user keys. */
public final class Level5CompanionTest {
    interface Checked {void run()throws Exception;}
    static void rejected(Checked action)throws Exception{try{action.run();throw new AssertionError("Expected rejection");}catch(GeneralSecurityException|java.io.IOException expected){}}
    static ExternalMu.Backend signer(KeyPair key){return (pub,mu)->{Level5Companion.same(pub,key.getPublic());var s=new MLDSASigner();s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(key.getPrivate().getEncoded()),RANDOM));return s.generateMuSignature(mu);};}
    public static void main(String[] args)throws Exception{
        MailEngine.init();var cert=SoftwareOpenPgp.generate("ML-DSA-87");var sign=SoftwareOpenPgp.generate("ML-DSA-87");var kem=SoftwareOpenPgp.generate("ML-KEM-1024");var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new ECGenParameterSpec("secp384r1"));var wrap=g.generateKeyPair();
        var publicKeys=Map.of("86",cert.getPublic(),"9c",sign.getPublic(),"9d",kem.getPublic(),"82",wrap.getPublic());var backend=new TokenKemTest.Simulator(kem,wrap);
        byte[] encoded,publicCert,signed,encrypted;byte[] text=bytes("Synthetic companion interoperability test\n");
        try(var created=Level5Companion.create(123456,publicKeys,List.of("companion@example.test"),signer(cert),signer(sign))){encoded=created.seal(signer(cert));publicCert=created.own.encoded;signed=created.sign(text,signer(sign));encrypted=encrypt(signed,created.own);check(Arrays.equals(text,openSigned(created.decrypt(encrypted,backend),created.own)),"Created companion round trip");}
        try(var restored=Level5Companion.restore(encoded,123456,publicKeys,backend)){
            check(Arrays.equals(restored.own.encoded,publicCert),"Certificate changed during restore");check(Arrays.equals(text,openSigned(restored.decrypt(encrypted,backend),restored.own)),"Restored decryption");check(Arrays.equals(text,openSigned(restored.sign(text,signer(sign)),restored.own)),"Restored signing");
        }
        byte[] tampered=encoded.clone();tampered[tampered.length/2]^=1;int before=backend.ecCalls;
        rejected(()->Level5Companion.restore(tampered,123456,publicKeys,backend));rejected(()->Level5Companion.restore(encoded,999999,publicKeys,backend));rejected(()->Level5Companion.restore(Arrays.copyOf(encoded,encoded.length-1),123456,publicKeys,backend));
        check(backend.ecCalls==before,"Invalid envelope contacted private backend");
        var wrong=new HashMap<>(publicKeys);wrong.put("82",g.generateKeyPair().getPublic());rejected(()->Level5Companion.restore(encoded,123456,wrong,backend));
        var wrongBackend=new TokenKemTest.Simulator(kem,g.generateKeyPair());rejected(()->Level5Companion.restore(encoded,123456,publicKeys,wrongBackend));
        var card=new OnKeyCompactTest.Card();card.keys=new HashMap<>();publicKeys.forEach((slot,key)->card.keys.put(slot,key.getEncoded()));
        // Sentinel ordinary certificate/public-bundle data must survive every write.
        card.objects.put(0x5fc10a,new byte[]{7,8,9});card.objects.put(0x5f5000,new byte[]{4,5,6});
        Path recovery=Files.createTempDirectory("companion-recovery-test-");
        try{
            int writes=(encoded.length+2047)/2048+1;
            for(int cut=0;cut<writes;cut++){
                var interrupted=card.copy();interrupted.fail=cut;
                rejected(()->CompanionStorage.save(interrupted,encoded,new char[]{'x'},recovery.resolve("replacement.pqcomp")));
                interrupted.fail=-1;CompanionStorage.save(interrupted,encoded,new char[]{'x'},recovery.resolve("replacement.pqcomp"));
                check(Arrays.equals(CompanionStorage.load(interrupted),encoded),"Interrupted companion recovery failed");
                check(Arrays.equals(interrupted.objects.get(0x5fc10a),new byte[]{7,8,9})&&Arrays.equals(interrupted.objects.get(0x5f5000),new byte[]{4,5,6}),"Unrelated objects changed");
            }
            card.objects.put(CompanionStorage.BASE+32,new byte[]{1});
            rejected(()->CompanionStorage.save(card,encoded,new char[]{'x'},recovery.resolve("replacement.pqcomp")));check(card.writes==0,"Collision caused writes");
        }finally{try(var paths=Files.walk(recovery)){for(Path file:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(file);}}
        backend.assertWiped();
        if(args.length==1){Path dir=Path.of(args[0]);Files.createDirectories(dir);Files.write(dir.resolve("companion.pqcomp"),encoded);Files.write(dir.resolve("public.pgp"),publicCert);Files.write(dir.resolve("java-signed.pgp"),signed);Files.write(dir.resolve("java-encrypted.pgp"),encrypted);Files.write(dir.resolve("plain.txt"),text);
            // These are generated test keys only, in an explicitly selected fixture folder.
            for(var entry:Map.of("86",cert,"9c",sign,"9d",kem,"82",wrap).entrySet()){Files.write(dir.resolve(entry.getKey()+".der"),entry.getValue().getPublic().getEncoded());Files.write(dir.resolve(entry.getKey()+"-test-private.der"),entry.getValue().getPrivate().getEncoded());}}
        System.out.println("PASS empty-password companion restore, signing, decryption, tamper/wrong-card/wrong-key rejection and secret cleanup");System.out.println("Public certificate: "+publicCert.length+" bytes; complete encrypted companion: "+encoded.length+" bytes");
    }
}
