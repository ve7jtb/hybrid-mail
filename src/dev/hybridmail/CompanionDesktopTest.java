package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;

/** Desktop workflow checks with synthetic certificates and an injectable card.
 * No test creates OnKeyDesktop, discovers hardware, or requests a user PIN. */
public final class CompanionDesktopTest {
    static Identity token(Identity software){return new Identity(software.signingCert(),null,software.encryptionCert(),null,null);}
    static void reject(Level5CompanionTest.Checked action)throws Exception{Level5CompanionTest.rejected(action);}
    public static void main(String[] args)throws Exception{
        MailEngine.init();String email="desktop-companion@example.test";
        var software=Identity.generate(email,Identity.HYBRID_87_SIGN);var selected=token(software);
        var signing=keys(software.signingCert().getPublicKey());var encryption=keys(software.encryptionCert().getPublicKey());
        var signPrivate=((CompositePrivateKey)software.signingKey()).getPrivateKeys();var kemPrivate=((CompositePrivateKey)software.encryptionKey()).getPrivateKeys();
        var sign=new KeyPair(signing.pq(),signPrivate.get(0));var kem=new KeyPair(encryption.pq(),kemPrivate.get(0));var wrapping=new KeyPair(encryption.ec(),kemPrivate.get(1));var certification=SoftwareOpenPgp.generate("ML-DSA-87");
        var hardware=Map.of("86",certification.getPublic(),"9c",sign.getPublic(),"9d",kem.getPublic(),"82",wrapping.getPublic());byte[] full,ultra;PublicIdentity own;
        try(var created=Level5Companion.create(123456,hardware,List.of(email),Level5CompanionTest.signer(certification),Level5CompanionTest.signer(sign))){full=created.seal(Level5CompanionTest.signer(certification));ultra=created.toUltra(Level5CompanionTest.signer(certification));own=created.own;}
        var upgrade=new CompanionDesktop.Upgrade(123456,full,ultra,own);var card=new CompanionCompactTest.Card();card.keys=new HashMap<>();hardware.forEach((slot,key)->card.keys.put(slot,key.getEncoded()));card.objects.put(0x5fc10a,new byte[]{1,2,3});
        Path root=Files.createTempDirectory("companion-desktop-test-");
        try{
            CompanionStorage.save(card,full,new char[]{'x'},root.resolve("seed.pqcomp"));card.mutations=0;
            Path journal=root.resolve("interrupted");var partial=card.copy();partial.failAt=1;reject(()->CompanionStorage.replaceUltra(partial,full,ultra,new char[]{'x'},journal));partial.failAt=-1;
            // This fresh test JVM has no activated identity. Serial parsing
            // fails before any real-card constructor; its credential still wipes.
            check(DesktopState.activeTokenSerial().isEmpty(),"Unexpected active token in synthetic test");char[] absentSerial={'s','e','c','r','e','t'};
            try{CompanionDesktop.resumeUltra(root,selected,journal,absentSerial);throw new AssertionError("Missing serial was accepted");}catch(NumberFormatException expected){}
            check(Arrays.equals(absentSerial,new char[absentSerial.length]),"Serial parsing failure retained management credential");
            var generator=KeyPairGenerator.getInstance("EC","BC");generator.initialize(new ECGenParameterSpec("secp384r1"));
            var wrongWrappingPublic=new CompositePublicKey(TokenProfile.LEVEL5.kemOid,kem.getPublic(),generator.generateKeyPair().getPublic());
            var name=new org.bouncycastle.asn1.x500.X500Name("CN=synthetic wrapping mismatch");var builder=new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name,java.math.BigInteger.ONE,new Date(0),new Date(4102444800000L),name,wrongWrappingPublic);
            var wrongWrappingCertificate=new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(software.signer(null)));
            var wrongWrap=new Identity(software.signingCert(),null,wrongWrappingCertificate,null,null);var wrongEmail=token(software.reissue("different@example.test",null));var wrongKeys=token(Identity.generate(email,Identity.HYBRID_87_SIGN));
            // Even a valid journal for this physical card must not mutate it
            // when the selected identity has different keys, wrapping or email.
            for(Identity wrong:List.of(wrongWrap,wrongEmail,wrongKeys)){
                int[] opens={0};CompanionDesktop.Cards factory=serial->{opens[0]++;return partial;};char[] management={'s','e','c','r','e','t'};int mutations=partial.mutations;
                reject(()->CompanionDesktop.commitUltra(root,wrong,upgrade,management,factory));check(opens[0]==0&&partial.mutations==mutations,"Wrong identity opened or mutated a card during commit");check(Arrays.equals(management,new char[management.length]),"Commit failure retained management credential");
                char[] resume={'s','e','c','r','e','t'};reject(()->CompanionDesktop.resumeUltra(root,wrong,123456,journal,resume,factory));check(opens[0]==0&&partial.mutations==mutations,"Wrong recovery identity opened or mutated a card");check(Arrays.equals(resume,new char[resume.length]),"Recovery failure retained management credential");
                reject(()->CompanionDesktop.fullForIdentity(full,wrong,123456));
            }
            // The selected matching identity resumes through the same tested
            // desktop entry point, saving a public cache and exact ciphertext.
            int[] opens={0};CompanionDesktop.resumeUltra(root,selected,123456,journal,new char[]{'x'},serial->{opens[0]++;return partial;});check(opens[0]==1&&Arrays.equals(CompanionStorage.load(partial),ultra),"Matching desktop recovery failed");
            check(!Files.exists(ownPath(root,selected)),"Test unexpectedly has an older .asc identity");
            check(OpenPgp.loadOwn(root,selected).fingerprint().equals(own.fingerprint()),"Fresh companion restore depended on an old .asc file");
            Path cache=CompanionDesktop.certificatePath(root,selected);Files.write(cache,b(1,2,3));
            reject(()->CompanionDesktop.cached(root,selected,ultra));reject(()->OpenPgp.loadOwn(root,selected));
            check(CompanionDesktop.cacheForExplicitRestore(root,selected,ultra)==null,"Explicit restore did not allow repairing corrupt public cache");
            // Cache repair authorizes no implicit private calls. The simulated
            // explicit reconstruction occurs separately, then publishes files.
            var backend=new TokenKemTest.Simulator(kem,wrapping);
            try(var reconstructed=Level5Companion.reconstruct(ultra,123456,hardware,backend,Level5CompanionTest.signer(certification),Level5CompanionTest.signer(sign))){CompanionDesktop.saveLocal(root,selected,ultra,reconstructed.own);}
            check(OpenPgp.loadOwn(root,selected).fingerprint().equals(own.fingerprint()),"Repaired public cache was unusable");backend.assertWiped();
            // A different authenticated envelope is not a cache repair. Its
            // selected-identity mismatch stays outside the invalid-cache catch.
            reject(()->CompanionDesktop.cacheForExplicitRestore(root,wrongWrap,ultra));
            System.out.println("PASS desktop companion: wrong key/email/wrapping rejected before card open; management arrays cleared; interrupted recovery succeeds; fresh restore needs no .asc; routine stale-cache use rejected and explicit cache repair succeeds");
        }finally{try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
