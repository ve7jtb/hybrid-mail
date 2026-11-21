package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/** Independent Java verification of Sequoia output. This accepts only the
 * synthetic fixture explicitly exported by Level3CompanionTest; it does not
 * read a user's card or write decrypted software key material. */
public final class Level3CompanionInteropTest {
    public static void main(String[] args)throws Exception {
        check(args.length==1,"Specify the generated synthetic interoperability fixture directory");MailEngine.init();Path root=Path.of(args[0]);
        var pairs=new LinkedHashMap<String,KeyPair>();var publics=new LinkedHashMap<String,PublicKey>();
        for(String slot:Level3Companion.SLOTS){
            PublicKey publicKey=Level3Companion.decodePublic(Files.readAllBytes(root.resolve(slot+".der")));
            byte[] encoded=Files.readAllBytes(root.resolve(slot+"-test-private.der"));
            try{String algorithm=slot.equals("83")?"EC":slot.equals("9d")?"X25519":"Ed25519";PrivateKey privateKey=KeyFactory.getInstance(algorithm,"BC").generatePrivate(new PKCS8EncodedKeySpec(encoded));pairs.put(slot,new KeyPair(publicKey,privateKey));publics.put(slot,publicKey);}
            finally{wipe(encoded);}
        }
        var card=new Level3CompanionTest.Hardware(pairs);byte[] message=Files.readAllBytes(root.resolve("message.mime"));
        try(var companion=Level3Companion.restore(Files.readAllBytes(root.resolve("companion.pqcomp")),123456,publics,card)){
            var own=companion.own;
            new LegacyOpenPgp(own.encoded,6).verify(Files.readAllBytes(root.resolve("signature.pgp")),message);
            check(Arrays.equals(message,openSigned(Files.readAllBytes(root.resolve("sequoia-signed.pgp")),own)),"Sequoia signed message mismatch");
            check(Arrays.equals(message,openSigned(companion.decrypt(Files.readAllBytes(root.resolve("sequoia-encrypted.pgp")),card),own)),"Sequoia encrypted message mismatch");
            check(card.wrappings==1&&card.decryptions==1&&card.signatures==0&&card.certifications==0,"Unexpected hardware operation during interoperability verification");
        }finally{for(var pair:pairs.values())try{pair.getPrivate().destroy();}catch(Exception ignored){/* Test provider may not support explicit destruction. */}}
        card.wiped();System.out.println("PASS Sequoia → PQ Mail: detached and embedded hybrid signatures, signed+encrypted decryption, exact plaintext and secret cleanup");
    }
}
