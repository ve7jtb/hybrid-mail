package dev.hybridmail;
import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.util.*;
/** Public-only preparation and independent signature verification for Sequoia. */
public final class CompanionInterop {
    static final byte[] BODY=bytes("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nSynthetic Sequoia YubiKey Level 3 interoperability test.\r\n");
    public static void main(String[] args)throws Exception{
        MailEngine.init();Path dir=Path.of(args[1]);var own=new PublicIdentity(Files.readAllBytes(dir.resolve("public.pgp")));
        if(args[0].equals("prepare")){Files.write(dir.resolve("pqmail-encrypted.pgp"),encrypt(frame(11,cat(b(98,0),n(0,4),BODY)),own));}
        else{var signature=packets(Files.readAllBytes(dir.resolve("signature.pgp")));check(signature.size()==1&&signature.get(0).tag()==2,"Expected detached signature");verify(signature.get(0).body(),Files.readAllBytes(dir.resolve("message.mime")),0,own.signingBody());System.out.println("PASS independent PQ Mail verification of Sequoia Level 5 signature");}
    }
}
