package dev.hybridmail;

import java.nio.file.*;
import java.util.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/** Optional real Sequoia interoperability test, using only generated software
 * fixtures. Pass sq executable and a NEW result directory. No account stores,
 * network access or user hardware. Synthetic secret keys are deleted on exit. */
public final class ChatBundleSequoiaTest {
    static Path root;static String sq;
    static String file(String name){return root.resolve(name).toString();}
    static void run(String... arguments)throws Exception{
        var command=new ArrayList<>(List.of(sq,"--cert-store=none","--key-store=none"));command.addAll(List.of(arguments));
        var builder=new ProcessBuilder(command).inheritIO();builder.environment().put("SEQUOIA_HOME",file("sq-home"));
        var process=builder.start();if(!process.waitFor(60,java.util.concurrent.TimeUnit.SECONDS)){process.destroyForcibly();throw new Exception("Sequoia command timed out");}
        if(process.exitValue()!=0)throw new Exception("Sequoia failed: "+String.join(" ",arguments));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("Usage: ChatBundleSequoiaTest /path/to/sq NEW-results-directory");
        sq=Path.of(args[0]).toAbsolutePath().toString();root=Path.of(args[1]).toAbsolutePath();Files.createDirectory(root);Files.setPosixFilePermissions(root,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));MailEngine.init();
        try{
            for(int level:List.of(3,5)){
                String prefix="level"+level+"-",secret=file(prefix+"sq-secret.pgp");
                run("key","generate","--own-key","--email",ChatBundleTest.EMAIL,"--profile","rfc9580","--cipher-suite",level==3?"mldsa65-ed25519":"mldsa87-ed448","--without-password","--cannot-authenticate","--output",secret,"--rev-cert",file(prefix+"sq.rev"));
                var ring=new PGPSecretKeyRing(PGPUtil.getDecoderStream(Files.newInputStream(Path.of(secret))),new BcKeyFingerprintCalculator());var publicKeys=new ArrayList<PGPPublicKey>();ring.getPublicKeys().forEachRemaining(publicKeys::add);
                var peer=new OpenPgp.PublicIdentity(new PGPPublicKeyRing(publicKeys).getEncoded());Files.write(root.resolve(prefix+"sq-public.asc"),peer.export());
                var fixture=level==3?ChatBundleTest.level3():ChatBundleTest.level5();Files.write(root.resolve(prefix+"pq-public.asc"),fixture.own().export());
                byte[] signed=ChatBundleTest.create(fixture,null);Files.write(root.resolve(prefix+"pq-signed.pgp"),signed);
                var opened=ChatBundle.open(signed,fixture.own(),null,null,null);Files.write(root.resolve(prefix+"original.mime"),opened.mime());
                run("verify","--message","--signer-file",file(prefix+"pq-public.asc"),"--output",file(prefix+"sq-verified.mime"),file(prefix+"pq-signed.pgp"));
                ChatBundleTest.check(Arrays.equals(opened.mime(),Files.readAllBytes(root.resolve(prefix+"sq-verified.mime"))),"Sequoia altered signed MIME");
                System.out.println("PASS Level "+level+" Sequoia verifies PQ Mail compressed signed bundle, exact MIME bytes");
                byte[] encrypted=ChatBundleTest.create(fixture,peer);Files.write(root.resolve(prefix+"pq-encrypted.pgp"),encrypted);
                run("decrypt","--recipient-file",secret,"--signer-file",file(prefix+"pq-public.asc"),"--output",file(prefix+"sq-decrypted.mime"),file(prefix+"pq-encrypted.pgp"));
                // MIME boundaries/Message-ID are intentionally unique per create.
                // Check every decoded part rather than comparing separate creates.
                byte[] recovered=Files.readAllBytes(root.resolve(prefix+"sq-decrypted.mime"));var body=VerifiedMime.body(MailEngine.parse(recovered));ChatBundleTest.check(body.plain().equals(ChatBundleTest.TEXT)&&body.html().equals(ChatBundleTest.HTML),"Sequoia decrypted alternatives differ");
                var mixed=(jakarta.mail.internet.MimeMultipart)MailEngine.parse(recovered).getContent();ChatBundleTest.check(Arrays.equals(ChatBundleTest.FILE,mixed.getBodyPart(1).getInputStream().readAllBytes()),"Sequoia decrypted attachment differs");
                System.out.println("PASS Level "+level+" Sequoia decrypts/verifies PQ Mail hybrid encrypted bundle with both alternatives and binary attachment");
                run("sign","--message","--binary","--signer-file",secret,"--output",file(prefix+"sq-signed.pgp"),file(prefix+"original.mime"));
                ChatBundleTest.content(ChatBundle.open(Files.readAllBytes(root.resolve(prefix+"sq-signed.pgp")),peer,null,null,null));
                // sq sign emits uncompressed packets. Wrap those unchanged with
                // standard compression to cover external signatures in both forms.
                byte[] sqSigned=Files.readAllBytes(root.resolve(prefix+"sq-signed.pgp"));ChatBundleTest.content(ChatBundle.open(ChatBundle.compress(sqSigned,2),peer,null,null,null));
                System.out.println("PASS Level "+level+" PQ Mail verifies Sequoia signed-only bundles, uncompressed and ZLIB-wrapped");
                for(String compression:List.of("zip","zlib")){
                    String name=prefix+"sq-encrypted-"+compression+".pgp";
                    run("encrypt","--for-file",file(prefix+"pq-public.asc"),"--signer-file",secret,"--compression",compression,"--binary","--output",file(name),file(prefix+"original.mime"));
                    var incoming=ChatBundle.open(Files.readAllBytes(root.resolve(name)),peer,fixture.own(),fixture.id(),fixture.decryption());ChatBundleTest.content(incoming);ChatBundleTest.check(incoming.encrypted()&&Arrays.equals(incoming.mime(),opened.mime()),"Incoming MIME changed");
                    System.out.println("PASS Level "+level+" PQ Mail decrypts/verifies Sequoia "+compression+" hybrid bundle, exact MIME and attachment bytes");
                }
            }
            Files.writeString(root.resolve("result.txt"),"PASS Level 3 and Level 5 RFC 9980 signing/encryption both directions; ZIP/ZLIB; text/HTML and binary attachments. Synthetic software keys only; not a live Chat/YubiKey test.\n");
        }finally{for(int level:List.of(3,5))Files.deleteIfExists(root.resolve("level"+level+"-sq-secret.pgp"));}
    }
}
