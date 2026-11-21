package dev.hybridmail;
import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Public local routing plus encrypted companion cache; no password/secret settings. */
final class CompanionDesktop {
    static Path path(Path root,Identity id)throws Exception{return OpenPgp.ownPath(root,id).resolveSibling(OpenPgp.ownPath(root,id).getFileName()+".pqcomp");}
    static Path certificatePath(Path root,Identity id)throws Exception{return path(root,id).resolveSibling(path(root,id).getFileName()+".public.pgp");}
    static boolean selected(Path root,Identity id)throws Exception{return id!=null&&id.signingKey()==null&&OpenPgp.classical(id)&&Files.isRegularFile(path(root,id));}
    /** The identity's signing key anchors the embedded OpenPGP signing subkey's
     * cross-certification. Never trust an envelope's self-declared keys alone. */
    static Map<String,PublicKey> expected(byte[] encoded,Identity id)throws Exception{
        encoded=CompanionEncoding.unpack(encoded);
        check(encoded.length<=Level5Companion.MAX,"Companion too large");var in=new DataInputStream(new ByteArrayInputStream(encoded));byte[] body=Level5Companion.field(in);var r=new DataInputStream(new ByteArrayInputStream(body));byte[] magic=r.readNBytes(8);check(Arrays.equals(magic,Level5Companion.MAGIC)||Arrays.equals(magic,bytes("PQMCP002")),"Unknown companion");r.readInt();var h=new LinkedHashMap<String,PublicKey>();for(String slot:Level5Companion.SLOTS)h.put(slot,Level5Companion.decodePublic(Level5Companion.field(r)));
        Level5Companion.same(h.get("9c"),keys(id.signingCert().getPublicKey()).pq());Level5Companion.same(h.get("9d"),keys(id.encryptionCert().getPublicKey()).pq());Level5Companion.same(h.get("82"),keys(id.encryptionCert().getPublicKey()).ec());return h;
    }
    static int serial(byte[] encoded)throws Exception{var in=new DataInputStream(new ByteArrayInputStream(CompanionEncoding.unpack(encoded)));var body=new DataInputStream(new ByteArrayInputStream(Level5Companion.field(in)));body.skipNBytes(8);return body.readInt();}
    static byte[] read(Path root,Identity id)throws Exception{Path p=path(root,id);check(Files.size(p)<=Level5Companion.MAX,"Companion too large");return Files.readAllBytes(p);}
    /** A public cache is usable only after certificate verification and exact
     * template matching. Its mere existence never skips crypto or grants trust. */
    static PublicIdentity cached(Path root,Identity id,byte[] encoded)throws Exception{
        var env=Level5Companion.inspect(encoded,serial(encoded),expected(encoded,id));
        if(!env.ultra())return env.own();
        Path cache=certificatePath(root,id);if(!Files.exists(cache))return null;
        check(Files.isRegularFile(cache,LinkOption.NOFOLLOW_LINKS)&&Files.size(cache)<=Level5Companion.MAX,"Invalid public companion cache");
        var own=new PublicIdentity(Files.readAllBytes(cache));
        return Level5Companion.inspect(encoded,serial(encoded),expected(encoded,id),own).own();
    }
    /** Only an explicitly requested restore may repair its public cache. The
     * envelope and selected key bindings are revalidated outside the catch so
     * an invalid card/identity can never be mistaken for a disposable cache. */
    static PublicIdentity cacheForExplicitRestore(Path root,Identity id,byte[] encoded)throws Exception{
        Level5Companion.inspect(encoded,serial(encoded),expected(encoded,id));
        try{return cached(root,id,encoded);}
        catch(GeneralSecurityException|IOException|IllegalArgumentException invalidPublicCache){return null;}
    }
    static PublicIdentity own(Path root,Identity id)throws Exception{byte[] encoded=read(root,id);var own=cached(root,id,encoded);check(own!=null,"Restore this ultra-compact companion once to reconstruct its public certificate");match(own,id);return own;}
    static CompanionOperation operation(Path root,Identity id,String signer,String kem,Map<String,String> config)throws Exception{
        byte[] encoded=read(root,id);int serial=serial(encoded);check(Integer.toString(serial).equals(DesktopState.activeTokenSerial()),"Selected credential requires YubiKey "+serial);
        var own=cached(root,id,encoded);check(own!=null,"Restore the ultra-compact companion before using it");
        return new CompanionOperation(encoded,serial,expected(encoded,id),signer,kem,config,own);
    }
    /** Public preflight checks every live component before saving ciphertext.
     * Ultra restore without a cache explicitly authorizes certificate reconstruction.
     * Original NIST/v4 public certificates are retained in their existing files. */
    static String restore(Path root,Identity id,int serial,String signer,String kem,Map<String,String> config)throws Exception{
        byte[] encoded;try(var card=new OnKeyDesktop(serial)){encoded=CompanionStorage.load(card);var h=expected(encoded,id);for(String slot:Level5Companion.SLOTS)check(Arrays.equals(h.get(slot).getEncoded(),card.publicKey(slot)),"Live key mismatch in "+slot);}
        var env=Level5Companion.inspect(encoded,serial,expected(encoded,id));var own=cacheForExplicitRestore(root,id,encoded);boolean reconstructed=false;
        if(own==null){
            var operation=new CompanionOperation(encoded,serial,expected(encoded,id),signer,kem,config);
            try(var restored=Level5Companion.reconstruct(encoded,serial,expected(encoded,id),operation,operation.certification(),operation)){own=restored.own;reconstructed=true;}
            finally{operation.clearSecrets();}
        }
        match(own,id);saveLocal(root,id,encoded,own);
        return "Restored "+(env.ultra()?"ultra-compact":"full")+" Level 5 companion for YubiKey "+serial+".\n"+own.description()+"\n"+(reconstructed?"Reconstructed and verified the public certificate; cached for this host.\n":"")+"Only ciphertext and public certificates saved; trust unchanged. Existing hardware keys and policies are unchanged.";
    }

    /** Preparation requests private operations but performs NO card data writes.
     * The caller reviews measured savings before requesting management access. */
    record Upgrade(int serial,byte[] previous,byte[] replacement,PublicIdentity certificate) {
        String review(){return "Full companion: "+previous.length+" bytes\nUltra-compact: "+replacement.length+" bytes\nSaved: "+(previous.length-replacement.length)+" bytes\nKeys and fingerprints are preserved. A new host needs PIN/touch once to reconstruct the public certificate.\nThe single bank is temporarily unavailable during replacement; a local recovery backup is saved first.";}
    }
    static Upgrade prepareUltra(Path root,Identity id,int serial,String signer,String kem,Map<String,String> config)throws Exception{
        byte[] previous;Map<String,PublicKey> hardware;
        try(var card=new OnKeyDesktop(serial)){previous=CompanionStorage.load(card);hardware=CompanionStorage.hardware(card);}
        var env=Level5Companion.inspect(previous,serial,hardware);check(!env.ultra(),"This companion already uses ultra-compact storage");
        // OpenPGP's Goldilocks profile shares the ML components with S/MIME,
        // but its wrapping key is the S/MIME P-384 key too. Check that binding
        // before any unwrap/PIN, rather than discovering a stale 82 after write.
        fullForIdentity(previous,id,serial);
        // Eligibility is checked before requesting the PIN. Unsupported or
        // third-party-certified material remains in complete storage form.
        UltraCertificate.template(env.own());
        var operation=new CompanionOperation(previous,serial,hardware,signer,kem,config,env.own());byte[] replacement;
        try(var restored=Level5Companion.restore(previous,serial,hardware,operation)){
            replacement=restored.toUltra(operation.certification());
            // Exercise the new wrapping while the operation authorization is
            // still live; a successful template check alone is insufficient.
            try(var checked=Level5Companion.restore(replacement,serial,hardware,operation,env.own())){check(Arrays.equals(checked.own.primary,env.own().primary),"Converted primary fingerprint changed");}
        }finally{operation.clearSecrets();}
        check(replacement.length<previous.length,"Ultra-compact encoding did not save storage");return new Upgrade(serial,previous,replacement,env.own());
    }
    @FunctionalInterface interface Cards {OnKeyBundle.Card open(int serial)throws Exception;}
    /** These pure preflight helpers run before opening a card for mutation, and
     * are also exercised with a fake card factory by the integration tests. */
    static PublicIdentity fullForIdentity(byte[] previous,Identity id,int serial)throws Exception{
        check(id!=null&&id.signingKey()==null&&classical(id),"Select the matching Level 5 YubiKey identity");
        var old=Level5Companion.inspect(previous,serial,expected(previous,id));check(!old.ultra()&&old.own()!=null,"Recovery requires the original full certificate");match(old.own(),id);return old.own();
    }
    static Upgrade validatedUpgrade(Identity id,int serial,byte[] previous,byte[] replacement,PublicIdentity certificate)throws Exception{
        PublicIdentity original=fullForIdentity(previous,id,serial);
        var next=Level5Companion.inspect(replacement,serial,expected(previous,id),original);
        check(next.ultra()&&replacement.length<previous.length,"Expected a smaller full-to-ultra replacement");
        UltraCertificate.validateCached(next.template(),certificate);match(certificate,id);
        return new Upgrade(serial,previous,replacement,certificate);
    }
    static String commitUltra(Path root,Identity id,Upgrade upgrade,char[] management)throws Exception{
        return commitUltra(root,id,upgrade,management,OnKeyDesktop::new);
    }
    static String commitUltra(Path root,Identity id,Upgrade upgrade,char[] management,Cards cards)throws Exception{
        try{
            validatedUpgrade(id,upgrade.serial(),upgrade.previous(),upgrade.replacement(),upgrade.certificate());
            Path recovery=root.resolve("companion-backups").resolve("ultra-"+upgrade.serial()+"-"+UUID.randomUUID());
            try(var card=cards.open(upgrade.serial())){CompanionStorage.replaceUltra(card,upgrade.previous(),upgrade.replacement(),management,recovery);}
            saveLocal(root,id,upgrade.replacement(),upgrade.certificate());
            return "Ultra-compact companion backed up and verified.\n"+upgrade.review()+"\nRecovery backup: "+recovery;
        }finally{Arrays.fill(management,'\0');}
    }
    static String resumeUltra(Path root,Identity id,Path recovery,char[] management)throws Exception{
        try{return resumeUltra(root,id,Integer.parseInt(DesktopState.activeTokenSerial()),recovery,management,OnKeyDesktop::new);}
        finally{Arrays.fill(management,'\0');}
    }
    static String resumeUltra(Path root,Identity id,int serial,Path recovery,char[] management,Cards cards)throws Exception{
        try{
            // Journal/selected-identity checks precede card opening, management
            // authentication and every mutation. Full backup supplies the cache
            // without regenerating certificate signatures during recovery.
            byte[] previous=bounded(recovery.resolve("previous.pqcomp")),replacement=bounded(recovery.resolve("replacement.pqcomp"));
            PublicIdentity own=fullForIdentity(previous,id,serial);validatedUpgrade(id,serial,previous,replacement,own);
            byte[] current;try(var card=cards.open(serial)){CompanionStorage.resumeUltra(card,recovery,management);current=CompanionStorage.load(card);}
            check(Arrays.equals(current,replacement),"Recovered card does not contain the selected journal replacement");
            Level5Companion.inspect(current,serial,expected(current,id),own);saveLocal(root,id,current,own);
            return "Ultra-compact backup recovered and verified; keys, policies and trust unchanged.";
        }finally{Arrays.fill(management,'\0');}
    }
    private static byte[] bounded(Path p)throws Exception{check(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<=Level5Companion.MAX,"Invalid companion file");return Files.readAllBytes(p);}
    static void saveLocal(Path root,Identity id,byte[] encoded,PublicIdentity own)throws Exception{
        var env=Level5Companion.inspect(encoded,serial(encoded),expected(encoded,id),own);match(own,id);
        Path p=path(root,id);Files.createDirectories(p.getParent());
        if(Files.exists(p)){
            byte[] old=bounded(p);
            if(!Arrays.equals(CompanionEncoding.unpack(old),CompanionEncoding.unpack(encoded))){
                var prior=Level5Companion.inspect(old,serial(encoded),expected(encoded,id));
                byte[] a=prior.ultra()?prior.template():UltraCertificate.template(prior.own());
                byte[] b=env.ultra()?env.template():UltraCertificate.template(env.own());
                check(Arrays.equals(a,b),"Different companion identity already saved; review before replacing");
            }
        }
        // Cache first: interruption before the ciphertext rename leaves a valid
        // old identity. Both files contain only public data or encrypted bytes.
        atomic(certificatePath(root,id),own.encoded);atomic(p,encoded);
    }
    private static void atomic(Path path,byte[] bytes)throws Exception{
        Path temp=Files.createTempFile(path.getParent(),"companion-",".tmp");try{Files.write(temp,bytes);Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}
    }
}
