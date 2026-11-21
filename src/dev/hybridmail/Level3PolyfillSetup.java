package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import com.google.gson.Gson;

/** Empty-card creation with explicit resume. Public journals and encrypted
 * staging survive interruption; hardware generation is never blindly repeated. */
final class Level3PolyfillSetup {
    record Plan(int version,int serial,List<String> emails){}
    record Paths(String signer,String kem,Map<String,String> config){}
    static Paths paths(DesktopState state){return new Paths(state.adapter(false),state.adapter(true),state.configuration());}
    static Identity create(DesktopState state,String serial,List<String> emails,Path folder,char[] pin,char[] management)throws Exception {
        try{check(!Files.exists(folder)||empty(folder),"Use Resume for an existing setup directory");var loaded=run(Integer.parseInt(serial),emails,folder,pin,management,false,paths(state));return Level3PolyfillDesktop.install(state,loaded);}
        finally{wipe(pin);wipe(management);}
    }
    static Identity resume(DesktopState state,Path folder,char[] pin,char[] management)throws Exception {
        try{var plan=plan(folder);var loaded=run(plan.serial(),plan.emails(),folder,pin,management,true,paths(state));return Level3PolyfillDesktop.install(state,loaded);}
        finally{wipe(pin);wipe(management);}
    }
    static Plan plan(Path folder)throws Exception {
        Path file=folder.resolve("level3-setup.json");check(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&Files.size(file)<=4096,"Invalid Level 3 setup journal");
        var plan=new Gson().fromJson(Files.readString(file),Plan.class);validate(plan);return plan;
    }
    static void validate(Plan plan)throws Exception {
        check(plan!=null&&plan.version()==1&&plan.serial()>0&&plan.emails()!=null&&plan.emails().size()>=1&&plan.emails().size()<=3,"Use a primary email and at most two additional addresses for this card storage budget");
        var seen=new HashSet<String>();for(String email:plan.emails()){validateEmail(email);check(seen.add(email.toLowerCase(Locale.ROOT)),"Duplicate email");}
    }
    /** Fixed PIV data capacity on YK5 is separate from FIDO. Retain at least
     * 8 KiB for factory/other PIV data and object overhead. Actual card writes
     * remain authoritative and failures retain the staged ciphertext. */
    static final int MAX_CARD_BYTES=51200-8192;
    /** Validate before card access, including a resume that skips generation.
     * Never put entered characters in an exception or a saved result. */
    static void validateManagement(char[] value)throws Exception {
        check(value!=null&&(value.length==32||value.length==48||value.length==64),"Management key must contain 32, 48 or 64 hexadecimal characters; this is not the YubiKey PIN");
        for(char c:value)check(c<128&&Character.digit(c,16)>=0,"Management key must contain hexadecimal characters only; this is not the YubiKey PIN");
    }
    static Level3PolyfillDesktop.Loaded run(int serial,List<String> emails,Path folder,char[] pin,char[] management,boolean resume,Paths paths)throws Exception {
        try{
            validateManagement(management);
            Plan selected=new Plan(1,serial,List.copyOf(emails));validate(selected);
            if(!resume){
                // The hardware test may already have written read-only audit
                // evidence here. Never reuse identity/provisioning artifacts.
                check(!Files.exists(folder.resolve("level3-setup.json"))&&!Files.exists(folder.resolve("hardware"))&&!Files.exists(folder.resolve("companion.pqcomp")),"Use Resume for an existing setup directory");TokenProvision.checkPolyfill(Integer.toString(serial));
                PrivateFiles.directory(folder);durable(folder.resolve("level3-setup.json"),new Gson().toJson(selected).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }else check(plan(folder).equals(selected),"Setup plan differs from the selected identity");
            Path keyJournal=folder.resolve("hardware");Map<String,PublicKey> keys;
            // An existing native journal decides which, if any, slots remain
            // to generate. Its public-key and policy checks precede mutation.
            if(TokenProvision.allPolyfillKeysSaved(keyJournal))keys=TokenProvision.readPolyfill(Integer.toString(serial),keyJournal);
            else if(Files.isRegularFile(keyJournal.resolve("provisioning.json")))keys=TokenProvision.resumePolyfill(Integer.toString(serial),keyJournal,pin.clone(),management.clone());
            else keys=TokenProvision.createPolyfill(Integer.toString(serial),keyJournal,pin.clone(),management.clone());
            wipe(pin);Level3Companion.validateHardware(serial,keys);
            // Check backup authorization before asking for signing/decryption
            // PINs. Authentication alone does not write objects or change keys.
            // The later backup reconnects and authenticates independently.
            try(var card=new OnKeyDesktop(serial)){check(card.serial()==serial,"Wrong YubiKey");card.authenticate(management.clone());}
            for(String slot:Level3Companion.SLOTS)Files.write(folder.resolve(slot+".der"),keys.get(slot).getEncoded());
            Path staged=folder.resolve("companion.pqcomp");byte[] encoded;
            if(Files.exists(staged)){
                check(Files.isRegularFile(staged,LinkOption.NOFOLLOW_LINKS)&&Files.size(staged)<=Level3Companion.MAX,"Invalid staged companion");encoded=Files.readAllBytes(staged);Level3Companion.inspect(encoded,serial,keys);
            }else{
                try(var hardware=new Level3PolyfillHardware(serial,keys,paths.signer(),paths.kem(),paths.config(),()->TokenPin.request("Create Level 3 OpenPGP certificates — Ed25519; touch for each signature"));var companion=Level3Companion.create(serial,keys,emails,hardware.certification(),hardware)){
                    encoded=companion.seal(hardware.certification());durable(staged,encoded);
                }
            }
            var env=Level3Companion.inspect(encoded,serial,keys);check(new HashSet<>(env.own().certifiedEmails()).equals(new HashSet<>(emails)),"Staged companion emails differ from setup plan");
            int stored=CompanionStorage.storedSize(encoded);Files.writeString(folder.resolve("size.txt"),"Compressed companion: "+encoded.length+" bytes\nCard objects: "+stored+" bytes\nPIV allocation: 51200 bytes; conservative budget: "+MAX_CARD_BYTES+" bytes\n");
            check(stored<=MAX_CARD_BYTES,"Companion exceeds conservative PIV budget; ciphertext retained, no bundle write attempted");
            // Test both components before committing the on-card envelope.
            // No test content leaves this process except synthetic ciphertext.
            byte[] plain=bytes("Synthetic Level 3 companion hardware test. No email sent.\n"),signed,encrypted;
            try(var hardware=new Level3PolyfillHardware(serial,keys,paths.signer(),paths.kem(),paths.config(),()->TokenPin.request("Test Ed25519 + ML-DSA-65 signing — touch required"));var restored=Level3Companion.restore(encoded,serial,keys,hardware)){
                signed=restored.sign(plain,hardware);check(Arrays.equals(plain,openSigned(signed,env.own())),"PQ Mail signature verification failed");encrypted=encrypt(signed,env.own());
            }
            try(var hardware=new Level3PolyfillHardware(serial,keys,paths.signer(),paths.kem(),paths.config(),()->TokenPin.request("Test X25519 + ML-KEM-768 decryption — touch required"));var restored=Level3Companion.restore(encoded,serial,keys,hardware)){
                check(Arrays.equals(plain,openSigned(restored.decrypt(encrypted,hardware),env.own())),"PQ Mail decryption failed");
            }
            Files.write(folder.resolve("public.pgp"),env.own().encoded);Files.write(folder.resolve("public.asc"),env.own().export());Files.write(folder.resolve("plain.txt"),plain);Files.write(folder.resolve("java-encrypted.pgp"),encrypted);Files.write(folder.resolve("java-signed.pgp"),signed);
            try(var card=new OnKeyDesktop(serial)){CompanionStorage.save(card,encoded,management.clone(),folder.resolve("recovery/companion.pqcomp"));check(Arrays.equals(CompanionStorage.load(card),encoded),"Card read-back mismatch");}
            // Native read also verifies each policy against the durable journal.
            TokenProvision.readPolyfill(Integer.toString(serial),keyJournal);
            Files.writeString(folder.resolve("pqmail-result.txt"),"PASS Level 3 companion restore, signing, decryption and fresh on-card restore. Ed25519 82/9c and X25519 9d require touch; dedicated P384 83 is PIN-protected/no-touch.\n");
            return new Level3PolyfillDesktop.Loaded(encoded,env);
        }finally{wipe(pin);wipe(management);}
    }
    private static boolean empty(Path folder)throws Exception {try(var files=Files.list(folder)){return files.findAny().isEmpty();}}
    static void durable(Path file,byte[] bytes)throws Exception {
        try(var c=FileChannel.open(file,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){ByteBuffer b=ByteBuffer.wrap(bytes);while(b.hasRemaining())c.write(b);c.force(true);}
        // The journal filename must survive a crash too, before any card write.
        try(var directory=FileChannel.open(file.getParent(),StandardOpenOption.READ)){directory.force(true);}
    }
    private static void wipe(char[] value){if(value!=null)Arrays.fill(value,'\0');}
}
