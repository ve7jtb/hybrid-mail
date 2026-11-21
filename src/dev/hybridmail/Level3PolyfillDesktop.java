package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Public identity routing and ciphertext-only local cache for PQMCP003.
 * The X.509 carriers are catalog metadata, never S/MIME credentials. No
 * decrypted PKCS#12, password, private seed or shared secret is saved here. */
final class Level3PolyfillDesktop {
    record Loaded(byte[] encoded,Level3Companion.Encoded env){}
    static Path path(Path root,Identity id)throws Exception{return ownPath(root,id).resolveSibling(ownPath(root,id).getFileName()+".l3pqcomp");}
    static Map<String,PublicKey> hardware(OnKeyBundle.Card card)throws Exception {
        var keys=new LinkedHashMap<String,PublicKey>();
        for(String slot:Level3Companion.SLOTS){byte[] der=card.publicKey(slot);check(der!=null,"Missing Level 3 companion key in slot "+slot);keys.put(slot,Level3Companion.decodePublic(der));}
        Level3Companion.validateHardware(card.serial(),keys);return keys;
    }
    /** Parsing these header keys grants no authority: inspect subsequently
     * verifies the complete envelope and compares the selected identity. */
    static Loaded inspect(byte[] encoded)throws Exception {
        var outer=new DataInputStream(new ByteArrayInputStream(CompanionEncoding.unpack(encoded)));
        var body=new DataInputStream(new ByteArrayInputStream(Level5Companion.field(outer)));
        check(Arrays.equals(body.readNBytes(8),Level3Companion.MAGIC),"Expected a Level 3 software-PQ companion");int serial=body.readInt();
        var hardware=new LinkedHashMap<String,PublicKey>();for(String slot:Level3Companion.SLOTS)hardware.put(slot,Level3Companion.decodePublic(Level5Companion.field(body)));
        return new Loaded(encoded,Level3Companion.inspect(encoded,serial,hardware));
    }
    static Loaded readCard(int serial)throws Exception {return readCard(serial,TokenProvision.helper());}
    static Loaded readCard(int serial,Path helper)throws Exception {
        try(var card=new OnKeyDesktop(serial,helper)){
            check(card.serial()==serial,"Wrong YubiKey");byte[] encoded=CompanionStorage.load(card);
            return new Loaded(encoded,Level3Companion.inspect(encoded,serial,hardware(card)));
        }
    }
    static Loaded local(Path root,Identity id)throws Exception {
        check(id!=null&&id.level3Polyfill(),"Select a Level 3 software-PQ companion identity");Path p=path(root,id);
        check(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<=Level3Companion.MAX,"Missing or invalid encrypted Level 3 companion");
        var loaded=inspect(Files.readAllBytes(p));var anchors=loaded.env().anchors();
        check(Arrays.equals(id.signingCert().getEncoded(),anchors.signingCert().getEncoded())&&Arrays.equals(id.encryptionCert().getEncoded(),anchors.encryptionCert().getEncoded()),"Companion does not match the selected identity");
        match(loaded.env().own(),id);return loaded;
    }
    static PublicIdentity own(Path root,Identity id)throws Exception{return local(root,id).env().own();}
    static Level3PolyfillOperation operation(Path root,Identity id,String signer,String kem,Map<String,String> config)throws Exception {
        var loaded=local(root,id);var e=loaded.env();check(Integer.toString(e.serial()).equals(DesktopState.activeTokenSerial()),"Selected identity requires YubiKey "+e.serial());
        return new Level3PolyfillOperation(loaded.encoded(),e.serial(),e.hardware(),signer,kem,config);
    }
    static Identity install(DesktopState state,Loaded loaded)throws Exception {
        // Revalidate even when the caller previously displayed a review. Save
        // public material/ciphertext before publishing the catalog selection.
        var env=Level3Companion.inspect(loaded.encoded(),loaded.env().serial(),loaded.env().hardware());Identity id=env.anchors();match(env.own(),id);
        saveLocal(state.directory(),id,loaded.encoded());
        String catalog=state.remember(id,env.own().email+" · Level 3 hybrid — software PQ companion",null);
        state.bindToken(catalog,Integer.toString(env.serial()),"9c","9d","83");state.save();return id;
    }
    static void saveLocal(Path root,Identity id,byte[] encoded)throws Exception {
        var loaded=inspect(encoded);match(loaded.env().own(),id);Path target=path(root,id);Files.createDirectories(target.getParent());
        if(Files.exists(target)){check(Arrays.equals(Files.readAllBytes(target),encoded),"A different companion is already saved for this identity");return;}
        atomic(ownPath(root,id),loaded.env().own().export());atomic(target,encoded);
    }
    private static void atomic(Path target,byte[] bytes)throws Exception {
        Path temp=Files.createTempFile(target.getParent(),"l3-companion-",".tmp");
        try{Files.write(temp,bytes);Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}
    }
}
