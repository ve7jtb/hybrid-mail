package dev.hybridmail;

import java.security.PublicKey;
import java.util.*;

/** One logical operation: a no-touch unwrap followed by one touch-required
 * classical message component. All PIN copies and software PQ keys are scoped
 * to this object; a later message must obtain a fresh authorization. */
final class Level3PolyfillOperation implements ExternalMu.Backend,ExternalKem.Backend,AutoCloseable {
    private final byte[] encoded;
    private final int serial;
    private final Map<String,PublicKey> hardware;
    private final String signer,kem;
    private final Map<String,String> config;
    private final ExternalMu.PinSource source;
    private final OpenPgp.PublicIdentity own;
    private final ExternalMu.OperationPinCache pins=new ExternalMu.OperationPinCache();
    private Level3Companion companion;
    private boolean ended;

    Level3PolyfillOperation(byte[] encoded,int serial,Map<String,PublicKey> hardware,String signer,String kem,Map<String,String> config)throws Exception {
        this(encoded,serial,hardware,signer,kem,config,()->{TokenPresence.require(signer,Integer.toString(serial),config);return TokenPin.request("Level 3 OpenPGP — YubiKey "+serial);});
    }
    Level3PolyfillOperation(byte[] encoded,int serial,Map<String,PublicKey> hardware,String signer,String kem,Map<String,String> config,ExternalMu.PinSource source)throws Exception {
        // Authentication, slot bindings and certificate verification precede
        // both the PIN prompt and any use of a card private key.
        own=Level3Companion.inspect(encoded,serial,hardware).own();
        this.encoded=encoded.clone();this.serial=serial;this.hardware=Map.copyOf(hardware);
        this.signer=signer;this.kem=kem;this.config=Map.copyOf(config);this.source=source;
    }
    public Level3PolyfillOperation newOperation(){try{return new Level3PolyfillOperation(encoded,serial,hardware,signer,kem,config,source);}catch(Exception e){throw new IllegalStateException(e);}}
    private Level3Companion unlock()throws Exception {
        OpenPgp.check(!ended,"Companion operation ended");
        if(companion==null)companion=Level3Companion.restore(encoded,serial,hardware,this);
        return companion;
    }
    private byte[] call(boolean signing,String algorithm,PublicKey key,byte[] input)throws Exception {
        OpenPgp.check(!ended,"Companion operation ended");
        var options=new HashMap<>(config);
        // The adapter recognizes this closed profile. Certificate data cannot
        // supply arbitrary commands, slot numbers or alternate module paths.
        options.put("PQMAIL_LEVEL3_POLYFILL","1");options.put("PKCS11_SERIAL",Integer.toString(serial));
        options.put("PKCS11_KEM_SLOT","9d");options.put("PKCS11_ECDH_SLOT","83");
        try{return ExternalMu.invoke(signing?signer:kem,algorithm,key,input,pins.copy(source),!signing,options);}
        catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] sign(PublicKey key,byte[] mu)throws Exception {
        try{Level3Companion.same(key,own.signing.pq());OpenPgp.check(mu.length==64,"Expected 64-byte ML-DSA external mu");return unlock().signComponent(key,mu);}catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] signEd25519(PublicKey key,byte[] digest)throws Exception {
        try{Level3Companion.same(key,hardware.get("9c"));OpenPgp.check(digest.length==48||digest.length==64,"Expected composite digest");return call(true,"Ed25519",key,digest);}catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception {
        try{Level3Companion.same(key,own.encryption.pq());OpenPgp.check(ciphertext.length==1088,"Expected ML-KEM-768 ciphertext");return unlock().decapsulate(key,ciphertext);}catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] derive(PublicKey key,PublicKey peer)throws Exception {
        // Only slot 83 can unwrap this companion. Message decryption always
        // uses the different, touch-required X25519 key in slot 9d.
        try{
            if(key instanceof java.security.interfaces.ECPublicKey){Level3Companion.same(key,hardware.get("83"));Level3Companion.same(OpenPgp.ec(OpenPgp.raw(peer)),peer);return call(false,"ECDH-P384",key,peer.getEncoded());}
            Level3Companion.same(key,hardware.get("9d"));Level3Companion.same(OpenPgp.curve25519(OpenPgp.raw(peer),false),peer);return call(false,"X25519",key,peer.getEncoded());
        }catch(Exception e){clearSecrets();throw e;}
    }
    public void clearSecrets(){ended=true;pins.clear();if(companion!=null){companion.close();companion=null;}}
    public void close(){clearSecrets();}
}
