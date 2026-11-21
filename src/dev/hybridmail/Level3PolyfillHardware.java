package dev.hybridmail;

import java.security.*;
import java.util.*;

/** Classical-only card interface for initial certificate issuance. The
 * software PQ component is supplied by Level3Companion, never by PKCS#11. */
final class Level3PolyfillHardware implements ExternalMu.Backend,ExternalKem.Backend,AutoCloseable {
    private final int serial;
    private final Map<String,PublicKey> hardware;
    private final String signer,kem;
    private final Map<String,String> config;
    private final ExternalMu.PinSource source;
    private final ExternalMu.OperationPinCache pins=new ExternalMu.OperationPinCache();
    private boolean ended;
    Level3PolyfillHardware(int serial,Map<String,PublicKey> hardware,String signer,String kem,Map<String,String> config,ExternalMu.PinSource source)throws Exception {
        Level3Companion.validateHardware(serial,hardware);this.serial=serial;this.hardware=Map.copyOf(hardware);
        this.signer=signer;this.kem=kem;this.config=Map.copyOf(config);this.source=source;
    }
    private byte[] call(boolean signing,String algorithm,PublicKey key,byte[] data,boolean cert)throws Exception {
        OpenPgp.check(!ended,"Hardware authorization ended");var options=new HashMap<>(config);
        options.put("PQMAIL_LEVEL3_POLYFILL","1");options.put("PKCS11_SERIAL",Integer.toString(serial));options.put("PKCS11_KEM_SLOT","9d");options.put("PKCS11_ECDH_SLOT","83");
        if(cert)options.put("PQMAIL_POLYFILL_CERTIFICATION","1");
        try{return ExternalMu.invoke(signing?signer:kem,algorithm,key,data,pins.copy(()->{TokenPresence.require(signer,Integer.toString(serial),config);return source.request();}),!signing,options);}catch(Exception e){close();throw e;}
    }
    ExternalMu.Backend certification(){return new ExternalMu.Backend(){
        public byte[] sign(PublicKey key,byte[] mu)throws Exception{throw new GeneralSecurityException("No hardware ML-DSA in this profile");}
        public byte[] signEd25519(PublicKey key,byte[] digest)throws Exception{Level3Companion.same(key,hardware.get("82"));return call(true,"Ed25519",key,digest,true);}
    };}
    public byte[] sign(PublicKey key,byte[] mu)throws Exception{throw new GeneralSecurityException("No hardware ML-DSA in this profile");}
    public byte[] signEd25519(PublicKey key,byte[] digest)throws Exception{Level3Companion.same(key,hardware.get("9c"));return call(true,"Ed25519",key,digest,false);}
    public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{throw new GeneralSecurityException("No hardware ML-KEM in this profile");}
    public byte[] derive(PublicKey key,PublicKey peer)throws Exception {
        String slot=key instanceof java.security.interfaces.ECPublicKey?"83":"9d";Level3Companion.same(key,hardware.get(slot));
        return call(false,slot.equals("83")?"ECDH-P384":"X25519",key,peer.getEncoded(),false);
    }
    public Level3PolyfillHardware newOperation(){try{return new Level3PolyfillHardware(serial,hardware,signer,kem,config,source);}catch(Exception e){throw new IllegalStateException(e);}}
    public void clearSecrets(){close();}
    public void close(){ended=true;pins.clear();}
}
