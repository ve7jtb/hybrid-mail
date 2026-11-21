package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** One PIN authorization shared by unwrap and the two message components.
 * A new message must get a new operation; neither PIN nor software key survives
 * clearSecrets. Existing PIV PIN Always and touch policies are not altered.
 */
final class CompanionOperation implements ExternalMu.Backend,ExternalKem.Backend {
    private final byte[] encoded;
    private final int serial;
    private final Map<String,PublicKey> hardware;
    private final String signer,kem;
    private final ExternalMu.OperationPinCache pins=new ExternalMu.OperationPinCache();
    private final Map<String,String> config;
    private final OpenPgp.PublicIdentity cached;
    private Level5Companion companion;
    private boolean ended;
    CompanionOperation(byte[] encoded,int serial,Map<String,PublicKey> hardware,String signer,String kem,Map<String,String> config)throws Exception{
        this(encoded,serial,hardware,signer,kem,config,null);
    }
    CompanionOperation(byte[] encoded,int serial,Map<String,PublicKey> hardware,String signer,String kem,Map<String,String> config,OpenPgp.PublicIdentity cached)throws Exception{
        Level5Companion.inspect(encoded,serial,hardware,cached);this.encoded=encoded.clone();this.serial=serial;this.hardware=Map.copyOf(hardware);this.signer=signer;this.kem=kem;this.config=Map.copyOf(config);this.cached=cached;
    }
    public CompanionOperation newOperation(){try{return new CompanionOperation(encoded,serial,hardware,signer,kem,config,cached);}catch(Exception e){throw new IllegalStateException(e);}}
    private byte[] invoke(boolean signing,String algorithm,PublicKey key,byte[] input,Map<String,String> extra)throws Exception{
        OpenPgp.check(!ended,"Companion operation ended");var options=new HashMap<>(config);options.put("PKCS11_SERIAL",Integer.toString(serial));options.put("PKCS11_KEM_SLOT","9d");options.put("PKCS11_ECDH_SLOT","82");options.putAll(extra);
        try{return ExternalMu.invoke(signing?signer:kem,algorithm,key,input,pins.copy(()->TokenPin.request(algorithm+" — YubiKey "+serial)),!signing,options);}catch(Exception e){clearSecrets();throw e;}
    }
    private Level5Companion unlock()throws Exception{OpenPgp.check(!ended,"Companion operation ended");if(companion==null)companion=Level5Companion.restore(encoded,serial,hardware,this,cached);return companion;}
    /** Certification is exposed only to the locally validated restore/conversion
     * workflow. Message signing continues to require the separate slot 9c key. */
    ExternalMu.Backend certification(){return (key,mu)->{Level5Companion.same(key,hardware.get("86"));return invoke(true,"ML-DSA-87",key,mu,Map.of("PQMAIL_CERTIFICATION_SLOTS","86,87"));};}
    public byte[] sign(PublicKey key,byte[] mu)throws Exception{Level5Companion.same(key,hardware.get("9c"));return invoke(true,"ML-DSA-87",key,mu,Map.of());}
    public byte[] signEd448(PublicKey key,byte[] digest)throws Exception{try{return unlock().signComponent(key,digest);}catch(Exception e){clearSecrets();throw e;}}
    public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{Level5Companion.same(key,hardware.get("9d"));OpenPgp.check(ct.length==1568,"Wrong ML-KEM ciphertext size");return invoke(false,"ML-KEM-1024",key,ct,Map.of());}
    public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
        if(key instanceof java.security.interfaces.ECPublicKey){Level5Companion.same(key,hardware.get("82"));return invoke(false,"ECDH-P384",key,peer.getEncoded(),Map.of());}
        try{return unlock().deriveComponent(key,peer);}catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] signCompatibilityEcdsa(PublicKey key,byte[] digest)throws Exception{return invoke(true,"ECDSA-P384-SHA384",key,digest,Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
    public byte[] decapsulateLevel5Compatibility(PublicKey key,byte[] ct)throws Exception{return invoke(false,"ML-KEM-768",key,ct,Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
    public byte[] deriveLevel5Compatibility(PublicKey key,PublicKey peer)throws Exception{return invoke(false,key instanceof java.security.interfaces.ECPublicKey?"ECDH-P384":"X25519",key,peer.getEncoded(),Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
    public void clearSecrets(){ended=true;pins.clear();if(companion!=null){companion.close();companion=null;}}
}
