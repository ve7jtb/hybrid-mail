package dev.hybridmail;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.piv.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** One connection and PIN per logical signature/decryption. No PKCS#11 or shell. */
final class YubiBackend implements ExternalMu.Backend, ExternalKem.Backend {
    interface DeviceSource {
        YubiKeyDevice get() throws Exception;
        default void setupFailed(String operation,int attempt,String frames)throws Exception{}
        default boolean retryBeforePin(String detail)throws Exception{return false;}
    }
    interface PinSource { char[] get(String algorithm) throws Exception; }
    private final DeviceSource devices;
    private final PinSource pins;
    private final int serial;
    private final Map<Slot,PublicKey> expected;
    private SmartCardConnection connection;
    private PivSession session;
    private final Map<Slot,KeyType> verifiedTypes=new EnumMap<>(Slot.class);
    private char[] pin;
    YubiBackend(DeviceSource devices, PinSource pins, int serial, Map<Slot,PublicKey> expected) {
        this.devices=devices;this.pins=pins;this.serial=serial;this.expected=Map.copyOf(expected);
    }
    public YubiBackend newOperation(){return new YubiBackend(devices,pins,serial,expected);}
    static PublicKey publicKey(PivSession piv, Slot slot)throws Exception {
        return publicKey(piv.getSlotMetadata(slot),slot);
    }
    private static PublicKey publicKey(SlotMetadata metadata,Slot slot)throws Exception {
        String algorithm=switch(metadata.getKeyType()) {
            case MLDSA44 -> "ML-DSA-44";case MLDSA65 -> "ML-DSA-65";case MLDSA87 -> "ML-DSA-87";
            case MLKEM768 -> "ML-KEM-768";case MLKEM1024 -> "ML-KEM-1024";
            case ECCP256, ECCP384 -> "EC";case ED25519 -> "Ed25519";case X25519 -> "X25519";
            default -> throw new GeneralSecurityException("Unsupported key in slot "+slot);
        };
        return KeyFactory.getInstance(algorithm,"BC").generatePublic(new X509EncodedKeySpec(metadata.getPublicKeyValues().getEncoded()));
    }
    static Map<Slot,PublicKey> keys(Identity identity) {
        return keys(identity,new String[]{"9c","83","9d","82"});
    }
    static Map<Slot,PublicKey> keys(Identity identity,String[] slots){
        Map<Slot,PublicKey> keys=new EnumMap<>(Slot.class);
        add(keys,identity.signingCert().getPublicKey(),Slot.fromValue(Integer.parseInt(slots[0],16)),Slot.fromValue(Integer.parseInt(slots[1],16)));
        if(identity.encryptionCert()!=null)add(keys,identity.encryptionCert().getPublicKey(),Slot.fromValue(Integer.parseInt(slots[2],16)),Slot.fromValue(Integer.parseInt(slots[3],16)));
        return keys;
    }
    static Map<Slot,PublicKey> pgpKeys(Identity id,String[] slots,OpenPgp.PublicIdentity own)throws Exception {
        OpenPgp.match(own,id);
        if(Level5Compatibility.supports(own)&&own.compatibility!=null){
            var result=keys(id,slots);var full=own.compatibility;Level5Compatibility.checkPair(own,full);
            result.put(Slot.RETIRED7,Level5Compatibility.key(full.legacy.primary));result.put(Slot.RETIRED8,Level5Compatibility.key(Level5Compatibility.classical(full).legacy.recipient));
            result.put(Slot.RETIRED3,OpenPgp.pq(OpenPgp.slice(full.subkey,38,full.subkey.length),false));result.put(Slot.RETIRED4,OpenPgp.curve25519(OpenPgp.slice(full.subkey,6,38),false));return result;
        }
        if(!OpenPgp.rfc9980(own))return keys(id,slots);
        Map<Slot,PublicKey> result=new EnumMap<>(Slot.class);
        result.put(Slot.fromValue(Integer.parseInt(slots[0],16)),own.signing.pq());
        result.put(Slot.RETIRED3,own.signing.ec());
        result.put(Slot.fromValue(Integer.parseInt(slots[2],16)),own.encryption.pq());
        result.put(Slot.RETIRED4,own.encryption.ec());
        return result;
    }
    private static void add(Map<Slot,PublicKey> keys,PublicKey key,Slot pq,Slot ec) {
        if(key instanceof org.bouncycastle.jcajce.CompositePublicKey c){keys.put(pq,c.getPublicKeys().get(0));keys.put(ec,c.getPublicKeys().get(1));}
        else keys.put(pq,key);
    }
    private void connect()throws Exception {
        if(session!=null)return;
        String stage="Opening smart-card connection";
        try {
            connection=new PivDiagnostic.Connection(devices.get().openConnection(SmartCardConnection.class));
            stage="Selecting and initializing PIV";
            session=PivSessions.open(connection);
            stage="Reading PIV serial number";
            if(session.getSerialNumber()!=serial)throw new GeneralSecurityException("Wrong YubiKey. Insert serial "+serial);
            // Check ALL bound public keys before submitting a PIN.
            for(var e:expected.entrySet()){
                stage="Reading public-key metadata for slot "+e.getKey();
                var metadata=session.getSlotMetadata(e.getKey());
                if(!MessageDigest.isEqual(e.getValue().getEncoded(),publicKey(metadata,e.getKey()).getEncoded()))
                    throw new GeneralSecurityException("YubiKey slot "+e.getKey()+" does not match this identity");
                verifiedTypes.put(e.getKey(),metadata.getKeyType());
            }
        }catch(Exception e){
            String detail=connection instanceof PivDiagnostic.Connection c?c.detail():"connection unavailable";
            boolean retryable=connection instanceof PivDiagnostic.Connection c&&c.getTransport()==com.yubico.yubikit.core.Transport.NFC&&c.transportFailed();
            // Preserve the operation PIN only while offering a bounded fresh-tap recovery.
            // No VERIFY has happened in connect(). All terminal exits clear it in the caller.
            char[] enteredPin=pin;pin=null;clearSecrets();pin=enteredPin;
            throw new PivDiagnostic(stage+" failed before PIN submission.\n"+detail+"\n"+e.getMessage(),e,retryable,stage+"\n"+detail);
        }
    }
    private Slot slotFor(PublicKey key)throws GeneralSecurityException{
        for(var entry:expected.entrySet())if(MessageDigest.isEqual(entry.getValue().getEncoded(),key.getEncoded()))return entry.getKey();
        throw new GeneralSecurityException("Unbound token key");
    }
    private KeyType authorize(Slot slot,PublicKey key,String label)throws Exception {
        PublicKey bound=expected.get(slot);
        if(bound==null||!MessageDigest.isEqual(bound.getEncoded(),key.getEncoded()))throw new GeneralSecurityException("Unbound token key");
        if(pin==null)pin=pins.get(label);
        for(int attempt=0;;attempt++){
            try{connect();break;}
            catch(PivDiagnostic e){
                if(e.retryableBeforePin)devices.setupFailed(label,attempt+1,e.frameDetail);
                if(!e.retryableBeforePin||attempt>=2||!devices.retryBeforePin(e.getMessage()))throw e;
            }
        } // Recovery is limited to read-only setup, before VERIFY or private-key commands.
        // PIN_ALWAYS requires VERIFY for each component. Never retry a rejected PIN.
        KeyType type=verifiedTypes.get(slot);
        if(type==null)throw new GeneralSecurityException("Slot metadata was not verified on this connection");
        session.verifyPin(pin);
        return type;
    }
    public byte[] sign(PublicKey key,byte[] mu)throws Exception {
        try {if(mu.length!=64)throw new GeneralSecurityException("Expected 64-byte external mu");
            return sessionSign(key,mu);
        }catch(Exception e){clearSecrets();throw e;}
    }
    private byte[] sessionSign(PublicKey key,byte[] mu)throws Exception {
        KeyType type=authorize(slotFor(key),key,key.getAlgorithm()+" signing");
        return session.rawSignExternalMu(slotFor(key),type,mu);
    }
    public byte[] signEcdsa(PublicKey key,byte[] digest)throws Exception {
        try {KeyType type=authorize(slotFor(key),key,"ECDSA signing");
            if(digest.length!=(type==KeyType.ECCP384?48:32))throw new GeneralSecurityException("Incorrect ECDSA digest size");
            return session.rawSignOrDecrypt(slotFor(key),type,digest);
        }catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] signCompatibilityEcdsa(PublicKey key,byte[] digest)throws Exception{
        if(slotFor(key)!=Slot.RETIRED7)throw new GeneralSecurityException("Compatibility signing requires slot 88");return signEcdsa(key,digest);
    }
    public byte[] decapsulateLevel5Compatibility(PublicKey key,byte[] ciphertext)throws Exception{
        if(slotFor(key)!=Slot.RETIRED3)throw new GeneralSecurityException("Compatibility KEM requires slot 84");return decapsulate(key,ciphertext);
    }
    public byte[] deriveLevel5Compatibility(PublicKey key,PublicKey peer)throws Exception{
        if(slotFor(key)!=(key instanceof java.security.interfaces.ECPublicKey?Slot.RETIRED8:Slot.RETIRED4))throw new GeneralSecurityException("Wrong compatibility ECDH slot");return derive(key,peer);
    }
    public byte[] signEd25519(PublicKey key,byte[] digest)throws Exception {
        try {
            if(digest.length!=48)throw new GeneralSecurityException("Expected OpenPGP SHA-384 digest");
            Slot slot=slotFor(key);KeyType type=authorize(slot,key,"RFC 9980 ML-DSA-65 + Ed25519 signing");
            if(type!=KeyType.ED25519)throw new GeneralSecurityException("Expected Ed25519 signing key");
            byte[] signature=session.rawSignOrDecrypt(slot,type,digest);
            if(signature.length!=64)throw new GeneralSecurityException("Invalid Ed25519 signature length");
            return signature;
        }catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception {
        try {KeyType type=authorize(slotFor(key),key,key.getAlgorithm()+" decryption");
            return session.decapsulate(slotFor(key),type,ciphertext);
        }catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] derive(PublicKey key,PublicKey peer)throws Exception {
        try {authorize(slotFor(key),key,key instanceof java.security.interfaces.ECPublicKey?"ECDH decryption":"RFC 9980 ML-KEM-768 + X25519 decryption");
            return session.calculateSecret(slotFor(key),PublicKeyValues.fromPublicKey(peer));
        }catch(Exception e){clearSecrets();throw e;}
    }
    public void clearSecrets() {
        if(pin!=null){Arrays.fill(pin,'\0');pin=null;}
        session=null;verifiedTypes.clear();
        if(connection!=null){try{connection.close();}catch(Exception ignored){}connection=null;}
    }
}
