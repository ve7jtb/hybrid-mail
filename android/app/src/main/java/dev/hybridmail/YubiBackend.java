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
    interface DeviceSource { YubiKeyDevice get() throws Exception; }
    interface PinSource { char[] get(String algorithm) throws Exception; }
    private final DeviceSource devices;
    private final PinSource pins;
    private final int serial;
    private final Map<Slot,PublicKey> expected;
    private SmartCardConnection connection;
    private PivSession session;
    private char[] pin;
    YubiBackend(DeviceSource devices, PinSource pins, int serial, Map<Slot,PublicKey> expected) {
        this.devices=devices;this.pins=pins;this.serial=serial;this.expected=Map.copyOf(expected);
    }
    public YubiBackend newOperation(){return new YubiBackend(devices,pins,serial,expected);}
    static PublicKey publicKey(PivSession piv, Slot slot)throws Exception {
        var metadata=piv.getSlotMetadata(slot);
        String algorithm=switch(metadata.getKeyType()) {
            case MLDSA44 -> "ML-DSA-44";case MLDSA65 -> "ML-DSA-65";case MLDSA87 -> "ML-DSA-87";
            case MLKEM768 -> "ML-KEM-768";case MLKEM1024 -> "ML-KEM-1024";
            case ECCP256, ECCP384 -> "EC";
            default -> throw new GeneralSecurityException("Unsupported key in slot "+slot);
        };
        return KeyFactory.getInstance(algorithm,"BC").generatePublic(new X509EncodedKeySpec(metadata.getPublicKeyValues().getEncoded()));
    }
    static Map<Slot,PublicKey> keys(Identity identity) {
        return keys(identity,new String[]{"9c","9a","9d","82"});
    }
    static Map<Slot,PublicKey> keys(Identity identity,String[] slots){
        Map<Slot,PublicKey> keys=new EnumMap<>(Slot.class);
        add(keys,identity.signingCert().getPublicKey(),Slot.fromValue(Integer.parseInt(slots[0],16)),Slot.fromValue(Integer.parseInt(slots[1],16)));
        if(identity.encryptionCert()!=null)add(keys,identity.encryptionCert().getPublicKey(),Slot.fromValue(Integer.parseInt(slots[2],16)),Slot.fromValue(Integer.parseInt(slots[3],16)));
        return keys;
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
            for(var e:expected.entrySet()){stage="Reading public-key metadata for slot "+e.getKey();if(!MessageDigest.isEqual(e.getValue().getEncoded(),publicKey(session,e.getKey()).getEncoded()))
                throw new GeneralSecurityException("YubiKey slot "+e.getKey()+" does not match this identity");}
        }catch(Exception e){String detail=connection instanceof PivDiagnostic.Connection c?c.detail():"connection unavailable";clearSecrets();throw new PivDiagnostic(stage+" failed before PIN submission.\n"+detail+"\n"+e.getMessage(),e);}
    }
    private Slot slotFor(PublicKey key)throws GeneralSecurityException{
        for(var entry:expected.entrySet())if(MessageDigest.isEqual(entry.getValue().getEncoded(),key.getEncoded()))return entry.getKey();
        throw new GeneralSecurityException("Unbound token key");
    }
    private KeyType authorize(Slot slot,PublicKey key,String label)throws Exception {
        PublicKey bound=expected.get(slot);
        if(bound==null||!MessageDigest.isEqual(bound.getEncoded(),key.getEncoded()))throw new GeneralSecurityException("Unbound token key");
        if(pin==null)pin=pins.get(label);
        connect(); // No NFC session is left idle while the user enters the PIN.
        // PIN_ALWAYS requires VERIFY for each component. Never retry a rejected PIN.
        session.verifyPin(pin);
        return session.getSlotMetadata(slot).getKeyType();
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
    public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception {
        try {KeyType type=authorize(slotFor(key),key,key.getAlgorithm()+" decryption");
            return session.decapsulate(slotFor(key),type,ciphertext);
        }catch(Exception e){clearSecrets();throw e;}
    }
    public byte[] derive(PublicKey key,PublicKey peer)throws Exception {
        try {authorize(slotFor(key),key,"ECDH decryption");
            return session.calculateSecret(slotFor(key),PublicKeyValues.fromPublicKey(peer));
        }catch(Exception e){clearSecrets();throw e;}
    }
    public void clearSecrets() {
        if(pin!=null){Arrays.fill(pin,'\0');pin=null;}
        session=null;
        if(connection!=null){try{connection.close();}catch(Exception ignored){}connection=null;}
    }
}
