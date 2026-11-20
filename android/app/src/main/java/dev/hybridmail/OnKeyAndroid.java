package dev.hybridmail;
import com.yubico.yubikit.core.smartcard.*;
import com.yubico.yubikit.piv.*;
import java.util.*;
import java.io.*;
/** Uses the same bounded NFC framing and session initialization as signing. */
final class OnKeyAndroid implements OnKeyBundle.Card {
    final SmartCardConnection connection;final PivSession piv;
    OnKeyAndroid(com.yubico.yubikit.core.YubiKeyDevice device)throws Exception{
        connection=new PivDiagnostic.Connection(device.openConnection(SmartCardConnection.class));
        try{piv=PivSessions.open(connection);}catch(Exception e){connection.close();throw e;}
    }
    public int serial()throws Exception{return piv.getSerialNumber();}
    public byte[] publicKey(String slot)throws Exception{try{return YubiBackend.publicKey(piv,Slot.fromValue(Integer.parseInt(slot,16))).getEncoded();}catch(ApduException e){if((e.getSw()&0xffff)==0x6a88)return null;throw e;}}
    public byte[] get(int tag)throws Exception{try{return piv.getObject(tag);}catch(ApduException e){if((e.getSw()&0xffff)==0x6a82)return null;throw e;}}
    public void put(int tag,byte[] data)throws Exception{piv.putObject(tag,data);}
    public void authenticate(char[] hex)throws Exception{
        byte[] raw=new byte[hex.length/2];try{
            if(!Set.of(32,48,64).contains(hex.length))throw new IOException("Management key must have 32, 48 or 64 hex characters");
            for(int i=0;i<raw.length;i++){int a=Character.digit(hex[2*i],16),b=Character.digit(hex[2*i+1],16);if(a<0||b<0)throw new IOException("Invalid management key");raw[i]=(byte)(a*16+b);}piv.authenticate(raw);
        }finally{Arrays.fill(hex,'\0');Arrays.fill(raw,(byte)0);}
    }
    public void move9aTo83()throws Exception{
        try{piv.getSlotMetadata(Slot.RETIRED2);throw new IOException("Slot 83 contains a key");}catch(ApduException e){if((e.getSw()&0xffff)!=0x6a88)throw e;}
        if(get(Slot.RETIRED2.objectId)!=null)throw new IOException("Slot 83 contains a certificate");
        var before=piv.getSlotMetadata(Slot.AUTHENTICATION);if(before.getKeyType()!=KeyType.ECCP256&&before.getKeyType()!=KeyType.ECCP384)throw new IOException("Migration requires ECDSA P-256/P-384");
        byte[] certificate=get(Slot.AUTHENTICATION.objectId);
        piv.moveKey(Slot.AUTHENTICATION,Slot.RETIRED2);
        var after=piv.getSlotMetadata(Slot.RETIRED2);
        if(!Arrays.equals(before.getPublicKeyValues().getEncoded(),after.getPublicKeyValues().getEncoded())||before.getPinPolicy()!=after.getPinPolicy()||before.getTouchPolicy()!=after.getTouchPolicy())throw new IOException("Key moved; metadata verification failed");
        if(certificate!=null){put(Slot.RETIRED2.objectId,certificate);if(!Arrays.equals(certificate,get(Slot.RETIRED2.objectId)))throw new IOException("Key moved; certificate verification failed");piv.putObject(Slot.AUTHENTICATION.objectId,null);}
    }
    public void close()throws Exception{connection.close();}
}
