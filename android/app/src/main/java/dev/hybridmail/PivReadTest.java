package dev.hybridmail;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.Slot;
import java.security.*;
import java.util.Map;

/** Read-only control: one PIV session with repeated bound public-key reads, no VERIFY/private APDUs. */
final class PivReadTest {
    static String run(YubiKeyDevice device,int serial,Map<Slot,PublicKey> expected)throws Exception {
        int completed=0;String stage="opening connection";
        try(var connection=new PivDiagnostic.Connection(device.openConnection(SmartCardConnection.class))){
            try{
                stage="selecting PIV";var piv=PivSessions.open(connection);
                for(int cycle=0;cycle<10;cycle++){
                    stage="reading serial";if(piv.getSerialNumber()!=serial)throw new GeneralSecurityException("Wrong YubiKey; expected "+serial);
                    for(var entry:expected.entrySet()){
                        stage="reading public key in "+entry.getKey();
                        if(!MessageDigest.isEqual(entry.getValue().getEncoded(),YubiBackend.publicKey(piv,entry.getKey()).getEncoded()))throw new GeneralSecurityException("Public key mismatch");
                    }
                    completed++;
                }
                return "PASS read-only "+device.getTransport()+" serial="+serial+": 10 cycles in one PIV session; serial and bound public keys matched.\n"+connection.detail()+"\nNo PIN or private-key operation performed.";
            }catch(Exception e){throw new PivDiagnostic("FAIL read-only "+device.getTransport()+" serial="+serial+": "+completed+"/10 cycles; "+stage+"\n"+connection.detail()+"\n"+e.getClass().getSimpleName()+": "+e.getMessage(),e);}
        }
    }
}
