package dev.hybridmail;
import com.yubico.yubikit.core.application.SessionVersionOverride;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.piv.PivSession;
/** Resolve development firmware from the same device, never a hard-coded override. */
final class PivSessions {
    static synchronized PivSession open(SmartCardConnection connection)throws Exception {
        SessionVersionOverride.set(null);
        try{
            var piv=new PivSession(connection);
            if(SessionVersionOverride.isDevelopmentVersion(piv.getVersion())){
                // ManagementSession reads the device's version qualifier and sets the SDK override.
                // Do not close it: the same physical connection is reselected for PIV below.
                new ManagementSession(connection);
                piv=new PivSession(connection);
            }
            return piv;
        }finally{SessionVersionOverride.set(null);}
    }
}
