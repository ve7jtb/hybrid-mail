package dev.hybridmail;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Locale;
/** Retains only command headers and status, never command/response payloads or PINs. */
final class PivDiagnostic extends GeneralSecurityException {
    PivDiagnostic(String message,Throwable cause){super(message,cause);}
    static final class Connection implements SmartCardConnection {
        private final SmartCardConnection delegate;
        private String command="no APDU sent",status="no response";
        Connection(SmartCardConnection delegate){this.delegate=delegate;}
        public byte[] sendAndReceive(byte[] apdu)throws IOException{
            command=apdu.length>=4?String.format(Locale.ROOT,"INS=%02X P1=%02X P2=%02X",apdu[1]&255,apdu[2]&255,apdu[3]&255):"invalid header";
            status="transport error";
            byte[] result=delegate.sendAndReceive(apdu);
            status=result.length>=2?String.format(Locale.ROOT,"SW=%02X%02X",result[result.length-2]&255,result[result.length-1]&255):"short response";
            return result;
        }
        String detail(){return getTransport()+" / "+command+" / "+status;}
        public Transport getTransport(){return delegate.getTransport();}
        public boolean isExtendedLengthApduSupported(){return delegate.isExtendedLengthApduSupported();}
        public byte[] getAtr(){return delegate.getAtr();}
        public void close()throws IOException{delegate.close();}
    }
}
