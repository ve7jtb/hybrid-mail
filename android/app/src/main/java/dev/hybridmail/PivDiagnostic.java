package dev.hybridmail;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Locale;
/** Retains only command headers and status, never command/response payloads or PINs. */
final class PivDiagnostic extends GeneralSecurityException {
    final boolean retryableBeforePin;
    final String frameDetail;
    PivDiagnostic(String message,Throwable cause){this(message,cause,false);}
    PivDiagnostic(String message,Throwable cause,boolean retryable){this(message,cause,retryable,"");}
    PivDiagnostic(String message,Throwable cause,boolean retryable,String frames){super(message,cause);retryableBeforePin=retryable;frameDetail=frames;}
    static final class Connection implements SmartCardConnection {
        private final SmartCardConnection delegate;
        private String command="no APDU sent",status="no response";
        private int sequence;
        private long elapsedMs;
        private int continuation=-1, responseLength;
        private boolean publicMetadataChain;
        private static final int NFC_PUBLIC_READ_LIMIT=240;
        private final java.util.ArrayDeque<String> frames=new java.util.ArrayDeque<>();
        Connection(SmartCardConnection delegate){this.delegate=delegate;}
        public byte[] sendAndReceive(byte[] apdu)throws IOException{
            // Limit only NFC PIV metadata reads (F7) and their C0 continuations.
            // 240 data bytes + SW fit below the observed 253-byte truncation boundary.
            // Private-operation responses and USB retain their existing behavior.
            boolean shortCommand=apdu.length==5 && apdu[0]==0;
            boolean getResponse=shortCommand && (apdu[1]&255)==0xc0 && apdu[2]==0 && apdu[3]==0;
            if(!getResponse)publicMetadataChain=shortCommand && (apdu[1]&255)==0xf7;
            if(getTransport()==Transport.NFC && shortCommand){
                int requested=apdu[4]&255;
                if(requested==0)requested=256;
                if(getResponse && continuation>=0)requested=Math.min(requested,continuation==0?256:continuation);
                if(publicMetadataChain)requested=Math.min(requested,NFC_PUBLIC_READ_LIMIT);
                if((apdu[4]&255)!=(requested==256?0:requested)){
                    apdu=apdu.clone();apdu[4]=(byte)requested;
                }
            }
            continuation=-1;responseLength=-1;
            command=apdu.length>=4?String.format(Locale.ROOT,"INS=%02X P1=%02X P2=%02X",apdu[1]&255,apdu[2]&255,apdu[3]&255):"invalid header";
            status="transport error";
            sequence++;long start=System.nanoTime();byte[] result;
            try{result=delegate.sendAndReceive(apdu);}
            catch(IOException e){status="transport error ("+e.getClass().getSimpleName()+")";elapsedMs=(System.nanoTime()-start)/1_000_000;remember(apdu);throw e;}
            finally{elapsedMs=(System.nanoTime()-start)/1_000_000;}
            responseLength=result.length;
            if(result.length<2){status="invalid response framing";remember(apdu);throw new IOException("APDU response missing status bytes");}
            if((result[result.length-2]&255)==0x61)continuation=result[result.length-1]&255;
            else publicMetadataChain=false;
            status=result.length>=2?String.format(Locale.ROOT,"SW=%02X%02X",result[result.length-2]&255,result[result.length-1]&255):"short response";
            remember(apdu);
            return result;
        }
        private void remember(byte[] apdu){
            if(frames.size()==8)frames.removeFirst();
            // Lengths/header/status only: never retain PIN, public-key, or secret payloads.
            frames.addLast("#"+sequence+" "+command+(apdu.length==5 && ((apdu[1]&255)==0xc0 || (apdu[1]&255)==0xf7)?" Le="+(apdu[4]&255):"")+" tx="+apdu.length+" rx="+responseLength+" "+status+" "+elapsedMs+"ms");
        }
        boolean transportFailed(){return status.startsWith("transport error");}
        String detail(){return getTransport()+" / "+command+" / "+status+" / APDU #"+sequence+" / "+elapsedMs+" ms / frames="+String.join("; ",frames);}
        public Transport getTransport(){return delegate.getTransport();}
        public boolean isExtendedLengthApduSupported(){return delegate.isExtendedLengthApduSupported();}
        public byte[] getAtr(){return delegate.getAtr();}
        public void close()throws IOException{delegate.close();}
    }
}
