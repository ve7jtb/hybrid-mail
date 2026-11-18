package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import com.yubico.yubikit.core.*;
import com.yubico.yubikit.core.util.*;
import java.io.IOException;
public class FreshDeviceGateTest {
    YubiKeyDevice device(Transport transport){return new YubiKeyDevice(){
        public Transport getTransport(){return transport;}
        public boolean supportsConnection(Class<? extends YubiKeyConnection> type){return false;}
        public <T extends YubiKeyConnection>T openConnection(Class<T> type)throws IOException{throw new IOException("Test must not open hardware");}
        public <T extends YubiKeyConnection>void requestConnection(Class<T> type,Callback<Result<T,IOException>> cb){cb.invoke(Result.failure(new IOException("No hardware")));}
    };}
    @Test public void oldNfcIsDiscardedAndEachOperationNeedsFreshTap()throws Exception{
        var gate=new FreshDeviceGate();var old=device(Transport.NFC);gate.discovered(old);
        var signing=gate.request();assertFalse(signing.isDone());var fresh=device(Transport.NFC);gate.discovered(fresh);assertSame(fresh,signing.get());
        var decryption=gate.request();assertFalse(decryption.isDone());gate.cancel();assertTrue(decryption.isCancelled());
        gate.discovered(old);var afterPause=gate.request();assertFalse(afterPause.isDone());gate.cancel();
    }
    @Test public void usbCanBeReusedButNfcDiscoverySwitchesTransport()throws Exception{
        var gate=new FreshDeviceGate();var usb=device(Transport.USB);gate.discovered(usb);
        assertSame(usb,gate.request().get());assertSame(usb,gate.request().get());
        gate.discovered(device(Transport.NFC));assertFalse(gate.request().isDone());gate.cancel();
    }
    @Test public void waitingStateEndsOnDeliveryAndCancellation(){
        var gate=new FreshDeviceGate();assertFalse(gate.isWaiting());
        gate.request();assertTrue(gate.isWaiting());gate.discovered(device(Transport.NFC));assertFalse(gate.isWaiting());
        gate.request();assertTrue(gate.isWaiting());gate.cancel();assertFalse(gate.isWaiting());
    }

}
