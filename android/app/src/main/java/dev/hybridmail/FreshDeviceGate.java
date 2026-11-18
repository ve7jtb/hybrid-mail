package dev.hybridmail;
import com.yubico.yubikit.core.*;
import java.util.concurrent.CompletableFuture;
/** NFC tags are delivered only to an operation already waiting for a fresh tap. */
final class FreshDeviceGate {
    private YubiKeyDevice usb;
    private CompletableFuture<YubiKeyDevice> waiting;
    synchronized boolean isWaiting(){return waiting!=null&&!waiting.isDone();}
    synchronized void discovered(YubiKeyDevice device){
        usb=device.getTransport()==Transport.USB?device:null;
        if(waiting!=null){waiting.complete(device);waiting=null;}
    }
    synchronized CompletableFuture<YubiKeyDevice> request(){
        if(usb!=null)return CompletableFuture.completedFuture(usb);
        if(waiting!=null)throw new IllegalStateException("Another operation is waiting for a YubiKey");
        waiting=new CompletableFuture<>();return waiting;
    }
    synchronized void cancel(){if(waiting!=null){waiting.cancel(false);waiting=null;}}
}
