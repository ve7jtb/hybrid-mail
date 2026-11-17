package dev.hybridmail;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import javax.swing.*;
/** Presence checks never authenticate or retry failed private operations. */
public final class TokenPresence {
    @FunctionalInterface interface Probe{int check()throws Exception;}
    @FunctionalInterface interface Prompt{boolean retry()throws Exception;}
    static void require(Probe probe,Prompt prompt)throws Exception{
        while(true){int code=probe.check();if(code==0)return;if(code!=2)throw new IOException("Cannot check YubiKey presence. Check the PKCS#11 module and serial in YubiKey configuration.");if(!prompt.retry())throw new IOException("YubiKey connection cancelled");}
    }
    public static void require(String adapter)throws Exception{
        String name=Path.of(adapter).getFileName().toString();if(!name.equals("pkcs11-mu.py")&&!name.equals("pkcs11-kem.py"))return;
        Path probe=Path.of(adapter).resolveSibling("pkcs11-presence.py");
        require(()->{
            Process process=DesktopState.process(probe.toString()).redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            try{if(!process.waitFor(15,TimeUnit.SECONDS))throw new IOException("YubiKey presence check timed out");return process.exitValue();}finally{if(process.isAlive())process.destroyForcibly();}
        },()->{
            if(GraphicsEnvironment.isHeadless())throw new IOException("Connect the configured YubiKey, then run the operation again");
            boolean[] retry={false};Runnable show=()->{Object[] options={"Retry","Cancel"};retry[0]=JOptionPane.showOptionDialog(null,"Connect your configured YubiKey, then choose Retry.\nIf another YubiKey is connected, insert the one selected in YubiKey configuration.\nNo PIN or private-key operation has been sent.","Connect your YubiKey",JOptionPane.DEFAULT_OPTION,JOptionPane.INFORMATION_MESSAGE,null,options,options[0])==0;};
            if(SwingUtilities.isEventDispatchThread())show.run();else SwingUtilities.invokeAndWait(show);return retry[0];
        });
    }
}
