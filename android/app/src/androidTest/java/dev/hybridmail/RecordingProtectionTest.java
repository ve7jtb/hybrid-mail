package dev.hybridmail;
import android.app.AlertDialog;
import android.content.Intent;
import android.view.WindowManager;
import android.widget.EditText;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
@RunWith(AndroidJUnit4.class)
public class RecordingProtectionTest {
    private boolean secure(android.view.Window w){return (w.getAttributes().flags&WindowManager.LayoutParams.FLAG_SECURE)!=0;}
    @Test public void temporaryCaptureProtectsSecretsAndBackground(){
        var i=InstrumentationRegistry.getInstrumentation();
        var a=(MainActivity)i.startActivitySync(new Intent(i.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        final RecordingProtection[] policy=new RecordingProtection[1];
        final EditText[] secret=new EditText[1];
        try{i.runOnMainSync(()->{
            var p=new RecordingProtection(a.getWindow());policy[0]=p;assertTrue(secure(a.getWindow()));
            p.start();assertFalse(secure(a.getWindow()));
            p.paused(true);assertTrue(secure(a.getWindow()));p.paused(false);assertFalse(secure(a.getWindow()));
            p.secretPage(true);assertTrue(secure(a.getWindow()));p.secretPage(false);assertFalse(secure(a.getWindow()));
            EditText input=new EditText(a);secret[0]=input;input.setText("synthetic-secret");
            var d=new AlertDialog.Builder(a).setView(input).create();
            p.showSecret(d,()->input.getText().clear());assertTrue(secure(d.getWindow()));assertTrue(secure(a.getWindow()));
            d.dismiss();
        });i.waitForIdleSync();i.runOnMainSync(()->{
            var p=policy[0];assertEquals(0,secret[0].length());assertFalse(secure(a.getWindow()));
            p.stop();assertTrue(secure(a.getWindow()));assertFalse(p.active());
            assertFalse(new RecordingProtection(a.getWindow()).active());
        });}finally{i.runOnMainSync(a::finish);}
    }
    @Test public void actualPasswordAndManualMailStayProtected(){
        var i=InstrumentationRegistry.getInstrumentation();
        var a=(MainActivity)i.startActivitySync(new Intent(i.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try{i.runOnMainSync(()->{try{
            var f=MainActivity.class.getDeclaredField("recording");f.setAccessible(true);var p=(RecordingProtection)f.get(a);p.start();
            var account=MainActivity.class.getDeclaredMethod("account");account.setAccessible(true);account.invoke(a);assertFalse(secure(a.getWindow()));
            var home=MainActivity.class.getDeclaredMethod("home");home.setAccessible(true);home.invoke(a);assertFalse(secure(a.getWindow()));
            var password=MainActivity.class.getDeclaredMethod("password",String.class,MainActivity.PasswordAction.class);password.setAccessible(true);
            password.invoke(a,"Synthetic password test",(MainActivity.PasswordAction)ignored->{});assertTrue(secure(a.getWindow()));
        }catch(Exception e){throw new AssertionError(e);}});}finally{i.runOnMainSync(a::finish);}
    }
    @Test public void actualPinProtectedUntilCancelled() throws Exception {
        var i=InstrumentationRegistry.getInstrumentation();
        var a=(MainActivity)i.startActivitySync(new Intent(i.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        var executor=java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            i.runOnMainSync(()->{try{var f=MainActivity.class.getDeclaredField("recording");f.setAccessible(true);((RecordingProtection)f.get(a)).start();}catch(Exception e){throw new AssertionError(e);}});
            var task=executor.submit(()->{try{var m=MainActivity.class.getDeclaredMethod("requestPin",String.class);m.setAccessible(true);m.invoke(a,"synthetic test — no hardware");}catch(java.lang.reflect.InvocationTargetException e){assertTrue(e.getCause() instanceof java.util.concurrent.CancellationException);}catch(Exception e){throw new AssertionError(e);}});
            var pending=MainActivity.class.getDeclaredField("pendingPin");pending.setAccessible(true);
            for(int n=0;n<100&&pending.get(a)==null;n++)Thread.sleep(20);
            assertNotNull(pending.get(a));i.waitForIdleSync();
            i.runOnMainSync(()->assertTrue(secure(a.getWindow())));
            ((java.util.concurrent.CompletableFuture<?>)pending.get(a)).cancel(false);
            task.get(5,java.util.concurrent.TimeUnit.SECONDS);i.waitForIdleSync();
            i.runOnMainSync(()->assertFalse(secure(a.getWindow())));
        }finally{executor.shutdownNow();i.runOnMainSync(a::finish);}
    }

}
