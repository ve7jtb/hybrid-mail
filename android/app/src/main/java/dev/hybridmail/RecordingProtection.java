package dev.hybridmail;

import android.app.AlertDialog;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Window;
import android.view.WindowManager;

/** In-memory, time-limited recording permission. Secret surfaces always stay secure. */
final class RecordingProtection {
    private final Window window;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private long expires;
    private boolean paused,secretPage;
    private int secretDialogs;
    private final Runnable timeout=this::stop;
    RecordingProtection(Window window){this.window=window;refresh();}
    boolean active(){return expires>SystemClock.elapsedRealtime();}
    void start(){expires=SystemClock.elapsedRealtime()+15*60_000;handler.removeCallbacks(timeout);handler.postDelayed(timeout,15*60_000);refresh();}
    void stop(){expires=0;handler.removeCallbacks(timeout);refresh();}
    void paused(boolean value){paused=value;refresh();}
    void secretPage(boolean value){secretPage=value;refresh();}
    private void refresh(){if(!active()||paused||secretPage||secretDialogs>0)window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);}
    void showSecret(AlertDialog dialog,Runnable clear){
        secretDialogs++;refresh();
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.setOnDismissListener(d->{clear.run();secretDialogs--;refresh();});
        dialog.show();
    }
}
