package dev.hybridmail;
import android.content.Intent;
import android.view.*;
import android.widget.*;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
@RunWith(AndroidJUnit4.class)
public class UiSmokeTest {
    private Button button(View v,String label){if(v instanceof Button b&&label.equals(b.getText().toString()))return b;if(v instanceof ViewGroup g)for(int i=0;i<g.getChildCount();i++){Button b=button(g.getChildAt(i),label);if(b!=null)return b;}return null;}
    @Test public void launchAndOpenIdentityForm(){
        var instrument=InstrumentationRegistry.getInstrumentation();
        var activity=(MainActivity)instrument.startActivitySync(new Intent(instrument.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try{instrument.runOnMainSync(()->{
            View root=activity.findViewById(android.R.id.content);assertNotNull(button(root,"Settings"));
            button(root,"Settings").performClick();
            button(root,"Identities & certificates").performClick();
            assertNotNull(button(root,"Import existing YubiKey certificate pair"));
            button(root,"Create software .p12 — four keys").performClick();assertNotNull(button(root,"Create encrypted .p12"));
        });}finally{instrument.runOnMainSync(activity::finish);}
    }
}
