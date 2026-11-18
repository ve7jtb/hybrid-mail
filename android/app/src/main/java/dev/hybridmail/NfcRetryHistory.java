package dev.hybridmail;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
/** App-private, bounded history. Only caller-supplied protocol metadata, never exception payloads. */
final class NfcRetryHistory {
    static synchronized void append(SharedPreferences prefs,int serial,String profile,String operation,int attempt,String frames)throws Exception {
        JSONArray previous=new JSONArray(prefs.getString("history","[]")),next=new JSONArray();
        for(int i=Math.max(0,previous.length()-49);i<previous.length();i++)next.put(previous.get(i));
        next.put(new JSONObject().put("time",java.time.Instant.now().toString())
            .put("serial",serial).put("profile",profile).put("operation",operation)
            .put("attempt",attempt).put("beforePin",true).put("diagnostic",frames));
        if(!prefs.edit().putString("history",next.toString()).commit())throw new IOException("Cannot save NFC attempt diagnostics");
    }
}
