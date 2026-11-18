package dev.hybridmail;
import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
/** Only refresh tokens and client configuration persist, in the login Keychain. */
final class GoogleSession {
    static GoogleOAuth.Client client(DesktopState state)throws IOException{
        if(!state.get("google.client.mode","shared").equals("custom"))return GoogleOAuth.bundledClient();
        String saved=MacKeychain.get("google-client");
        if(saved!=null){try{var j=JsonParser.parseString(saved).getAsJsonObject();return new GoogleOAuth.Client(j.get("id").getAsString(),j.get("secret").getAsString());}catch(RuntimeException e){throw new IOException("Saved custom Google client is invalid; import it again in Advanced settings");}}
        throw new IOException("Custom Google client is unavailable; import it in Advanced settings or select the shared PQ Mail client.");
    }
    static void saveClient(GoogleOAuth.Client client,DesktopState state)throws IOException{
        boolean shared=false;
        try{shared=client.equals(GoogleOAuth.bundledClient());}catch(IOException absent){/* Custom-only build. */}
        if(!shared){var j=new JsonObject();j.addProperty("id",client.id());j.addProperty("secret",client.secret());MacKeychain.put("google-client",j.toString());}
        state.set("google.client.mode",shared?"shared":"custom");state.save();
    }
    static void save(GoogleOAuth.Client client,String email,GoogleOAuth.Token token)throws IOException{
        String refresh=token.refreshToken();if(refresh==null)throw new IOException("Google did not issue a refresh token. Sign in again and approve offline access.");
        var j=new JsonObject();j.addProperty("scope",GoogleOAuth.SCOPE);j.addProperty("client",client.id());j.addProperty("email",email);j.addProperty("refresh",refresh);if(System.getProperty("os.name").startsWith("Mac") && (MacKeychain.protectedSession()||Boolean.parseBoolean(DesktopState.open().get("google.authenticateRestore","false"))))MacKeychain.putProtected("google-session",j.toString());else MacKeychain.put("google-session",j.toString());
    }
    static GoogleOAuth.Token restore(GoogleOAuth.Client client,String email)throws Exception{
        boolean authenticate=System.getProperty("os.name").startsWith("Mac") && (MacKeychain.protectedSession()||Boolean.parseBoolean(DesktopState.open().get("google.authenticateRestore","false")));
        if(authenticate&&!MacKeychain.protectedSession())MacKeychain.protectSession(true);
        String saved=MacKeychain.get("google-session",authenticate);if(saved==null)throw new IOException("Sign in with Google once to save your session in the system credential store");
        JsonObject j;try{j=JsonParser.parseString(saved).getAsJsonObject();if(!j.has("scope")||!GoogleOAuth.SCOPE.equals(j.get("scope").getAsString()))throw new IOException("Sign in again to authorize Gmail read-only and send access. Previous IMAP/SMTP sessions are not reused.");if(!client.id().equals(j.get("client").getAsString())||!email.equalsIgnoreCase(j.get("email").getAsString()))throw new IOException("Saved Google session belongs to another client or account. Sign in again.");}catch(RuntimeException e){throw new IOException("Saved Google session is invalid. Sign in again.");}
        GoogleOAuth.Token token=GoogleOAuth.refresh(client,j.get("refresh").getAsString());
        // Google normally retains the same refresh token. Rewriting the protected
        // item would ask for user presence a second time with a new helper process.
        try{if(!java.util.Objects.equals(j.get("refresh").getAsString(),token.refreshToken()))save(client,email,token);return token;}catch(Exception e){token.close();throw e;}
    }
}
