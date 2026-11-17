package dev.hybridmail;
import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
/** Only refresh tokens and client configuration persist, in the login Keychain. */
final class GoogleSession {
    static GoogleOAuth.Client client(DesktopState state)throws IOException{
        String saved=MacKeychain.get("google-client");
        if(saved!=null){try{var j=JsonParser.parseString(saved).getAsJsonObject();return new GoogleOAuth.Client(j.get("id").getAsString(),j.get("secret").getAsString());}catch(RuntimeException e){throw new IOException("Saved Google client is invalid; import it again");}}
        Path legacy=state.directory().resolve("google-client.json");
        GoogleOAuth.Client client=GoogleOAuth.Client.read(legacy);saveClient(client);Files.delete(legacy);return client;
    }
    static void saveClient(GoogleOAuth.Client client)throws IOException{
        var j=new JsonObject();j.addProperty("id",client.id());j.addProperty("secret",client.secret());MacKeychain.put("google-client",j.toString());
    }
    static void save(GoogleOAuth.Client client,String email,GoogleOAuth.Token token)throws IOException{
        String refresh=token.refreshToken();if(refresh==null)throw new IOException("Google did not issue a refresh token. Sign in again and approve offline access.");
        var j=new JsonObject();j.addProperty("client",client.id());j.addProperty("email",email);j.addProperty("refresh",refresh);MacKeychain.put("google-session",j.toString());
    }
    static GoogleOAuth.Token restore(GoogleOAuth.Client client,String email)throws Exception{
        String saved=MacKeychain.get("google-session");if(saved==null)throw new IOException("Sign in with Google once to save your session in Mac Keychain");
        JsonObject j;try{j=JsonParser.parseString(saved).getAsJsonObject();if(!client.id().equals(j.get("client").getAsString())||!email.equalsIgnoreCase(j.get("email").getAsString()))throw new IOException("Saved Google session belongs to another client or account. Sign in again.");}catch(RuntimeException e){throw new IOException("Saved Google session is invalid. Sign in again.");}
        GoogleOAuth.Token token=GoogleOAuth.refresh(client,j.get("refresh").getAsString());
        try{save(client,email,token);return token;}catch(Exception e){token.close();throw e;}
    }
}
