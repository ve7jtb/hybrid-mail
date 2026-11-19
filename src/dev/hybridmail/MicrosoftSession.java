package dev.hybridmail;
import com.google.gson.*;
import java.io.*;
/** Public client ID in settings; only the refresh token lives in the OS credential store. */
final class MicrosoftSession {
 static MicrosoftOAuth.Client client(DesktopState state)throws IOException {
  String id=state.get("microsoft.client.id","");
  return id.isBlank()?MicrosoftOAuth.bundledClient():new MicrosoftOAuth.Client(id);
 }
 static void save(MicrosoftOAuth.Client client,String email,MicrosoftOAuth.Token token)throws IOException {
  String refresh=token.refreshToken();if(refresh==null)throw new IOException("Microsoft did not issue a refresh token; sign in again with offline access.");
  var j=new JsonObject();j.addProperty("scope",MicrosoftOAuth.SCOPE);j.addProperty("client",client.id());j.addProperty("email",email);j.addProperty("refresh",refresh);
  MacKeychain.put("microsoft-session",j.toString());
 }
 static MicrosoftOAuth.Token restore(MicrosoftOAuth.Client client,String email)throws Exception {
  String saved=MacKeychain.get("microsoft-session");if(saved==null)throw new IOException("Sign in with Microsoft from the Inbox tab first.");
  JsonObject j;
  try{j=JsonParser.parseString(saved).getAsJsonObject();if(!client.id().equals(j.get("client").getAsString())||!email.equalsIgnoreCase(j.get("email").getAsString())||!MicrosoftOAuth.SCOPE.equals(j.get("scope").getAsString()))throw new IOException("Saved Microsoft session belongs to another account, client or permission set. Sign in again.");}
  catch(RuntimeException e){throw new IOException("Invalid saved Microsoft session. Sign in again.");}
  var token=MicrosoftOAuth.refresh(client,j.get("refresh").getAsString());
  try{if(!java.util.Objects.equals(token.refreshToken(),j.get("refresh").getAsString()))save(client,email,token);return token;}catch(Exception e){token.close();throw e;}
 }
}
