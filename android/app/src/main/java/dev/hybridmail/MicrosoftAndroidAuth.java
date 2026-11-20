package dev.hybridmail;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import net.openid.appauth.*;
import java.util.*;
/** Browser PKCE; Microsoft refresh credentials persist only inside the unlocked PRF vault. */
final class MicrosoftAndroidAuth {
 static final int REQUEST=74;
 static final String CLIENT="a8ec73d4-2c8c-465b-9570-6cbe34857fab";
 static final String REDIRECT="msauth://org.pqmail.android/blzVMjzH3J0y9UioCkOtwsqCWdg%3D";
 static final String[] SCOPES={"https://graph.microsoft.com/Mail.Read","https://graph.microsoft.com/Mail.Send","https://graph.microsoft.com/User.Read","offline_access"};
 private static final AuthorizationServiceConfiguration CONFIG=new AuthorizationServiceConfiguration(Uri.parse("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"),Uri.parse("https://login.microsoftonline.com/consumers/oauth2/v2.0/token"));
 interface Callback{void ready(String accessToken);void failed(Exception error);void cancelled();void unlockRequired(Runnable resume);}
 private AuthorizationService service;private Callback pending;private PrfVault vault;private String access;private long expires;private int generation;
 void connect(Activity activity,PrfVault unlocked,Callback callback){if(!unlocked.unlocked()){callback.failed(new IllegalStateException("Unlock the passkey vault first"));return;}vault=unlocked;if(service==null)service=new AuthorizationService(activity);if(access!=null&&System.currentTimeMillis()<expires){callback.ready(access);return;}String refresh=vault.get("microsoft.refresh");if(!refresh.isEmpty()){var request=new TokenRequest.Builder(CONFIG,CLIENT).setGrantType(GrantTypeValues.REFRESH_TOKEN).setRefreshToken(refresh).setScopes(SCOPES).build();exchange(request,callback,false);return;}pending=callback;var request=new AuthorizationRequest.Builder(CONFIG,CLIENT,ResponseTypeValues.CODE,Uri.parse(REDIRECT)).setScopes(SCOPES).setPrompt("select_account").build();activity.startActivityForResult(service.getAuthorizationRequestIntent(request),REQUEST);}
 boolean result(int request,int result,Intent data){if(request!=REQUEST)return false;Callback callback=pending;pending=null;if(callback==null)return true;if(result!=Activity.RESULT_OK||data==null){callback.cancelled();return true;}var response=AuthorizationResponse.fromIntent(data);var error=AuthorizationException.fromIntent(data);if(response==null||error!=null){callback.failed(new java.io.IOException("Microsoft authorization failed"));return true;}Runnable resume=()->exchange(response.createTokenExchangeRequest(),callback,true);if(!vault.unlocked())callback.unlockRequired(resume);else resume.run();return true;}
 private void exchange(TokenRequest request,Callback callback,boolean initial){int current=generation;service.performTokenRequest(request,(response,error)->{if(current!=generation||!vault.unlocked()){callback.failed(new java.io.IOException("Vault locked; token response discarded"));return;}if(error!=null||response==null||response.accessToken==null){callback.failed(new java.io.IOException("Microsoft session could not be restored. Sign out of Microsoft in Settings, then reconnect."));return;}try{if(initial){var granted=new HashSet<String>();if(response.scope!=null)for(String s:response.scope.split(" "))granted.add(s.replace("https://graph.microsoft.com/",""));if(!granted.containsAll(List.of("Mail.Read","Mail.Send","User.Read")))throw new java.io.IOException("Microsoft read/send consent is missing");if(response.refreshToken==null)throw new java.io.IOException("Microsoft did not issue a refresh token");}if(response.refreshToken!=null)vault.put("microsoft.refresh",response.refreshToken);access=response.accessToken;expires=response.accessTokenExpirationTime==null?0:response.accessTokenExpirationTime-60000;callback.ready(access);}catch(Exception e){callback.failed(e);}});}
 void lock(){generation++;access=null;expires=0;}
 void close(){pending=null;lock();if(service!=null)service.dispose();service=null;}
 void signOut(Runnable done,java.util.function.Consumer<Exception> failed){try{if(vault==null||!vault.unlocked())throw new IllegalStateException("Unlock the vault before signing out");vault.put("microsoft.refresh",null);pending=null;lock();done.run();}catch(Exception e){failed.accept(e);}}
}
