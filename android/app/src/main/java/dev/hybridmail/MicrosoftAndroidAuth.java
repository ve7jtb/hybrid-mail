package dev.hybridmail;
import android.app.Activity;
import com.microsoft.identity.client.*;
import com.microsoft.identity.client.exception.*;
/** MSAL owns the protected token cache; PQ Mail never serializes OAuth tokens. */
final class MicrosoftAndroidAuth {
 static final String AUTHORITY="https://login.microsoftonline.com/consumers";
 static final String[] SCOPES={"https://graph.microsoft.com/Mail.Read","https://graph.microsoft.com/Mail.Send","https://graph.microsoft.com/User.Read"};
 interface Callback{void ready(String accessToken);void failed(Exception error);void cancelled();}
 private ISingleAccountPublicClientApplication client;
 void connect(Activity activity,Callback callback){
  if(client==null){PublicClientApplication.createSingleAccountPublicClientApplication(activity,R.raw.microsoft_auth,new IPublicClientApplication.ISingleAccountApplicationCreatedListener(){public void onCreated(ISingleAccountPublicClientApplication c){client=c;connect(activity,callback);}public void onError(MsalException e){callback.failed(e);}});return;}
  client.getCurrentAccountAsync(new ISingleAccountPublicClientApplication.CurrentAccountCallback(){
   public void onAccountLoaded(IAccount account){if(account==null)interactive(activity,callback,true);else client.acquireTokenSilentAsync(SCOPES,AUTHORITY,new SilentAuthenticationCallback(){public void onSuccess(IAuthenticationResult r){deliver(r,callback);}public void onError(MsalException e){if(e instanceof MsalUiRequiredException)interactive(activity,callback,false);else callback.failed(e);}});}
   public void onAccountChanged(IAccount before,IAccount after){}
   public void onError(MsalException e){callback.failed(e);}
  });
 }
 private void interactive(Activity activity,Callback callback,boolean fresh){var cb=new AuthenticationCallback(){public void onSuccess(IAuthenticationResult r){deliver(r,callback);}public void onError(MsalException e){callback.failed(e);}public void onCancel(){callback.cancelled();}};if(fresh)client.signIn(activity,null,SCOPES,cb);else client.acquireToken(activity,SCOPES,cb);}
 private void deliver(IAuthenticationResult result,Callback callback){var granted=new java.util.HashSet<String>();for(String scope:result.getScope())granted.add(scope.replace("https://graph.microsoft.com/",""));if(!granted.containsAll(java.util.List.of("Mail.Read","Mail.Send","User.Read"))){callback.failed(new java.io.IOException("Microsoft read and send consent is required."));return;}callback.ready(result.getAccessToken());}
 void signOut(Runnable done,java.util.function.Consumer<Exception> failed){if(client==null){failed.accept(new java.io.IOException("Connect Microsoft first to manage its saved session."));return;}client.signOut(new ISingleAccountPublicClientApplication.SignOutCallback(){public void onSignOut(){done.run();}public void onError(MsalException e){failed.accept(e);}});}
}
