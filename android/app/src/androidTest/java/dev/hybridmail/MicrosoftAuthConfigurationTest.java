package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
public class MicrosoftAuthConfigurationTest {
 @Test public void browserPkceHasNoClientSecret(){assertTrue(MicrosoftAndroidAuth.REDIRECT.startsWith("msauth://org.pqmail.android/"));assertTrue(java.util.List.of(MicrosoftAndroidAuth.SCOPES).contains("offline_access"));assertEquals(4,MicrosoftAndroidAuth.SCOPES.length);}
 @Test public void browserReturnHasAppCompatTheme()throws Exception{
  var context=androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getTargetContext();
  var info=context.getPackageManager().getActivityInfo(new android.content.ComponentName(context,net.openid.appauth.RedirectUriReceiverActivity.class),0);
  var themed=new android.view.ContextThemeWrapper(context,info.getThemeResource());
  var attrs=themed.obtainStyledAttributes(new int[]{androidx.appcompat.R.attr.windowActionBar});
  try{assertTrue("Browser return must use an AppCompat theme",attrs.hasValue(0));}finally{attrs.recycle();}
  var intent=new android.content.Intent(android.content.Intent.ACTION_VIEW,android.net.Uri.parse(MicrosoftAndroidAuth.REDIRECT+"?state=synthetic"));intent.addCategory(android.content.Intent.CATEGORY_BROWSABLE);
  assertEquals(net.openid.appauth.RedirectUriReceiverActivity.class.getName(),context.getPackageManager().resolveActivity(intent,android.content.pm.PackageManager.MATCH_DEFAULT_ONLY).activityInfo.name);
 }
 @Test public void browserReturnAfterLockRequestsUnlockInsteadOfRestart()throws Exception{
  var p=java.nio.file.Files.createTempDirectory("oauth-test").resolve("vault.json");var vault=new PrfVault(p);vault.create("YWJj",PrfVault.random(32),PrfVault.random(32));
  try{var auth=new MicrosoftAndroidAuth();boolean[] asked={false};
   var field=MicrosoftAndroidAuth.class.getDeclaredField("vault");field.setAccessible(true);field.set(auth,vault);
   field=MicrosoftAndroidAuth.class.getDeclaredField("pending");field.setAccessible(true);field.set(auth,new MicrosoftAndroidAuth.Callback(){public void ready(String token){fail();}public void failed(Exception e){fail(e.getMessage());}public void cancelled(){fail();}public void unlockRequired(Runnable resume){asked[0]=true;assertNotNull(resume);}});
   auth.lock();vault.close();
   var config=new net.openid.appauth.AuthorizationServiceConfiguration(android.net.Uri.parse("https://example.com/auth"),android.net.Uri.parse("https://example.com/token"));
   var request=new net.openid.appauth.AuthorizationRequest.Builder(config,"test","code",android.net.Uri.parse(MicrosoftAndroidAuth.REDIRECT)).build();
   var response=new net.openid.appauth.AuthorizationResponse.Builder(request).setAuthorizationCode("synthetic-code").build();
   assertTrue(auth.result(MicrosoftAndroidAuth.REQUEST,android.app.Activity.RESULT_OK,response.toIntent()));assertTrue(asked[0]);auth.close();
  }finally{vault.close();java.nio.file.Files.deleteIfExists(p);java.nio.file.Files.deleteIfExists(p.getParent());}
 }
}
