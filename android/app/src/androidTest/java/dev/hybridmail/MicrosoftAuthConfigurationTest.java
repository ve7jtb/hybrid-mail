package dev.hybridmail;
import org.junit.*;
import static org.junit.Assert.*;
import androidx.test.platform.app.InstrumentationRegistry;
import com.microsoft.identity.client.*;
import com.microsoft.identity.client.exception.*;
public class MicrosoftAuthConfigurationTest {
 @Test public void configuredPreviewCanInitialize()throws Exception{
  Assume.assumeTrue("true".equals(InstrumentationRegistry.getArguments().getString("pqmailMicrosoftConfig")));
  var future=new java.util.concurrent.CompletableFuture<ISingleAccountPublicClientApplication>();
  var i=InstrumentationRegistry.getInstrumentation();i.runOnMainSync(()->PublicClientApplication.createSingleAccountPublicClientApplication(i.getTargetContext(),R.raw.microsoft_auth,new IPublicClientApplication.ISingleAccountApplicationCreatedListener(){public void onCreated(ISingleAccountPublicClientApplication app){future.complete(app);}public void onError(MsalException e){future.completeExceptionally(e);}}));
  assertNotNull(future.get(30,java.util.concurrent.TimeUnit.SECONDS));
 }
}
