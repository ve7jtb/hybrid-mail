package dev.hybridmail;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.*;

/** Tests public wire metadata; never requests a real credential. */
public final class WindowsPasskeyTest {
 public static void main(String[] args)throws Exception {
  byte[] challenge=new byte[32],salt=new byte[32];for(int i=0;i<32;i++){challenge[i]=(byte)i;salt[i]=(byte)(i+32);}
  var wrapper=new JsonObject();wrapper.addProperty("credential","AQID");
  var request=NativePasskeyPrf.requestData("Test",wrapper,salt,PrfVault.b64(challenge),NativePasskeyPrf.WINDOWS_KEY);
  byte[] encoded=NativePasskeyPrf.windowsRequest(request);
  // This is also the portable/native C++ self-test fixture, independent of Java serialization.
  var expected=new ByteArrayOutputStream();expected.writeBytes("PQPRF001".getBytes(StandardCharsets.US_ASCII));expected.write(1);expected.writeBytes(challenge);expected.writeBytes(salt);expected.writeBytes(new byte[]{0,3,1,2,3,0,4,'T','e','s','t'});
  DesktopVaultTest.check(Arrays.equals(encoded,expected.toByteArray()),"Windows native wire protocol and raw PRF salt");
  var discovery=NativePasskeyPrf.requestData("Existing platform key",null,salt,PrfVault.b64(challenge),NativePasskeyPrf.WINDOWS_PLATFORM);
  try(var in=new DataInputStream(new ByteArrayInputStream(NativePasskeyPrf.windowsRequest(discovery)))){in.skipNBytes(8);DesktopVaultTest.check(in.readUnsignedByte()==2,"Platform selector");in.skipNBytes(64);DesktopVaultTest.check(in.readUnsignedShort()==0,"Discover existing without creating");}
  for(String key:List.of("rp","operation","provider","salt","challenge","name")){
   var invalid=request.deepCopy();invalid.addProperty(key,key.equals("name")?"bad\nname":"invalid");DesktopVaultTest.reject(()->NativePasskeyPrf.windowsRequest(invalid));
  }
  var empty=request.deepCopy();empty.addProperty("credential","");DesktopVaultTest.reject(()->NativePasskeyPrf.windowsRequest(empty));
  var longId=request.deepCopy();longId.addProperty("credential",PrfVault.b64(new byte[2049]));DesktopVaultTest.reject(()->NativePasskeyPrf.windowsRequest(longId));
  DesktopVaultTest.check(Arrays.equals(NativePasskeyPrf.methods("Windows 11"),new String[]{NativePasskeyPrf.BROWSER,NativePasskeyPrf.WINDOWS_KEY,NativePasskeyPrf.WINDOWS_PLATFORM}),"Windows options");
  DesktopVaultTest.check(Arrays.equals(NativePasskeyPrf.methods("Linux"),new String[]{NativePasskeyPrf.BROWSER,NativePasskeyPrf.LINUX_KEY}),"Linux HID helper option");
  DesktopVaultTest.check(NativePasskeyPrf.selected(NativePasskeyPrf.WINDOWS_KEY)&&!NativePasskeyPrf.windowsMethod(NativePasskeyPrf.SECURITY_KEY),"Platform dispatch");
  // Both native backends use the same authenticated response/vault validation.
  NativePasskeyTest.main(new String[0]);
  System.out.println("PASS Windows request framing, assertion-only discovery, provider routing, salt preservation, malformed-input rejection and OS-specific UI choices");
 }
}
