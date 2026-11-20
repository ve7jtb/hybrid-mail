package dev.hybridmail;
import java.nio.file.*;
public final class PasskeyBrowserTest {
 public static void main(String[] args)throws Exception{
  Path dir=Files.createTempDirectory("browser-preference-test");try{
   var state=new DesktopState(dir);state.set("unrelated.setting","keep");state.set("passkey.browser","Default browser");state.save();
   if(!"Google Chrome".equals(DesktopPasskeyPrf.saveBrowserChoice(state,0)))throw new AssertionError();
   if(!"Google Chrome".equals(state.get("passkey.browser",""))||!"Google Chrome".equals(new DesktopState(dir).get("passkey.browser","")))throw new AssertionError("Choice not persisted");
   DesktopPasskeyPrf.saveBrowserChoice(state,2);DesktopPasskeyPrf.saveBrowserChoice(state,-1);
   var loaded=new DesktopState(dir);if(!"Google Chrome".equals(loaded.get("passkey.browser",""))||!"keep".equals(loaded.get("unrelated.setting","")))throw new AssertionError("Cancel changed settings");
   if(!"Default browser".equals(DesktopPasskeyPrf.saveBrowserChoice(state,1)))throw new AssertionError();
   System.out.println("PASS Chrome/default persistence, cancellation and unrelated settings preservation");
  }finally{Files.deleteIfExists(dir.resolve("settings.properties"));Files.delete(dir);}
 }
}
