package dev.hybridmail;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import javax.swing.*;
import com.google.gson.*;

/** Desktop coordinator. The PRF output and decrypted vault are never persisted. */
final class DesktopVault {
 private static DesktopState state;private static PrfVault vault;private static Component owner;
 static void configure(DesktopState s,Component parent)throws Exception {if(state!=s){if(vault!=null)vault.close();state=s;vault=new PrfVault(s.directory().resolve("account-vault.json"));}owner=parent;}
 static DesktopState settings()throws IOException{return state!=null?state:DesktopState.open();}
 static boolean configured(){return vault!=null;}
 static boolean unlocked(){return vault!=null&&vault.unlocked();}
 static PrfVault vault()throws Exception{ensure();return vault;}
 static void lock(){if(vault!=null)vault.close();}
 private static <T>T ui(Callable<T> task)throws Exception{if(SwingUtilities.isEventDispatchThread())return task.call();var f=new FutureTask<T>(task);SwingUtilities.invokeAndWait(f);return f.get();}
 static void ensure()throws Exception {
  if(vault==null)throw new IOException("Open PQ Mail to set up the passkey vault");if(vault.unlocked())return;
  if(SwingUtilities.isEventDispatchThread()){
   JDialog dialog=new JDialog((Frame)null,"Unlock PQ Mail vault",true);dialog.add(new JLabel("  Complete the passkey operation in the system prompt or selected browser.  "));dialog.pack();dialog.setLocationRelativeTo(owner);dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
   var worker=new SwingWorker<Void,Void>(){protected Void doInBackground()throws Exception{unlock();return null;}protected void done(){dialog.dispose();}};JButton cancel=new JButton("Cancel");cancel.addActionListener(e->worker.cancel(true));dialog.add(cancel,java.awt.BorderLayout.SOUTH);dialog.pack();worker.execute();dialog.setVisible(true);worker.get();
  }else unlock();
 }
 private static void unlock()throws Exception {
  if(!vault.exists()){enroll();return;}
  var wrappers=vault.wrappers();String[] names=wrappers.stream().map(w->vault.passkeyName(w.get("credential").getAsString())).toArray(String[]::new);
  Integer selected=ui(()->{JComboBox<String> box=new JComboBox<>(names);return JOptionPane.showConfirmDialog(owner,box,"Unlock passkey vault",JOptionPane.OK_CANCEL_OPTION)==JOptionPane.OK_OPTION?box.getSelectedIndex():-1;});
  if(selected<0)throw new IOException("Vault unlock cancelled");var w=wrappers.get(selected);
  try(var result=DesktopPasskeyPrf.request(names[selected],w)){vault.unlock(result.credential(),result.prf());}
  migrateSettings();
 }
 static boolean enroll()throws Exception {
  String name=ui(()->JOptionPane.showInputDialog(owner,"Name this passkey (for example, MacBook or backup security key).\nFirst select an existing PQ Mail passkey. Create a new one only if needed.\nYour provider must support WebAuthn PRF.","Add vault passkey",JOptionPane.QUESTION_MESSAGE));
  if(name==null)throw new IOException("Passkey setup cancelled");name=name.trim();if(name.isEmpty()||name.length()>80||name.codePoints().anyMatch(Character::isISOControl))throw new IOException("Use a passkey name of 1–80 characters");
  if(vault.exists()&&!vault.unlocked())throw new IOException("Unlock the existing vault before adding a passkey");
  try(var result=DesktopPasskeyPrf.request(name,null,NativePasskeyPrf.LINUX_KEY.equals(settings().get("passkey.method",NativePasskeyPrf.BROWSER)))){
   if(alreadyEnrolled(result.credential()))return false;
   if(vault.exists())vault.addPasskey(result.credential(),result.salt(),result.prf());else vault.create(result.credential(),result.salt(),result.prf());
   vault.renamePasskey(result.credential(),name);vault.put("passkey.user."+result.credential(),result.user());
  }
  migrateSettings();
  return true;
 }
 // A fresh discovery uses a new PRF salt: never use that output to replace an
 // existing wrapper or to unlock it. Duplicate enrollment is a no-op only in
 // an already authenticated vault session.
 static boolean alreadyEnrolled(String credential)throws IOException {
  if(!vault.exists())return false;
  if(!vault.unlocked())throw new IOException("Unlock the existing vault before adding a passkey");
  return vault.wrappers().stream().anyMatch(w->credential.equals(w.get("credential").getAsString()));
 }
 static boolean enrollExisting()throws Exception {
  if(!vault.unlocked())throw new IOException("Unlock the vault before adding an existing passkey");
  String name=ui(()->JOptionPane.showInputDialog(owner,"Name the existing passkey for this vault.\nChoose it in the system prompt or selected browser; no credential will be created or replaced.","Use existing passkey",JOptionPane.QUESTION_MESSAGE));
  if(name==null)throw new IOException("Passkey selection cancelled");name=name.trim();if(name.isEmpty()||name.length()>80||name.codePoints().anyMatch(Character::isISOControl))throw new IOException("Use a name of 1–80 characters");
  try(var result=DesktopPasskeyPrf.request(name,null,true)){
   if(alreadyEnrolled(result.credential()))return false;
   vault.addPasskey(result.credential(),result.salt(),result.prf());vault.renamePasskey(result.credential(),name);if(!result.user().isEmpty())vault.put("passkey.user."+result.credential(),result.user());
  }
  return true;
 }
 static boolean sensitive(String name){return name.startsWith("imap.")||name.startsWith("smtp.");}
 static void migrateSettings()throws Exception{
  for(String prefix:List.of("imap.","smtp."))for(String field:List.of("host","port","user","password")){
   String name=prefix+field,value=state.rawGet(name,null);if(value!=null){vault.put("setting."+name,value);state.rawSet(name,null);}
  }state.save();
 }
 static String setting(String name,String fallback){try{ensure();String value=vault.get("setting."+name);return value.isEmpty()?fallback:value;}catch(Exception e){throw new IllegalStateException("Unlock the passkey vault to read mail server settings",e);}}
 static void putSetting(String name,String value){try{ensure();vault.put("setting."+name,value);}catch(Exception e){throw new IllegalStateException("Cannot save encrypted mail server settings",e);}}
 static String get(String account)throws IOException{
  try{ensure();String value=vault.get("credential."+account);if(!value.isEmpty())return value;
   // Copy and verify the protected payload before removing a legacy unprotected item.
   byte[] legacy=MacKeychain.call("get",account,null);if(legacy==null)return null;
   try{value=new String(legacy,java.nio.charset.StandardCharsets.UTF_8);vault.put("credential."+account,value);MacKeychain.call("delete",account,null);return value;}finally{Arrays.fill(legacy,(byte)0);}
  }catch(Exception e){throw new IOException("Passkey vault access failed: "+e.getMessage(),e);}
 }
 static void put(String account,String value)throws IOException{try{ensure();vault.put("credential."+account,value);}catch(Exception e){throw new IOException("Cannot save credential in passkey vault",e);}}
 static void delete(String account)throws IOException{try{ensure();vault.put("credential."+account,null);MacKeychain.call("delete",account,null);}catch(Exception e){throw new IOException("Cannot remove credential",e);}}
 static void migrateCredentials()throws Exception{
  ensure();migrateSettings();
  for(String account:List.of("microsoft-session","google-client"))get(account);
  if(!MacKeychain.protectedSession())get("google-session");
 }
 static JsonObject transferPasskey()throws Exception{
  ensure();var wrappers=vault.wrappers();String[] names=wrappers.stream().map(w->vault.passkeyName(w.get("credential").getAsString())).toArray(String[]::new);
  int selected=ui(()->{JComboBox<String> box=new JComboBox<>(names);return JOptionPane.showConfirmDialog(owner,box,"Passkey also enrolled on the receiving instance",JOptionPane.OK_CANCEL_OPTION)==JOptionPane.OK_OPTION?box.getSelectedIndex():-1;});
  if(selected<0)throw new IOException("Transfer cancelled");return wrappers.get(selected);
 }
 static void requireEnrolled(String credential)throws Exception{
  ensure();if(vault.wrappers().stream().noneMatch(w->credential.equals(w.get("credential").getAsString())))throw new IOException("Enroll this bundle's passkey using Keys → Unlock / manage passkeys → Use existing passkey, then import again.");
 }
 static void manage()throws Exception{
  ensure();var wrappers=vault.wrappers();String[] names=wrappers.stream().map(w->vault.passkeyName(w.get("credential").getAsString())).toArray(String[]::new);
  JComboBox<String> choices=new JComboBox<>(names);Object[] actions={"Find or create passkey","Use existing passkey","Rename","Remove from vault","Close"};
  int choice=JOptionPane.showOptionDialog(owner,choices,"Passkeys protecting this vault",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,actions,actions[4]);
  String id=wrappers.get(choices.getSelectedIndex()).get("credential").getAsString();
  if(choice==0||choice==1){var worker=new SwingWorker<Boolean,Void>(){protected Boolean doInBackground()throws Exception{return choice==0?enroll():enrollExisting();}protected void done(){try{boolean added=get();JOptionPane.showMessageDialog(owner,added?"Backup passkey added.":"This passkey is already registered and the vault is unlocked.\nNo changes were made. Use Rename to change its label.");}catch(Exception e){JOptionPane.showMessageDialog(owner,e.getMessage());}}};worker.execute();}
  if(choice==2){String name=JOptionPane.showInputDialog(owner,"Passkey name",vault.passkeyName(id));if(name!=null)vault.renamePasskey(id,name);}
  if(choice==3&&JOptionPane.showConfirmDialog(owner,"Remove this passkey's access to this vault?\nAlso remove it in your passkey provider if no longer needed.","Remove passkey",JOptionPane.OK_CANCEL_OPTION)==JOptionPane.OK_OPTION)vault.removePasskey(id);
 }
}
