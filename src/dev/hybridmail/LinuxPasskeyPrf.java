package dev.hybridmail;

import com.google.gson.*;
import java.awt.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.Arrays;
import java.util.concurrent.*;
import javax.swing.*;

/** Interactive anonymous-pipe bridge. The helper has no terminal or browser. */
final class LinuxPasskeyPrf {
 interface Interaction {char[] pin()throws Exception;void touch()throws Exception;int select(String[] choices)throws Exception;}
 static byte[] request(Path helper,JsonObject request)throws Exception{
  if(SwingUtilities.isEventDispatchThread())throw new IOException("Native vault unlocking must run outside the UI thread");
  Prompt prompt=new Prompt(request.get("name").getAsString(),Thread.currentThread());
  try{byte[] result=exchange(helper,request,prompt,300);boolean accepted=false;try{prompt.finish();accepted=true;return result;}finally{if(!accepted)Arrays.fill(result,(byte)0);}}finally{prompt.close();}
 }
 static byte[] exchange(Path helper,JsonObject request,Interaction ui,int timeout)throws Exception{
  Process p=new ProcessBuilder(helper.toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
  ExecutorService executor=Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
  byte[] input=request.toString().getBytes(StandardCharsets.UTF_8);
  CompletableFuture<byte[]> operation=null;boolean delivered=false;
  try{
   var out=new DataOutputStream(p.getOutputStream());out.write(input);out.writeByte('\n');out.flush();
   operation=CompletableFuture.supplyAsync(()->{try{return dialogue(p,out,ui);}catch(Exception e){throw new CompletionException(e);}},executor);
   byte[] response=operation.get(timeout,TimeUnit.SECONDS);
   boolean accepted=false;
   try{if(!p.waitFor(5,TimeUnit.SECONDS)||p.exitValue()!=0)throw new IOException("Linux passkey helper failed; vault remains locked");accepted=true;delivered=true;return response;}
   finally{if(!accepted)Arrays.fill(response,(byte)0);}
  }catch(TimeoutException e){throw new IOException("FIDO operation timed out; vault remains locked",e);}
  catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("FIDO operation cancelled; vault remains locked",e);}
  catch(ExecutionException e){if(e.getCause() instanceof Exception cause)throw cause;throw new IOException("FIDO helper failed",e);}
  finally{
   Arrays.fill(input,(byte)0);p.destroyForcibly();
   try{p.getInputStream().close();p.getOutputStream().close();}catch(IOException ignored){}
   if(!delivered&&operation!=null)operation.whenComplete((bytes,error)->{if(bytes!=null)Arrays.fill(bytes,(byte)0);});executor.shutdownNow();
  }
 }
 static byte[] dialogue(Process p,DataOutputStream out,Interaction ui)throws Exception{
  boolean pinRequested=false,selectionRequested=false;int total=0;
  for(int messages=0;messages<32;messages++){
   byte[] wire=line(p.getInputStream());total+=wire.length;
   try{
    if(total>262144)throw new IOException("Too much FIDO helper output");
    var event=JsonParser.parseString(new String(wire,StandardCharsets.UTF_8)).getAsJsonObject();
    switch(event.get("event").getAsString()){
     case "pin"->{
      if(pinRequested)throw new IOException("Repeated FIDO PIN request rejected; no automatic retry");pinRequested=true;
      char[] chars=ui.pin();byte[] pin=null;
      try{if(chars==null)throw new IOException("FIDO PIN entry cancelled");pin=encodePin(chars);out.writeShort(pin.length);out.write(pin);out.flush();}
      finally{if(chars!=null)Arrays.fill(chars,'\0');if(pin!=null)Arrays.fill(pin,(byte)0);}
     }
     case "touch"->ui.touch();
     case "select"->{
      if(selectionRequested)throw new IOException("Repeated credential selection");selectionRequested=true;
      var choices=event.getAsJsonArray("choices");if(choices.size()<2||choices.size()>64)throw new IOException("Invalid passkey selection");
      String[] names=new String[choices.size()];for(int i=0;i<names.length;i++){names[i]=choices.get(i).getAsString();if(names[i].length()>3000||names[i].codePoints().anyMatch(Character::isISOControl))throw new IOException("Invalid passkey label");}
      int choice=ui.select(names);if(choice<0||choice>=names.length)throw new IOException("Passkey selection cancelled");out.writeShort(choice);out.flush();
     }
     case "result"->{byte[] result=event.getAsJsonObject("result").toString().getBytes(StandardCharsets.UTF_8);if(Thread.currentThread().isInterrupted()){Arrays.fill(result,(byte)0);throw new InterruptedException();}return result;}
     case "error"->{String error=event.get("error").getAsString().replaceAll("[\\p{Cntrl}]"," ");throw new IOException("Native YubiKey: "+error.substring(0,Math.min(400,error.length())));}
     default->throw new IOException("Unknown FIDO helper event");
    }
   }finally{Arrays.fill(wire,(byte)0);}
  }
  throw new IOException("Too many FIDO helper events");
 }
 static byte[] line(InputStream in)throws IOException{
  byte[] buf=new byte[131073];int size=0;
  try{while(size<buf.length){int b=in.read();if(b<0)throw new IOException("FIDO helper disconnected");if(b=='\n')return Arrays.copyOf(buf,size);buf[size++]=(byte)b;}throw new IOException("FIDO helper response too large");}finally{Arrays.fill(buf,(byte)0);}
 }
 static byte[] encodePin(char[] pin)throws IOException{
  int count=Character.codePointCount(pin,0,pin.length);for(char c:pin)if(c==0)throw new IOException("FIDO PIN must not contain NUL");
  if(count<4)throw new IOException("FIDO PIN must contain at least four characters");
  ByteBuffer b=null;try{b=StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(pin));if(b.remaining()>63)throw new IOException("FIDO PIN must be at most 63 UTF-8 bytes");byte[] result=new byte[b.remaining()];b.get(result);return result;}
  catch(CharacterCodingException e){throw new IOException("Invalid FIDO PIN encoding",e);}
  finally{if(b!=null&&b.hasArray())Arrays.fill(b.array(),(byte)0);}
 }
 static final class Prompt implements Interaction,AutoCloseable {
  private JDialog dialog;private JPanel content;private final Thread caller;private volatile boolean closed;
  Prompt(String name,Thread caller)throws Exception{this.caller=caller;try{SwingUtilities.invokeAndWait(()->{
   if(closed)return;
   Window owner=KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
   for(Window window:Window.getWindows())if(window instanceof Dialog d&&d.isVisible()&&d.isModal())owner=window;
   dialog=new JDialog(owner,"Unlock vault — "+name,Dialog.ModalityType.MODELESS);dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
   dialog.addWindowListener(new java.awt.event.WindowAdapter(){public void windowClosing(java.awt.event.WindowEvent e){cancel();}});
   content=new JPanel(new BorderLayout(8,8));content.setBorder(BorderFactory.createEmptyBorder(16,16,16,16));
   dialog.add(content);JButton cancel=new JButton("Cancel");cancel.addActionListener(e->cancel());dialog.add(cancel,BorderLayout.SOUTH);
   status("Connect one FIDO2 YubiKey. Checking its capabilities…");dialog.setLocationRelativeTo(null);dialog.setVisible(true);
  });}catch(Exception e){close();throw e;}}
  void finish()throws Exception{var cancelled=new java.util.concurrent.atomic.AtomicBoolean();SwingUtilities.invokeAndWait(()->{cancelled.set(closed);closed=true;if(dialog!=null)dialog.dispose();});if(cancelled.get()||Thread.currentThread().isInterrupted())throw new IOException("FIDO operation cancelled; vault remains locked");}
  private void cancel(){closed=true;caller.interrupt();dialog.dispose();}
  private void status(String text){content.removeAll();content.add(new JLabel(text),BorderLayout.CENTER);dialog.pack();content.revalidate();content.repaint();}
  public char[] pin()throws Exception{
   var value=new CompletableFuture<char[]>();
   SwingUtilities.invokeLater(()->{if(closed){value.complete(null);return;}
    content.removeAll();content.add(new JLabel("FIDO2 PIN for this YubiKey (not the PIV PIN)"),BorderLayout.NORTH);
    var field=new JPasswordField(24);content.add(field,BorderLayout.CENTER);var submit=new JButton("Unlock");content.add(submit,BorderLayout.SOUTH);
    Runnable confirm=()->{char[] entered=field.getPassword();byte[] test=null;try{test=encodePin(entered);}catch(IOException e){Arrays.fill(entered,'\0');JOptionPane.showMessageDialog(dialog,e.getMessage());return;}finally{if(test!=null)Arrays.fill(test,(byte)0);}
     field.setText("");submit.setEnabled(false);if(!value.complete(entered))Arrays.fill(entered,'\0');status("Verifying FIDO PIN. Touch your YubiKey when it flashes…");};
    submit.addActionListener(e->confirm.run());field.addActionListener(e->confirm.run());dialog.pack();SwingUtilities.invokeLater(field::requestFocusInWindow);
   });
   boolean returned=false;try{char[] result=value.get();returned=true;return result;}finally{if(!returned)value.whenComplete((pin,e)->{if(pin!=null)Arrays.fill(pin,'\0');});}
  }
  public void touch(){SwingUtilities.invokeLater(()->{if(!closed)status("Touch your YubiKey to unlock the vault. Keep it connected until completion.");});}
  public int select(String[] choices)throws Exception{
   var value=new CompletableFuture<Integer>();SwingUtilities.invokeLater(()->{if(closed){value.complete(-1);return;}
    content.removeAll();content.add(new JLabel("Choose the existing PQ Mail passkey to enroll"),BorderLayout.NORTH);var box=new JComboBox<>(choices);box.setPreferredSize(new Dimension(520,30));content.add(box,BorderLayout.CENTER);
    var choose=new JButton("Use this passkey");choose.addActionListener(e->{value.complete(box.getSelectedIndex());status("Completing vault unlock…");});content.add(choose,BorderLayout.SOUTH);dialog.pack();
   });return value.get();
  }
  public void close(){closed=true;SwingUtilities.invokeLater(()->{if(dialog!=null)dialog.dispose();});}
 }
}
