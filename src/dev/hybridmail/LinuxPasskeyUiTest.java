package dev.hybridmail;
import java.awt.*;
import java.util.Arrays;
import java.util.concurrent.*;
import javax.swing.*;
/** Runs only under CI Xvfb, with synthetic PINs and no helper/device/account. */
public final class LinuxPasskeyUiTest {
 static <T extends Component>T find(Container root,Class<T> type,String text){
  for(Component c:root.getComponents()){if(type.isInstance(c)&&(text==null||c instanceof JButton b&&b.getText().equals(text)))return type.cast(c);if(c instanceof Container child){T found=find(child,type,text);if(found!=null)return found;}}return null;
 }
 static JDialog prompt(){for(Window w:Window.getWindows())if(w instanceof JDialog d&&d.isVisible()&&d.getTitle().equals("Unlock vault — Synthetic key"))return d;throw new AssertionError("No PIN prompt");}
 public static void main(String[] args)throws Exception{
  var opened=new CountDownLatch(1);var parent=new JDialog((Frame)null,"Synthetic vault modal",true);parent.add(new JLabel("Synthetic test"));parent.pack();parent.addWindowListener(new java.awt.event.WindowAdapter(){public void windowOpened(java.awt.event.WindowEvent e){opened.countDown();}});
  var executor=Executors.newSingleThreadExecutor();LinuxPasskeyPrf.Prompt ui=null;
  try{
   SwingUtilities.invokeLater(()->parent.setVisible(true));if(!opened.await(5,TimeUnit.SECONDS))throw new AssertionError("Modal parent did not open");
   Thread caller=new Thread();ui=new LinuxPasskeyPrf.Prompt("Synthetic key",caller);var active=ui;
   SwingUtilities.invokeAndWait(()->{if(prompt().getOwner()!=parent)throw new AssertionError("PIN dialog would be blocked by the vault modal");});
   Future<char[]> pin=executor.submit(active::pin);
   long deadline=System.nanoTime()+5_000_000_000L;boolean entered=false;
   while(!entered&&System.nanoTime()<deadline){var ready=new java.util.concurrent.atomic.AtomicBoolean();SwingUtilities.invokeAndWait(()->{var dialog=prompt();var field=find(dialog,JPasswordField.class,null);if(field!=null){if(field.getEchoChar()==0)throw new AssertionError("Unmasked PIN");field.setText("1234");find(dialog,JButton.class,"Unlock").doClick();ready.set(true);}});entered=ready.get();if(!entered)Thread.sleep(10);}
   char[] value=pin.get(5,TimeUnit.SECONDS);if(!Arrays.equals(value,"1234".toCharArray()))throw new AssertionError("PIN not delivered");Arrays.fill(value,'\0');active.finish();
   ui=new LinuxPasskeyPrf.Prompt("Synthetic key",caller);var cancelled=ui;SwingUtilities.invokeAndWait(()->find(prompt(),JButton.class,"Cancel").doClick());if(!caller.isInterrupted())throw new AssertionError("Cancel did not interrupt operation");
   try{cancelled.finish();throw new AssertionError("Cancelled operation accepted");}catch(java.io.IOException expected){}
   System.out.println("PASS native Linux PIN dialog owns the vault modal, masks input, completes and rejects cancellation; no hardware accessed");
  }finally{if(ui!=null)ui.close();executor.shutdownNow();SwingUtilities.invokeAndWait(()->{for(Window w:Window.getWindows())w.dispose();});}
 }
}
