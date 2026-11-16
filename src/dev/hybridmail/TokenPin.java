package dev.hybridmail;

import java.awt.*;
import java.io.Console;
import java.util.Arrays;
import javax.swing.*;

/** Per-operation PIN entry. No persistence or application PIN cache. */
public final class TokenPin {
    public static char[] request(String algorithm)throws Exception {
        char[][] result={null};
        if(GraphicsEnvironment.isHeadless()){
            Console c=System.console();if(c==null)throw new IllegalStateException("No secure PIN input available");
            result[0]=c.readPassword("YubiKey PIN (%s): ",algorithm);
        }else{
            Runnable prompt=()->{
                JPasswordField field=new JPasswordField(16);
                JPanel panel=new JPanel(new GridLayout(0,1,0,8));
                panel.add(new JLabel("YubiKey PIN — "+algorithm));panel.add(field);
                panel.add(new JLabel("PIN is reused for this signature’s components, then cleared."));
                JLabel validation=new JLabel("Enter your 6–8 character PIV PIN (not the identity-file password).");
                panel.add(validation);
                field.addAncestorListener(new javax.swing.event.AncestorListener(){
                    public void ancestorAdded(javax.swing.event.AncestorEvent e){SwingUtilities.invokeLater(field::requestFocusInWindow);}
                    public void ancestorRemoved(javax.swing.event.AncestorEvent e){}
                    public void ancestorMoved(javax.swing.event.AncestorEvent e){}
                });
                while(true){
                    int answer=JOptionPane.showConfirmDialog(null,panel,"YubiKey PIN",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE);
                    if(answer!=JOptionPane.OK_OPTION){field.setText("");break;}
                    char[] entered=field.getPassword();field.setText("");
                    if(valid(entered)){result[0]=entered;break;}
                    Arrays.fill(entered,'\0');
                    validation.setText("Use 6–8 ASCII characters. Nothing was sent to the YubiKey.");
                    validation.setForeground(new Color(160,30,30));
                }
            };
            if(SwingUtilities.isEventDispatchThread())prompt.run();else SwingUtilities.invokeAndWait(prompt);
        }
        if(result[0]==null)throw new java.security.SignatureException("YubiKey PIN entry cancelled");
        if(!valid(result[0])){Arrays.fill(result[0],'\0');throw new java.security.SignatureException("Use a 6–8 character ASCII PIV PIN");}
        return result[0];
    }
    private static boolean valid(char[] pin){
        if(pin.length<6||pin.length>8)return false;
        for(char c:pin)if(c<32||c>126)return false;
        return true;
    }
    public static AutoCloseable progress(){
        if(GraphicsEnvironment.isHeadless())return ()->{};
        JDialog[] dialog={null};
        SwingUtilities.invokeLater(()->{
            JDialog d=new JDialog((Frame)null,"YubiKey signing",false);dialog[0]=d;
            d.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            JLabel label=new JLabel("Signing… touch only if the key’s policy requires it.");
            label.setBorder(BorderFactory.createEmptyBorder(20,25,20,25));d.add(label);d.pack();d.setLocationRelativeTo(null);d.setVisible(true);
        });
        return ()->SwingUtilities.invokeLater(()->{if(dialog[0]!=null)dialog[0].dispose();});
    }
}
