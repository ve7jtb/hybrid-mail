package dev.hybridmail;

import java.util.*;
import javax.swing.*;

/** MIME alternatives must be signed/encrypted as one entity in every compose path. */
public final class FormattedComposeTest {
    static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    public static void main(String[] args)throws Exception{
        MailEngine.init();String[] html={null},text={null};
        SwingUtilities.invokeAndWait(()->{
            try{
                DesktopComposeBody editor=new DesktopComposeBody(new JTextArea("Hello café\nSecond line"));
                check(editor.html()==null&&editor.text().startsWith("Hello café"),"Default plain compose");editor.formatting.doClick();
                int first=editor.rich.getDocument().getText(0,editor.rich.getDocument().getLength()).indexOf("Hello");editor.rich.select(first,first+5);
                ((JButton)editor.tools.getComponent(0)).doClick();
                html[0]=editor.html();check(html[0].contains("<b>Hello</b>"),"Bold output lost: "+html[0]);
                editor.rich.setCaretPosition(editor.rich.getDocument().getLength());editor.insertBlock("ul","List item");
                editor.insertBlock("h2","Heading");editor.rich.setCaretPosition(editor.rich.getDocument().getLength());editor.insertLink("https://example.test/");
                html[0]=editor.html();text[0]=editor.text();check(html[0].contains("<ul>")&&html[0].contains("<h2>")&&html[0].contains("href=\"https://example.test/\""),"Toolbar markup missing: "+html[0]);
                var pasted=new java.awt.datatransfer.StringSelection("<img src='https://example.test/pixel'>");check(editor.rich.getTransferHandler().importData(new TransferHandler.TransferSupport(editor.rich,pasted)),"Paste failed");check(!editor.html().contains("<img"),"Paste interpreted as HTML");
            }catch(Exception e){throw new RuntimeException(e);}
        });
        String email="format@example.test";var profiles=Identity.generateSoftwareProfile(email,TokenProfile.LEVEL3);
        for(var id:profiles)for(boolean encrypted:new boolean[]{false,true}){
            var attachment=new MailEngine.Attachment("sample.txt","Synthetic attachment".getBytes());
            var message=MailEngine.composeAttachments(id,email,email,"Formatting",text[0],encrypted?id.encryptionCert():null,null,List.of(attachment),html[0]);
            var read=MailEngine.open(message,id,id.signingCert());check(read.text().equals(text[0])&&read.html().equals(html[0])&&read.encrypted()==encrypted&&read.attachments().size()==1,"S/MIME alternatives and attachment round trip");
        }
        var id=profiles.getLast();var own=OpenPgp.create(id,null);
        for(boolean encrypted:new boolean[]{false,true}){
            var message=OpenPgp.composeForRecipient(id,own,own,encrypted,email,email,"Formatting",text[0],html[0],null);
            var read=OpenPgp.open(message,own,own,id,null);check(read.text().equals(text[0])&&read.html().equals(html[0])&&read.encrypted()==encrypted,"v6 hybrid round trip");
        }
        var software=SoftwareIdentityVault.addLevel5OpenPgp(Identity.generateSoftwareProfile(email,TokenProfile.LEVEL5,List.of())).getLast();var modern=software.softwareOpenPgp().own();
        for(var recipient:List.of(modern,modern.compatibility,OpenPgp.classicalOnlyCompatibility(modern.compatibility)))for(boolean encrypted:new boolean[]{false,true}){
            var message=OpenPgp.composeForRecipient(software,modern,recipient,encrypted,email,email,"Formatting",text[0],html[0],null);
            var read=OpenPgp.open(message,recipient.version()==6?modern:modern.compatibility,modern,software,null);check(read.text().equals(text[0])&&read.html().equals(html[0])&&read.encrypted()==encrypted,"Level 5 v6/v4 alternatives round trip");
        }
        System.out.println("PASS formatting toolbar and text-only paste; signed/encrypted S/MIME with attachments; OpenPGP v6 and both v4 software profiles retain both alternatives");
    }
}
