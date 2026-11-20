package dev.hybridmail;

import java.awt.*;
import java.util.*;
import javax.swing.*;

/** Edits a selection only; Cancel never changes stored trust. */
final class PgpTrustSelectionPanel extends JPanel {
    final JCheckBox selectAll=new JCheckBox("Select all email addresses");
    final Map<String,JCheckBox> addresses=new LinkedHashMap<>();
    private boolean syncing;
    PgpTrustSelectionPanel(DesktopState state,OpenPgp.PublicIdentity key,String selectedEmail)throws Exception{
        super(new BorderLayout(0,12));
        JTextArea description=new JTextArea("Full primary-key fingerprint:\n"+key.fingerprint()+"\nEncryption: "+key.encryptionDescription()+"\n\nConfirm this fingerprint with the owner through an independent trusted channel.\nChoose the certified email addresses to trust with this key.",6,64);
        description.setEditable(false);description.setLineWrap(true);description.setWrapStyleWord(true);description.setOpaque(false);add(description,BorderLayout.NORTH);
        JPanel list=new JPanel();list.setLayout(new BoxLayout(list,BoxLayout.Y_AXIS));list.add(selectAll);
        for(String email:key.certifiedEmails()){
            JCheckBox box=new JCheckBox(email,state.isPgpTrusted(email,key.fingerprint())||email.equalsIgnoreCase(selectedEmail));
            addresses.put(email,box);list.add(box);box.addActionListener(e->syncAll());
        }
        selectAll.addActionListener(e->{if(!syncing){for(var box:addresses.values())box.setSelected(selectAll.isSelected());syncAll();}});
        JScrollPane scroll=new JScrollPane(list);scroll.setPreferredSize(new Dimension(580,Math.min(300,50+addresses.size()*28)));add(scroll,BorderLayout.CENTER);
        JTextArea note=new JTextArea("Checked addresses will be trusted; unchecked addresses will be untrusted.\nSaving also adds selected addresses to Certificates. Cancel leaves everything unchanged.\nTrust covers this primary key’s valid signing and encryption subkeys.\nIt does not remove classical-algorithm warnings.");
        note.setEditable(false);note.setLineWrap(true);note.setWrapStyleWord(true);note.setOpaque(false);add(note,BorderLayout.SOUTH);syncAll();
    }
    private void syncAll(){syncing=true;selectAll.setSelected(!addresses.isEmpty()&&addresses.values().stream().allMatch(JCheckBox::isSelected));syncing=false;}
    Set<String> selectedEmails(){var selected=new LinkedHashSet<String>();addresses.forEach((email,box)->{if(box.isSelected())selected.add(email);});return Set.copyOf(selected);}
}
