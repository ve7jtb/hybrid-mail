package dev.hybridmail;

import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import javax.swing.*;

/** Default-off desktop Chat UI. Network and cryptographic work run through the
 * host's modal worker, so no UI action races a PIN request or vault lock. */
final class GoogleChatPanel extends JPanel {
    private final MailApp host;
    private GoogleChatSession session;
    private final JTextField email=new JTextField(24),recipient=new JTextField(24),subject=new JTextField("PQ Mail Chat test",24);
    private final JLabel status=new JLabel("Experimental Chat · unlock your PRF vault to connect");
    private final JComboBox<GoogleChatApi.Space> spaces=new JComboBox<>();
    private final DefaultListModel<GoogleChatApi.Message> messages=new DefaultListModel<>();
    private final JList<GoogleChatApi.Message> list=new JList<>(messages);
    private final JTextArea body=new JTextArea(7,45);private final DesktopComposeBody composer=new DesktopComposeBody(body);
    private final JCheckBox encrypt=new JCheckBox("Encrypt for recipient (hybrid v6)",true);
    private final JComboBox<KeyChoice> keys=new JComboBox<>();
    private final DefaultListModel<Path> files=new DefaultListModel<>();private final JList<Path> fileList=new JList<>(files);
    private final DesktopMessageView view=new DesktopMessageView();
    private final Deque<String> back=new ArrayDeque<>();private String page="",next="",spaceNext="";
    private OpenPgp.PublicIdentity receivedCertificate;private ChatBundle.Opened received;
    record KeyChoice(String email,OpenPgp.PublicIdentity cert,boolean trusted){public String toString(){try{return email+" · "+(trusted?"Trusted":"Not trusted")+" · v"+cert.version()+" · "+cert.encryptionAlgorithm()+" · "+cert.fingerprint().substring(0,16)+"…";}catch(Exception e){return "Invalid certificate";}}}
    GoogleChatPanel(MailApp host){
        super(new BorderLayout(8,8));this.host=host;setBorder(BorderFactory.createEmptyBorder(8,8,8,8));
        JPanel top=new JPanel(new GridLayout(0,1,0,4));top.add(row(new JLabel("Google Chat account"),email,button("Sign in or reconnect",()->connect(false)),button("Sign in again",()->connect(true)),button("Disconnect / forget login",this::forget)));
        top.add(row(button("Enable / configure…",host::chatConfigure),button("Pin current identity",this::pin),button("Certificates & trust",host::chatContacts),status));
        top.add(row(new JLabel("Conversation"),spaces,button("Refresh",()->loadSpaces(false)),button("More conversations",()->loadSpaces(true)),button("Open",()->loadMessages("",false)),button("Newer",this::newer),button("Older",this::older)));
        // Page tokens belong to one conversation. Selecting another space must
        // never reuse its predecessor's cursors or leave stale plaintext visible.
        spaces.addActionListener(e->{back.clear();page=next="";messages.clear();view.clear();received=null;receivedCertificate=null;});
        try{email.setText(state().get("google.email",""));}catch(Exception unavailable){/* An account can be entered explicitly. */}
        spaces.setPreferredSize(new Dimension(420,28));keys.setPreferredSize(new Dimension(680,28));add(top,BorderLayout.NORTH);
        // Google names are plain text, never interpreted as Swing HTML.
        list.setCellRenderer(new DefaultListCellRenderer(){public Component getListCellRendererComponent(JList<?> l,Object v,int i,boolean s,boolean f){super.getListCellRendererComponent(l,v,i,s,f);putClientProperty("html.disable",Boolean.TRUE);setText(String.valueOf(v));return this;}});
        spaces.setRenderer(new DefaultListCellRenderer(){public Component getListCellRendererComponent(JList<?> l,Object v,int i,boolean s,boolean f){super.getListCellRendererComponent(l,v,i,s,f);putClientProperty("html.disable",Boolean.TRUE);setText(v==null?"Select an existing Chat conversation":v.toString());return this;}});
        JPanel reading=new JPanel(new BorderLayout(6,6));JScrollPane rows=new JScrollPane(list);rows.setPreferredSize(new Dimension(600,130));reading.add(rows,BorderLayout.NORTH);reading.add(view);reading.add(row(button("Open / verify bundle",this::open),button("Save verified sender certificate",this::saveCertificate),button("Review trust…",host::chatContacts),button("Save decrypted attachment…",this::saveFile)),BorderLayout.SOUTH);
        JPanel writing=new JPanel(new BorderLayout(6,6));
        JPanel fields=new JPanel(new BorderLayout(0,6));
        JPanel recipients=new JPanel(new GridLayout(0,1,0,4));
        recipients.add(row(new JLabel("Recipient email (inside signed bundle)"),recipient,button("Find saved certificates",this::refreshKeys)));
        recipients.add(row(new JLabel("Recipient certificate"),keys));fields.add(recipients,BorderLayout.NORTH);
        // Give the subject its own full-width row, rather than letting a FlowLayout
        // hide it among recipient and encryption controls at ordinary window sizes.
        JPanel subjectPanel=new JPanel(new BorderLayout(0,6));
        subjectPanel.setBorder(BorderFactory.createEmptyBorder(8,6,4,6));
        JLabel subjectLabel=new JLabel();subjectLabel.setFont(subjectLabel.getFont().deriveFont(Font.BOLD,16f));subjectLabel.setLabelFor(subject);
        subject.setFont(subject.getFont().deriveFont(18f));subject.setMargin(new Insets(8,10,8,10));
        JLabel subjectHelp=new JLabel();
        Runnable updateSubjectLabel=()->{
            String label=encrypt.isSelected()?"Subject (inside encrypted bundle)":"Subject (inside signed bundle)";
            String help=encrypt.isSelected()?"Shown after decryption in PQ Mail; not included in the Google Chat caption.":"Signed but not encrypted; anyone who downloads the bundle can read it.";
            subjectLabel.setText(label);subjectHelp.setText(help);
            subject.getAccessibleContext().setAccessibleName(label);subject.getAccessibleContext().setAccessibleDescription(help);
            subject.setToolTipText(help);
        };
        encrypt.addActionListener(e->updateSubjectLabel.run());updateSubjectLabel.run();
        subjectPanel.add(subjectLabel,BorderLayout.NORTH);subjectPanel.add(subject,BorderLayout.CENTER);subjectPanel.add(subjectHelp,BorderLayout.SOUTH);
        fields.add(subjectPanel,BorderLayout.CENTER);fields.add(row(encrypt),BorderLayout.SOUTH);
        writing.add(fields,BorderLayout.NORTH);writing.add(composer);
        JPanel bottom=new JPanel(new GridLayout(0,1));fileList.setVisibleRowCount(2);bottom.add(new JScrollPane(fileList));bottom.add(row(button("Add attachments…",this::addFiles),button("Remove selected",()->{for(Path p:fileList.getSelectedValuesList())files.removeElement(p);}),button("Sign and send bundle…",this::send)));writing.add(bottom,BorderLayout.SOUTH);
        JTabbedPane content=new JTabbedPane();content.addTab("Conversation",reading);content.addTab("Send bundle",writing);add(content);
        for(JLabel label:List.of(status))label.putClientProperty("html.disable",Boolean.TRUE);
    }
    private static JPanel row(Component... items){JPanel p=new JPanel(new FlowLayout(FlowLayout.LEFT,6,2));for(var c:items)p.add(c);return p;}
    private static JButton button(String name,Runnable action){return DesktopMailShell.action(name,action);}
    private void error(Exception e){host.chatError(e);}
    private DesktopState state()throws Exception{return host.chatState();}
    private GoogleChatVault vault()throws Exception{return new GoogleChatVault(DesktopVault.vault());}
    private GoogleChatApi api()throws Exception{if(session==null)throw new IOException("Connect Google Chat first");GoogleChatExperiment.requireEnabled(state(),host.chatGmailClient());session.account();return session.api();}
    private String account()throws Exception{if(session==null)throw new IOException("Connect Google Chat first");return session.account().email();}
    private Identity identity()throws Exception{Identity id=host.chatIdentity();if(id==null)throw new IOException("Load your saved Chat identity in Keys, then pin it for Chat");vault().requirePinned(state(),account(),id);return id;}
    private void connect(boolean fresh){final String address=email.getText().trim();host.chatJob("Unlocking PRF vault and connecting Google Chat…",()->{
        var s=state();GoogleChatExperiment.requireEnabled(s,host.chatGmailClient());var v=DesktopVault.vault();
        if(!GoogleChatExperiment.clientId(s).equals(GoogleChatSession.client().id()))throw new IOException("Open Enable / configure to select this build’s Chat client");
        if(session==null)session=new GoogleChatSession(v,GoogleChatSession.client());
        var result=session.connect(address,fresh,uri->{try{Desktop.getDesktop().browse(uri);}catch(Exception e){throw new IllegalStateException("Cannot open Google sign-in browser",e);}});
        return result;
    },a->{status.setText("Connected: "+a.email()+" · Chat login protected by passkey vault");loadSpaces(false);});}
    private void forget(){String address=email.getText().trim();if(JOptionPane.showConfirmDialog(this,"Forget this account's saved Chat login on this computer? Gmail is unaffected.","Forget Chat login",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;host.chatJob("Removing encrypted Chat login…",()->{var v=vault();v.forgetRefresh(GoogleChatSession.client().id(),address);return true;},ok->locked());}
    void locked(){if(session!=null)session.close();session=null;messages.clear();spaces.removeAllItems();view.clear();received=null;receivedCertificate=null;back.clear();page=next=spaceNext="";status.setText("Chat disconnected · reconnect after vault unlock");}
    private void pin(){host.chatJob("Checking current v6 identity and pinning it in the vault…",()->{Identity id=host.chatIdentity();if(id==null)throw new IOException("First load a saved identity in Keys");return vault().pin(state(),account(),id);},p->{status.setText("Pinned v6 identity: "+p.fingerprint());recipient.setText(p.email());refreshKeys();});}
    private void loadSpaces(boolean more){final String cursor=more?spaceNext:"";if(more&&cursor.isEmpty())return;host.chatJob("Loading Chat conversations…",()->api().spaces(cursor),result->{if(!more)spaces.removeAllItems();for(var s:result.items())spaces.addItem(s);spaceNext=result.next();messages.clear();back.clear();page=next="";status.setText(spaces.getItemCount()==0?"No conversations returned. Create a test space in Google Chat first.":"Choose a conversation and click Open");});}
    private void loadMessages(String cursor,boolean remember){var target=(GoogleChatApi.Space)spaces.getSelectedItem();if(target==null){error(new IOException("Select an existing conversation"));return;}String old=page;host.chatJob("Loading Chat messages…",()->api().messages(target.name(),cursor),result->{if(remember)back.push(old);else if(cursor.isEmpty())back.clear();page=cursor;next=result.next();messages.clear();for(var m:result.items())messages.addElement(m);view.clear();received=null;receivedCertificate=null;status.setText("Loaded "+result.items().size()+" messages · kept in memory only");});}
    private void older(){if(!next.isEmpty())loadMessages(next,true);}
    private void newer(){if(!back.isEmpty())loadMessages(back.pop(),false);}
    private void refreshKeys(){String address=recipient.getText().trim();host.chatJob("Reading saved recipient certificates…",()->{
        GoogleChatVault.email(address);var s=state();var found=new ArrayList<KeyChoice>();var seen=new HashSet<String>();
        // Our explicitly pinned identity is safe for self-test encryption. This
        // does not grant contact trust or apply to certificates merely attached.
        try{var own=vault().requirePinned(s,account(),identity());if(own.matchesEmail(address)){found.add(new KeyChoice(address,own,true));seen.add(own.fingerprint());}}catch(Exception noOwn){/* Other contacts still usable. */}
        for(var c:s.pgpContacts()){var cert=s.pgpCertificate(c);if(cert.matchesEmail(address)&&cert.version()==6&&cert.quantumEncryption()&&cert.canEncrypt()&&seen.add(cert.fingerprint()))found.add(new KeyChoice(address,cert,s.isPgpTrusted(address,cert.fingerprint())));}
        return found;
    },found->{keys.removeAllItems();for(var k:found)keys.addItem(k);status.setText(found.isEmpty()?"No saved hybrid v6 recipient certificate. Import and review in Certificates.":"Recipient certificates loaded; encryption requires trust or your pinned self identity.");});}
    private void addFiles(){JFileChooser c=new JFileChooser();c.setMultiSelectionEnabled(true);if(c.showOpenDialog(this)==JFileChooser.APPROVE_OPTION)for(File f:c.getSelectedFiles()){if(files.size()>=20){error(new IOException("At most 20 attachments"));break;}files.addElement(f.toPath());}}
    private void send(){
        var target=(GoogleChatApi.Space)spaces.getSelectedItem();var key=(KeyChoice)keys.getSelectedItem();boolean encrypted=encrypt.isSelected();String address=recipient.getText().trim(),title=subject.getText(),text=composer.text();final String html;
        try{html=composer.html();if(target==null)throw new IOException("Select the destination conversation");GoogleChatVault.email(address);if(encrypted&&(key==null||!key.email().equalsIgnoreCase(address)||!key.trusted()))throw new IOException("Select a trusted hybrid v6 certificate matching the recipient");}catch(Exception e){error(e);return;}
        JTextArea confirm=new JTextArea("Send "+(encrypted?"a signed and encrypted":"a signed, UNENCRYPTED")+" bundle to this Google Chat conversation?\n\n"+target+"\nRecipient inside bundle: "+address+"\n\nAll space members can download both attachments. Your public v6 certificate (including its certified emails and fingerprint) is attached outside the bundle.\n"+(encrypted?"Only the selected recipient key can decrypt the bundle.":"Everyone in the conversation can read the bundle.")+"\nGoogle still sees conversation and file metadata.",10,65);confirm.setEditable(false);confirm.setLineWrap(true);confirm.setWrapStyleWord(true);
        if(JOptionPane.showConfirmDialog(this,new JScrollPane(confirm),"Confirm Chat send",JOptionPane.OK_CANCEL_OPTION,JOptionPane.WARNING_MESSAGE)!=JOptionPane.OK_OPTION)return;
        var paths=Collections.list(files.elements());host.chatJob("Signing Chat bundle, uploading attachments and sending…",()->{
            var transport=api();var s=state();Identity id=identity();var own=vault().requirePinned(s,account(),id);var attachments=new ArrayList<MailEngine.Attachment>();long total=0;
            for(Path p:paths){long n=Files.size(p);total+=n;if(total>ChatBundle.MAX_ATTACHMENT_BYTES)throw new IOException("Attachments exceed 10 MiB");byte[] bytes;try(var in=Files.newInputStream(p)){bytes=in.readNBytes(ChatBundle.MAX_ATTACHMENT_BYTES+1);}if(bytes.length>ChatBundle.MAX_ATTACHMENT_BYTES)throw new IOException("Attachment too large");attachments.add(new MailEngine.Attachment(p.getFileName().toString(),bytes));}
            var chosen=encrypted?new OpenPgp.PublicIdentity(key.cert().encoded):null;
            if(chosen!=null&&!chosen.fingerprint().equals(own.fingerprint())&&!s.isPgpTrusted(address,chosen.fingerprint()))throw new IOException("Recipient trust changed; review it again");
            byte[] bytes=ChatBundle.create(id,own,chosen,account(),address,title,text,html,attachments,host.chatSigning());
            return transport.send(target.name(),bytes,own.encoded);
        },sent->{JOptionPane.showMessageDialog(this,"Chat message sent.\n"+sent.name()+"\nTwo linked messages: message.pgp and your public v6 certificate.");loadMessages("",false);});
    }
    record Read(ChatBundle.Opened opened,OpenPgp.PublicIdentity certificate,String transportSender,boolean ownSender,boolean trusted){}
    private void open(){var selected=list.getSelectedValue();if(selected==null)return;view.clear();received=null;receivedCertificate=null;host.chatJob("Downloading and verifying Chat bundle…",()->{
        var transport=api();Identity id=identity();var own=vault().requirePinned(state(),account(),id);
        var bundle=selected.attachments().stream().filter(a->a.filename().equals(ChatBundle.FILENAME)).findFirst().orElseThrow(()->new IOException("This message has no PQ Mail message.pgp attachment"));
        if(selected.attachments().stream().filter(a->a.filename().equals(ChatBundle.FILENAME)).count()!=1)throw new IOException("Ambiguous bundle attachments");
        var candidates=new ArrayList<OpenPgp.PublicIdentity>();var seen=new HashSet<String>();
        for(var a:transport.senderCertificates(selected))if(a.filename().equals("pq-mail-sender-key.pgp")){if(candidates.size()>=4)throw new IOException("Too many attached certificates");candidates.add(new OpenPgp.PublicIdentity(transport.download(a,1024*1024)));}
        candidates.add(own);for(var c:state().pgpContacts())candidates.add(state().pgpCertificate(c));byte[] bytes=transport.download(bundle,ChatBundle.MAX_BYTES);Exception last=null;
        // Decrypt only once, then test candidate signatures without repeating PIN
        // operations. Attached certificates never modify saved contacts or trust.
        byte[] signed=bytes;Object first=LegacyOpenPgp.objects(bytes).nextObject();boolean encrypted=first instanceof org.bouncycastle.openpgp.PGPEncryptedDataList;
        if(encrypted){if(id.softwareOpenPgp()!=null)signed=id.softwareOpenPgp().decrypt(bytes);else{var env=OpenPgp.envelope(bytes,own);byte[] kek=OpenPgp.recover(env.ct(),id,host.chatDecryption(),own);try{signed=env.open(kek);}finally{OpenPgp.wipe(kek);}}}
        for(var cert:candidates){if(!seen.add(cert.fingerprint()))continue;try{var r=ChatBundle.open(signed,cert,own,id,null);if(!GoogleChatVault.email(r.to()).equals(account()))throw new IOException("Signed recipient does not match your account");
            boolean self=selected.sender().equals(session.account().user());if(self&&!GoogleChatVault.email(r.from()).equals(account()))throw new IOException("Google sender and signed sender disagree");
            r=new ChatBundle.Opened(r.from(),r.to(),r.subject(),r.text(),r.html(),r.attachments(),r.signerFingerprint(),encrypted,r.postQuantum(),r.mime());return new Read(r,cert,selected.sender(),self,state().isPgpTrusted(r.from(),r.signerFingerprint()));
        }catch(Exception e){last=e;}}
        throw new IOException("No supplied certificate verified this Chat bundle",last);
    },r->{received=r.opened();receivedCertificate=r.certificate();view.showMessage("Signature valid · "+(received.postQuantum()?"Hybrid PQ":"WARNING: classical signature")+" · "+(received.encrypted()?"Decrypted":"Not encrypted")+"\nSigned sender: "+received.from()+"\nFingerprint: "+received.signerFingerprint()+"\n"+(r.trusted()?"Trusted email / fingerprint":"Not trusted — confirm fingerprint separately")+"\nGoogle sender: "+r.transportSender()+" · "+(r.ownSender()?"matches authenticated self account":"email not independently mapped; do not infer trust from Google display name")+"\nSubject: "+received.subject(),received.text(),received.html());});}
    private void saveCertificate(){if(received==null||receivedCertificate==null)return;try{state().rememberPgp(receivedCertificate,received.from());status.setText("Certificate saved. Trust unchanged; review it in Certificates & trust.");}catch(Exception e){error(e);}}
    private void saveFile(){if(received==null||received.attachments().isEmpty()){error(new IOException("No decrypted attachments"));return;}var options=received.attachments().stream().map(MailEngine.Attachment::name).toArray(String[]::new);String selected=(String)JOptionPane.showInputDialog(this,"Attachment","Save attachment",JOptionPane.PLAIN_MESSAGE,null,options,options[0]);if(selected==null)return;var file=received.attachments().get(Arrays.asList(options).indexOf(selected));JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File(file.name()));if(chooser.showSaveDialog(this)==JFileChooser.APPROVE_OPTION)try{Files.write(chooser.getSelectedFile().toPath(),file.data(),StandardOpenOption.CREATE_NEW);}catch(Exception e){error(e);}}
}
