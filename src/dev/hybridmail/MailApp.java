package dev.hybridmail;

import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.Callable;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import jakarta.mail.internet.MimeMessage;

public final class MailApp extends JFrame {
    private java.util.List<DesktopState.Contact> certificateContacts=java.util.List.of();
    private final javax.swing.table.DefaultTableModel certificateModel=new javax.swing.table.DefaultTableModel(new String[]{"Email","Purpose","Trust","Algorithm","SHA-256 fingerprint"},0){public boolean isCellEditable(int row,int column){return false;}};
    private final JTable certificateTable=new JTable(certificateModel);
    private boolean syncingOutgoing;
    private final JComboBox<DesktopState.SavedIdentity> outgoingIdentity=new JComboBox<>();
    private record EncryptionChoice(String email,X509Certificate certificate){
        public String toString(){try{return email+" · "+certificate.getPublicKey().getAlgorithm()+" · "+Identity.fingerprint(certificate).substring(0,23);}catch(Exception e){return email;}}
    }
    private final JComboBox<EncryptionChoice> outgoingEncryption=new JComboBox<>();
    private final JButton trustIncoming=new JButton("Trust signer fingerprint…");
    private ReadResult currentRead;
    private record ReadResult(String plain,MailEngine.Opened verified,String subject){}
    private Identity identity;
    private ImapInbox inbox;
    private GoogleOAuth.Token googleToken;
    private String googleEmail;
    private java.util.List<ImapInbox.Entry> inboxEntries=java.util.List.of();
    private final javax.swing.table.DefaultTableModel inboxModel=new javax.swing.table.DefaultTableModel(new String[]{"From","Subject","Received"},0){public boolean isCellEditable(int row,int column){return false;}};
    private final JTable inboxTable=new JTable(inboxModel);
    private final JLabel inboxLabel=new JLabel("Not connected · shows the 10 most recent arrivals");
    private final JLabel googleLabel=new JLabel("Google: signed out");
    private DesktopState desktopState;
    private final JComboBox<DesktopState.SavedIdentity> savedIdentities=new JComboBox<>();
    private X509Certificate recipient, pinnedSigner;
    private String adapter,kemAdapter;
    private final JLabel kemLabel=new JLabel("Decryption: software");
    private final JTextField from = new JTextField("alice@example.test"), to = new JTextField("bob@example.test"), subject = new JTextField("A private conversation");
    private final JTextArea body = new JTextArea("Hello,\n\nThis message is signed using post-quantum cryptography.\n"), reader = new JTextArea();
    private final JCheckBox encrypt = new JCheckBox("Also encrypt for recipient (optional)", false);
    private final JLabel identityLabel = new JLabel("No identity loaded"), recipientLabel = new JLabel("No recipient certificate"), tokenLabel = new JLabel("Signing: software"), pinLabel = new JLabel("No signer certificate pinned");
    private final JLabel status = new JLabel("Create or load an identity to begin. No network connection is made on startup.");
    private final JTabbedPane tabs = new JTabbedPane();
    public MailApp() {
        super("Hybrid Mail · S/MIME lab");
        setDefaultCloseOperation(EXIT_ON_CLOSE); setSize(1060, 800); setMinimumSize(new Dimension(850,650)); setLocationRelativeTo(null);
        JPanel root = new JPanel(new BorderLayout(0,18)); root.setBorder(new EmptyBorder(22,28,18,28)); setContentPane(root);
        JPanel heading = new JPanel(new BorderLayout()); JLabel title = new JLabel("Hybrid Mail"); title.setFont(title.getFont().deriveFont(Font.BOLD, 30f));
        heading.add(title, BorderLayout.NORTH); heading.add(new JLabel("ML-DSA & composite S/MIME  /  local development build"), BorderLayout.SOUTH); root.add(heading,BorderLayout.NORTH);
        tabs.addTab("Compose", composePanel()); tabs.addTab("Read & verify", readPanel()); tabs.addTab("Keys & token", keysPanel()); tabs.addTab("Inbox",inboxPanel()); tabs.addTab("Certificates",certificatesPanel()); root.add(tabs);
        status.setBorder(new EmptyBorder(10,0,0,0)); root.add(status, BorderLayout.SOUTH);
        body.setLineWrap(true); body.setWrapStyleWord(true); body.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,16)); body.setMargin(new Insets(16,16,16,16));
        reader.setEditable(false); reader.setLineWrap(true); reader.setWrapStyleWord(true); reader.setFont(new Font(Font.MONOSPACED,Font.PLAIN,13)); reader.setMargin(new Insets(16,16,16,16));
    }
    private JPanel composePanel() {
        JPanel p = panel(); JPanel fields = new JPanel(new GridLayout(0,1,0,8));
        fields.add(row("From",from)); fields.add(row("To",to)); fields.add(row("Subject",subject));
        fields.add(row("Sign with",outgoingIdentity));fields.add(encrypt);fields.add(row("Encrypt to",outgoingEncryption));
        outgoingIdentity.addActionListener(e->{if(!syncingOutgoing){var chosen=(DesktopState.SavedIdentity)outgoingIdentity.getSelectedItem();if(chosen!=null)openSaved(chosen);}});
        outgoingEncryption.setEnabled(encrypt.isSelected());encrypt.addActionListener(e->outgoingEncryption.setEnabled(encrypt.isSelected()));
        outgoingEncryption.addActionListener(e->{if(!syncingOutgoing){var chosen=(EncryptionChoice)outgoingEncryption.getSelectedItem();if(chosen!=null){recipient=chosen.certificate();to.setText(chosen.email());recipientLabel.setText(chosen.email()+" · "+recipient.getPublicKey().getAlgorithm());try{state().saveCertificate("recipient",recipient);}catch(Exception error){error(error);}}}}); fields.add(new JLabel("All outgoing messages are signed. Enable encryption only when you have the recipient’s encryption certificate.")); p.add(fields,BorderLayout.NORTH);
        p.add(new JScrollPane(body));
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(new JLabel("Body is signed; encryption is optional. Outer From / To / Subject headers are unprotected."),BorderLayout.NORTH);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(button("Recipient certificates…",()->tabs.setSelectedIndex(4))); actions.add(button("Save signed .eml…", () -> compose(false))); actions.add(button("Send via SMTP…", () -> compose(true)));
        bottom.add(actions, BorderLayout.SOUTH); p.add(bottom,BorderLayout.SOUTH); return p;
    }
    private JPanel readPanel() {
        JPanel p = panel(); p.add(new JScrollPane(reader)); JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Open .eml…", () -> {
            Path file = choose(false,"Open S/MIME message"); if(file == null)return;
            clearReadTrust();Identity id = identity; X509Certificate pin = pinnedSigner;
            job("Verifying message…", () -> { if(Files.size(file)>MailEngine.MAX_MESSAGE) throw new IOException("Message too large"); return display(MailEngine.parse(Files.readAllBytes(file)),id,pin); }, this::showMessage);
        }));
        actions.add(button("Open inbox",()->tabs.setSelectedIndex(3)));
        trustIncoming.setEnabled(false);trustIncoming.addActionListener(e->trustIncomingSigner());actions.add(trustIncoming);
        p.add(actions,BorderLayout.NORTH); return p;
    }
    private JPanel inboxPanel(){
        JPanel p=panel();JPanel top=new JPanel(new GridLayout(0,1,0,6));
        top.add(inboxLabel);top.add(googleLabel);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Connect IMAP…",()->connectInbox(false)));
        actions.add(button("Connect Gmail",()->connectInbox(true)));
        actions.add(button("Refresh",this::refreshInbox));
        actions.add(button("Disconnect",this::disconnectInbox));top.add(actions);
        JPanel google=new JPanel(new FlowLayout(FlowLayout.LEFT));
        google.add(button("Import Google OAuth client…",this::importGoogleClient));
        google.add(button("Enter Google client credentials…",this::enterGoogleClient));
        google.add(button("Sign in with Google…",this::signInGoogle));
        google.add(button("Sign out of Google",this::signOutGoogle));top.add(google);p.add(top,BorderLayout.NORTH);
        inboxTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);inboxTable.setRowHeight(30);inboxTable.setAutoCreateRowSorter(true);
        // Mail headers are untrusted; disable Swing's implicit HTML renderer.
        inboxTable.setDefaultRenderer(Object.class,new javax.swing.table.DefaultTableCellRenderer(){
            public Component getTableCellRendererComponent(JTable table,Object value,boolean selected,boolean focus,int row,int column){
                putClientProperty("html.disable",Boolean.TRUE);return super.getTableCellRendererComponent(table,value,selected,focus,row,column);
            }
        });
        inboxTable.getColumnModel().getColumn(1).setPreferredWidth(420);
        inboxTable.addMouseListener(new java.awt.event.MouseAdapter(){public void mouseClicked(java.awt.event.MouseEvent e){if(e.getClickCount()==2)openInboxMessage();}});
        inboxTable.getInputMap().put(KeyStroke.getKeyStroke("ENTER"),"open-message");inboxTable.getActionMap().put("open-message",new AbstractAction(){public void actionPerformed(java.awt.event.ActionEvent e){openInboxMessage();}});
        p.add(new JScrollPane(inboxTable));JPanel bottom=new JPanel(new BorderLayout());bottom.add(new JLabel("Read-only · headers are unverified · message bodies load only when opened"),BorderLayout.NORTH);
        bottom.add(left(button("Open selected message",this::openInboxMessage)),BorderLayout.SOUTH);p.add(bottom,BorderLayout.SOUTH);return p;
    }
    private void connectInbox(boolean gmail){
        Account a=gmail?googleAccount(false):account(false);if(a==null)return;
        job("Connecting to inbox…",()->{try{
            ImapInbox next=ImapInbox.connect(a.host,a.port,a.user,new String(a.password),a.oauth);
            try{var entries=next.latest();if(inbox!=null)try{inbox.close();}catch(Exception ignored){}inbox=next;return entries;}
            catch(Exception e){next.close();throw e;}
        }finally{Arrays.fill(a.password,'\0');}},entries->{showInbox(entries);inboxLabel.setText(a.user+" · "+entries.size()+" most recent messages · read-only");tabs.setSelectedIndex(3);});
    }
    private void showInbox(java.util.List<ImapInbox.Entry> entries){
        inboxEntries=entries;inboxModel.setRowCount(0);
        var format=java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(java.time.ZoneId.systemDefault());
        for(var entry:entries)inboxModel.addRow(new Object[]{entry.sender(),entry.subject(),entry.received()==null?"":format.format(entry.received())});
        status.setText(entries.isEmpty()?"Inbox is empty":"Showing "+entries.size()+" most recent arrivals, newest first");
    }
    private void refreshInbox(){if(inbox==null){error(new IOException("Connect to an inbox first"));return;}job("Refreshing inbox…",()->inbox.latest(),this::showInbox);}
    private void disconnectInbox(){
        ImapInbox previous=inbox;inbox=null;inboxEntries=java.util.List.of();inboxModel.setRowCount(0);inboxLabel.setText("Not connected");
        if(previous!=null)job("Disconnecting…",()->{previous.close();return "Disconnected";},status::setText);
    }
    private void openInboxMessage(){
        int selected=inboxTable.getSelectedRow();if(selected<0||inbox==null)return;
        clearReadTrust();var entry=inboxEntries.get(inboxTable.convertRowIndexToModel(selected));ImapInbox current=inbox;Identity id=identity;X509Certificate pin=pinnedSigner;
        job("Opening selected message…",()->display(current.message(entry.uid()),id,pin),this::showMessage);
    }
    private void importGoogleClient(){
        Path path=choose(false,"Import Google Desktop OAuth client JSON");if(path==null)return;
        try{GoogleOAuth.Client.read(path);state().importGoogleClient(path);googleLabel.setText("Google client configured · sign in to connect");status.setText("Desktop OAuth client saved locally; not uploaded");}catch(Exception e){error(e);}
    }
    private void enterGoogleClient(){
        JTextField clientId=new JTextField(42);JPasswordField secret=new JPasswordField(42);
        JPanel fields=new JPanel(new GridLayout(0,1,0,8));fields.add(new JLabel("Use the client ID and secret from a Google Desktop app OAuth client."));
        fields.add(row("Client ID",clientId));fields.add(row("Client secret",secret));
        fields.add(new JLabel("Saved only in this Mac's Hybrid Mail configuration; not uploaded to GitHub."));
        if(JOptionPane.showConfirmDialog(this,fields,"Google Desktop client credentials",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)!=JOptionPane.OK_OPTION){secret.setText("");return;}
        char[] value=secret.getPassword();secret.setText("");
        try{state().saveGoogleClient(new GoogleOAuth.Client(clientId.getText().trim(),new String(value).trim()));googleLabel.setText("Google client configured · sign in to connect");status.setText("Desktop OAuth client saved locally. Choose Sign in with Google.");}
        catch(Exception e){error(e);}finally{Arrays.fill(value,'\0');}
    }
    private void signInGoogle(){
        try{
            GoogleOAuth.Client client=GoogleOAuth.Client.read(state().directory().resolve("google-client.json"));
            JTextField email=new JTextField(state().get("google.email",""),30);
            JPanel prompt=new JPanel(new GridLayout(0,1,0,8));prompt.add(new JLabel("Google account email"));prompt.add(email);
            prompt.add(new JLabel("Google requires full mail permission for IMAP/SMTP. Review consent in your browser."));
            prompt.add(new JLabel("Tokens stay in memory and are cleared on sign-out or app exit."));
            if(JOptionPane.showConfirmDialog(this,prompt,"Sign in with Google",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();new jakarta.mail.internet.InternetAddress(address,true).validate();
            var cancelled=new java.util.concurrent.atomic.AtomicBoolean();
            JDialog progress=new JDialog(this,"Google sign-in",false);JPanel content=new JPanel(new BorderLayout(12,12));content.setBorder(new EmptyBorder(20,20,20,20));content.add(new JLabel("Complete sign-in in your browser, then return here."));content.add(button("Cancel",()->cancelled.set(true)),BorderLayout.SOUTH);progress.setContentPane(content);progress.pack();progress.setLocationRelativeTo(this);progress.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);progress.addWindowListener(new java.awt.event.WindowAdapter(){public void windowClosing(java.awt.event.WindowEvent e){cancelled.set(true);}});progress.setVisible(true);
            job("Waiting for Google sign-in…",()->{
                try{return GoogleOAuth.authorize(client,address,uri->{try{Desktop.getDesktop().browse(uri);}catch(Exception e){throw new IllegalStateException("Could not open the system browser");}},cancelled::get);}
                finally{SwingUtilities.invokeLater(progress::dispose);}
            },token->{if(googleToken!=null)googleToken.close();googleToken=token;googleEmail=address;googleLabel.setText("Google: "+address+" · signed in for this session");try{state().set("google.email",address);state().save();}catch(Exception e){error(e);}status.setText("Google sign-in ready. Connect Gmail or send with Google OAuth.");});
        }catch(NoSuchFileException e){error(new IOException("Import your Google Desktop OAuth client JSON first"));}catch(Exception e){error(e);}
    }
    private void signOutGoogle(){if(googleToken!=null)googleToken.close();googleToken=null;googleEmail=null;googleLabel.setText("Google: signed out");disconnectInbox();status.setText("Local Google session cleared. You can revoke app access in your Google account.");}
    private Account googleAccount(boolean smtp){
        try{if(googleToken==null||!googleToken.valid())throw new IOException("Sign in with Google from the Inbox tab first");return new Account(smtp?"smtp.gmail.com":"imap.gmail.com",smtp?587:993,googleEmail,googleToken.credential(),true);}catch(Exception e){error(e);tabs.setSelectedIndex(3);return null;}
    }
    private JPanel certificatesPanel(){
        JPanel p=panel();JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Import signing certificate…",()->importCert(true)));
        actions.add(button("Import encryption certificate…",()->importCert(false)));
        actions.add(button("Refresh",this::refreshContacts));p.add(actions,BorderLayout.NORTH);
        certificateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);certificateTable.setAutoCreateRowSorter(true);certificateTable.setRowHeight(30);
        certificateTable.setDefaultRenderer(Object.class,new javax.swing.table.DefaultTableCellRenderer(){public Component getTableCellRendererComponent(JTable t,Object value,boolean selected,boolean focus,int row,int column){putClientProperty("html.disable",Boolean.TRUE);return super.getTableCellRendererComponent(t,value,selected,focus,row,column);}});
        certificateTable.getColumnModel().getColumn(0).setPreferredWidth(200);certificateTable.getColumnModel().getColumn(4).setPreferredWidth(350);p.add(new JScrollPane(certificateTable));
        JPanel bottom=new JPanel(new GridLayout(0,1));JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(button("Details…",this::contactDetails));controls.add(button("Mark trusted…",()->setContactTrust(true)));controls.add(button("Remove trust",()->setContactTrust(false)));controls.add(button("Use selected certificate",this::useContact));controls.add(button("Export…",this::exportContact));controls.add(button("Remove",this::removeContact));bottom.add(controls);
        bottom.add(new JLabel("Trust is saved for exact certificate fingerprints. Importing or selecting a certificate does not grant trust."));p.add(bottom,BorderLayout.SOUTH);return p;
    }
    private DesktopState.Contact selectedContact(){int row=certificateTable.getSelectedRow();return row<0?null:certificateContacts.get(certificateTable.convertRowIndexToModel(row));}
    private void refreshContacts(){
        try{certificateContacts=state().contacts();certificateModel.setRowCount(0);for(var contact:certificateContacts){var certificate=state().contactCertificate(contact);certificateModel.addRow(new Object[]{contact.email(),contact.role(),state().isTrusted(certificate,contact.role())?"Trusted":"Not trusted",certificate.getPublicKey().getAlgorithm(),Identity.fingerprint(certificate)});}refreshOutgoingEncryption();}catch(Exception e){error(e);}
    }
    private void contactDetails(){
        var contact=selectedContact();if(contact==null)return;
        try{var certificate=state().contactCertificate(contact);JTextArea text=new JTextArea("Email: "+contact.email()+"\nPurpose: "+contact.role()+"\nSubject: "+certificate.getSubjectX500Principal()+"\nIssuer: "+certificate.getIssuerX500Principal()+"\nSAN: "+certificate.getSubjectAlternativeNames()+"\nAlgorithm: "+certificate.getPublicKey().getAlgorithm()+"\nValid: "+certificate.getNotBefore()+" through "+certificate.getNotAfter()+"\n\nSHA-256: "+Identity.fingerprint(certificate),12,65);text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);JOptionPane.showMessageDialog(this,new JScrollPane(text),"Certificate details",JOptionPane.PLAIN_MESSAGE);}catch(Exception e){error(e);}
    }
    private void useContact(){
        var contact=selectedContact();if(contact==null)return;
        try{applyContact(contact,state().contactCertificate(contact));}catch(Exception e){error(e);}
    }
    private void applyContact(DesktopState.Contact contact,X509Certificate certificate)throws Exception{
        certificate.checkValidity();
        if(contact.role().equals("encryption")){recipient=certificate;recipientLabel.setText(contact.email()+" · "+certificate.getPublicKey().getAlgorithm());to.setText(contact.email());encrypt.setSelected(true);state().saveCertificate("recipient",certificate);refreshOutgoingEncryption();tabs.setSelectedIndex(0);status.setText("Encryption enabled for "+contact.email());}
        else{pinnedSigner=certificate;pinLabel.setText(contact.email()+" · "+certificate.getPublicKey().getAlgorithm());state().saveCertificate("pinned",certificate);status.setText(state().isTrusted(certificate,"signing")?"Trusted signing certificate selected":"Signing certificate selected but not trusted; use Mark trusted in Certificates");}
    }
    private void exportContact(){
        var contact=selectedContact();if(contact==null)return;Path target=choose(true,"Export certificate (.pem or .cer)");if(target==null)return;
        try{var certificate=state().contactCertificate(contact);Files.write(target,target.toString().toLowerCase().endsWith(".pem")?DesktopState.pem(certificate):certificate.getEncoded(),StandardOpenOption.CREATE_NEW);status.setText("Certificate exported");}catch(Exception e){error(e);}
    }
    private void removeContact(){
        var contact=selectedContact();if(contact==null)return;
        if(JOptionPane.showConfirmDialog(this,"Remove "+contact.role()+" certificate for "+contact.email()+" from the saved contact list?","Remove certificate",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        try{var certificate=state().contactCertificate(contact);state().removeContact(contact);
            if(certificate.equals(recipient)){recipient=null;recipientLabel.setText("No recipient certificate");state().clearCertificate("recipient");}
            if(certificate.equals(pinnedSigner)){pinnedSigner=null;pinLabel.setText("No signer certificate pinned");state().clearCertificate("pinned");}
            refreshContacts();refreshReadTrust();status.setText("Removed from contacts; public certificate retained under removed-contacts");
        }catch(Exception e){error(e);}
    }
    private JPanel keysPanel() {
        JPanel outer = panel(); JPanel p = new JPanel(); p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS)); outer.add(new JScrollPane(p),BorderLayout.CENTER);
        p.add(section("1  Your identity",identityLabel));
        JPanel saved=new JPanel(new FlowLayout(FlowLayout.LEFT));saved.add(savedIdentities);
        saved.add(button("Open saved identity",()->openSaved((DesktopState.SavedIdentity)savedIdentities.getSelectedItem())));p.add(saved);
        JPanel keys = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keys.add(button("Create identity…",this::generate)); keys.add(button("Import PKCS#12…",this::load));
        keys.add(button("Export signing certificate…",()->export(true))); keys.add(button("Export encryption certificate…",()->export(false))); p.add(keys);
        p.add(section("2  Recipient encryption certificate",recipientLabel));
        p.add(left(button("Import recipient certificate…", () -> importCert(false))));
        p.add(section("3  Pinned signer for verification",pinLabel));
        p.add(left(button("Pin signer certificate…", () -> importCert(true))));
        JPanel settings=new JPanel(new FlowLayout(FlowLayout.LEFT));
        settings.add(button("YubiKey configuration…",this::configureYubiKey));
        settings.add(button("Update token certificate email…",this::reissueTokenCertificates));
        settings.add(button("Show saved identity files",()->{try{Desktop.getDesktop().open(state().directory().toFile());}catch(Exception e){error(e);}}));p.add(settings);
        p.add(section("4  Token signing",tokenLabel));
        JPanel token = new JPanel(new FlowLayout(FlowLayout.LEFT)); token.add(button("Choose adapter executable…",()->{
            Path path=choose(false,"Choose trusted external-mu adapter executable"); if(path==null)return;
            if(!Files.isExecutable(path)){error(new IOException("Select an executable adapter"));return;}
            adapter=path.toAbsolutePath().toString(); saveAdapter(false,adapter); tokenLabel.setText("External adapter: " + path.getFileName() + " (hardware not detected)");
        })); token.add(button("Use software signer",()->{adapter=null;saveAdapter(false,"software");tokenLabel.setText("Signing: software");})); p.add(token);
        p.add(new JLabel("YubiKey settings and identities are saved on this Mac. PINs are not saved."));
        p.add(Box.createVerticalStrut(12));
        p.add(new JLabel("PKCS#11: PIN dialog in app. ykman: launch from Terminal for PIN prompts."));
        p.add(section("5  Token decryption",kemLabel));
        JPanel kem=new JPanel(new FlowLayout(FlowLayout.LEFT));
        kem.add(button("Choose PKCS#11 KEM adapter…",()->{
            Path path=choose(false,"Choose trusted PKCS#11 KEM adapter executable");if(path==null)return;
            if(!Files.isExecutable(path)){error(new IOException("Select an executable adapter"));return;}
            kemAdapter=path.toAbsolutePath().toString();saveAdapter(true,kemAdapter);kemLabel.setText("Token decryption: "+path.getFileName());
        }));
        kem.add(button("Use software decryption",()->{kemAdapter=null;saveAdapter(true,"software");kemLabel.setText("Decryption: software");}));p.add(kem);
        p.add(new JLabel("ML-KEM and hybrid decryption use the token; one PIN prompt per message."));
        p.add(Box.createVerticalStrut(24));
        p.add(new JLabel("Generated identities are local test identities. Exchange certificate fingerprints out of band."));
        p.add(new JLabel("Private keys stay local. Account passwords are not saved by this app."));
        return outer;
    }
    private DesktopState state()throws Exception{
        if(desktopState==null){desktopState=DesktopState.open();desktopState.activate();}return desktopState;
    }
    private void updateBackendLabels(){
        tokenLabel.setText(adapter==null?"Signing: software":"Token signing · app PIN dialog");
        kemLabel.setText(kemAdapter==null?"Decryption: software":"Token decryption · app PIN dialog");
    }
    private void saveAdapter(boolean kem,String value){
        try{state().set(kem?"decrypt.adapter":"sign.adapter",value);state().save();}catch(Exception e){error(e);}
    }
    private void refreshSaved(){
        syncingOutgoing=true;
        try{savedIdentities.removeAllItems();outgoingIdentity.removeAllItems();if(desktopState==null)return;
            String selected=desktopState.get("selected.identity","");
            for(var saved:desktopState.identities()){savedIdentities.addItem(saved);outgoingIdentity.addItem(saved);if(saved.id().equals(selected)){savedIdentities.setSelectedItem(saved);outgoingIdentity.setSelectedItem(saved);}}
        }finally{syncingOutgoing=false;}
    }
    private static String certificateEmail(X509Certificate certificate)throws Exception{
        var names=certificate.getSubjectAlternativeNames();if(names!=null)for(var name:names)if(Integer.valueOf(1).equals(name.get(0)))return name.get(1).toString();return "(no email SAN)";
    }
    private void refreshOutgoingEncryption()throws Exception{
        syncingOutgoing=true;
        try{
            outgoingEncryption.removeAllItems();boolean selected=false;
            for(var contact:state().contacts())if(contact.role().equals("encryption")){
                var certificate=state().contactCertificate(contact);var choice=new EncryptionChoice(contact.email(),certificate);outgoingEncryption.addItem(choice);
                if(certificate.equals(recipient)){outgoingEncryption.setSelectedItem(choice);selected=true;}
            }
            if(recipient!=null&&!selected){var choice=new EncryptionChoice(certificateEmail(recipient),recipient);outgoingEncryption.addItem(choice);outgoingEncryption.setSelectedItem(choice);}
            else if(recipient==null)outgoingEncryption.setSelectedIndex(-1);
            outgoingEncryption.setEnabled(encrypt.isSelected());
        }finally{syncingOutgoing=false;}
    }
    private void rememberIdentity(Identity id,Path original,String name){
        try{state().remember(id,name,original);setIdentity(id);refreshSaved();status.setText("Identity saved on this Mac.");}catch(Exception e){error(e);}
    }
    private void openSaved(DesktopState.SavedIdentity saved){
        if(saved==null)return;
        char[] password=new char[0];
        if(saved.passwordRequired()){
            JPasswordField field=new JPasswordField();
            if(JOptionPane.showConfirmDialog(this,field,"Saved identity password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){field.setText("");refreshSaved();return;}
            password=field.getPassword();field.setText("");
        }
        char[] secret=password;
        job("Opening saved identity…",()->{try{return state().loadIdentity(saved.id(),secret);}catch(Exception e){SwingUtilities.invokeLater(this::refreshSaved);throw e;}finally{Arrays.fill(secret,'\0');}},id->{
            setIdentity(id);try{state().set("selected.identity",saved.id());state().save();refreshSaved();if(!Identity.matchesEmail(id.signingCert(),from.getText().trim()))from.setText(certificateEmail(id.signingCert()));}catch(Exception e){error(e);}
            status.setText("Saved identity ready. PIN requested only for token operations.");
        });
    }
    private void restoreDesktop(){
        try{
            state();desktopState.migrateTrust();refreshSaved();refreshContacts();adapter=desktopState.adapter(false);kemAdapter=desktopState.adapter(true);updateBackendLabels();
            recipient=desktopState.certificate("recipient");pinnedSigner=desktopState.certificate("pinned");refreshOutgoingEncryption();
            if(recipient!=null)recipientLabel.setText(recipient.getPublicKey().getAlgorithm()+" · "+recipient.getSubjectX500Principal());
            if(pinnedSigner!=null)pinLabel.setText(pinnedSigner.getSubjectX500Principal().toString());
            from.setText(desktopState.get("mail.from",from.getText()));to.setText(desktopState.get("mail.to",to.getText()));
            if(savedIdentities.getSelectedItem()!=null)openSaved((DesktopState.SavedIdentity)savedIdentities.getSelectedItem());
            else status.setText("Configure your YubiKey and import an identity to begin.");
        }catch(Exception e){error(e);}
    }
    private void configureYubiKey(){
        try{
            DesktopState settings=state();JTextField serial=new JTextField(settings.get("token.serial",""));
            JComboBox<String> rsa=new JComboBox<>(new String[]{"9a","9d","82","83","84","85"});rsa.setSelectedItem(settings.get("token.rsaSlot","9a"));
            JComboBox<String> kem=new JComboBox<>(new String[]{"9d","82","83","84","85"});kem.setSelectedItem(settings.get("token.kemSlot","9d"));
            JComboBox<String> ecdh=new JComboBox<>(new String[]{"82","83","84","85","9d"});ecdh.setSelectedItem(settings.get("token.ecdhSlot","82"));
            JPanel basic=new JPanel(new GridLayout(0,1,0,8));basic.add(row("Serial",serial));
            basic.add(new JLabel("ML-DSA signing key: slot 9c"));basic.add(row("RSA slot",rsa));basic.add(row("ML-KEM slot",kem));basic.add(row("ECDH slot",ecdh));
            basic.add(new JLabel("Uses existing keys. Saving settings never generates or replaces keys."));
            JPanel advanced=new JPanel(new GridLayout(0,1,0,8));advanced.add(new JLabel("Leave crypto paths blank to use the app's bundled libraries."));
            String[] names={"openssl.path","provider.path","module.path","python.path"};String[] labels={"OpenSSL","Provider","Module","Python 3"};
            JTextField[] paths=new JTextField[4];for(int i=0;i<4;i++){paths[i]=new JTextField(settings.get(names[i],i==3?"/usr/bin/python3":""),38);advanced.add(row(labels[i],paths[i]));}
            JTabbedPane panes=new JTabbedPane();panes.addTab("YubiKey",basic);panes.addTab("Advanced",advanced);
            if(JOptionPane.showConfirmDialog(this,panes,"Saved YubiKey configuration",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)!=JOptionPane.OK_OPTION)return;
            if(!serial.getText().trim().matches("[0-9]+"))throw new IOException("Enter the YubiKey's numeric serial number");
            var slots=new java.util.HashSet<>(java.util.List.of("9c",rsa.getSelectedItem().toString(),kem.getSelectedItem().toString(),ecdh.getSelectedItem().toString()));
            if(slots.size()!=4)throw new IOException("Choose separate signing and encryption slots");
            for(int i=0;i<4;i++){String value=paths[i].getText().trim();if(!value.isEmpty()&&(!Path.of(value).isAbsolute()||!Files.isRegularFile(Path.of(value))))throw new IOException("Invalid "+labels[i]+" path");}
            settings.set("token.serial",serial.getText().trim());settings.set("token.rsaSlot",rsa.getSelectedItem().toString());settings.set("token.kemSlot",kem.getSelectedItem().toString());settings.set("token.ecdhSlot",ecdh.getSelectedItem().toString());
            for(int i=0;i<4;i++)settings.set(names[i],paths[i].getText().isBlank()?null:paths[i].getText().trim());
            settings.set("sign.adapter","pkcs11");settings.set("decrypt.adapter","pkcs11");settings.save();settings.activate();
            adapter=settings.adapter(false);kemAdapter=settings.adapter(true);updateBackendLabels();status.setText("YubiKey configuration saved. PINs remain temporary.");
        }catch(Exception e){error(e);}
    }
    private void reissueTokenCertificates(){
        try{
            DesktopState settings=state();JTextField email=new JTextField(settings.get("google.email",from.getText()),30);
            JPanel prompt=new JPanel(new GridLayout(0,1,0,8));prompt.add(new JLabel("New email for your saved token certificate profiles"));prompt.add(email);
            prompt.add(new JLabel("Reuses existing keys and preserves old identities. Two PIN prompts per profile."));
            if(JOptionPane.showConfirmDialog(this,prompt,"Update local test certificates",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();new jakarta.mail.internet.InternetAddress(address,true).validate();
            String executable=settings.adapter(false);if(executable==null)throw new IOException("Configure a token signing adapter first");
            var profiles=new java.util.LinkedHashMap<String,Identity>();
            for(var saved:settings.identities())if(!saved.passwordRequired()){Identity old=settings.loadIdentity(saved.id(),null);profiles.put(old.signatureAlgorithm(),old);}
            if(profiles.isEmpty())throw new IOException("Import a certificate-only token identity first");
            job("Signing new certificates with existing token keys…",()->{
                var updated=new java.util.ArrayList<Identity>();
                for(Identity old:profiles.values()){
                    Identity renewed=old.reissue(address,ExternalMu.executable(executable));
                    settings.remember(renewed,address+" · "+renewed.signatureAlgorithm(),null);updated.add(renewed);
                }
                return updated.getLast();
            },renewed->{
                setIdentity(renewed);refreshSaved();from.setText(address);to.setText(address);recipient=renewed.encryptionCert();pinnedSigner=renewed.signingCert();
                try{settings.set("mail.from",address);settings.set("mail.to",address);settings.saveCertificate("pinned",pinnedSigner);if(recipient!=null)settings.saveCertificate("recipient",recipient);settings.save();}catch(Exception e){error(e);}
                pinLabel.setText(pinnedSigner.getSubjectX500Principal().toString());if(recipient!=null)recipientLabel.setText(recipient.getPublicKey().getAlgorithm()+" · "+recipient.getSubjectX500Principal());
                try{refreshOutgoingEncryption();}catch(Exception e){error(e);}
                status.setText("New email certificates saved (DER and PEM). Token keys unchanged. No email sent.");
            });
        }catch(Exception e){error(e);}
    }
    private void generate() {
        JTextField email=new JTextField(from.getText()); JComboBox<String> mode=new JComboBox<>(new String[]{"Pure: ML-DSA-65 + ML-KEM-768","Hybrid: ML-DSA-65/ECDSA + ML-KEM-768/ECDH"});
        mode.setSelectedIndex(1); JPasswordField pass=new JPasswordField();
        JPanel p=new JPanel(new GridLayout(0,1,0,8)); p.add(new JLabel("Email address"));p.add(email);p.add(mode);p.add(new JLabel("New PKCS#12 password (12+ characters)"));p.add(pass);
        if(JOptionPane.showConfirmDialog(this,p,"Create local test identity",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        Path file=choose(true,"Save new identity (choose a new .p12 filename)");if(file==null)return;
        char[] password=pass.getPassword();String address=email.getText().trim();boolean hybrid=mode.getSelectedIndex()==1;
        job("Generating identity…",()->{try {Identity id=Identity.generate(address,hybrid);id.save(file,password);return id;}finally{Arrays.fill(password,'\0');}},id->{setIdentity(id);from.setText(address);rememberIdentity(id,file,address);});
    }
    private void load() {
        Path file=choose(false,"Load identity .p12");if(file==null)return;
        JPasswordField pass=new JPasswordField();if(JOptionPane.showConfirmDialog(this,pass,"Identity password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        char[] password=pass.getPassword();job("Loading identity…",()->{try{return Identity.load(file,password);}finally{Arrays.fill(password,'\0');}},id->{setIdentity(id);rememberIdentity(id,file,file.getFileName().toString());});
    }
    private void setIdentity(Identity id) {identity=id;
        if(desktopState!=null){adapter=id.signingKey()==null?desktopState.adapter(false):null;kemAdapter=id.encryptionKey()==null&&id.encryptionCert()!=null?desktopState.adapter(true):null;updateBackendLabels();}
        identityLabel.setText(id.signatureAlgorithm()+" · "+id.signingCert().getSubjectX500Principal());status.setText("Identity ready. Import a recipient certificate to encrypt.");}
    private void export(boolean signing) {
        if(identity==null){error(new IOException("Load an identity first"));return;}
        X509Certificate c=signing?identity.signingCert():identity.encryptionCert();if(c==null){error(new IOException("No certificate available"));return;}
        Path file=choose(true,"Export public certificate (.pem or .cer)");if(file==null)return;
        job("Exporting certificate…",()->{Files.write(file,file.getFileName().toString().toLowerCase().endsWith(".pem")?DesktopState.pem(c):c.getEncoded(),StandardOpenOption.CREATE_NEW);return "Certificate exported";},status::setText);
    }
    private void importCert(boolean pin){
        Path file=choose(false,pin?"Import signing certificate (.pem or .cer)":"Import encryption certificate (.pem or .cer)");if(file==null)return;
        job("Reading certificate…",()->Identity.readCertificate(file),certificate->{
            try{
                var emails=new java.util.ArrayList<String>();var sans=certificate.getSubjectAlternativeNames();
                if(sans!=null)for(var san:sans)if(Integer.valueOf(1).equals(san.get(0)))emails.add(san.get(1).toString());
                if(emails.isEmpty())throw new IOException("Certificate has no email Subject Alternative Name");
                String email=emails.size()==1?emails.getFirst():(String)JOptionPane.showInputDialog(this,"Choose the contact mailbox","Certificate email",JOptionPane.PLAIN_MESSAGE,null,emails.toArray(),emails.getFirst());if(email==null)return;
                JTextArea detail=new JTextArea("Email: "+email+"\nPurpose: "+(pin?"signature verification":"encryption")+"\nSubject: "+certificate.getSubjectX500Principal()+"\nAlgorithm: "+certificate.getPublicKey().getAlgorithm()+"\nValid until: "+certificate.getNotAfter()+"\n\nSHA-256 fingerprint:\n"+Identity.fingerprint(certificate)+"\n\nConfirm this fingerprint with the owner before trusting it.",10,65);detail.setEditable(false);detail.setLineWrap(true);detail.setWrapStyleWord(true);
                if(JOptionPane.showConfirmDialog(this,new JScrollPane(detail),"Save certificate (trust can be marked separately)?",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
                var contact=state().rememberContact(certificate,email,pin?"signing":"encryption");refreshContacts();applyContact(contact,certificate);
            }catch(Exception e){error(e);}
        });
    }
    private void compose(boolean send) {
        if(identity==null){error(new IOException("Create or load an identity first"));tabs.setSelectedIndex(2);return;}
        if(encrypt.isSelected()&&recipient==null){error(new IOException("Import recipient encryption certificate first"));tabs.setSelectedIndex(2);return;}
        try{
            if(!Identity.matchesEmail(identity.signingCert(),from.getText().trim()))throw new IOException("From address does not match your signing certificate");
            if(encrypt.isSelected()&&!Identity.matchesEmail(recipient,to.getText().trim())){tabs.setSelectedIndex(4);throw new IOException("Choose an encryption certificate matching the To address, or turn off optional encryption to send signed-only mail");}
        }catch(Exception e){error(e);return;}
        Path file=send?null:choose(true,"Save signed S/MIME message (.eml)");if(!send&&file==null)return;
        Account a=send?account(true):null;if(send&&a==null)return;
        Identity id=identity; X509Certificate r=encrypt.isSelected()?recipient:null; ExternalMu.Backend backend=adapter==null?null:ExternalMu.executable(adapter);
        String f=from.getText().trim(),t=to.getText().trim(),s=subject.getText(),b=body.getText();
        try{state().set("mail.from",f);state().set("mail.to",t);state().save();}catch(Exception e){error(e);return;}
        if(send&&JOptionPane.showConfirmDialog(this,"Send this "+(r!=null?"signed and encrypted":"signed, unencrypted")+" message to "+t+"?","Send message",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){Arrays.fill(a.password,'\0');return;}
        job(send?"Signing and sending…":"Signing and saving…",()->{
            try {
                MimeMessage m=MailEngine.compose(id,f,t,s,b,r,backend);
                if(send)MailEngine.send(m,a.host,a.port,a.user,new String(a.password),a.oauth);
                else Files.write(file,MailEngine.encode(m),StandardOpenOption.CREATE_NEW);
                return send?"Message sent":"Saved "+file.getFileName();
            } finally {if(a!=null)Arrays.fill(a.password,'\0');}
        },status::setText);
    }
    private ReadResult display(MimeMessage message,Identity id,X509Certificate pin)throws Exception {
        if(MailPreview.isOrdinary(message))return new ReadResult(MailPreview.display(message),null,message.getSubject());
        var opened=MailEngine.open(message,id,pin,kemAdapter==null?null:ExternalKem.executable(kemAdapter));
        return new ReadResult(null,opened,message.getSubject());
    }
    private String formatRead(ReadResult result)throws Exception{
        if(result.verified()==null)return result.plain();var o=result.verified();
        boolean trusted=state().isTrusted(o.signerCertificate(),"signing");
        return "SIGNATURE VALID · "+o.signatureAlgorithm()+"\n"+(o.encrypted()?"AES-256-GCM authenticated decryption succeeded":"Not encrypted")+"\n"+
            (trusted?"SIGNER TRUSTED: SHA-256 certificate fingerprint matches your saved trust":"SIGNER NOT TRUSTED: fingerprint has not been marked trusted")+"\n"+
            (o.fromMatches()?"Outer From matches certificate email (header itself is unsigned)":"WARNING: outer From does not match signing certificate")+
            "\nSHA-256: "+o.fingerprint()+"\n\nOuter subject (unprotected): "+result.subject()+"\n\n──────── Signed body ────────\n\n"+o.text();
    }
    private void clearReadTrust(){currentRead=null;trustIncoming.setEnabled(false);}
    private void showMessage(ReadResult result){
        try{showMessage(formatRead(result));currentRead=result;trustIncoming.setEnabled(result.verified()!=null);}catch(Exception e){clearReadTrust();error(e);}
    }
    private void showMessage(String text){clearReadTrust();reader.setText(text);reader.setCaretPosition(0);tabs.setSelectedIndex(1);status.setText("Message opened. Review the security status above.");}
    private void refreshReadTrust(){if(currentRead!=null)try{reader.setText(formatRead(currentRead));reader.setCaretPosition(0);}catch(Exception e){error(e);}}
    private boolean confirmTrust(X509Certificate certificate,String role,String warning)throws Exception{
        JTextArea detail=new JTextArea("Trust this exact "+role+" certificate fingerprint?\n\nSubject: "+certificate.getSubjectX500Principal()+"\nEmail SANs: "+certificate.getSubjectAlternativeNames()+"\nAlgorithm: "+certificate.getPublicKey().getAlgorithm()+"\n\nSHA-256:\n"+Identity.fingerprint(certificate)+"\n\n"+warning+"\nCompare the fingerprint with the owner through a trusted channel before accepting. Trust is not a CA-chain validation.",12,65);detail.setEditable(false);detail.setLineWrap(true);detail.setWrapStyleWord(true);
        return JOptionPane.showConfirmDialog(this,new JScrollPane(detail),"Mark certificate trusted",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)==JOptionPane.OK_OPTION;
    }
    private void setContactTrust(boolean trusted){
        var contact=selectedContact();if(contact==null)return;
        try{var certificate=state().contactCertificate(contact);if(trusted&&!confirmTrust(certificate,contact.role(),"This trust decision is saved on this Mac."))return;
            state().setTrusted(certificate,contact.role(),trusted);refreshContacts();refreshReadTrust();status.setText(trusted?"Certificate fingerprint marked trusted":"Certificate trust removed");
        }catch(Exception e){error(e);}
    }
    private void trustIncomingSigner(){
        if(currentRead==null||currentRead.verified()==null)return;
        try{var verified=currentRead.verified();var certificate=verified.signerCertificate();
            if(!confirmTrust(certificate,"signing",verified.fromMatches()?"The signature is valid. This does not by itself prove the sender's identity.":"WARNING: the outer From address does not match this certificate. Trust applies to the certificate SANs, not the outer From."))return;
            var names=certificate.getSubjectAlternativeNames();if(names==null)throw new IOException("Signer has no email SAN");
            boolean saved=false;for(var name:names)if(Integer.valueOf(1).equals(name.get(0))){state().rememberContact(certificate,name.get(1).toString(),"signing");saved=true;}
            if(!saved)throw new IOException("Signer has no email SAN");
            state().setTrusted(certificate,"signing",true);refreshContacts();refreshReadTrust();status.setText("Incoming signer's SHA-256 certificate fingerprint saved as trusted");
        }catch(Exception e){error(e);}
    }
    private record Account(String host,int port,String user,char[] password,boolean oauth){}
    private Account account(boolean smtp){
        if(smtp){Object[] choices={"Google OAuth","Server password","Cancel"};int choice=JOptionPane.showOptionDialog(this,"Choose how to authenticate for sending","SMTP authentication",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,choices,choices[0]);if(choice==0)return googleAccount(true);if(choice!=1)return null;}
        String prefix=smtp?"smtp.":"imap.";
        DesktopState settings;try{settings=state();}catch(Exception e){error(e);return null;}
        JTextField host=new JTextField(settings.get(prefix+"host","")),port=new JTextField(settings.get(prefix+"port",smtp?"587":"993")),user=new JTextField(settings.get(prefix+"user",from.getText()));JPasswordField pass=new JPasswordField();
        JPanel p=new JPanel(new GridLayout(0,1,0,6));p.add(new JLabel(smtp?"SMTP with required STARTTLS":"IMAP over TLS"));p.add(row("Host",host));p.add(row("Port",port));p.add(row("User",user));p.add(row("Password",pass));
        if(JOptionPane.showConfirmDialog(this,p,smtp?"SMTP account":"IMAP account",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return null;
        try {int n=Integer.parseInt(port.getText());if(n<1||n>65535||host.getText().isBlank())throw new IllegalArgumentException("Invalid host or port");settings.set(prefix+"host",host.getText().trim());settings.set(prefix+"port",Integer.toString(n));settings.set(prefix+"user",user.getText().trim());settings.save();char[] credential=pass.getPassword();pass.setText("");return new Account(host.getText().trim(),n,user.getText().trim(),credential,false);}catch(Exception e){error(e);return null;}
    }
    private <T> void job(String label,Callable<T> task,java.util.function.Consumer<T> success){
        status.setText(label);setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));setEnabled(false);
        new SwingWorker<T,Void>(){protected T doInBackground()throws Exception{return task.call();}protected void done(){setEnabled(true);setCursor(Cursor.getDefaultCursor());try{T result=get();status.setText("Ready");success.accept(result);}catch(Exception e){error(e.getCause()==null?e:e.getCause());}}}.execute();
    }
    private void error(Throwable e){String message=e.getMessage();status.setText("Operation failed");JOptionPane.showMessageDialog(this,message==null?e.getClass().getSimpleName():message,"Hybrid Mail",JOptionPane.ERROR_MESSAGE);}
    private Path choose(boolean save,String title){JFileChooser c=new JFileChooser();c.setDialogTitle(title);return (save?c.showSaveDialog(this):c.showOpenDialog(this))==JFileChooser.APPROVE_OPTION?c.getSelectedFile().toPath():null;}
    private static JPanel panel(){JPanel p=new JPanel(new BorderLayout(12,12));p.setBorder(new EmptyBorder(16,8,8,8));return p;}
    private static JPanel row(String name,JComponent field){JPanel p=new JPanel(new BorderLayout(8,0));JLabel l=new JLabel(name);l.setPreferredSize(new Dimension(80,24));p.add(l,BorderLayout.WEST);p.add(field);return p;}
    private static JPanel left(JComponent c){JPanel p=new JPanel(new FlowLayout(FlowLayout.LEFT));p.add(c);return p;}
    private static JPanel section(String name,JLabel detail){JPanel p=new JPanel(new GridLayout(0,1,0,6));p.setBorder(new EmptyBorder(20,6,4,0));JLabel h=new JLabel(name);h.setFont(h.getFont().deriveFont(Font.BOLD,16f));p.add(h);p.add(detail);return p;}
    private static JButton button(String label,Runnable action){JButton b=new JButton(label);b.addActionListener(e->action.run());return b;}
    public static void openTokenSession(Identity id, String executable, MimeMessage verifiedMail) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                MailApp app = new MailApp();
                app.setIdentity(id); app.adapter = executable;
                app.tokenLabel.setText((executable.contains("pkcs11") ? "PKCS#11" : "ykman") + " adapter · " + (executable.contains("pkcs11") ? "PIN dialog + touch" : "PIN/touch in Terminal"));
                app.pinnedSigner = id.signingCert(); app.pinLabel.setText("Pinned local Beta0 test signing certificate");
                app.from.setText("beta0@example.test"); app.to.setText("recipient@example.test"); app.encrypt.setSelected(false);
                app.showMessage(app.display(verifiedMail, id, id.signingCert()));
                app.setVisible(true);
            } catch (Exception error) { throw new RuntimeException(error); }
        });
    }
    public static void openKemSession(Identity id,String signAdapter,String decryptAdapter,MimeMessage mail,MailEngine.Opened checked){
        SwingUtilities.invokeLater(()->{
            try{
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                MailApp app=new MailApp();app.setIdentity(id);app.adapter=signAdapter;app.kemAdapter=decryptAdapter;
                app.tokenLabel.setText("PKCS#11 signing · PIN dialog");app.kemLabel.setText("PKCS#11 ML-KEM + ECDH decryption · one PIN per message");
                app.recipient=id.encryptionCert();app.recipientLabel.setText(id.encryptionCert().getPublicKey().getAlgorithm());
                app.pinnedSigner=id.signingCert();app.pinLabel.setText("Pinned local test signer");
                app.from.setText("beta0@example.test");app.to.setText("beta0@example.test");app.encrypt.setSelected(true);
                app.showMessage("SIGNATURE VALID · "+checked.signatureAlgorithm()+"\nToken-backed authenticated decryption succeeded\n\n"+checked.text());
                app.setVisible(true);
            }catch(Exception e){throw new RuntimeException(e);}
        });
    }
    public static void main(String[]args){MailEngine.init();SwingUtilities.invokeLater(()->{try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ignored){}MailApp app=new MailApp();app.setVisible(true);app.restoreDesktop();});}
}
