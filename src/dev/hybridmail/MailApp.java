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
    private final DefaultListModel<Path> attachmentModel=new DefaultListModel<>();
    private final JList<Path> attachmentList=new JList<>(attachmentModel);
    private final JButton saveAttachment=new JButton("Save attachment…");
    private record ReadResult(String plain,MailEngine.Opened verified,String subject){}
    private Identity identity;
    private final JComboBox<String> mailFormat=new JComboBox<>(new String[]{"S/MIME","OpenPGP (Level 3 hybrid draft)"});
    private OpenPgp.PublicIdentity pgpRecipient,pgpSigner;
    private final JTextArea pgpStatus=new JTextArea("Select a Level 3 hybrid identity. OpenPGP uses separate public identities and fingerprints; private keys stay in the existing software bundle or YubiKey.");
    private boolean usePgp(){return mailFormat.getSelectedIndex()==1;}
    private MailInbox inbox;
    private final JCheckBox smimeInboxOnly=new JCheckBox("S/MIME only");
    private final JButton newerMail=new JButton("Newer"),olderMail=new JButton("Older");
    private GoogleOAuth.Token googleToken;
    private String googleEmail;
    private java.util.List<ImapInbox.Entry> inboxEntries=java.util.List.of();
    private final javax.swing.table.DefaultTableModel inboxModel=new javax.swing.table.DefaultTableModel(new String[]{"From","Subject","Received"},0){public boolean isCellEditable(int row,int column){return false;}};
    private final JTable inboxTable=new JTable(inboxModel);
    private final JLabel inboxLabel=new JLabel("Not connected · shows the 10 most recent arrivals");
    private final JLabel googleLabel=new JLabel("Google: signed out");
    private DesktopState desktopState;
    private final JComboBox<DesktopState.SavedIdentity> savedIdentities=new JComboBox<>();
    private final JComboBox<DesktopState.SavedIdentity> softwareIdentities=new JComboBox<>(),yubikeyIdentities=new JComboBox<>();
    private X509Certificate recipient, pinnedSigner;
    private String adapter,kemAdapter;
    private final JTextField from = new JTextField("alice@example.test"), to = new JTextField("bob@example.test"), subject = new JTextField("A private conversation");
    private final JTextArea body = new JTextArea("Hello,\n\nThis message is signed using post-quantum cryptography.\n"), reader = new JTextArea();
    private final JCheckBox encrypt = new JCheckBox("Also encrypt for recipient (optional)", false);
    private final JLabel identityLabel = new JLabel("No identity loaded"), recipientLabel = new JLabel("No recipient certificate");
    private final JLabel status = new JLabel("Create or load an identity to begin. No network connection is made on startup.");
    private final JTabbedPane tabs = new JTabbedPane();
    public MailApp() {
        super("PQ Mail · S/MIME & OpenPGP lab");
        setDefaultCloseOperation(EXIT_ON_CLOSE); setSize(1060, 800); setMinimumSize(new Dimension(850,650)); setLocationRelativeTo(null);
        JPanel root = new JPanel(new BorderLayout(0,18)); root.setBorder(new EmptyBorder(22,28,18,28)); setContentPane(root);
        JPanel heading = new JPanel(new BorderLayout()); JLabel title = new JLabel("PQ Mail"); title.setFont(title.getFont().deriveFont(Font.BOLD, 30f));
        heading.add(title, BorderLayout.NORTH); heading.add(new JLabel("S/MIME & Level 3 hybrid OpenPGP  /  local development build"), BorderLayout.SOUTH); root.add(heading,BorderLayout.NORTH);
        tabs.addTab("Compose", composePanel()); tabs.addTab("Read & verify", readPanel()); tabs.addTab("Keys", keysPanel()); tabs.addTab("Inbox",inboxPanel()); tabs.addTab("Certificates",certificatesPanel()); tabs.addTab("OpenPGP",openPgpPanel()); root.add(tabs);
        status.setBorder(new EmptyBorder(10,0,0,0)); root.add(status, BorderLayout.SOUTH);
        body.setLineWrap(true); body.setWrapStyleWord(true); body.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,16)); body.setMargin(new Insets(16,16,16,16));
        reader.setEditable(false); reader.setLineWrap(true); reader.setWrapStyleWord(true); reader.setFont(new Font(Font.MONOSPACED,Font.PLAIN,13)); reader.setMargin(new Insets(16,16,16,16));
    }
    private JPanel composePanel() {
        JPanel p = panel(); JPanel fields = new JPanel(new GridLayout(0,1,0,8));
        fields.add(row("From",from)); fields.add(row("To",to)); fields.add(row("Subject",subject));
        fields.add(row("Message format",mailFormat));fields.add(row("Sign with",outgoingIdentity));fields.add(encrypt);fields.add(row("Encrypt to",outgoingEncryption));
        outgoingIdentity.addActionListener(e->{if(!syncingOutgoing){var chosen=(DesktopState.SavedIdentity)outgoingIdentity.getSelectedItem();if(chosen!=null)openSaved(chosen);}});
        outgoingEncryption.setEnabled(encrypt.isSelected());encrypt.addActionListener(e->outgoingEncryption.setEnabled(encrypt.isSelected()));
        outgoingEncryption.addActionListener(e->{if(!syncingOutgoing){var chosen=(EncryptionChoice)outgoingEncryption.getSelectedItem();if(chosen!=null){recipient=chosen.certificate();to.setText(chosen.email());recipientLabel.setText(chosen.email()+" · "+recipient.getPublicKey().getAlgorithm());try{state().saveCertificate("recipient",recipient);}catch(Exception error){error(error);}}}}); fields.add(new JLabel("All outgoing messages are signed. OpenPGP uses its own recipient public key from the OpenPGP tab; attachments currently require S/MIME.")); p.add(fields,BorderLayout.NORTH);
        JPanel content=new JPanel(new BorderLayout(0,6));content.add(new JScrollPane(body));
        JPanel attachments=new JPanel(new BorderLayout());attachmentList.setVisibleRowCount(2);
        attachments.add(new JScrollPane(attachmentList));JPanel fileActions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileActions.add(button("Add attachments…",()->{JFileChooser c=new JFileChooser();c.setMultiSelectionEnabled(true);if(c.showOpenDialog(this)==JFileChooser.APPROVE_OPTION){for(File file:c.getSelectedFiles()){if(attachmentModel.size()>=20){error(new IOException("At most 20 attachments"));break;}attachmentModel.addElement(file.toPath());}}}));
        fileActions.add(button("Remove selected",()->{for(Path file:attachmentList.getSelectedValuesList())attachmentModel.removeElement(file);}));
        attachments.add(fileActions,BorderLayout.NORTH);content.add(attachments,BorderLayout.SOUTH);p.add(content);
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(new JLabel("Body and attachments are signed; enable encryption to protect both. Outer From / To / Subject headers are unprotected."),BorderLayout.NORTH);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(button("Recipient certificates…",()->tabs.setSelectedIndex(4))); actions.add(button("Save signed .eml…", () -> compose(false))); actions.add(button("Send…", () -> compose(true)));
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
        trustIncoming.setEnabled(false);trustIncoming.addActionListener(e->trustIncomingSigner());actions.add(trustIncoming);actions.add(button("Trust signer for encryption…",this::trustIncomingEncryption));
        saveAttachment.setEnabled(false);saveAttachment.addActionListener(e->saveReadAttachment());actions.add(saveAttachment);
        p.add(actions,BorderLayout.NORTH); return p;
    }
    private JPanel openPgpPanel(){
        JPanel p=panel();pgpStatus.setEditable(false);pgpStatus.setLineWrap(true);pgpStatus.setWrapStyleWord(true);p.add(new JScrollPane(pgpStatus));
        JPanel actions=new JPanel(new GridLayout(0,2,8,8));
        actions.add(button("Create OpenPGP public identity",()->{
            Identity id=identity;String path=adapter;
            job("Creating OpenPGP bindings (one PIN operation; three hybrid signatures)…",()->OpenPgp.createOwn(state().directory(),id,path==null?null:ExternalMu.executable(path)).description(),pgpStatus::setText);
        }));
        actions.add(button("Import my OpenPGP public identity…",()->{
            Path file=choose(false,"Import my OpenPGP public identity");if(file==null)return;Identity id=identity;
            job("Checking public key bindings…",()->OpenPgp.saveOwn(state().directory(),id,readPgp(file)).description(),pgpStatus::setText);
        }));
        actions.add(button("Export my OpenPGP public key…",()->{
            Path file=chooseSave("Export public OpenPGP key","PQ-Mail-public.asc","asc");if(file==null)return;Identity id=identity;
            job("Exporting public key…",()->{Files.write(file,OpenPgp.loadOwn(state().directory(),id).export(),StandardOpenOption.CREATE_NEW);return "Public key exported; no private keys or PINs included.";},pgpStatus::setText);
        }));
        actions.add(button("Use my OpenPGP key as recipient",()->{try{pgpRecipient=OpenPgp.loadOwn(state().directory(),identity);pgpStatus.setText(pgpRecipient.description());to.setText(pgpRecipient.email);}catch(Exception e){error(e);}}));
        actions.add(button("Import recipient OpenPGP public key…",()->importPgpContact(true)));
        actions.add(button("Import sender OpenPGP public key…",()->importPgpContact(false)));
        actions.add(button("Verify with my OpenPGP key",()->{pgpSigner=null;pgpStatus.setText("Incoming OpenPGP verification uses the selected identity's public key.");}));
        p.add(actions,BorderLayout.NORTH);p.add(new JLabel("<html>Draft-05 Level 3 only: ML-DSA-65 + P-384 / ML-KEM-768 + P-384.<br>Existing keys are reused; no YubiKey slots are changed. Import the same public identity on other devices to preserve fingerprints.<br>Self-signature verification does not establish trust. This preview supports plain-text PGP/MIME; use S/MIME for attachments.</html>"),BorderLayout.SOUTH);return p;
    }
    private byte[] readPgp(Path file)throws IOException{if(Files.size(file)>128*1024)throw new IOException("OpenPGP public key exceeds 128 KiB");return Files.readAllBytes(file);}
    private void importPgpContact(boolean recipientRole){
        Path file=choose(false,"Import "+(recipientRole?"recipient":"sender")+" OpenPGP public key");if(file==null)return;
        job("Verifying OpenPGP key bindings…",()->new OpenPgp.PublicIdentity(readPgp(file)),key->{
            try{if(JOptionPane.showConfirmDialog(this,key.description(),"Use this OpenPGP public key?",JOptionPane.OK_CANCEL_OPTION)==JOptionPane.OK_OPTION){if(recipientRole){pgpRecipient=key;to.setText(key.email);}else pgpSigner=key;pgpStatus.setText(key.description());}}catch(Exception e){error(e);}
        });
    }
    private void googleAdvancedSettings(){
        JDialog dialog=new JDialog(this,"Advanced settings — Google OAuth",true);
        JPanel settings=new JPanel(new BorderLayout(12,12));settings.setBorder(BorderFactory.createEmptyBorder(16,16,16,16));
        settings.add(new JLabel("<html>PQ Mail’s shared Google client is the default; no client registration is needed.<br>Custom clients are optional for developers and organizations.<br>Changing clients requires signing in again.</html>"),BorderLayout.NORTH);
        JPanel google=new JPanel(new GridLayout(0,1,0,8));
        google.add(button("Use PQ Mail Google client",()->{try{GoogleSession.saveClient(GoogleOAuth.bundledClient(),state());if(googleToken!=null){googleToken.close();googleToken=null;}googleLabel.setText("PQ Mail Google client · testing: registered testers only");status.setText("Choose Sign in with Google. Your previous custom registration is no longer selected.");}catch(Exception e){error(e);}}));
        google.add(button("Import Google OAuth client…",this::importGoogleClient));
        google.add(button("Enter Google client credentials…",this::enterGoogleClient));
google.add(button("Test "+credentialStore()+"",()->job("Testing "+credentialStore()+" with disposable data…",()->{String value=java.util.UUID.randomUUID().toString();try{MacKeychain.put("self-test",value);if(!value.equals(MacKeychain.get("self-test")))throw new IOException("Keychain round trip failed");}finally{MacKeychain.delete("self-test");}return true;},ok->status.setText("PASS "+credentialStore()+" write/read/delete; no Google credentials used"))));
        if(System.getProperty("os.name").startsWith("Mac")){
            JCheckBox authenticate=new JCheckBox("Protect Google OAuth refresh token with Touch ID or Mac password");
            try{authenticate.setSelected(Boolean.parseBoolean(state().get("google.authenticateRestore","false")));}catch(Exception e){error(e);}
            authenticate.addActionListener(e->{boolean enabled=authenticate.isSelected();authenticate.setEnabled(false);
                new SwingWorker<Boolean,Void>(){
                    protected Boolean doInBackground()throws Exception{MacKeychain.protectSession(enabled);return enabled;}
                    protected void done(){try{boolean value=get();MailApp.this.state().set("google.authenticateRestore",Boolean.toString(value));MailApp.this.state().save();status.setText("Google OAuth refresh token protection updated. Applies to the next session restore.");}catch(Exception failure){authenticate.setSelected(!enabled);error(failure);}finally{authenticate.setEnabled(true);}}
                }.execute();
            });
            authenticate.setEnabled(MacKeychain.protectedHelperAvailable());
            google.add(authenticate);
            google.add(new JLabel("<html>macOS chooses Touch ID or password. Applies to the next session restore.<br>Keychain requires authentication before releasing your Google OAuth refresh token.</html>"));
        }
        settings.add(google,BorderLayout.CENTER);
        settings.add(left(button("Close",dialog::dispose)),BorderLayout.SOUTH);
        dialog.setContentPane(settings);dialog.pack();dialog.setLocationRelativeTo(this);dialog.setVisible(true);
    }
    private JPanel inboxPanel(){
        JPanel p=panel();JPanel top=new JPanel(new GridLayout(0,1,0,6));
        top.add(inboxLabel);top.add(googleLabel);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Connect IMAP…",()->connectInbox(false)));
        actions.add(button("Connect Gmail",()->connectInbox(true)));
        actions.add(button("Refresh",this::refreshInbox));
        newerMail.setEnabled(false);olderMail.setEnabled(false);newerMail.addActionListener(e->gmailPage(false));olderMail.addActionListener(e->gmailPage(true));actions.add(newerMail);actions.add(olderMail);
        smimeInboxOnly.setEnabled(false);smimeInboxOnly.addActionListener(e->{if(inbox instanceof GmailApi api){api.setSmimeOnly(smimeInboxOnly.isSelected());refreshInbox();}});actions.add(smimeInboxOnly);
        actions.add(button("Disconnect",this::disconnectInbox));top.add(actions);
        JPanel google=new JPanel(new FlowLayout(FlowLayout.LEFT));
        google.add(button("Sign in with Google…",this::signInGoogle));
        google.add(button("Sign out of Google",this::signOutGoogle));
        google.add(button("Advanced settings…",this::googleAdvancedSettings));
        top.add(google);p.add(top,BorderLayout.NORTH);
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
            MailInbox next;
            if(gmail){var api=new GmailApi(this::googleCredential);api.verifyAccount(a.user);api.setSmimeOnly(smimeInboxOnly.isSelected());next=api;}else next=ImapInbox.connect(a.host,a.port,a.user,new String(a.password),false);
            try{var entries=next.latest();if(inbox!=null)try{inbox.close();}catch(Exception ignored){}inbox=next;return entries;}
            catch(Exception e){next.close();throw e;}
        }finally{Arrays.fill(a.password,'\0');}},entries->{showInbox(entries);inboxLabel.setText(a.user+" · "+(gmail?"Gmail API · 50 per page · no disk cache":"IMAP · 10 most recent")+" · read-only");tabs.setSelectedIndex(3);});
    }
    private void showInbox(java.util.List<ImapInbox.Entry> entries){
        inboxEntries=entries;inboxModel.setRowCount(0);
        var format=java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(java.time.ZoneId.systemDefault());
        for(var entry:entries)inboxModel.addRow(new Object[]{entry.sender(),entry.subject(),entry.received()==null?"":format.format(entry.received())});
        smimeInboxOnly.setEnabled(inbox instanceof GmailApi);
        newerMail.setEnabled(inbox instanceof GmailApi g&&g.hasNewer());olderMail.setEnabled(inbox instanceof GmailApi g&&g.hasOlder());
        status.setText(entries.isEmpty()?"No matching messages on this page; use Older if available":"Showing "+entries.size()+" messages, newest first"+(inbox instanceof GmailApi?" · use Older/Newer for the entire inbox":""));
    }
    private void gmailPage(boolean older){if(!(inbox instanceof GmailApi api))return;job("Loading Gmail headers…",()->older?api.older():api.newer(),this::showInbox);}
    private void refreshInbox(){if(inbox==null){error(new IOException("Connect to an inbox first"));return;}job("Refreshing inbox…",()->inbox.latest(),this::showInbox);}
    private void disconnectInbox(){
        MailInbox previous=inbox;inbox=null;smimeInboxOnly.setEnabled(false);newerMail.setEnabled(false);olderMail.setEnabled(false);inboxEntries=java.util.List.of();inboxModel.setRowCount(0);inboxLabel.setText("Not connected");
        if(previous!=null)job("Disconnecting…",()->{previous.close();return "Disconnected";},status::setText);
    }
    private void openInboxMessage(){
        int selected=inboxTable.getSelectedRow();if(selected<0||inbox==null)return;
        clearReadTrust();var entry=inboxEntries.get(inboxTable.convertRowIndexToModel(selected));MailInbox current=inbox;Identity id=identity;X509Certificate pin=pinnedSigner;
        job("Opening selected message…",()->display(current.message(entry.uid()),id,pin),this::showMessage);
    }
    private void importGoogleClient(){
        Path path=choose(false,"Import Google Desktop OAuth client JSON");if(path==null)return;
        try{GoogleOAuth.Client.read(path);GoogleSession.saveClient(GoogleOAuth.Client.read(path),state());Files.deleteIfExists(state().directory().resolve("google-client.json"));googleLabel.setText("Google client configured · sign in to connect");status.setText("Desktop OAuth client saved in "+credentialStore()+"; not uploaded");}catch(Exception e){error(e);}
    }
    private void enterGoogleClient(){
        JTextField clientId=new JTextField(42);JPasswordField secret=new JPasswordField(42);
        JPanel fields=new JPanel(new GridLayout(0,1,0,8));fields.add(new JLabel("Use the client ID and secret from a Google Desktop app OAuth client."));
        fields.add(row("Client ID",clientId));fields.add(row("Client secret",secret));
        fields.add(new JLabel("Custom client saved only in "+credentialStore()+"; not uploaded to GitHub."));
        if(JOptionPane.showConfirmDialog(this,fields,"Google Desktop client credentials",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)!=JOptionPane.OK_OPTION){secret.setText("");return;}
        char[] value=secret.getPassword();secret.setText("");
        try{GoogleSession.saveClient(new GoogleOAuth.Client(clientId.getText().trim(),new String(value).trim()),state());Files.deleteIfExists(state().directory().resolve("google-client.json"));googleLabel.setText("Google client configured · sign in to connect");status.setText("Desktop OAuth client saved in "+credentialStore()+". Choose Sign in with Google.");}
        catch(Exception e){error(e);}finally{Arrays.fill(value,'\0');}
    }
    private static String credentialStore(){return DesktopState.windows()?"Windows Credential Manager":"Mac Keychain";}
    private void signInGoogle(){
        try{
            GoogleOAuth.Client client=GoogleSession.client(state());
            JTextField email=new JTextField(state().get("google.email",""),30);
            JPanel prompt=new JPanel(new GridLayout(0,1,0,8));prompt.add(new JLabel("Google account email"));prompt.add(email);
            prompt.add(new JLabel("Allow reading and sending Gmail messages. No delete or modify permission is requested."));
            prompt.add(new JLabel("Your refresh token is saved in "+credentialStore()+" until you sign out."));
            if(JOptionPane.showConfirmDialog(this,prompt,"Sign in with Google",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();new jakarta.mail.internet.InternetAddress(address,true).validate();
            var cancelled=new java.util.concurrent.atomic.AtomicBoolean();
            JDialog progress=new JDialog(this,"Google sign-in",false);JPanel content=new JPanel(new BorderLayout(12,12));content.setBorder(new EmptyBorder(20,20,20,20));content.add(new JLabel("Complete sign-in in your browser, then return here."));content.add(button("Cancel",()->cancelled.set(true)),BorderLayout.SOUTH);progress.setContentPane(content);progress.pack();progress.setLocationRelativeTo(this);progress.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);progress.addWindowListener(new java.awt.event.WindowAdapter(){public void windowClosing(java.awt.event.WindowEvent e){cancelled.set(true);}});progress.setVisible(true);
            job("Waiting for Google sign-in…",()->{
                try{GoogleOAuth.Token token=GoogleOAuth.authorize(client,address,uri->{try{Desktop.getDesktop().browse(uri);}catch(Exception e){throw new IllegalStateException("Could not open the system browser");}},cancelled::get);try{GoogleSession.save(client,address,token);return token;}catch(Exception e){token.close();throw e;}}
                finally{SwingUtilities.invokeLater(progress::dispose);}
            },token->{if(googleToken!=null)googleToken.close();googleToken=token;googleEmail=address;googleLabel.setText("Google: "+address+" · saved in "+credentialStore()+"");try{state().set("google.email",address);state().save();}catch(Exception e){error(e);}status.setText("Google sign-in ready. Connect Gmail or send with Google OAuth.");});
        }catch(NoSuchFileException e){error(new IOException("Import your Google Desktop OAuth client JSON first"));}catch(Exception e){error(e);}
    }
    private void signOutGoogle(){
        if(googleToken!=null)googleToken.close();googleToken=null;googleEmail=null;disconnectInbox();
        googleLabel.setText("Google: signed out locally · removing saved session…");
        job("Removing Google session from "+credentialStore()+"…",()->{MacKeychain.deleteProtectedSession();MacKeychain.delete("google-session");return true;},ok->{googleLabel.setText("Google: signed out");status.setText("Google refresh token removed from Keychain. Client configuration retained; access can also be revoked at Google.");});
    }
    private GoogleOAuth.Token restoreGoogleSession()throws Exception{
        JDialog progress=new JDialog(this,"Google session",true);progress.add(new JLabel("  Restoring Google sign-in from "+credentialStore()+"…  "));progress.pack();progress.setLocationRelativeTo(this);progress.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        String email=state().get("google.email","");if(email.isBlank())throw new IOException("Sign in with Google from the Inbox tab first");
        var worker=new SwingWorker<GoogleOAuth.Token,Void>(){
            protected GoogleOAuth.Token doInBackground()throws Exception{return GoogleSession.restore(GoogleSession.client(MailApp.this.state()),email);}
            protected void done(){progress.dispose();}
        };worker.execute();progress.setVisible(true);
        try{GoogleOAuth.Token token=worker.get();googleEmail=email;googleLabel.setText("Google: "+email+" · restored from "+credentialStore()+"");return token;}
        catch(java.util.concurrent.ExecutionException e){throw new IOException(e.getCause().getMessage());}
    }
    private synchronized char[] googleCredential()throws Exception{
        if(googleToken==null||!googleToken.valid()){if(googleToken!=null)googleToken.close();googleToken=GoogleSession.restore(GoogleSession.client(state()),state().get("google.email",""));}
        return googleToken.credential();
    }
    private Account googleAccount(boolean smtp){
        try{if(googleToken==null||!googleToken.valid()){if(googleToken!=null)googleToken.close();googleToken=restoreGoogleSession();}return new Account(smtp?"smtp.gmail.com":"imap.gmail.com",smtp?587:993,googleEmail,googleToken.credential(),true);}catch(Exception e){error(e);tabs.setSelectedIndex(3);return null;}
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
        else{pinnedSigner=certificate;state().saveCertificate("pinned",certificate);status.setText(state().isTrusted(certificate,"signing")?"Trusted signing certificate selected":"Signing certificate selected but not trusted; use Mark trusted in Certificates");}
    }
    private void exportContact(){
        var contact=selectedContact();if(contact==null)return;Path target=chooseSave("Export certificate", "recipient-certificate.pem", "pem", "cer");if(target==null)return;
        try{var certificate=state().contactCertificate(contact);Files.write(target,target.toString().toLowerCase().endsWith(".pem")?DesktopState.pem(certificate):certificate.getEncoded(),StandardOpenOption.CREATE_NEW);status.setText("Certificate exported");}catch(Exception e){error(e);}
    }
    private void removeContact(){
        var contact=selectedContact();if(contact==null)return;
        if(JOptionPane.showConfirmDialog(this,"Remove "+contact.role()+" certificate for "+contact.email()+" from the saved contact list?","Remove certificate",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        try{var certificate=state().contactCertificate(contact);state().removeContact(contact);
            if(certificate.equals(recipient)){recipient=null;recipientLabel.setText("No recipient certificate");state().clearCertificate("recipient");}
            if(certificate.equals(pinnedSigner)){pinnedSigner=null;state().clearCertificate("pinned");}
            refreshContacts();refreshReadTrust();status.setText("Removed from contacts; public certificate retained under removed-contacts");
        }catch(Exception e){error(e);}
    }
    private JPanel keysPanel() {
        JPanel outer = panel(); JPanel p = new JPanel(); p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS)); outer.add(new JScrollPane(p),BorderLayout.CENTER);
        p.add(section("Selected outgoing identity",identityLabel));
        p.add(section("1  Software identities (.p12)",new JLabel("Private keys are encrypted in a local PKCS#12 file; no YubiKey provisioning.")));
        JPanel saved=new JPanel(new FlowLayout(FlowLayout.LEFT));saved.add(softwareIdentities);
        saved.add(button("Open software identity",()->openSaved((DesktopState.SavedIdentity)softwareIdentities.getSelectedItem())));p.add(saved);
        p.add(left(button("Create software identity…",this::generate),button("Import software PKCS#12…",this::load)));
        p.add(section("2  YubiKey identities",new JLabel("Private keys stay on the bound YubiKey. Each identity remembers its serial and slots.")));
        JPanel hardware=new JPanel(new FlowLayout(FlowLayout.LEFT));hardware.add(yubikeyIdentities);
        hardware.add(button("Select YubiKey identity",()->openSaved((DesktopState.SavedIdentity)yubikeyIdentities.getSelectedItem())));p.add(hardware);
        JButton pendingHelp=button("ⓘ",()->JOptionPane.showMessageDialog(this,
            "Use this if YubiKey key generation completed, but certificate creation was interrupted\n"
            +"(for example, you cancelled a PIN dialog).\n\n"
            +"Choose setup.properties from the saved token-setups folder. PQ Mail checks the\n"
            +"YubiKey serial and public keys, then creates the pure and hybrid signing and\n"
            +"encryption certificates and saves the identities. You may be asked for your PIN.\n\n"
            +"This does not generate, replace, or delete keys. It cannot resume partial key generation.\n"
            +"You do not need it after a successful identity creation.",
            "About finishing pending certificates",JOptionPane.INFORMATION_MESSAGE));
        pendingHelp.setToolTipText("Help: when to finish pending certificates");
        pendingHelp.getAccessibleContext().setAccessibleName("Help about finishing pending certificates");
        p.add(left(button("Create identity on empty YubiKey…",this::provisionYubiKey),button("Finish pending certificates…",this::finishTokenCertificates),pendingHelp));
        p.add(left(button("Export selected signing certificate…",()->export(true)),button("Export selected encryption certificate…",()->export(false))));
        p.add(left(button("Share certificates…",this::shareCertificates),button("Import certificate bundle…",()->{Path file=choose(false,"Import PQ Mail certificate bundle (.pqcert)");if(file!=null)importCertificateBundle(file);})));
        JPanel settings=new JPanel(new FlowLayout(FlowLayout.LEFT));
        settings.add(button("YubiKey configuration…",this::configureYubiKey));
        settings.add(button("Update YubiKey certificate email…",this::reissueTokenCertificates));
        settings.add(button("Show saved identity files",()->{try{Desktop.getDesktop().open(state().directory().toFile());}catch(Exception e){error(e);}}));p.add(settings);
        p.add(Box.createVerticalStrut(24));
        p.add(new JLabel("Generated identities are local test identities. Exchange certificate fingerprints out of band."));
        p.add(new JLabel("Private keys stay local. Account passwords are not saved by this app."));
        return outer;
    }
    private DesktopState state()throws Exception{
        if(desktopState==null){desktopState=DesktopState.open();desktopState.activate();}return desktopState;
    }
    private void refreshSaved(){
        syncingOutgoing=true;
        try{savedIdentities.removeAllItems();softwareIdentities.removeAllItems();yubikeyIdentities.removeAllItems();outgoingIdentity.removeAllItems();if(desktopState==null)return;
            String selected=desktopState.get("selected.identity","");
            for(var saved:desktopState.selectableIdentities()){savedIdentities.addItem(saved);(saved.passwordRequired()?softwareIdentities:yubikeyIdentities).addItem(saved);outgoingIdentity.addItem(saved);if(saved.id().equals(selected)){savedIdentities.setSelectedItem(saved);(saved.passwordRequired()?softwareIdentities:yubikeyIdentities).setSelectedItem(saved);outgoingIdentity.setSelectedItem(saved);}}
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
            state();if(!desktopState.get("google.email","").isBlank())googleLabel.setText("Google: connect to restore saved Keychain session");desktopState.migrateTrust();desktopState.migrateTokenBindings();refreshSaved();refreshContacts();adapter=desktopState.adapter(false);kemAdapter=desktopState.adapter(true);
            recipient=desktopState.certificate("recipient");pinnedSigner=desktopState.certificate("pinned");refreshOutgoingEncryption();
            if(recipient!=null)recipientLabel.setText(recipient.getPublicKey().getAlgorithm()+" · "+recipient.getSubjectX500Principal());
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
            basic.add(new JLabel("ML-DSA signing key: slot 9c"));basic.add(row("Classical signing slot (ECDSA)",rsa));basic.add(row("ML-KEM slot",kem));basic.add(row("ECDH slot",ecdh));
            basic.add(new JLabel("Uses existing keys. Saving settings never generates or replaces keys."));
            JPanel advanced=new JPanel(new GridLayout(0,1,0,8));advanced.add(new JLabel("Leave crypto paths blank to use the app's bundled libraries."));
            String[] names={"openssl.path","provider.path","module.path","python.path"};String[] labels={"OpenSSL","Provider","Module","Python 3"};
            JTextField[] paths=new JTextField[4];for(int i=0;i<4;i++){paths[i]=new JTextField(settings.get(names[i],i==3?DesktopState.defaultPython():""),38);advanced.add(row(labels[i],paths[i]));}
            JTabbedPane panes=new JTabbedPane();panes.addTab("YubiKey",basic);panes.addTab("Advanced",advanced);
            if(JOptionPane.showConfirmDialog(this,panes,"Saved YubiKey configuration",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE)!=JOptionPane.OK_OPTION)return;
            if(!serial.getText().trim().matches("[0-9]+"))throw new IOException("Enter the YubiKey's numeric serial number");
            var slots=new java.util.HashSet<>(java.util.List.of("9c",rsa.getSelectedItem().toString(),kem.getSelectedItem().toString(),ecdh.getSelectedItem().toString()));
            if(slots.size()!=4)throw new IOException("Choose separate signing and encryption slots");
            for(int i=0;i<4;i++){String value=paths[i].getText().trim();if(!value.isEmpty()&&(!Path.of(value).isAbsolute()||!Files.isRegularFile(Path.of(value))))throw new IOException("Invalid "+labels[i]+" path");}
            settings.set("token.serial",serial.getText().trim());settings.set("token.rsaSlot",rsa.getSelectedItem().toString());settings.set("token.kemSlot",kem.getSelectedItem().toString());settings.set("token.ecdhSlot",ecdh.getSelectedItem().toString());
            for(int i=0;i<4;i++)settings.set(names[i],paths[i].getText().isBlank()?null:paths[i].getText().trim());
            settings.set("sign.adapter","pkcs11");settings.set("decrypt.adapter","pkcs11");settings.save();settings.activate();
            if(identity!=null)setIdentity(identity);else{adapter=settings.adapter(false);kemAdapter=settings.adapter(true);}status.setText("YubiKey defaults saved. Selected credentials keep their own serial and slots.");
        }catch(Exception e){error(e);}
    }
    private void reissueTokenCertificates(){
        try{
            DesktopState settings=state();JTextField email=new JTextField(settings.get("google.email",from.getText()),30);
            JTextField extraEmails=new JTextField(30);
            JPanel prompt=new JPanel(new GridLayout(0,1,0,8));prompt.add(new JLabel("Primary email address for your YubiKey certificates"));prompt.add(email);
            prompt.add(new JLabel("Additional subject alternative email addresses (up to 4, comma-separated)"));prompt.add(extraEmails);
            prompt.add(new JLabel("Reuses existing keys and preserves old identities. Two PIN prompts per profile."));
            if(JOptionPane.showConfirmDialog(this,prompt,"Update YubiKey certificate email",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();var extra=Identity.additionalEmails(address,extraEmails.getText());
            String executable=settings.adapter(false);if(executable==null)throw new IOException("Configure a token signing adapter first");
            var profiles=new java.util.LinkedHashMap<String,Identity>();
            for(var saved:settings.selectableIdentities())if(!saved.passwordRequired()){Identity old=settings.loadIdentity(saved.id(),null);profiles.put(old.signatureAlgorithm(),old);}
            if(profiles.isEmpty())throw new IOException("Import a certificate-only token identity first");
            job("Signing new certificates with existing token keys…",()->{
                var updated=new java.util.ArrayList<Identity>();
                for(Identity old:profiles.values()){
                    Identity renewed=old.reissue(address,ExternalMu.executable(executable),extra);
                    settings.remember(renewed,address+" · "+renewed.signatureAlgorithm(),null);updated.add(renewed);
                }
                return updated.getLast();
            },renewed->{
                setIdentity(renewed);refreshSaved();from.setText(address);to.setText(address);recipient=renewed.encryptionCert();pinnedSigner=renewed.signingCert();
                try{settings.set("mail.from",address);settings.set("mail.to",address);settings.saveCertificate("pinned",pinnedSigner);if(recipient!=null)settings.saveCertificate("recipient",recipient);settings.save();}catch(Exception e){error(e);}
                if(recipient!=null)recipientLabel.setText(recipient.getPublicKey().getAlgorithm()+" · "+recipient.getSubjectX500Principal());
                try{refreshOutgoingEncryption();}catch(Exception e){error(e);}
                status.setText("New email certificates saved (DER and PEM). Token keys unchanged. No email sent.");
            });
        }catch(Exception e){error(e);}
    }
    private void provisionYubiKey(){
        job("Detecting inserted YubiKey and checking all PIV slots…",TokenProvision::detectEmpty,this::provisionDetectedYubiKey);
    }
    private void provisionDetectedYubiKey(String number){
        try{
            JTextField email=new JTextField(from.getText()),extraEmails=new JTextField();
            JComboBox<TokenProfile> profile=new JComboBox<>(TokenProfile.values());profile.setSelectedItem(TokenProfile.LEVEL5);
            JPanel form=new JPanel(new GridLayout(0,1,0,8));form.add(new JLabel("Inserted YubiKey serial: "+number+" (all user PIV slots empty)"));form.add(new JLabel("Certificate email address"));form.add(email);form.add(new JLabel("Additional email addresses (up to 4, comma-separated)"));form.add(extraEmails);form.add(new JLabel("Security profile (all options create four keys and both pure/hybrid identities)"));form.add(profile);
            form.add(new JLabel("Requires all 24 user PIV slots empty. Factory attestation is excluded."));
            form.add(new JLabel("No reset, import, deletion or replacement of existing keys is performed."));
            if(JOptionPane.showConfirmDialog(this,form,"Create YubiKey identity",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();new jakarta.mail.internet.InternetAddress(address,true).validate();TokenProfile selected=(TokenProfile)profile.getSelectedItem();var extra=Identity.additionalEmails(address,extraEmails.getText());
            job("Checking every PIV slot on YubiKey "+number+"…",()->{TokenProvision.check(number);return true;},ok->provisionCredentials(number,address,selected,extra));
        }catch(Exception e){error(e);}
    }
    private void provisionCredentials(String serial,String email,TokenProfile profile,java.util.List<String> extra){
        JPasswordField pin=new JPasswordField(),management=new JPasswordField();JCheckBox factory=new JCheckBox("Use factory-default management key",true);
        JPanel form=new JPanel(new GridLayout(0,1,0,8));form.add(new JLabel("YubiKey "+serial+" passed the empty-slot check."));
        form.add(new JLabel("Generate "+profile.ml+" in 9c; "+profile.kem+" in 9d."));form.add(new JLabel("Also generate ECDSA and ECDH "+(profile.category==2?"P-256":"P-384")+" in 9a and 82."));
        form.add(new JLabel("All keys: PIN Always, Touch Never. Private keys never leave the device."));
        form.add(new JLabel("YubiKey PIN"));form.add(pin);form.add(factory);form.add(new JLabel("Management key (hex, only if not factory default)"));form.add(management);
        form.add(new JLabel("Creating keys is not atomic: a failure can leave some slots provisioned. No automatic retry."));
        if(JOptionPane.showConfirmDialog(this,form,"Generate keys on empty YubiKey",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){pin.setText("");management.setText("");return;}
        char[] secret=pin.getPassword(),admin=factory.isSelected()?"010203040506070801020304050607080102030405060708".toCharArray():management.getPassword();pin.setText("");management.setText("");
        if(secret.length<6||secret.length>8||!new String(secret).matches("[ -~]+")||!new String(admin).matches("(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{48}|[a-fA-F0-9]{64})")){Arrays.fill(secret,'\0');Arrays.fill(admin,'\0');error(new IOException("Use a 6–8 character ASCII PIN and a valid hexadecimal management key"));return;}
        job("Generating keys on YubiKey "+serial+"…",()->{
            Path parent=state().directory().resolve("token-setups");Files.createDirectories(parent);Path folder=parent.resolve(java.util.UUID.randomUUID().toString());
            try{
                var keys=TokenProvision.create(serial,profile,folder,secret,admin);
                var manifest=new java.util.Properties();manifest.setProperty("serial",serial);manifest.setProperty("email",email);manifest.setProperty("hybrid","true");manifest.setProperty("preferHybrid","true");manifest.setProperty("profile",profile.code);manifest.setProperty("additionalEmails",String.join(",",extra));
                try(var out=Files.newOutputStream(folder.resolve("setup.properties"),StandardOpenOption.CREATE_NEW)){manifest.store(out,"Public setup metadata; keys remain on YubiKey");}
                return issueTokenIdentities(serial,email,true,keys,true,profile,extra);
            }finally{Arrays.fill(secret,'\0');Arrays.fill(admin,'\0');if(identity!=null)state().activateIdentity(identity);}
        },created->{setIdentity(created);refreshSaved();from.setText(email);status.setText("YubiKey identities saved. Keys generated on serial "+serial+"; no private keys stored on this Mac.");});
    }
    private Identity issueTokenIdentities(String serial,String email,boolean hybrid,java.util.Map<String,java.security.PublicKey> keys,boolean preferHybrid,TokenProfile profile,java.util.List<String> extra)throws Exception{
                state().set("token.serial",serial);state().set("token.rsaSlot","9a");state().set("token.kemSlot","9d");state().set("token.ecdhSlot","82");state().activate();
                String signer=DesktopState.resources().resolve("adapters/pkcs11-mu.py").toString();Identity selected=null;
                for(boolean composite:hybrid?new boolean[]{!preferHybrid,preferHybrid}:new boolean[]{false}){
                    selected=Identity.forTokenProfile(email,profile,keys.get("9c"),composite?keys.get("9a"):null,keys.get("9d"),composite?keys.get("82"):null,ExternalMu.executable(signer),extra);
                    String id=state().remember(selected,email+" · "+selected.signatureAlgorithm(),null);state().bindToken(id,serial,"9a","9d","82");
                }return selected;
    }
    private void finishTokenCertificates(){
        Path manifest=choose(false,"Choose setup.properties from a pending YubiKey setup (certificate creation only)");if(manifest==null)return;
        job("Checking pending setup keys; no key generation…",()->{
            var values=new java.util.Properties();try(var input=Files.newInputStream(manifest)){values.load(input);}
            String serial=values.getProperty("serial",""),email=values.getProperty("email","");boolean hybrid=Boolean.parseBoolean(values.getProperty("hybrid","false"));
            new jakarta.mail.internet.InternetAddress(email,true).validate();
            TokenProfile profile=TokenProfile.parse(values.getProperty("profile","level5"));
            var keys=values.containsKey("profile")?TokenProvision.read(serial,profile,manifest.getParent()):TokenProvision.read(serial,hybrid,manifest.getParent());
            try{return issueTokenIdentities(serial,email,hybrid,keys,Boolean.parseBoolean(values.getProperty("preferHybrid",Boolean.toString(hybrid))),profile,Identity.additionalEmails(email,values.getProperty("additionalEmails","")));}finally{if(identity!=null)state().activateIdentity(identity);}
        },created->{setIdentity(created);refreshSaved();status.setText("Pending public certificates completed for the existing YubiKey keys");});
    }
    private void generate() {
        JTextField email=new JTextField(from.getText()),extraEmails=new JTextField();JComboBox<TokenProfile> mode=new JComboBox<>(TokenProfile.values());mode.setSelectedItem(TokenProfile.LEVEL5);
        JPasswordField pass=new JPasswordField();JPanel p=new JPanel(new GridLayout(0,1,0,8));
        p.add(new JLabel("Email address"));p.add(email);p.add(new JLabel("Additional email addresses (up to 4, comma-separated)"));p.add(extraEmails);p.add(new JLabel("Security profile (four software keys; both pure and hybrid identities)"));p.add(mode);
        p.add(new JLabel("One password-protected .p12 file stores both identities. No YubiKey is changed."));
        p.add(new JLabel("New PKCS#12 password (12+ characters)"));p.add(pass);
        if(JOptionPane.showConfirmDialog(this,p,"Create software identities (.p12)",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){pass.setText("");return;}
        Path file=chooseSave("Save new identity bundle", "identity.p12", "p12");if(file==null){pass.setText("");return;}
        char[] password=pass.getPassword();pass.setText("");String address=email.getText().trim(),additional=extraEmails.getText();TokenProfile profile=(TokenProfile)mode.getSelectedItem();
        job("Generating four software keys…",()->{try{
            if(password.length<12)throw new IllegalArgumentException("Use at least 12 characters for the identity password");
            var profiles=Identity.generateSoftwareProfile(address,profile,Identity.additionalEmails(address,additional));profiles.get(1).save(file,password,profiles.get(0));return profiles;
        }finally{Arrays.fill(password,'\0');}},profiles->rememberSoftwareProfiles(profiles,file,address));
    }
    private void rememberSoftwareProfiles(java.util.List<Identity> profiles,Path file,String name){
        try{state().rememberSoftwareProfiles(profiles,file,name);setIdentity(profiles.getLast());from.setText(certificateEmail(identity.signingCert()));refreshSaved();status.setText("Software identities saved. Select pure or hybrid in Sign with.");}catch(Exception e){error(e);}
    }
    private void load() {
        Path file=choose(false,"Load identity .p12");if(file==null)return;
        JPasswordField pass=new JPasswordField();if(JOptionPane.showConfirmDialog(this,pass,"Identity password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){pass.setText("");return;}
        char[] password=pass.getPassword();pass.setText("");job("Loading identity…",()->{try{
            var profiles=Identity.loadProfiles(file,password);for(var id:profiles)if(id.signingKey()==null)throw new IOException("This file has no software signing key. Select its saved YubiKey identity instead.");return profiles;
        }finally{Arrays.fill(password,'\0');}},profiles->rememberSoftwareProfiles(profiles,file,file.getFileName().toString()));
    }
    private String tokenAdapter(boolean kem){String selected=desktopState.adapter(kem);return selected==null?DesktopState.resources().resolve("adapters").resolve(kem?"pkcs11-kem.py":"pkcs11-mu.py").toString():selected;}
    private void setIdentity(Identity id) {
        try{if(desktopState!=null)desktopState.activateIdentity(id);}catch(Exception e){error(e);return;}identity=id;
        if(desktopState!=null){adapter=id.signingKey()==null?tokenAdapter(false):null;kemAdapter=id.encryptionKey()==null&&id.encryptionCert()!=null?tokenAdapter(true):null;}
        identityLabel.setText(id.signatureAlgorithm()+" · "+id.signingCert().getSubjectX500Principal());status.setText("Identity ready. Import a recipient certificate to encrypt.");}
    private void shareCertificates(){
        try{var entries=state().certificateBundle(identity);JTextArea review=new JTextArea(CertificateBundle.review(entries),18,76);review.setEditable(false);review.setLineWrap(true);review.setWrapStyleWord(true);
            Object[] options=System.getProperty("os.name").startsWith("Mac")?new Object[]{"Share…","Save bundle…","Cancel"}:new Object[]{"Save bundle…","Cancel"};
            int choice=JOptionPane.showOptionDialog(this,new JScrollPane(review),"Share public certificate profiles",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,options,options[0]);if(choice<0||choice==options.length-1)return;
            byte[] bytes=CertificateBundle.encode(entries);
            if(options[choice].equals("Save bundle…")){Path file=chooseSave("Save public certificate bundle","PQ-Mail-certificates.pqcert","pqcert");if(file!=null)Files.write(file,bytes,StandardOpenOption.CREATE_NEW);return;}
            Path helper=DesktopState.resources().resolve("native/PQMailShare.app");if(!Files.isDirectory(helper))throw new IOException("Native sharing helper is missing; use Save bundle and Finder Share");
            Path folder=Files.createTempDirectory("pq-mail-certificates-");Path file=folder.resolve("PQ-Mail-certificates.pqcert");Files.write(file,bytes);file.toFile().deleteOnExit();folder.toFile().deleteOnExit();
            new ProcessBuilder("/usr/bin/open","-n","-a",helper.toString(),"--args",file.toString()).start();status.setText("Choose AirDrop or another destination in the sharing window.");
        }catch(Exception e){error(e);}
    }
    private void importCertificateBundle(Path file){
        job("Reading public certificate bundle…",()->{if(Files.size(file)>CertificateBundle.MAX_BYTES)throw new IOException("Bundle too large");return CertificateBundle.decode(Files.readAllBytes(file));},entries->{
            try{JTextArea review=new JTextArea(CertificateBundle.review(entries),18,76);review.setEditable(false);review.setLineWrap(true);review.setWrapStyleWord(true);
                Object[] options={"Use with my YubiKey","Add contact certificates","Cancel"};int choice=JOptionPane.showOptionDialog(this,new JScrollPane(review),"Review certificate bundle — no automatic trust",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,options,options[2]);if(choice<0||choice==2)return;
                state().importCertificateBundle(entries,choice==0);refreshSaved();refreshContacts();status.setText("Public certificates imported. Trust unchanged; select an identity before use.");
            }catch(Exception e){error(e);}
        });
    }
    private void export(boolean signing) {
        if(identity==null){error(new IOException("Load an identity first"));return;}
        X509Certificate c=signing?identity.signingCert():identity.encryptionCert();if(c==null){error(new IOException("No certificate available"));return;}
        Path file=chooseSave("Export public certificate", signing?"signing-certificate.pem":"encryption-certificate.pem", "pem", "cer");if(file==null)return;
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
        if(!usePgp()&&encrypt.isSelected()&&recipient==null){error(new IOException("Import recipient encryption certificate first"));tabs.setSelectedIndex(2);return;}
        try{
            if(!Identity.matchesEmail(identity.signingCert(),from.getText().trim()))throw new IOException("From address does not match your signing certificate");
            if(!usePgp()&&encrypt.isSelected()&&!Identity.matchesEmail(recipient,to.getText().trim())){tabs.setSelectedIndex(4);throw new IOException("Choose an encryption certificate matching the To address, or turn off optional encryption to send signed-only mail");}
        }catch(Exception e){error(e);return;}
        if(usePgp()&&(!OpenPgp.supported(identity)||!attachmentModel.isEmpty())){error(new IOException("OpenPGP requires a Level 3 hybrid identity and plain text. Use S/MIME for attachments."));return;}
        if(usePgp()&&encrypt.isSelected()&&pgpRecipient==null){error(new IOException("Import the recipient OpenPGP public key in the OpenPGP tab, or select Use my OpenPGP key."));tabs.setSelectedIndex(5);return;}
        final boolean pgp=usePgp(),pgpEncrypt=encrypt.isSelected();final OpenPgp.PublicIdentity pgpTo=pgpRecipient;
        Path file=send?null:chooseSave("Save signed message", "message.eml", "eml");if(!send&&file==null)return;
        Account a=send?account(true):null;if(send&&a==null)return;
        Identity id=identity; X509Certificate r=encrypt.isSelected()?recipient:null; ExternalMu.Backend backend=adapter==null?null:ExternalMu.executable(adapter);
        var files=java.util.Collections.list(attachmentModel.elements());
        String f=from.getText().trim(),t=to.getText().trim(),s=subject.getText(),b=body.getText();
        try{state().set("mail.from",f);state().set("mail.to",t);state().save();}catch(Exception e){error(e);return;}
        if(send&&JOptionPane.showConfirmDialog(this,"Send this "+((pgp?pgpEncrypt:r!=null)?"signed and encrypted":"signed, unencrypted")+" message with "+files.size()+" attachment(s) to "+t+"?","Send message",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){Arrays.fill(a.password,'\0');return;}
        job(send?"Signing and sending…":"Signing and saving…",()->{
            try {
                MimeMessage m=pgp?MailEngine.parse(OpenPgp.compose(id,OpenPgp.loadOwn(state().directory(),id),pgpEncrypt?pgpTo:null,f,t,s,b,backend)):MailEngine.compose(id,f,t,s,b,r,backend,files);
                if(send){if(a.oauth){try(var api=new GmailApi(this::googleCredential)){api.verifyAccount(a.user);api.send(m);}}else MailEngine.send(m,a.host,a.port,a.user,new String(a.password),false);}
                else Files.write(file,MailEngine.encode(m),StandardOpenOption.CREATE_NEW);
                return send?"Message sent":"Saved "+file.getFileName();
            } finally {if(a!=null)Arrays.fill(a.password,'\0');}
        },status::setText);
    }
    private ReadResult display(MimeMessage message,Identity id,X509Certificate pin)throws Exception {
        byte[] encoded=MailEngine.encode(message);
        if(OpenPgp.isOpenPgp(encoded)){
            OpenPgp.PublicIdentity own=null;
            if(OpenPgp.parts(encoded).encrypted()||pgpSigner==null)own=OpenPgp.loadOwn(state().directory(),id);
            var opened=OpenPgp.open(encoded,pgpSigner==null?own:pgpSigner,own,id,kemAdapter==null?null:ExternalKem.executable(kemAdapter));
            return new ReadResult(opened.display(),null,message.getSubject());
        }
        if(MailPreview.isOrdinary(message))return new ReadResult(MailPreview.display(message),null,message.getSubject());
        var opened=MailEngine.open(message,id,pin,kemAdapter==null?null:ExternalKem.executable(kemAdapter));
        return new ReadResult(null,opened,message.getSubject());
    }
    private String formatRead(ReadResult result)throws Exception{
        if(result.verified()==null)return result.plain();var o=result.verified();
        if(o.signerCertificate()==null)return "DECRYPTED · UNSIGNED MESSAGE\nSender and content are not signature-verified. Do not infer signer trust from encryption.\n\nOuter subject (unprotected): "+result.subject()+"\n\n"+o.text()+"\n\nAttachments: "+o.attachments();
        boolean trusted=state().isTrusted(o.signerCertificate(),"signing");
        return "SIGNATURE VALID · "+o.signatureAlgorithm()+"\n"+(o.encrypted()?"Decryption succeeded; signed content verified":"Not encrypted")+"\n"+
            (trusted?"SIGNER TRUSTED: SHA-256 certificate fingerprint matches your saved trust":"SIGNER NOT TRUSTED: fingerprint has not been marked trusted")+"\n"+
            (o.fromMatches()?"Outer From matches certificate email (header itself is unsigned)":"WARNING: outer From does not match signing certificate")+
            "\nSHA-256: "+o.fingerprint()+"\n\nOuter subject (unprotected): "+result.subject()+"\n\n──────── Signed body ────────\n\n"+o.text()+"\n\nAttachments: "+o.attachments();
    }
    private void clearReadTrust(){currentRead=null;trustIncoming.setEnabled(false);saveAttachment.setEnabled(false);}
    private void showMessage(ReadResult result){
        try{showMessage(formatRead(result));currentRead=result;trustIncoming.setEnabled(result.verified()!=null&&result.verified().signerCertificate()!=null);saveAttachment.setEnabled(result.verified()!=null&&!result.verified().attachments().isEmpty());}catch(Exception e){clearReadTrust();error(e);}
    }
    private void showMessage(String text){clearReadTrust();reader.setText(text);reader.setCaretPosition(0);tabs.setSelectedIndex(1);status.setText("Message opened. Review the security status above.");}
    private void saveReadAttachment(){
        if(currentRead==null||currentRead.verified()==null)return;
        var files=currentRead.verified().attachments();if(files.isEmpty())return;
        var file=(MailEngine.Attachment)JOptionPane.showInputDialog(this,"Save a verified attachment (saved files are decrypted)","Attachments",JOptionPane.PLAIN_MESSAGE,null,files.toArray(),files.getFirst());
        if(file==null)return;JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File(file.name()));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        try{Files.write(chooser.getSelectedFile().toPath(),file.data(),StandardOpenOption.CREATE_NEW);status.setText("Attachment saved; existing files are never overwritten.");}catch(Exception e){error(e);}
    }
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
    private void trustIncomingEncryption(){
        if(currentRead==null||currentRead.verified()==null||currentRead.verified().signerCertificate()==null){error(new IOException("Open a verified signed message first"));return;}
        try{var cert=currentRead.verified().signerCertificate();Identity.validateCertificatePurpose(cert,"encryption");
            if(!confirmTrust(cert,"encryption","Only use this certificate if its owner intends it for encrypted mail."))return;
            var sans=cert.getSubjectAlternativeNames();boolean saved=false;
            if(sans!=null)for(var san:sans)if(Integer.valueOf(1).equals(san.get(0))){state().rememberContact(cert,san.get(1).toString(),"encryption");saved=true;}
            if(!saved)throw new IOException("Certificate has no email SAN; import the owner's encryption certificate instead");
            state().setTrusted(cert,"encryption",true);refreshContacts();status.setText("Incoming certificate trusted for encryption");
        }catch(Exception e){error(e);}
    }
    private void trustIncomingSigner(){
        if(currentRead==null||currentRead.verified()==null||currentRead.verified().signerCertificate()==null)return;
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
        if(smtp){Object[] choices={"Gmail API","Other host (SMTP)","Cancel"};int choice=JOptionPane.showOptionDialog(this,"Choose how to authenticate for sending","Send using",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,choices,choices[0]);if(choice==0)return googleAccount(true);if(choice!=1)return null;}
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
    private void error(Throwable e){String message=e.getMessage();status.setText("Operation failed");JOptionPane.showMessageDialog(this,message==null?e.getClass().getSimpleName():message,"PQ Mail",JOptionPane.ERROR_MESSAGE);}
    private Path chooseSave(String title,String filename,String... extensions){
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle(title);
        chooser.setAcceptAllFileFilterUsed(false);
        for(String extension:extensions)chooser.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            extension.equals("pem")?"PEM certificate (*.pem)":extension.equals("cer")?"DER certificate (*.cer)":extension.equals("p12")?"PKCS#12 identity (*.p12)":"Email message (*.eml)",extension));
        chooser.setFileFilter(chooser.getChoosableFileFilters()[0]);
        chooser.setSelectedFile(new java.io.File(filename));
        chooser.addPropertyChangeListener(JFileChooser.FILE_FILTER_CHANGED_PROPERTY,event->{
            var selected=chooser.getSelectedFile();
            if(selected!=null && event.getNewValue() instanceof javax.swing.filechooser.FileNameExtensionFilter filter){
                String name=selected.getName();
                for(String extension:extensions)if(name.toLowerCase(java.util.Locale.ROOT).endsWith("."+extension)){
                    chooser.setSelectedFile(new java.io.File(selected.getParentFile(),name.substring(0,name.length()-extension.length())+filter.getExtensions()[0]));break;
                }
            }
        });
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return null;
        Path selected=chooser.getSelectedFile().toPath();String name=selected.getFileName().toString();
        for(String extension:extensions)if(name.toLowerCase(java.util.Locale.ROOT).endsWith("."+extension))return selected;
        String extension=((javax.swing.filechooser.FileNameExtensionFilter)chooser.getFileFilter()).getExtensions()[0];
        return selected.resolveSibling(name+"."+extension);
    }
    private Path choose(boolean save,String title){JFileChooser c=new JFileChooser();c.setDialogTitle(title);return (save?c.showSaveDialog(this):c.showOpenDialog(this))==JFileChooser.APPROVE_OPTION?c.getSelectedFile().toPath():null;}
    private static JPanel panel(){JPanel p=new JPanel(new BorderLayout(12,12));p.setBorder(new EmptyBorder(16,8,8,8));return p;}
    private static JPanel row(String name,JComponent field){JPanel p=new JPanel(new BorderLayout(8,0));JLabel l=new JLabel(name);l.setPreferredSize(new Dimension(80,24));p.add(l,BorderLayout.WEST);p.add(field);return p;}
    private static JPanel left(JComponent... controls){JPanel p=new JPanel(new FlowLayout(FlowLayout.LEFT));for(var c:controls)p.add(c);return p;}
    private static JPanel section(String name,JLabel detail){JPanel p=new JPanel(new GridLayout(0,1,0,6));p.setBorder(new EmptyBorder(20,6,4,0));JLabel h=new JLabel(name);h.setFont(h.getFont().deriveFont(Font.BOLD,16f));p.add(h);p.add(detail);return p;}
    private static JButton button(String label,Runnable action){JButton b=new JButton(label);b.addActionListener(e->action.run());return b;}
    public static void openTokenSession(Identity id, String executable, MimeMessage verifiedMail) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                MailApp app = new MailApp();
                app.setIdentity(id); app.adapter = app.tokenAdapter(false);
                app.pinnedSigner = id.signingCert();
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
                MailApp app=new MailApp();app.setIdentity(id);app.adapter=app.tokenAdapter(false);app.kemAdapter=app.tokenAdapter(true);
                app.recipient=id.encryptionCert();app.recipientLabel.setText(id.encryptionCert().getPublicKey().getAlgorithm());
                app.pinnedSigner=id.signingCert();
                app.from.setText("beta0@example.test");app.to.setText("beta0@example.test");app.encrypt.setSelected(true);
                app.showMessage("SIGNATURE VALID · "+checked.signatureAlgorithm()+"\nToken-backed authenticated decryption succeeded\n\n"+checked.text());
                app.setVisible(true);
            }catch(Exception e){throw new RuntimeException(e);}
        });
    }
    public static void main(String[]args){MailEngine.init();SwingUtilities.invokeLater(()->{try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ignored){}MailApp app=new MailApp();app.setVisible(true);app.restoreDesktop();if(Desktop.isDesktopSupported()&&Desktop.getDesktop().isSupported(Desktop.Action.APP_OPEN_FILE))Desktop.getDesktop().setOpenFileHandler(event->SwingUtilities.invokeLater(()->{if(!event.getFiles().isEmpty())app.importCertificateBundle(event.getFiles().get(0).toPath());}));if(args.length>0)app.importCertificateBundle(Path.of(args[0]));});}
}
