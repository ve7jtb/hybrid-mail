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
    private final javax.swing.table.DefaultTableModel certificateModel=new javax.swing.table.DefaultTableModel(new String[]{"Email","Purpose","Trust","Version","Signing algorithm(s)","Encryption algorithm","Full fingerprint (OpenPGP primary / X.509 SHA-256)"},0){public boolean isCellEditable(int row,int column){return false;}};
    private final JTable certificateTable=new JTable(certificateModel);
    private boolean syncingOutgoing;
    private final JComboBox<DesktopState.SavedIdentity> outgoingIdentity=new JComboBox<>();
    private record EncryptionChoice(String email,X509Certificate certificate){
        public String toString(){try{return email+" · "+certificate.getPublicKey().getAlgorithm()+" · "+Identity.fingerprint(certificate).substring(0,23);}catch(Exception e){return email;}}
    }
    private final JComboBox<EncryptionChoice> outgoingEncryption=new JComboBox<>();
    private final JButton trustIncoming=new JButton("Trust signer fingerprint…");
    private final JButton saveIncomingPgp=new JButton("Save sender OpenPGP certificate…");
    private ReadResult currentRead;
    private final DefaultListModel<Path> attachmentModel=new DefaultListModel<>();
    private final JList<Path> attachmentList=new JList<>(attachmentModel);
    private final JButton saveAttachment=new JButton("Save attachment…");
    private record ReadResult(String plain,MailEngine.Opened verified,String subject,OpenPgp.Opened pgp,String pgpMailbox,OpenPgp.PublicIdentity pgpCertificate){
        ReadResult(String plain,MailEngine.Opened verified,String subject,OpenPgp.Opened pgp,String pgpMailbox){this(plain,verified,subject,pgp,pgpMailbox,null);}
        ReadResult(String plain,MailEngine.Opened verified,String subject){this(plain,verified,subject,null,null);}
    }
    private Identity identity;
    private final JComboBox<String> mailFormat=new JComboBox<>(new String[]{"S/MIME","OpenPGP"});
    private OpenPgp.PublicIdentity pgpRecipient,pgpSigner;
    private final OpenPgpRecipients pgpRecipients=new OpenPgpRecipients();
    private OpenPgpRecipients.Ticket pgpLookupTicket;
    private final JComboBox<OpenPgp.PublicIdentity> pgpEncryption=new JComboBox<>();
    private final JLabel pgpLookupStatus=new JLabel("Enter To to find an OpenPGP recipient key.");
    private final JPanel encryptionOptions=new JPanel(new CardLayout());
    private final javax.swing.Timer pgpLookupTimer=new javax.swing.Timer(900,e->lookupPgpRecipient());
    private boolean syncingPgp;
    private final JTextArea pgpStatus=new JTextArea("Select Level 3 hybrid for outgoing OpenPGP signing. Classical v4 certificates are supported for recipient encryption and incoming verification. OpenPGP uses separate public identities and fingerprints; private keys stay in the existing software bundle or YubiKey.");
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
        heading.add(title, BorderLayout.NORTH); heading.add(new JLabel("S/MIME & OpenPGP  /  local development build"), BorderLayout.SOUTH); root.add(heading,BorderLayout.NORTH);
        tabs.addTab("Compose", composePanel()); tabs.addTab("Read & verify", readPanel()); tabs.addTab("Keys", keysPanel()); tabs.addTab("Inbox",inboxPanel()); tabs.addTab("Certificates",certificatesPanel()); tabs.addTab("OpenPGP",openPgpPanel()); root.add(tabs);
        status.setBorder(new EmptyBorder(10,0,0,0)); root.add(status, BorderLayout.SOUTH);
        body.setLineWrap(true); body.setWrapStyleWord(true); body.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,16)); body.setMargin(new Insets(16,16,16,16));
        reader.setEditable(false); reader.setLineWrap(true); reader.setWrapStyleWord(true); reader.setFont(new Font(Font.MONOSPACED,Font.PLAIN,13)); reader.setMargin(new Insets(16,16,16,16));
    }
    private JPanel composePanel() {
        JPanel p = panel(); JPanel fields = new JPanel();fields.setLayout(new BoxLayout(fields,BoxLayout.Y_AXIS));
        fields.add(row("From",from)); fields.add(row("To",to)); fields.add(row("Subject",subject));
        fields.add(row("Message format",mailFormat));fields.add(row("Sign with",outgoingIdentity));fields.add(encrypt);encryptionOptions.add(row("Encrypt to",outgoingEncryption),"S/MIME");
        JPanel pgpOptions=new JPanel(new GridLayout(0,1,0,3));pgpOptions.add(row("Recipient key",pgpEncryption));pgpOptions.add(pgpLookupStatus);
        pgpOptions.add(left(button("Look up To on keys.openpgp.org",this::lookupPgpRecipient),button("Review recipient key…",()->{try{if(pgpRecipient!=null)JOptionPane.showMessageDialog(this,pgpContactDescription(pgpRecipient,to.getText().trim()));}catch(Exception e){error(e);}})));
        encryptionOptions.add(pgpOptions,"OpenPGP");fields.add(encryptionOptions);
        pgpLookupTimer.setRepeats(false);
        mailFormat.addActionListener(e->{encrypt.setSelected(false);refreshSaved();recipientAddressChanged();((CardLayout)encryptionOptions.getLayout()).show(encryptionOptions,usePgp()?"OpenPGP":"S/MIME");if(!usePgp())encrypt.setEnabled(true);});
        to.getDocument().addDocumentListener(new javax.swing.event.DocumentListener(){public void insertUpdate(javax.swing.event.DocumentEvent e){recipientAddressChanged();}public void removeUpdate(javax.swing.event.DocumentEvent e){recipientAddressChanged();}public void changedUpdate(javax.swing.event.DocumentEvent e){recipientAddressChanged();}});
        pgpEncryption.addActionListener(e->{if(!syncingPgp){pgpRecipient=(OpenPgp.PublicIdentity)pgpEncryption.getSelectedItem();encrypt.setEnabled(!usePgp()||pgpRecipient!=null);if(pgpRecipient==null)encrypt.setSelected(false);else pgpLookupStatus.setText(pgpTrustStatus(pgpRecipient,to.getText().trim())+" · "+(pgpRecipient.quantumEncryption()?"Hybrid PQ encryption":"WARNING: Classical encryption — not post-quantum resistant."));}});
        outgoingIdentity.addActionListener(e->{if(!syncingOutgoing){var chosen=(DesktopState.SavedIdentity)outgoingIdentity.getSelectedItem();if(chosen!=null)openSaved(chosen);}});
        outgoingEncryption.setEnabled(!usePgp()&&encrypt.isSelected());encrypt.addActionListener(e->outgoingEncryption.setEnabled(!usePgp()&&encrypt.isSelected()));
        outgoingEncryption.addActionListener(e->{if(!syncingOutgoing){var chosen=(EncryptionChoice)outgoingEncryption.getSelectedItem();if(chosen!=null){recipient=chosen.certificate();to.setText(chosen.email());recipientLabel.setText(chosen.email()+" · "+recipient.getPublicKey().getAlgorithm());try{state().saveCertificate("recipient",recipient);}catch(Exception error){error(error);}}}}); fields.add(new JLabel("Outgoing OpenPGP signatures are hybrid PQ. To lookups go to keys.openpgp.org; a found key is not automatically trusted.")); for(Component item:fields.getComponents())if(item instanceof JComponent c){c.setAlignmentX(Component.LEFT_ALIGNMENT);c.setMaximumSize(new Dimension(Integer.MAX_VALUE,c.getPreferredSize().height));}p.add(fields,BorderLayout.NORTH);
        JPanel content=new JPanel(new BorderLayout(0,6));content.add(new JScrollPane(body));
        JPanel attachments=new JPanel(new BorderLayout());attachmentList.setVisibleRowCount(2);
        attachments.add(new JScrollPane(attachmentList));JPanel fileActions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileActions.add(button("Add attachments…",()->{JFileChooser c=new JFileChooser();c.setMultiSelectionEnabled(true);if(c.showOpenDialog(this)==JFileChooser.APPROVE_OPTION){for(File file:c.getSelectedFiles()){if(attachmentModel.size()>=20){error(new IOException("At most 20 attachments"));break;}attachmentModel.addElement(file.toPath());}}}));
        fileActions.add(button("Remove selected",()->{for(Path file:attachmentList.getSelectedValuesList())attachmentModel.removeElement(file);}));
        attachments.add(fileActions,BorderLayout.NORTH);content.add(attachments,BorderLayout.SOUTH);p.add(content);
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(new JLabel("Body and attachments are signed; enable encryption to protect both. Outer From / To / Subject headers are unprotected."),BorderLayout.NORTH);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(button("Mail servers…",this::mailServerSettings));actions.add(button("Recipient certificates…",()->tabs.setSelectedIndex(4))); actions.add(button("Save signed .eml…", () -> compose(false))); actions.add(button("Send…", () -> compose(true)));
        bottom.add(actions, BorderLayout.SOUTH); p.add(bottom,BorderLayout.SOUTH); return p;
    }
    private void selectPgpRecipient(OpenPgp.PublicIdentity key)throws Exception{
        state().rememberPgp(key,key.matchesEmail(to.getText().trim())?to.getText().trim():key.email);refreshContacts();pgpRecipients.remember(key);to.setText(key.matchesEmail(to.getText().trim())?to.getText().trim():key.email);
        recipientAddressChanged();pgpLookupTimer.stop();refreshPgpChoices();pgpEncryption.setSelectedItem(key);pgpStatus.setText(pgpContactDescription(key,to.getText().trim()));
    }
    private void recipientAddressChanged(){
        pgpLookupTimer.stop();pgpLookupTicket=pgpRecipients.change(to.getText());pgpRecipient=null;
        if(usePgp()){encrypt.setSelected(false);encrypt.setEnabled(false);refreshPgpChoices();
            try{OpenPgp.validateEmail(to.getText().trim());if(pgpRecipient==null){pgpLookupStatus.setText("Looking up To on keys.openpgp.org…");pgpLookupTimer.restart();}}catch(Exception e){pgpLookupStatus.setText("Enter one complete recipient email address.");}
        }
    }
    private void refreshPgpChoices(){
        var previous=pgpRecipient;syncingPgp=true;
        try{pgpEncryption.removeAllItems();for(var key:pgpRecipients.choices())pgpEncryption.addItem(key);if(previous!=null)for(int i=0;i<pgpEncryption.getItemCount();i++)try{if(pgpEncryption.getItemAt(i).fingerprint().equals(previous.fingerprint()))pgpEncryption.setSelectedIndex(i);}catch(Exception ignored){}
            pgpRecipient=(OpenPgp.PublicIdentity)pgpEncryption.getSelectedItem();
            if(usePgp()){encrypt.setEnabled(pgpRecipient!=null);if(pgpRecipient==null)encrypt.setSelected(false);}
            pgpLookupStatus.setText(pgpRecipient==null?"No usable recipient key — encryption unavailable.":pgpTrustStatus(pgpRecipient,to.getText().trim())+" · "+(pgpRecipient.quantumEncryption()?"Hybrid PQ encryption":"WARNING: Classical encryption — not post-quantum resistant."));
        }finally{syncingPgp=false;}
    }
    private void lookupPgpRecipient(){
        pgpLookupTimer.stop();if(!usePgp())return;final String address=to.getText().trim();
        try{OpenPgp.validateEmail(address);}catch(Exception e){pgpLookupStatus.setText("Enter one complete recipient email address.");return;}
        final var ticket=pgpLookupTicket;pgpLookupStatus.setText("Looking up "+address+" on keys.openpgp.org…");
        new SwingWorker<OpenPgp.PublicIdentity,Void>(){
            protected OpenPgp.PublicIdentity doInBackground()throws Exception{return OpenPgpKeyserver.lookup(address);}
            protected void done(){if(!usePgp()||!pgpRecipients.current(ticket))return;
                try{var key=get();if(pgpRecipients.accept(ticket,key)){MailApp.this.state().rememberPgp(key,address);refreshContacts();refreshPgpChoices();}}
                catch(Exception failure){refreshPgpChoices();if(pgpRecipient==null){Throwable cause=failure.getCause()==null?failure:failure.getCause();pgpLookupStatus.setText("Encryption unavailable: "+cause.getMessage());}}
            }
        }.execute();
    }
    private JPanel readPanel() {
        JPanel p = panel(); p.add(new JScrollPane(reader)); JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Open .eml…", () -> {
            Path file = choose(false,"Open S/MIME message"); if(file == null)return;
            clearReadTrust();Identity id = identity; X509Certificate pin = pinnedSigner;
            job("Verifying message…", () -> { if(Files.size(file)>MailEngine.MAX_MESSAGE) throw new IOException("Message too large"); return display(MailEngine.parse(Files.readAllBytes(file)),id,pin); }, this::showMessage);
        }));
        actions.add(button("Open inbox",()->tabs.setSelectedIndex(3)));
        saveIncomingPgp.setEnabled(false);saveIncomingPgp.addActionListener(e->saveIncomingPgpCertificate());actions.add(saveIncomingPgp);trustIncoming.setEnabled(false);trustIncoming.addActionListener(e->trustIncomingSigner());actions.add(trustIncoming);actions.add(button("Trust signer for encryption…",this::trustIncomingEncryption));
        saveAttachment.setEnabled(false);saveAttachment.addActionListener(e->saveReadAttachment());actions.add(saveAttachment);
        p.add(actions,BorderLayout.NORTH); return p;
    }
    private JPanel openPgpPanel(){
        JPanel p=panel();pgpStatus.setEditable(false);pgpStatus.setLineWrap(true);pgpStatus.setWrapStyleWord(true);p.add(new JScrollPane(pgpStatus));
        JPanel actions=new JPanel(new GridLayout(0,2,8,8));
        actions.add(button("Create OpenPGP public identity",()->{
            Identity id=identity;String path=adapter;
            job("Creating OpenPGP bindings (one PIN operation; three signatures)…",()->OpenPgp.createOwn(state().directory(),id,path==null?null:ExternalMu.executable(path)).description(),detail->{pgpStatus.setText(detail);offerBundleBackup();});
        }));
        actions.add(button("Create RFC 9980 OpenPGP identity from YubiKey…",()->{try{
            Identity id=identity;var entries=state().certificateBundle(id);int serial=entries.get(0).serial();String path=tokenAdapter(false);
            if(!Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm()))throw new IOException("Select the Level 3 hybrid YubiKey identity.");
            if(JOptionPane.showConfirmDialog(this,"Create ML-DSA-65 + Ed25519 signing and ML-KEM-768 + X25519 encryption certificates?\nUses existing slots 9c/84 and 9d/85 on YubiKey "+serial+". No keys are generated.\nThe previous OpenPGP identity will be preserved in a local backup.\nThe new identity will become selected; back it up to the YubiKey afterward.","Create RFC 9980 OpenPGP certificate",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            job("Checking extra keys and creating RFC 9980 OpenPGP certificate…",()->{
                java.security.PublicKey ed,x;
                try(var card=new OnKeyDesktop(serial)){OnKeyBundle.check(card,entries);byte[] edDer=card.publicKey("84"),xDer=card.publicKey("85");if(edDer==null||xDer==null)throw new IOException("Provision Ed25519 in empty slot 84 and X25519 in empty slot 85 first.");ed=java.security.KeyFactory.getInstance("Ed25519","BC").generatePublic(new java.security.spec.X509EncodedKeySpec(edDer));x=java.security.KeyFactory.getInstance("X25519","BC").generatePublic(new java.security.spec.X509EncodedKeySpec(xDer));}
                var own=OpenPgp.createRfc9980(id,ExternalMu.executable(path),ed,x);OpenPgp.replaceOwn(state().directory(),id,own);return own.description();
            },detail->{pgpRecipient=null;pgpSigner=null;pgpStatus.setText(detail);offerBundleBackup();});
        }catch(Exception e){error(e);}}));
        actions.add(button("Import my OpenPGP public identity…",()->{
            Path file=choose(false,"Import my OpenPGP public identity");if(file==null)return;Identity id=identity;
            job("Checking public key bindings…",()->OpenPgp.saveOwn(state().directory(),id,readPgp(file)).description(),pgpStatus::setText);
        }));
        actions.add(button("Export my OpenPGP public key…",()->{
            Path file=chooseSave("Export public OpenPGP key","PQ-Mail-public.asc","asc");if(file==null)return;Identity id=identity;
            job("Exporting public key…",()->{Files.write(file,OpenPgp.loadOwn(state().directory(),id).export(),StandardOpenOption.CREATE_NEW);return "Public key exported; no private keys or PINs included.";},pgpStatus::setText);
        }));
        actions.add(button("Use my OpenPGP key as recipient",()->{try{selectPgpRecipient(OpenPgp.loadOwn(state().directory(),identity));}catch(Exception e){error(e);}}));
        actions.add(button("Find key on keys.openpgp.org…",()->{
            String query=JOptionPane.showInputDialog(this,"Email address or full fingerprint.\nThis lookup is sent to keys.openpgp.org; downloading a certificate does not establish trust.","Find OpenPGP key",JOptionPane.QUESTION_MESSAGE);
            if(query==null)return;
            job("Looking up OpenPGP public certificate…",()->OpenPgpKeyserver.lookup(query),key->{try{
                JTextArea review=new JTextArea(key.description(),10,65);review.setEditable(false);review.setLineWrap(true);review.setWrapStyleWord(true);
                int choice=JOptionPane.showOptionDialog(this,new JScrollPane(review),"Review keyserver certificate",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,new Object[]{"Use for encryption","Use to verify signatures","Cancel"},"Cancel");
                if(choice==0){selectPgpRecipient(key);}else if(choice==1){savePgpSigner(key);}
            }catch(Exception e){error(e);}});
        }));
        actions.add(button("Import recipient OpenPGP public key…",()->importPgpContact(true)));
        actions.add(button("Import sender OpenPGP public key…",()->importPgpContact(false)));
        actions.add(button("Verify with my OpenPGP key",()->{pgpSigner=null;pgpStatus.setText("Incoming OpenPGP verification uses the selected identity's public key.");}));
        p.add(actions,BorderLayout.NORTH);p.add(new JLabel("<html>Level 3: RFC 9980 Ed25519/X25519, or experimental NIST/Brainpool draft P-384 hybrid. Incoming v4 classical signatures are supported; outgoing signing requires a hybrid PQ profile.<br>Existing keys are reused; no YubiKey slots are changed. Import the same public identity on other devices to preserve fingerprints.<br>Self-signature verification does not establish trust. Reads signed HTML and multipart PGP/MIME as text. Attached public certificates can verify signatures without being saved or trusted. Use S/MIME for outgoing attachments.</html>"),BorderLayout.SOUTH);return p;
    }
    private byte[] readPgp(Path file)throws IOException{if(Files.size(file)>128*1024)throw new IOException("OpenPGP public key exceeds 128 KiB");return Files.readAllBytes(file);}
    private void importPgpContact(boolean recipientRole){
        Path file=choose(false,"Import "+(recipientRole?"recipient":"sender")+" OpenPGP public key");if(file==null)return;
        job("Verifying OpenPGP key bindings…",()->new OpenPgp.PublicIdentity(readPgp(file)),key->{
            try{if(JOptionPane.showConfirmDialog(this,key.description(),"Use this OpenPGP public key?",JOptionPane.OK_CANCEL_OPTION)==JOptionPane.OK_OPTION){if(recipientRole){selectPgpRecipient(key);}else savePgpSigner(key);pgpStatus.setText(key.description());}}catch(Exception e){error(e);}
        });
    }
    private void savePgpSigner(OpenPgp.PublicIdentity key)throws Exception{
        java.util.List<String> emails=key.legacy==null?java.util.List.of(key.email):key.legacy.emails;
        String email=emails.size()==1?emails.getFirst():(String)JOptionPane.showInputDialog(this,"Choose the certified email address for this contact. Trust applies only to that address.","Save OpenPGP contact",JOptionPane.QUESTION_MESSAGE,null,emails.toArray(),key.email);
        if(email==null)return;state().rememberPgp(key,email);pgpSigner=key;refreshContacts();pgpStatus.setText(pgpContactDescription(key,email));
    }
    private String pgpContactDescription(OpenPgp.PublicIdentity key,String email)throws Exception{return key.description().replace("Trust is not established; confirm the fingerprint independently.",pgpTrustStatus(key,email)+"\nTrust scope: "+email+" / "+key.fingerprint());}
    private String pgpTrustStatus(OpenPgp.PublicIdentity key,String email){
        try{return state().isPgpTrusted(email,key.fingerprint())?"Trusted email / primary-key fingerprint":"Not trusted — verify the full fingerprint with the owner";}catch(Exception e){return "Not trusted — certificate unavailable or invalid";}
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
        top.add(google);top.add(left(button("Mail servers…",this::mailServerSettings),new JLabel("Manual IMAP / SMTP settings · passwords requested at connection")));p.add(top,BorderLayout.NORTH);
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
    private static String credentialStore(){return DesktopState.windows()?"Windows Credential Manager":DesktopState.linux()?"Linux Secret Service":"Mac Keychain";}
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
        actions.add(button("Import OpenPGP contact…",()->importPgpContact(false)));actions.add(button("Refresh",this::refreshContacts));p.add(actions,BorderLayout.NORTH);
        certificateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);certificateTable.setAutoCreateRowSorter(true);certificateTable.setRowHeight(30);
        certificateTable.setDefaultRenderer(Object.class,new javax.swing.table.DefaultTableCellRenderer(){public Component getTableCellRendererComponent(JTable t,Object value,boolean selected,boolean focus,int row,int column){putClientProperty("html.disable",Boolean.TRUE);return super.getTableCellRendererComponent(t,value,selected,focus,row,column);}});
        certificateTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);int[] widths={190,90,115,85,290,290,480};for(int i=0;i<widths.length;i++)certificateTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);certificateTable.setToolTipText("OpenPGP: current valid signing keys and the encryption subkey used for outgoing messages. Scroll horizontally for full fingerprints.");p.add(new JScrollPane(certificateTable));
        JPanel bottom=new JPanel(new GridLayout(0,1));JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(button("Details…",this::contactDetails));controls.add(button("Mark trusted…",()->setContactTrust(true)));controls.add(button("Remove trust",()->setContactTrust(false)));controls.add(button("Use selected certificate",this::useContact));controls.add(button("Export…",this::exportContact));controls.add(button("Remove",this::removeContact));bottom.add(controls);
        bottom.add(new JLabel("OpenPGP trust binds one email to its full primary-key fingerprint. Importing or selecting a certificate never grants trust."));p.add(bottom,BorderLayout.SOUTH);return p;
    }
    private DesktopState.Contact selectedContact(){int row=certificateTable.getSelectedRow();return row<0?null:certificateContacts.get(certificateTable.convertRowIndexToModel(row));}
    private void refreshContacts(){
        try{var all=new java.util.ArrayList<>(state().contacts());all.addAll(state().pgpContacts());certificateContacts=java.util.List.copyOf(all);certificateModel.setRowCount(0);
            for(var contact:certificateContacts){if(contact.role().equals("OpenPGP")){
                try{var key=state().pgpCertificate(contact);pgpRecipients.remember(key);certificateModel.addRow(new Object[]{contact.email(),"OpenPGP",state().isPgpTrusted(contact.email(),key.fingerprint())?"Trusted":"Not trusted","v"+key.version(),key.signingAlgorithms(),key.encryptionAlgorithm(),key.fingerprint()});}
                catch(Exception invalid){certificateModel.addRow(new Object[]{contact.email(),"OpenPGP","Unavailable / invalid","Unknown","Refresh or reimport","Refresh or reimport",state().get("pgp."+contact.id()+".fingerprint","")});}
            }else{var certificate=state().contactCertificate(contact);certificateModel.addRow(new Object[]{contact.email(),contact.role(),state().isTrusted(certificate,contact.role())?"Trusted":"Not trusted","X.509 v"+certificate.getVersion(),contact.role().equals("signing")?certificate.getPublicKey().getAlgorithm():"—",contact.role().equals("encryption")?certificate.getPublicKey().getAlgorithm():"—",Identity.fingerprint(certificate)});}}
            refreshOutgoingEncryption();if(usePgp())refreshPgpChoices();
        }catch(Exception e){error(e);}
    }
    private boolean pgpContactAction(DesktopState.Contact contact,String action){
        if(!contact.role().equals("OpenPGP"))return false;
        try{
            if(action.equals("remove")){
                if(JOptionPane.showConfirmDialog(this,"Remove saved OpenPGP contact and trust for "+contact.email()+"?\nThe public certificate is retained under removed-contacts.","Remove OpenPGP contact",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return true;
                state().removePgp(contact);pgpRecipients.clear();pgpRecipient=null;pgpSigner=null;encrypt.setSelected(false);refreshContacts();refreshReadTrust();return true;
            }
            if(action.equals("untrust")){state().setPgpTrusted(contact,false);refreshContacts();refreshReadTrust();return true;}
            var key=state().pgpCertificate(contact);String detail="Contact email: "+contact.email()+"\nFull primary-key fingerprint: "+key.fingerprint()+"\n"+key.profile()+"\nVersion: v"+key.version()+"\nSigning: "+key.signingAlgorithms()+"\nEncryption: "+key.encryptionAlgorithm()+"\n"+pgpTrustStatus(key,contact.email())+"\n\n"+key.encryptionDescription();
            if(action.equals("trust")){
                var choices=new PgpTrustSelectionPanel(state(),key,contact.email());
                if(JOptionPane.showOptionDialog(this,choices,"Trust OpenPGP email addresses",JOptionPane.DEFAULT_OPTION,JOptionPane.WARNING_MESSAGE,null,new Object[]{"Save trust choices","Cancel"},"Cancel")==0){
                    state().setPgpTrustSelection(key,choices.selectedEmails());refreshContacts();refreshReadTrust();status.setText("OpenPGP trust choices saved for "+choices.selectedEmails().size()+" email address(es)");
                }
            }else if(action.equals("details"))JOptionPane.showMessageDialog(this,detail,"OpenPGP contact",JOptionPane.INFORMATION_MESSAGE);
            else if(action.equals("export")){Path file=chooseSave("Export OpenPGP contact","OpenPGP-public.asc","asc");if(file!=null)Files.write(file,key.export(),StandardOpenOption.CREATE_NEW);}
            else if(action.equals("use")){
                Object[] choices=key.canEncrypt()?new Object[]{"Encrypt to contact","Verify signatures","Cancel"}:new Object[]{"Verify signatures","Cancel"};
                int choice=JOptionPane.showOptionDialog(this,detail,"Use OpenPGP contact",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,choices,"Cancel");
                if(choice>=0&&choices[choice].equals("Encrypt to contact")){to.setText(contact.email());selectPgpRecipient(key);mailFormat.setSelectedIndex(1);tabs.setSelectedIndex(0);}
                else if(choice>=0&&choices[choice].equals("Verify signatures")){pgpSigner=key;pgpStatus.setText(detail);status.setText("Saved OpenPGP verification contact selected");}
            }
        }catch(Exception e){error(e);}return true;
    }

    private void contactDetails(){
        var contact=selectedContact();if(contact==null)return;if(pgpContactAction(contact,"details"))return;
        try{var certificate=state().contactCertificate(contact);JTextArea text=new JTextArea("Email: "+contact.email()+"\nPurpose: "+contact.role()+"\nSubject: "+certificate.getSubjectX500Principal()+"\nIssuer: "+certificate.getIssuerX500Principal()+"\nSAN: "+certificate.getSubjectAlternativeNames()+"\nAlgorithm: "+certificate.getPublicKey().getAlgorithm()+"\nValid: "+certificate.getNotBefore()+" through "+certificate.getNotAfter()+"\n\nSHA-256: "+Identity.fingerprint(certificate),12,65);text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);JOptionPane.showMessageDialog(this,new JScrollPane(text),"Certificate details",JOptionPane.PLAIN_MESSAGE);}catch(Exception e){error(e);}
    }
    private void useContact(){
        var contact=selectedContact();if(contact==null)return;if(pgpContactAction(contact,"use"))return;
        try{applyContact(contact,state().contactCertificate(contact));}catch(Exception e){error(e);}
    }
    private void applyContact(DesktopState.Contact contact,X509Certificate certificate)throws Exception{
        certificate.checkValidity();
        if(contact.role().equals("encryption")){recipient=certificate;recipientLabel.setText(contact.email()+" · "+certificate.getPublicKey().getAlgorithm());to.setText(contact.email());encrypt.setSelected(true);state().saveCertificate("recipient",certificate);refreshOutgoingEncryption();tabs.setSelectedIndex(0);status.setText("Encryption enabled for "+contact.email());}
        else{pinnedSigner=certificate;state().saveCertificate("pinned",certificate);status.setText(state().isTrusted(certificate,"signing")?"Trusted signing certificate selected":"Signing certificate selected but not trusted; use Mark trusted in Certificates");}
    }
    private void exportContact(){
        var contact=selectedContact();if(contact==null)return;if(pgpContactAction(contact,"export"))return;Path target=chooseSave("Export certificate", "recipient-certificate.pem", "pem", "cer");if(target==null)return;
        try{var certificate=state().contactCertificate(contact);Files.write(target,target.toString().toLowerCase().endsWith(".pem")?DesktopState.pem(certificate):certificate.getEncoded(),StandardOpenOption.CREATE_NEW);status.setText("Certificate exported");}catch(Exception e){error(e);}
    }
    private void removeContact(){
        var contact=selectedContact();if(contact==null)return;if(pgpContactAction(contact,"remove"))return;
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
        hardware.add(button("Select YubiKey identity",()->openSaved((DesktopState.SavedIdentity)yubikeyIdentities.getSelectedItem())));
        hardware.add(button("Forget YubiKey identity…",this::forgetYubiKeyIdentity));p.add(hardware);
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
        p.add(left(button("Share certificates…",this::shareCertificates),button("Import certificate bundle from file…",()->{Path file=choose(false,"Import certificate bundle from file (.pqcert)");if(file!=null)importCertificateBundle(file);})));
        p.add(left(button("Back up certificate bundle to YubiKey…",()->onKeyAction(false)),button("Restore certificate bundle from YubiKey…",this::importOnKey)));
        JPanel settings=new JPanel(new FlowLayout(FlowLayout.LEFT));
        settings.add(button("YubiKey configuration…",this::configureYubiKey));
        settings.add(button("Update YubiKey certificate email…",this::reissueTokenCertificates));
        settings.add(button("Show saved identity files",()->{try{Desktop.getDesktop().open(state().directory().toFile());}catch(Exception e){error(e);}}));p.add(settings);
        p.add(Box.createVerticalStrut(24));
        p.add(new JLabel("Generated identities are local test identities. Exchange certificate fingerprints out of band."));
        p.add(new JLabel("Private keys stay local. Account passwords are not saved by this app."));
        return outer;
    }
    private void forgetYubiKeyIdentity(){
        var saved=(DesktopState.SavedIdentity)yubikeyIdentities.getSelectedItem();if(saved==null)return;
        String message="Forget this local identity?\n\n"+saved+"\n\nRemoves its saved certificates, slot mappings and local OpenPGP identity.\nOther pure/hybrid profiles are separate and remain saved.\nNo YubiKey connection is needed. Device keys, certificates and on-key bundles\nare unchanged; a saved bundle can import this identity again.";
        if(JOptionPane.showConfirmDialog(this,message,"Forget YubiKey identity",JOptionPane.OK_CANCEL_OPTION,JOptionPane.WARNING_MESSAGE)!=JOptionPane.OK_OPTION)return;
        try{
            boolean active=identity!=null&&DesktopState.identityId(identity).equals(saved.id());
            state().forgetYubiKeyIdentity(saved.id());
            if(active){identity=null;adapter=null;kemAdapter=null;identityLabel.setText("No identity selected");pgpStatus.setText("Select an identity to use OpenPGP.");state().activate();}
            refreshSaved();status.setText("Local YubiKey identity forgotten. Device keys and certificates unchanged.");
        }catch(Exception e){error(e);}
    }
    private DesktopState state()throws Exception{
        if(desktopState==null){desktopState=DesktopState.open();desktopState.activate();}return desktopState;
    }
    private void refreshSaved(){
        syncingOutgoing=true;
        try{savedIdentities.removeAllItems();softwareIdentities.removeAllItems();yubikeyIdentities.removeAllItems();outgoingIdentity.removeAllItems();if(desktopState==null)return;
            String selected=desktopState.get("selected.identity","");
            for(var saved:desktopState.selectableIdentities()){savedIdentities.addItem(saved);(saved.passwordRequired()?softwareIdentities:yubikeyIdentities).addItem(saved);if(outgoingAllowed(saved))outgoingIdentity.addItem(saved);if(saved.id().equals(selected)){savedIdentities.setSelectedItem(saved);(saved.passwordRequired()?softwareIdentities:yubikeyIdentities).setSelectedItem(saved);if(outgoingAllowed(saved))outgoingIdentity.setSelectedItem(saved);}}
            if(usePgp()&&(identity==null||!Identity.HYBRID_65_P384_SIGN.equals(identity.signatureAlgorithm())))outgoingIdentity.setSelectedIndex(-1);
        }finally{syncingOutgoing=false;}
    }
    private boolean outgoingAllowed(DesktopState.SavedIdentity saved){
        if(!usePgp())return true;
        try{return Identity.HYBRID_65_P384_SIGN.equals(Identity.readCertificate(desktopState.directory().resolve("identities").resolve(saved.id()).resolve("signing.cer")).getPublicKey().getAlgorithm());}catch(Exception e){return false;}
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
            outgoingEncryption.setEnabled(!usePgp()&&encrypt.isSelected());
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
            if(identity==null||identity.signingKey()!=null)throw new IOException("Select a saved YubiKey identity first");
            DesktopState settings=state();JTextField email=new JTextField(settings.get("google.email",from.getText()),30);
            JTextField extraEmails=new JTextField(30);
            JPanel prompt=new JPanel(new GridLayout(0,1,0,8));prompt.add(new JLabel("Primary email address for your YubiKey certificates"));prompt.add(email);
            prompt.add(new JLabel("Additional subject alternative email addresses (up to 4, comma-separated)"));prompt.add(extraEmails);
            prompt.add(new JLabel("Reuses this identity's YubiKey keys and preserves old identities. Two PIN prompts per profile."));
            JCheckBox refreshPgp=new JCheckBox("Also create/preserve OpenPGP public identity for supported profiles",true);prompt.add(refreshPgp);
            if(JOptionPane.showConfirmDialog(this,prompt,"Update YubiKey certificate email",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            String address=email.getText().trim();var extra=Identity.additionalEmails(address,extraEmails.getText());
            String executable=settings.adapter(false);if(executable==null)throw new IOException("Configure a token signing adapter first");
            var profiles=new java.util.LinkedHashMap<String,CertificateBundle.Entry>();
            for(var entry:settings.certificateBundle(identity))profiles.put(entry.identity().signatureAlgorithm(),entry);
            boolean withPgp=refreshPgp.isSelected();
            if(profiles.isEmpty())throw new IOException("Import a certificate-only token identity first");
            job("Signing new certificates with existing token keys…",()->{
                var updated=new java.util.ArrayList<Identity>();
                for(var entry:profiles.values()){
                    Identity old=entry.identity();settings.activateIdentity(old);
                    Identity renewed=old.reissue(address,ExternalMu.executable(executable),extra);
                    String saved=settings.remember(renewed,address+" · "+renewed.signatureAlgorithm(),null);
                    settings.bindToken(saved,Integer.toString(entry.serial()),entry.traditionalSlot(),entry.kemSlot(),entry.ecdhSlot());updated.add(renewed);
                    if(withPgp&&OpenPgp.supported(renewed)){
                        settings.activateIdentity(renewed);
                        if(Files.exists(OpenPgp.ownPath(settings.directory(),old))&&OpenPgp.email(old).equals(OpenPgp.email(renewed)))OpenPgp.saveOwn(settings.directory(),renewed,OpenPgp.loadOwn(settings.directory(),old).encoded);
                        else OpenPgp.createOwn(settings.directory(),renewed,ExternalMu.executable(executable));
                    }
                }
                return updated.getLast();
            },renewed->{
                setIdentity(renewed);refreshSaved();from.setText(address);to.setText(address);recipient=renewed.encryptionCert();pinnedSigner=renewed.signingCert();
                try{settings.set("mail.from",address);settings.set("mail.to",address);settings.saveCertificate("pinned",pinnedSigner);if(recipient!=null)settings.saveCertificate("recipient",recipient);settings.save();}catch(Exception e){error(e);}
                if(recipient!=null)recipientLabel.setText(recipient.getPublicKey().getAlgorithm()+" · "+recipient.getSubjectX500Principal());
                try{refreshOutgoingEncryption();}catch(Exception e){error(e);}
                status.setText("New email certificates saved (DER and PEM). Token keys unchanged. No email sent.");offerBundleBackup();
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
        form.add(new JLabel("Generate "+profile.ml+" in 9c; "+profile.kem+" in 9d."));form.add(new JLabel("Also generate ECDSA and ECDH "+(profile.category==2?"P-256":"P-384")+" in 83 and 82."));
        form.add(new JLabel("All keys: PIN Always. Touch required: 9c / 9d; no touch: 82 / 83."));
        JCheckBox createPgp=new JCheckBox(profile==TokenProfile.LEVEL5?"Also create classical P-384 OpenPGP identity (not PQ)":"Also create hybrid OpenPGP public identity",profile!=TokenProfile.LEVEL2);createPgp.setEnabled(profile!=TokenProfile.LEVEL2);form.add(createPgp);
        form.add(new JLabel(profile!=TokenProfile.LEVEL2?"Uncheck to opt out. OpenPGP adds signing operations; Level 5 uses slots 83 / 82 only.":"OpenPGP is not supported for Level 2."));
        form.add(new JLabel("YubiKey PIN"));form.add(pin);form.add(factory);form.add(new JLabel("Management key (hex, only if not factory default)"));form.add(management);
        form.add(new JLabel("Creating keys is not atomic: a failure can leave some slots provisioned. No automatic retry."));
        if(JOptionPane.showConfirmDialog(this,form,"Generate keys on empty YubiKey",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){pin.setText("");management.setText("");return;}
        char[] secret=pin.getPassword(),admin=factory.isSelected()?"010203040506070801020304050607080102030405060708".toCharArray():management.getPassword();pin.setText("");management.setText("");
        if(secret.length<6||secret.length>8||!new String(secret).matches("[ -~]+")||!new String(admin).matches("(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{48}|[a-fA-F0-9]{64})")){Arrays.fill(secret,'\0');Arrays.fill(admin,'\0');error(new IOException("Use a 6–8 character ASCII PIN and a valid hexadecimal management key"));return;}
        boolean pgpRequested=createPgp.isSelected();
        job("Generating keys on YubiKey "+serial+"…",()->{
            Path parent=state().directory().resolve("token-setups");Files.createDirectories(parent);Path folder=parent.resolve(java.util.UUID.randomUUID().toString());
            try{
                var keys=TokenProvision.create(serial,profile,folder,secret,admin);
                var manifest=new java.util.Properties();manifest.setProperty("serial",serial);manifest.setProperty("email",email);manifest.setProperty("hybrid","true");manifest.setProperty("preferHybrid","true");manifest.setProperty("profile",profile.code);manifest.setProperty("additionalEmails",String.join(",",extra));manifest.setProperty("createOpenPgp",Boolean.toString(pgpRequested));
                try(var out=Files.newOutputStream(folder.resolve("setup.properties"),StandardOpenOption.CREATE_NEW)){manifest.store(out,"Public setup metadata; keys remain on YubiKey");}
                return issueTokenIdentities(serial,email,true,keys,true,profile,extra,pgpRequested);
            }finally{Arrays.fill(secret,'\0');Arrays.fill(admin,'\0');if(identity!=null)state().activateIdentity(identity);}
        },created->{setIdentity(created);refreshSaved();from.setText(email);status.setText("YubiKey identities saved. Keys generated on serial "+serial+"; no private keys stored on this Mac.");offerBundleBackup();});
    }
    private Identity issueTokenIdentities(String serial,String email,boolean hybrid,java.util.Map<String,java.security.PublicKey> keys,boolean preferHybrid,TokenProfile profile,java.util.List<String> extra,boolean createPgp)throws Exception{
                String traditional=keys.containsKey("83")?"83":"9a";state().set("token.serial",serial);state().set("token.rsaSlot",traditional);state().set("token.kemSlot","9d");state().set("token.ecdhSlot","82");state().activate();
                String signer=DesktopState.resources().resolve("adapters/pkcs11-mu.py").toString();Identity selected=null;
                for(boolean composite:hybrid?new boolean[]{!preferHybrid,preferHybrid}:new boolean[]{false}){
                    selected=Identity.forTokenProfile(email,profile,keys.get("9c"),composite?keys.get(traditional):null,keys.get("9d"),composite?keys.get("82"):null,ExternalMu.executable(signer),extra);
                    String id=state().remember(selected,email+" · "+selected.signatureAlgorithm(),null);state().bindToken(id,serial,traditional,"9d","82");
                    if(createPgp&&OpenPgp.supported(selected)){state().activateIdentity(selected);OpenPgp.createOwn(state().directory(),selected,ExternalMu.executable(signer));}
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
            try{return issueTokenIdentities(serial,email,hybrid,keys,Boolean.parseBoolean(values.getProperty("preferHybrid",Boolean.toString(hybrid))),profile,Identity.additionalEmails(email,values.getProperty("additionalEmails","")),Boolean.parseBoolean(values.getProperty("createOpenPgp","false")));}finally{if(identity!=null)state().activateIdentity(identity);}
        },created->{setIdentity(created);refreshSaved();status.setText("Pending public certificates completed for the existing YubiKey keys");offerBundleBackup();});
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
        try{if(OpenPgp.supported(id))pgpRecipients.remember(OpenPgp.loadOwn(state().directory(),id));}catch(Exception ignored){}
        identityLabel.setText(id.signatureAlgorithm()+" · "+id.signingCert().getSubjectX500Principal());status.setText("Identity ready. Import a recipient certificate to encrypt.");}

    private char[] managementKey(){
        JPasswordField field=new JPasswordField();JCheckBox factory=new JCheckBox("Use factory-default AES-192 management key");
        JPanel p=new JPanel(new GridLayout(0,1));p.add(new JLabel("Management key authorizes public storage / migration. It is not the PIN."));p.add(field);p.add(factory);
        int choice=JOptionPane.showConfirmDialog(this,p,"YubiKey management authorization",JOptionPane.OK_CANCEL_OPTION);
        char[] result=choice==JOptionPane.OK_OPTION?(factory.isSelected()?"010203040506070801020304050607080102030405060708".toCharArray():field.getPassword()):null;field.setText("");return result;
    }
    private void offerBundleBackup(){
        if(identity==null||identity.signingKey()!=null)return;
        if(JOptionPane.showOptionDialog(this,"Back up the current certificate bundle to this YubiKey now?\nIncludes pure/hybrid S/MIME certificates, any saved OpenPGP public identity,\nserial and slot mappings. This regenerates the bundle; it does not generate keys.\nNo private keys, PINs or account credentials are backed up.","Back up certificate bundle",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,new Object[]{"Back up now","Not now"},"Back up now")==0)onKeyAction(false);
    }
    private void onKeyAction(boolean migrate){try{
        var entries=state().certificateBundle(identity);String review=CertificateBundle.review(entries)+"\nSaved OpenPGP public identities: "+OnKeyBundle.collect(entries,state().directory()).stream().filter(p->p.pgp().length>0).count();
        String explanation=migrate?"Move the existing ECDSA private key from 9a to empty 83, preserving its public key. Update all matching local mappings. No key generation. If interrupted, inspect/recover before retrying. Save the on-key bundle again afterward.":"Regenerate a signed bundle from the current saved S/MIME certificates, OpenPGP public identities and slot mappings, then back it up on this YubiKey. Anyone holding the key can read them. No passwords, OAuth credentials or trust settings are included. A full key can reject this write; the previous bank is retained.";
        JTextArea text=new JTextArea(explanation+"\n\n"+review,18,76);text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);
        if(JOptionPane.showConfirmDialog(this,new JScrollPane(text),migrate?"Migrate 9a → 83":"Back up certificate bundle to YubiKey",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        char[] admin=managementKey();if(admin==null)return;
        job(migrate?"Migrating existing key; do not disconnect…":"Signing and writing public bundle…",()->{
            try{
                if(migrate){
                    Path backup=state().directory().resolve("migration-"+entries.get(0).serial()+"-"+System.currentTimeMillis()+".pqcert");Files.write(backup,CertificateBundle.encode(entries),StandardOpenOption.CREATE_NEW);
                    try(var card=new OnKeyDesktop(entries.get(0).serial())){OnKeyBundle.migrate(card,entries,admin);}
                    state().migrateTokenBindings(entries);return "Key moved to 83 and local mappings updated. Save certificates on YubiKey to refresh its bundle. Public backup: "+backup;
                }
                var profiles=OnKeyBundle.collect(entries,state().directory());int signer=0;for(int i=0;i<entries.size();i++)if(entries.get(i).identity().signingCert().getPublicKey() instanceof org.bouncycastle.jcajce.CompositePublicKey)signer=i;
                state().activateIdentity(entries.get(signer).identity());byte[] encoded=OnKeyBundle.sign(profiles,signer,ExternalMu.executable(tokenAdapter(false)));
                try(var card=new OnKeyDesktop(entries.get(0).serial())){OnKeyStorage.save(card,encoded,admin);}return "Public certificates and configuration saved and read-back verified on YubiKey.";
            }finally{Arrays.fill(admin,'\0');if(identity!=null)state().activateIdentity(identity);}
        },result->{refreshSaved();status.setText(result);});
    }catch(Exception e){error(e);}}
    private void importOnKey(){job("Reading YubiKey public bundle (no PIN)…",()->{try(var card=new OnKeyDesktop(0)){return OnKeyStorage.load(card);}},bundle->{try{
        JTextArea text=new JTextArea(bundle.review(),18,76);text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);
        if(JOptionPane.showConfirmDialog(this,new JScrollPane(text),"Restore verified certificate bundle — trust unchanged",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        state().importOnKey(bundle);refreshSaved();status.setText("On-key identities imported. Select pure or hybrid to use them.");
    }catch(Exception e){error(e);}});}

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
        if(usePgp()&&(!Identity.HYBRID_65_P384_SIGN.equals(identity.signatureAlgorithm())||!attachmentModel.isEmpty())){error(new IOException("Outgoing OpenPGP requires a Level 3 hybrid signing identity and plain text. Use S/MIME for attachments."));return;}
        if(usePgp()&&encrypt.isSelected()&&(pgpRecipient==null||!pgpRecipient.matchesEmail(to.getText().trim())||!pgpRecipient.canEncrypt())){error(new IOException("Wait for a matching, usable recipient key in Compose, or import it from the OpenPGP tab."));tabs.setSelectedIndex(5);return;}
        if(encrypt.isSelected()&&(usePgp()?!pgpRecipient.quantumEncryption():!CryptoWarnings.pq(recipient.getPublicKey(),false))){
            String algorithm=usePgp()?pgpRecipient.encryptionDescription():recipient.getPublicKey().getAlgorithm();
            if(JOptionPane.showOptionDialog(this,CryptoWarnings.encryption(algorithm),"Non-PQ encryption",JOptionPane.DEFAULT_OPTION,JOptionPane.WARNING_MESSAGE,null,new Object[]{"Cancel","Encrypt anyway"},"Cancel")!=1)return;
        }
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
        },result->{
            status.setText(result);
            if(send){JTextArea receipt=new JTextArea("Message sent\n\nTo: "+t+"\nSubject: "+s+"\nVia: "+(a.oauth?"Gmail API":a.host)+"\n\nThe sending service accepted the message. This is not a delivery or read receipt.",7,58);receipt.setEditable(false);receipt.setLineWrap(true);receipt.setWrapStyleWord(true);receipt.setOpaque(false);JOptionPane.showMessageDialog(this,receipt,"Message sent",JOptionPane.INFORMATION_MESSAGE);}
        });
    }
    private ReadResult display(MimeMessage message,Identity id,X509Certificate pin)throws Exception {
        byte[] encoded=MailEngine.encode(message);
        if(OpenPgp.isOpenPgp(encoded)){
            OpenPgp.PublicIdentity own=null;boolean encrypted=OpenPgp.parts(encoded).encrypted();
            if(encrypted)own=OpenPgp.loadOwn(state().directory(),id);
            String mailbox="";try{var addresses=jakarta.mail.internet.InternetAddress.parseHeader(message.getHeader("From",null),true);if(addresses.length==1)mailbox=addresses[0].getAddress().toLowerCase(java.util.Locale.ROOT);}catch(Exception ignored){}
            var candidates=new java.util.ArrayList<OpenPgp.PublicIdentity>();
            if(pgpSigner!=null)candidates.add(pgpSigner);else for(var c:state().pgpContacts())if(c.email().equalsIgnoreCase(mailbox))try{candidates.add(state().pgpCertificate(c));}catch(Exception ignored){}
            for(var attached:AttachedOpenPgp.find(message))if(candidates.stream().noneMatch(k->{try{return k.fingerprint().equals(attached.fingerprint());}catch(Exception e){return false;}}))candidates.add(attached);
            if(candidates.isEmpty()){if(own==null)try{own=OpenPgp.loadOwn(state().directory(),id);}catch(Exception ignored){}if(own!=null)candidates.add(own);}
            // Decryption is performed once; selecting among saved signer certificates must not repeat a PIN operation.
            if(encrypted&&candidates.size()>1)throw new IOException("Multiple OpenPGP signer certificates match From. Select the sender under Certificates before decrypting.");
            Exception failure=null;
            for(var signer:candidates)try{var opened=OpenPgp.open(encoded,signer,own,id,kemAdapter==null?null:ExternalKem.executable(kemAdapter));opened=new OpenPgp.Opened(opened.text(),opened.email(),opened.fingerprint(),opened.encrypted(),signer.matchesEmail(mailbox),opened.profile(),opened.postQuantum());return new ReadResult(opened.display(),null,message.getSubject(),opened,signer.matchesEmail(mailbox)?mailbox:null,signer);}catch(Exception e){failure=e;}
            throw failure==null?new IOException("No matching OpenPGP signer certificate"):failure;
        }
        if(MailPreview.isOrdinary(message))return new ReadResult(MailPreview.display(message),null,message.getSubject());
        var opened=MailEngine.open(message,id,pin,kemAdapter==null?null:ExternalKem.executable(kemAdapter));
        return new ReadResult(null,opened,message.getSubject());
    }
    private String formatRead(ReadResult result)throws Exception{
        if(result.pgp()!=null){boolean trusted=false;try{trusted=result.pgpMailbox()!=null&&state().isPgpTrusted(result.pgpMailbox(),result.pgp().fingerprint());}catch(Exception ignored){}
            return result.pgp().display().replace("Signature valid; trust not established",trusted?"Signature valid; TRUSTED email / primary-key fingerprint: "+result.pgpMailbox():"Signature valid; NOT TRUSTED for this sender email / primary-key fingerprint");}
        if(result.verified()==null)return result.plain();var o=result.verified();
        if(o.signerCertificate()==null)return "DECRYPTED · UNSIGNED MESSAGE\nSender and content are not signature-verified. Do not infer signer trust from encryption.\n\nOuter subject (unprotected): "+result.subject()+"\n\n"+o.text()+"\n\nAttachments: "+o.attachments();
        boolean trusted=state().isTrusted(o.signerCertificate(),"signing");
        return (CryptoWarnings.pq(o.signerCertificate().getPublicKey(),true)?"":CryptoWarnings.SIGNATURE)+"SIGNATURE VALID · "+o.signatureAlgorithm()+"\n"+(o.encrypted()?"Decryption succeeded; signed content verified":"Not encrypted")+"\n"+
            (trusted?"SIGNER TRUSTED: SHA-256 certificate fingerprint matches your saved trust":"SIGNER NOT TRUSTED: fingerprint has not been marked trusted")+"\n"+
            (o.fromMatches()?"Outer From matches certificate email (header itself is unsigned)":"WARNING: outer From does not match signing certificate")+
            "\nSHA-256: "+o.fingerprint()+"\n\nOuter subject (unprotected): "+result.subject()+"\n\n──────── Signed body ────────\n\n"+o.text()+"\n\nAttachments: "+o.attachments();
    }
    private void clearReadTrust(){currentRead=null;saveIncomingPgp.setEnabled(false);trustIncoming.setEnabled(false);saveAttachment.setEnabled(false);}
    private void showMessage(ReadResult result){
        try{showMessage(formatRead(result));currentRead=result;saveIncomingPgp.setEnabled(result.pgpCertificate()!=null);trustIncoming.setEnabled(result.pgpCertificate()!=null||(result.verified()!=null&&result.verified().signerCertificate()!=null));saveAttachment.setEnabled(result.verified()!=null&&!result.verified().attachments().isEmpty());}catch(Exception e){clearReadTrust();error(e);}
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
        var contact=selectedContact();if(contact==null)return;if(pgpContactAction(contact,trusted?"trust":"untrust"))return;
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
    private void saveIncomingPgpCertificate(){
        if(currentRead==null||currentRead.pgpCertificate()==null)return;
        try{var key=currentRead.pgpCertificate();String email=currentRead.pgpMailbox();
            if(email==null){var emails=key.certifiedEmails();email=(String)JOptionPane.showInputDialog(this,"From does not match this certificate. Choose a certified email to save.","Save OpenPGP certificate",JOptionPane.WARNING_MESSAGE,null,emails.toArray(),key.email);}
            if(email==null)return;
            JTextArea review=new JTextArea(key.description()+"\n\nSave contact: "+email+"\nSaving does not grant trust.",12,65);review.setEditable(false);
            if(JOptionPane.showConfirmDialog(this,new JScrollPane(review),"Save sender OpenPGP certificate",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
            state().rememberPgp(key,email);refreshContacts();refreshReadTrust();status.setText("OpenPGP certificate saved; existing trust unchanged.");
        }catch(Exception e){error(e);}
    }
    private void trustIncomingSigner(){
        if(currentRead!=null&&currentRead.pgpCertificate()!=null){
            try{var key=currentRead.pgpCertificate();var choices=new PgpTrustSelectionPanel(state(),key,currentRead.pgpMailbox()==null?key.email:currentRead.pgpMailbox());
                if(JOptionPane.showOptionDialog(this,choices,"Trust OpenPGP email addresses",JOptionPane.DEFAULT_OPTION,JOptionPane.WARNING_MESSAGE,null,new Object[]{"Save trust choices","Cancel"},"Cancel")==0){state().setPgpTrustSelection(key,choices.selectedEmails());refreshContacts();refreshReadTrust();status.setText("OpenPGP trust choices saved.");}
            }catch(Exception e){error(e);}return;
        }
        if(currentRead==null||currentRead.verified()==null||currentRead.verified().signerCertificate()==null)return;
        try{var verified=currentRead.verified();var certificate=verified.signerCertificate();
            if(!confirmTrust(certificate,"signing",verified.fromMatches()?"The signature is valid. This does not by itself prove the sender's identity.":"WARNING: the outer From address does not match this certificate. Trust applies to the certificate SANs, not the outer From."))return;
            var names=certificate.getSubjectAlternativeNames();if(names==null)throw new IOException("Signer has no email SAN");
            boolean saved=false;for(var name:names)if(Integer.valueOf(1).equals(name.get(0))){state().rememberContact(certificate,name.get(1).toString(),"signing");saved=true;}
            if(!saved)throw new IOException("Signer has no email SAN");
            state().setTrusted(certificate,"signing",true);refreshContacts();refreshReadTrust();status.setText("Incoming signer's SHA-256 certificate fingerprint saved as trusted");
        }catch(Exception e){error(e);}
    }
    private void mailServerSettings(){
        try{
            DesktopState settings=state();JPanel form=new JPanel(new GridLayout(0,1,0,6));
            JTextField imapHost=new JTextField(settings.get("imap.host","")),imapPort=new JTextField(settings.get("imap.port","993")),imapUser=new JTextField(settings.get("imap.user",from.getText()));
            JTextField smtpHost=new JTextField(settings.get("smtp.host","")),smtpPort=new JTextField(settings.get("smtp.port","587")),smtpUser=new JTextField(settings.get("smtp.user",from.getText()));
            form.add(new JLabel("IMAP — TLS connection (normally port 993)"));form.add(row("Host",imapHost));form.add(row("Port",imapPort));form.add(row("Username",imapUser));
            form.add(new JLabel("SMTP — required STARTTLS (normally port 587)"));form.add(row("Host",smtpHost));form.add(row("Port",smtpPort));form.add(row("Username",smtpUser));
            form.add(new JLabel("Passwords/app passwords are requested when connecting or sending; they are not saved."));
            form.add(new JLabel("Save does not connect or send. Gmail API continues to use Google sign-in."));
            while(JOptionPane.showOptionDialog(this,form,"Manual mail servers",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,new Object[]{"Save settings","Cancel"},"Save settings")==0){
                try{int ip=Integer.parseInt(imapPort.getText().trim()),sp=Integer.parseInt(smtpPort.getText().trim());if(ip<1||ip>65535||sp<1||sp>65535)throw new IllegalArgumentException("Ports must be between 1 and 65535");
                    for(String host:java.util.List.of(imapHost.getText().trim(),smtpHost.getText().trim()))if(host.contains("://")||host.matches(".*[\\s/].*"))throw new IllegalArgumentException("Enter a server hostname without a URL scheme, path or spaces");
                    settings.set("imap.host",imapHost.getText().trim());settings.set("imap.port",Integer.toString(ip));settings.set("imap.user",imapUser.getText().trim());
                    settings.set("smtp.host",smtpHost.getText().trim());settings.set("smtp.port",Integer.toString(sp));settings.set("smtp.user",smtpUser.getText().trim());settings.save();
                    status.setText("Mail server settings saved. Use Inbox → Connect IMAP, or Send → Other host (SMTP).");return;
                }catch(IllegalArgumentException invalid){JOptionPane.showMessageDialog(this,invalid.getMessage(),"Check mail server settings",JOptionPane.ERROR_MESSAGE);}
            }
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
