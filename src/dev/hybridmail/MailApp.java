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
    private Identity identity;
    private X509Certificate recipient, pinnedSigner;
    private String adapter;
    private final JTextField from = new JTextField("alice@example.test"), to = new JTextField("bob@example.test"), subject = new JTextField("A private conversation");
    private final JTextArea body = new JTextArea("Hello,\n\nThis message is signed using post-quantum cryptography.\n"), reader = new JTextArea();
    private final JCheckBox encrypt = new JCheckBox("Encrypt for recipient", true);
    private final JLabel identityLabel = new JLabel("No identity loaded"), recipientLabel = new JLabel("No recipient certificate"), tokenLabel = new JLabel("Signing: software"), pinLabel = new JLabel("No signer certificate pinned");
    private final JLabel status = new JLabel("Create or load an identity to begin. No network connection is made on startup.");
    private final JTabbedPane tabs = new JTabbedPane();
    public MailApp() {
        super("Hybrid Mail · S/MIME lab");
        setDefaultCloseOperation(EXIT_ON_CLOSE); setSize(1060, 800); setMinimumSize(new Dimension(850,650)); setLocationRelativeTo(null);
        JPanel root = new JPanel(new BorderLayout(0,18)); root.setBorder(new EmptyBorder(22,28,18,28)); setContentPane(root);
        JPanel heading = new JPanel(new BorderLayout()); JLabel title = new JLabel("Hybrid Mail"); title.setFont(title.getFont().deriveFont(Font.BOLD, 30f));
        heading.add(title, BorderLayout.NORTH); heading.add(new JLabel("ML-DSA & composite S/MIME  /  local development build"), BorderLayout.SOUTH); root.add(heading,BorderLayout.NORTH);
        tabs.addTab("Compose", composePanel()); tabs.addTab("Read & verify", readPanel()); tabs.addTab("Keys & token", keysPanel()); root.add(tabs);
        status.setBorder(new EmptyBorder(10,0,0,0)); root.add(status, BorderLayout.SOUTH);
        body.setLineWrap(true); body.setWrapStyleWord(true); body.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,16)); body.setMargin(new Insets(16,16,16,16));
        reader.setEditable(false); reader.setLineWrap(true); reader.setWrapStyleWord(true); reader.setFont(new Font(Font.MONOSPACED,Font.PLAIN,13)); reader.setMargin(new Insets(16,16,16,16));
    }
    private JPanel composePanel() {
        JPanel p = panel(); JPanel fields = new JPanel(new GridLayout(0,1,0,8));
        fields.add(row("From",from)); fields.add(row("To",to)); fields.add(row("Subject",subject)); fields.add(encrypt); p.add(fields,BorderLayout.NORTH);
        p.add(new JScrollPane(body));
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(new JLabel("Body is protected. Outer From / To / Subject headers are not signed or encrypted."),BorderLayout.NORTH);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        actions.add(button("Save signed .eml…", () -> compose(false))); actions.add(button("Send via SMTP…", () -> compose(true)));
        bottom.add(actions, BorderLayout.SOUTH); p.add(bottom,BorderLayout.SOUTH); return p;
    }
    private JPanel readPanel() {
        JPanel p = panel(); p.add(new JScrollPane(reader)); JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(button("Open .eml…", () -> {
            Path file = choose(false,"Open S/MIME message"); if(file == null)return;
            Identity id = identity; X509Certificate pin = pinnedSigner;
            job("Verifying message…", () -> { if(Files.size(file)>MailEngine.MAX_MESSAGE) throw new IOException("Message too large"); return display(MailEngine.parse(Files.readAllBytes(file)),id,pin); }, this::showMessage);
        }));
        actions.add(button("Fetch latest via IMAP…", () -> {
            Account a = account(false); if(a==null)return;
            Identity id=identity; X509Certificate pin=pinnedSigner;
            job("Fetching latest message…", () -> { try { return display(MailEngine.fetchLatest(a.host,a.port,a.user,new String(a.password)),id,pin); } finally { Arrays.fill(a.password,'\0'); } },this::showMessage);
        }));
        p.add(actions,BorderLayout.NORTH); return p;
    }
    private JPanel keysPanel() {
        JPanel outer = panel(); JPanel p = new JPanel(); p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS)); outer.add(p,BorderLayout.NORTH);
        p.add(section("1  Your identity",identityLabel));
        JPanel keys = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keys.add(button("Create identity…",this::generate)); keys.add(button("Load PKCS#12…",this::load));
        keys.add(button("Export signing certificate…",()->export(true))); keys.add(button("Export encryption certificate…",()->export(false))); p.add(keys);
        p.add(section("2  Recipient encryption certificate",recipientLabel));
        p.add(left(button("Import recipient certificate…", () -> importCert(false))));
        p.add(section("3  Pinned signer for verification",pinLabel));
        p.add(left(button("Pin signer certificate…", () -> importCert(true))));
        p.add(section("4  External μ signing",tokenLabel));
        JPanel token = new JPanel(new FlowLayout(FlowLayout.LEFT)); token.add(button("Choose adapter executable…",()->{
            Path path=choose(false,"Choose trusted external-mu adapter executable"); if(path==null)return;
            if(!Files.isExecutable(path)){error(new IOException("Select an executable adapter"));return;}
            adapter=path.toAbsolutePath().toString(); tokenLabel.setText("External adapter: " + path.getFileName() + " (hardware not detected)");
        })); token.add(button("Use software signer",()->{adapter=null;tokenLabel.setText("Signing: software");})); p.add(token);
        p.add(new JLabel("Adapter receives public key + 64-byte μ. Returned signatures are verified before use."));
        p.add(Box.createVerticalStrut(12));
        p.add(new JLabel("YubiKey transport is an extension point; no YubiKey firmware or APDU support is assumed."));
        p.add(Box.createVerticalStrut(24));
        p.add(new JLabel("Generated identities are local test identities. Exchange certificate fingerprints out of band."));
        p.add(new JLabel("Certificates, keys and account passwords stay local. Passwords are not saved by this app."));
        return outer;
    }
    private void generate() {
        JTextField email=new JTextField(from.getText()); JComboBox<String> mode=new JComboBox<>(new String[]{"Pure: ML-DSA-65 + ML-KEM-768","Hybrid: ML-DSA-65/ECDSA + ML-KEM-768/ECDH"});
        mode.setSelectedIndex(1); JPasswordField pass=new JPasswordField();
        JPanel p=new JPanel(new GridLayout(0,1,0,8)); p.add(new JLabel("Email address"));p.add(email);p.add(mode);p.add(new JLabel("New PKCS#12 password (12+ characters)"));p.add(pass);
        if(JOptionPane.showConfirmDialog(this,p,"Create local test identity",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        Path file=choose(true,"Save new identity (choose a new .p12 filename)");if(file==null)return;
        char[] password=pass.getPassword();String address=email.getText().trim();boolean hybrid=mode.getSelectedIndex()==1;
        job("Generating identity…",()->{try {Identity id=Identity.generate(address,hybrid);id.save(file,password);return id;}finally{Arrays.fill(password,'\0');}},id->{setIdentity(id);from.setText(address);});
    }
    private void load() {
        Path file=choose(false,"Load identity .p12");if(file==null)return;
        JPasswordField pass=new JPasswordField();if(JOptionPane.showConfirmDialog(this,pass,"Identity password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        char[] password=pass.getPassword();job("Loading identity…",()->{try{return Identity.load(file,password);}finally{Arrays.fill(password,'\0');}},this::setIdentity);
    }
    private void setIdentity(Identity id) {identity=id;identityLabel.setText(id.signatureAlgorithm()+" · "+id.signingCert().getSubjectX500Principal());status.setText("Identity ready. Import a recipient certificate to encrypt.");}
    private void export(boolean signing) {
        if(identity==null){error(new IOException("Load an identity first"));return;}
        X509Certificate c=signing?identity.signingCert():identity.encryptionCert();if(c==null){error(new IOException("No certificate available"));return;}
        Path file=choose(true,"Export public certificate (.cer)");if(file==null)return;
        job("Exporting certificate…",()->{Files.write(file,c.getEncoded(),StandardOpenOption.CREATE_NEW);return "Certificate exported";},status::setText);
    }
    private void importCert(boolean pin) {
        Path file=choose(false,pin?"Pin sender signing certificate":"Import recipient encryption certificate");if(file==null)return;
        job("Reading certificate…",()->Identity.readCertificate(file),cert->{
            try {
                String fp=Identity.fingerprint(cert);
                JTextArea detail=new JTextArea(cert.getSubjectX500Principal()+"\n"+cert.getPublicKey().getAlgorithm()+"\n\nSHA-256 fingerprint:\n"+fp+"\n\nConfirm this fingerprint with the owner before trusting it.");detail.setEditable(false);detail.setLineWrap(true);detail.setWrapStyleWord(true);detail.setColumns(60);detail.setRows(8);
                if(JOptionPane.showConfirmDialog(this,new JScrollPane(detail),"Trust this certificate for this session?",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
                if(pin){pinnedSigner=cert;pinLabel.setText(cert.getSubjectX500Principal().toString());}
                else{recipient=cert;recipientLabel.setText(cert.getPublicKey().getAlgorithm()+" · "+cert.getSubjectX500Principal());}
            } catch(Exception e){error(e);}
        });
    }
    private void compose(boolean send) {
        if(identity==null){error(new IOException("Create or load an identity first"));tabs.setSelectedIndex(2);return;}
        if(encrypt.isSelected()&&recipient==null){error(new IOException("Import recipient encryption certificate first"));tabs.setSelectedIndex(2);return;}
        Path file=send?null:choose(true,"Save signed S/MIME message (.eml)");if(!send&&file==null)return;
        Account a=send?account(true):null;if(send&&a==null)return;
        Identity id=identity; X509Certificate r=encrypt.isSelected()?recipient:null; ExternalMu.Backend backend=adapter==null?null:ExternalMu.executable(adapter);
        String f=from.getText().trim(),t=to.getText().trim(),s=subject.getText(),b=body.getText();
        if(send&&JOptionPane.showConfirmDialog(this,"Send this "+(r!=null?"signed and encrypted":"signed, unencrypted")+" message to "+t+"?","Send message",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){Arrays.fill(a.password,'\0');return;}
        job(send?"Signing and sending…":"Signing and saving…",()->{
            try {
                MimeMessage m=MailEngine.compose(id,f,t,s,b,r,backend);
                if(send)MailEngine.send(m,a.host,a.port,a.user,new String(a.password));
                else Files.write(file,MailEngine.encode(m),StandardOpenOption.CREATE_NEW);
                return send?"Message sent":"Saved "+file.getFileName();
            } finally {if(a!=null)Arrays.fill(a.password,'\0');}
        },status::setText);
    }
    private String display(MimeMessage m,Identity id,X509Certificate pin)throws Exception {
        var o=MailEngine.open(m,id,pin);
        return "SIGNATURE VALID · "+o.signatureAlgorithm()+"\n"+(o.encrypted()?"AES-256-GCM authenticated decryption succeeded":"Not encrypted")+"\n"+
            (o.pinned()?"Signer matches the certificate you pinned":"SIGNER NOT TRUSTED: no matching pinned certificate")+"\n"+
            (o.fromMatches()?"Outer From matches certificate email (header itself is unsigned)":"WARNING: outer From does not match signing certificate")+
            "\nSHA-256: "+o.fingerprint()+"\n\nOuter subject (unprotected): "+m.getSubject()+"\n\n──────── Signed body ────────\n\n"+o.text();
    }
    private void showMessage(String text){reader.setText(text);reader.setCaretPosition(0);tabs.setSelectedIndex(1);status.setText("Signature checked. Review signer trust and header status above.");}
    private record Account(String host,int port,String user,char[] password){}
    private Account account(boolean smtp){
        JTextField host=new JTextField(),port=new JTextField(smtp?"587":"993"),user=new JTextField(from.getText());JPasswordField pass=new JPasswordField();
        JPanel p=new JPanel(new GridLayout(0,1,0,6));p.add(new JLabel(smtp?"SMTP with required STARTTLS":"IMAP over TLS"));p.add(row("Host",host));p.add(row("Port",port));p.add(row("User",user));p.add(row("Password",pass));
        if(JOptionPane.showConfirmDialog(this,p,smtp?"SMTP account":"IMAP account",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return null;
        try {int n=Integer.parseInt(port.getText());if(n<1||n>65535||host.getText().isBlank())throw new IllegalArgumentException("Invalid host or port");return new Account(host.getText().trim(),n,user.getText(),pass.getPassword());}catch(Exception e){error(e);return null;}
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
    public static void main(String[]args){MailEngine.init();SwingUtilities.invokeLater(()->{try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ignored){}new MailApp().setVisible(true);});}
}
