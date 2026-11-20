package dev.hybridmail;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicTabbedPaneUI;

/** Mail-first navigation. Provider operations and secret access remain in MailApp. */
final class DesktopMailShell extends JPanel {
    static final Color TEAL=new Color(0x00566B),LIME=new Color(0xA4CE39),SURFACE=new Color(0xF1F7F5),INK=new Color(0x16383E);
    final JTabbedPane pages;
    final JPanel screens=new JPanel(new CardLayout());
    final JLabel title=new JLabel("Connect your email"),account=new JLabel("Choose a provider to sign in or reconnect"),activity=new JLabel(" ");
    final JProgressBar progress=new JProgressBar();
    final DesktopLoadingOverlay loading=new DesktopLoadingOverlay();
    final JButton inboxButton,composeButton,settingsButton;
    private boolean welcome=true;
    DesktopMailShell(JTabbedPane pages,JLabel status,Runnable gmail,Runnable microsoft,Runnable imap,Runnable lock){
        super(new BorderLayout(0,12));this.pages=pages;setBackground(SURFACE);setBorder(new EmptyBorder(18,20,12,20));
        JPanel heading=new JPanel(new BorderLayout(20,8));heading.setOpaque(false);
        JLabel brand=new JLabel("PQ Mail");brand.setFont(brand.getFont().deriveFont(Font.BOLD,27f));brand.setForeground(TEAL);heading.add(brand,BorderLayout.WEST);
        JPanel context=new JPanel(new GridLayout(0,1,0,4));context.setOpaque(false);title.setFont(title.getFont().deriveFont(Font.BOLD,20f));title.setForeground(INK);account.putClientProperty("html.disable",Boolean.TRUE);account.setForeground(TEAL);context.add(title);context.add(account);heading.add(context);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.RIGHT,8,0));actions.setOpaque(false);settingsButton=action("Settings",()->settings());actions.add(settingsButton);heading.add(actions,BorderLayout.EAST);add(heading,BorderLayout.NORTH);
        pages.setUI(new BasicTabbedPaneUI(){protected int calculateTabAreaHeight(int p,int runs,int h){return 0;}protected Insets getContentBorderInsets(int p){return new Insets(0,0,0,0);}protected void paintTabArea(Graphics g,int p,int s){}});
        pages.setBorder(new EmptyBorder(0,0,0,0));pages.setFocusable(false);
        JPanel mail=new JPanel(new BorderLayout(16,0));mail.setOpaque(false);JPanel navigation=new JPanel();navigation.setLayout(new BoxLayout(navigation,BoxLayout.Y_AXIS));navigation.setOpaque(false);navigation.setPreferredSize(new Dimension(160,400));
        composeButton=nav("Compose",()->showPage(0),LIME);inboxButton=nav("Inbox",()->showPage(3),new Color(0xDCEAE5));navigation.add(composeButton);navigation.add(Box.createVerticalStrut(12));navigation.add(inboxButton);navigation.add(Box.createVerticalStrut(8));navigation.add(nav("Read message",()->showPage(1),SURFACE));navigation.add(Box.createVerticalStrut(8));navigation.add(nav("Google Chat",()->showPage(7),SURFACE));navigation.add(Box.createVerticalGlue());navigation.add(nav("Switch account",this::showWelcome,SURFACE));navigation.add(Box.createVerticalStrut(8));navigation.add(nav("Lock vault",lock,SURFACE));
        mail.add(navigation,BorderLayout.WEST);mail.add(pages);screens.setOpaque(false);screens.add(welcome(gmail,microsoft,imap),"connect");screens.add(mail,"mail");
        // Cover the content, not native PIN/passkey dialogs. JLayer keeps the
        // spinner above the inbox without resizing or discarding its rows.
        JLayer<JPanel> content=new JLayer<>(screens);content.setGlassPane(loading);add(content);
        JPanel footer=new JPanel(new BorderLayout(12,6));footer.setOpaque(false);status.putClientProperty("html.disable",Boolean.TRUE);status.setBorder(new EmptyBorder(2,0,0,0));footer.add(status,BorderLayout.SOUTH);
        progress.setIndeterminate(true);progress.setPreferredSize(new Dimension(130,14));progress.setVisible(false);progress.setForeground(TEAL);activity.setForeground(TEAL);activity.putClientProperty("html.disable",Boolean.TRUE);footer.add(activity);footer.add(progress,BorderLayout.EAST);add(footer,BorderLayout.SOUTH);
        pages.addChangeListener(e->showSelected());showWelcome();
    }
    private JPanel welcome(Runnable gmail,Runnable microsoft,Runnable imap){
        JPanel outer=new JPanel(new GridBagLayout());outer.setOpaque(false);JPanel panel=new JPanel();panel.setOpaque(false);panel.setLayout(new BoxLayout(panel,BoxLayout.Y_AXIS));
        JLabel intro=new JLabel("Your mail, protected on this device.");intro.setForeground(INK);intro.setFont(intro.getFont().deriveFont(Font.BOLD,25f));intro.setAlignmentX(0);panel.add(intro);panel.add(Box.createVerticalStrut(12));
        JLabel detail=new JLabel("Reconnect with saved credentials, or sign in for the first time.");detail.setAlignmentX(0);panel.add(detail);panel.add(Box.createVerticalStrut(24));
        panel.add(provider("Gmail","Google sign-in · Gmail API",gmail));panel.add(Box.createVerticalStrut(12));panel.add(provider("Hotmail / Outlook","Microsoft sign-in · Microsoft Graph",microsoft));panel.add(Box.createVerticalStrut(12));panel.add(provider("Other mail provider","IMAP for reading · SMTP for sending",imap));panel.add(Box.createVerticalStrut(24));
        JLabel privacy=new JLabel("<html>When needed, unlock your passkey vault or authenticate to macOS Keychain.<br>PQ Mail explains which credentials it needs before asking you to authenticate.</html>");privacy.setForeground(TEAL);privacy.setAlignmentX(0);panel.add(privacy);panel.add(Box.createVerticalStrut(14));
        JButton offline=action("Use offline / manage identities",()->showPage(2));offline.setAlignmentX(0);panel.add(offline);outer.add(panel);return outer;
    }
    private JPanel provider(String name,String detail,Runnable connect){
        JPanel p=new JPanel(new BorderLayout(30,5));p.setBackground(Color.WHITE);p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0xDCEAE5)),new EmptyBorder(18,20,18,20)));p.setAlignmentX(0);p.setMaximumSize(new Dimension(780,100));
        JPanel labels=new JPanel(new GridLayout(0,1,0,5));labels.setOpaque(false);JLabel n=new JLabel(name);n.setForeground(TEAL);n.setFont(n.getFont().deriveFont(Font.BOLD,18f));labels.add(n);labels.add(new JLabel(detail));p.add(labels);JButton button=action("Sign in or reconnect",connect);button.getAccessibleContext().setAccessibleName("Sign in or reconnect to "+name);p.add(button,BorderLayout.EAST);return p;
    }
    static JButton action(String text,Runnable action){JButton b=new JButton(text);b.setForeground(TEAL);b.addActionListener(e->action.run());return b;}
    private JButton nav(String text,Runnable action,Color color){JButton b=action(text,action);b.setUI(new javax.swing.plaf.basic.BasicButtonUI());b.setOpaque(true);b.setBackground(color);b.setBorder(new EmptyBorder(14,16,14,16));b.setHorizontalAlignment(SwingConstants.LEFT);b.setAlignmentX(0);b.setMaximumSize(new Dimension(160,48));return b;}
    private void settings(){JPopupMenu menu=new JPopupMenu();String[] names={"Mail accounts", "Keys & passkey vault", "Certificates & trust", "OpenPGP", "Google Chat (experimental)"};int[] indexes={6,2,4,5,7};for(int i=0;i<names.length;i++){final int index=indexes[i];JMenuItem item=new JMenuItem(names[i]);item.addActionListener(e->showPage(index));menu.add(item);}menu.show(settingsButton,0,settingsButton.getHeight());}
    void showPage(int index){pages.setSelectedIndex(index);showSelected();}
    private void showSelected(){welcome=false;((CardLayout)screens.getLayout()).show(screens,"mail");title.setText(pages.getTitleAt(pages.getSelectedIndex()));}
    void showWelcome(){welcome=true;((CardLayout)screens.getLayout()).show(screens,"connect");title.setText("Connect your email");}
    boolean isWelcome(){return welcome;}
    void account(String text){account.setText(text);}
    void busy(String text){activity.setText(text);progress.setVisible(true);loading.showActivity(text);}
    void idle(){loading.clear();activity.setText(" ");progress.setVisible(false);}
}
