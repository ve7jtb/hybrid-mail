package dev.hybridmail;

import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.*;
import javax.swing.text.html.*;

/** Local HTML body rendering. Security/trust text is a separate Swing control. */
final class DesktopMessageView extends JPanel {
    final JTextArea security=new JTextArea(7,50),plain=new JTextArea();
    final JTabbedPane views=new JTabbedPane();
    final JEditorPane formatted=new JEditorPane(){
        // Even a future accidental caller cannot turn this email pane into a browser.
        @Override public void setPage(URL url)throws IOException{throw new IOException("Network navigation is disabled in the message viewer");}
    };
    private final JLabel note=new JLabel("Formatting is local. Images and active content are not loaded.");

    DesktopMessageView(){
        super(new BorderLayout(0,10));
        security.setEditable(false);security.setLineWrap(true);security.setWrapStyleWord(true);security.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,13));security.setMargin(new Insets(10,12,10,12));security.setBackground(DesktopMailShell.SURFACE);security.setForeground(DesktopMailShell.INK);
        security.getAccessibleContext().setAccessibleName("PQ Mail security and sender information");
        JScrollPane summary=new JScrollPane(security);summary.setBorder(BorderFactory.createTitledBorder("Security & sender — reported by PQ Mail"));add(summary,BorderLayout.NORTH);
        plain.setEditable(false);plain.setLineWrap(true);plain.setWrapStyleWord(true);plain.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,16));plain.setMargin(new Insets(16,16,16,16));plain.getAccessibleContext().setAccessibleName("Plain-text message body");
        HTMLEditorKit kit=new HTMLEditorKit(){
            private final ViewFactory factory=new HTMLFactory(){
                @Override public View create(Element e){
                    Object tag=e.getAttributes().getAttribute(StyleConstants.NameAttribute);
                    // Defense in depth: these renderer types can fetch URLs or
                    // create interactive components; none belongs in email.
                    if(tag==HTML.Tag.IMG||tag==HTML.Tag.OBJECT||tag==HTML.Tag.FRAME||tag==HTML.Tag.INPUT||tag==HTML.Tag.SELECT||tag==HTML.Tag.TEXTAREA)return new LabelView(e);
                    return super.create(e);
                }
            };
            @Override public ViewFactory getViewFactory(){return factory;}
        };
        kit.setAutoFormSubmission(false);formatted.setEditorKit(kit);formatted.setEditable(false);formatted.setBackground(Color.WHITE);formatted.getAccessibleContext().setAccessibleName("Formatted message body");
        formatted.addHyperlinkListener(e->{if(e.getEventType()==HyperlinkEvent.EventType.ACTIVATED)openLink(e.getDescription());});
        JPanel html=new JPanel(new BorderLayout(0,6));html.add(new JScrollPane(formatted));note.setBorder(BorderFactory.createEmptyBorder(5,8,5,8));add(note,BorderLayout.SOUTH);
        views.addTab("Formatted HTML",html);views.addTab("Plain text",new JScrollPane(plain));add(views);clear();
    }

    void showMessage(String status,String text,String html){
        security.setText(status);security.setCaretPosition(0);plain.setText(text);plain.setCaretPosition(0);
        // Construct a fresh document every time: no previous message's links,
        // styles, body, or base URL survive opening another message or locking.
        formatted.setDocument(formatted.getEditorKit().createDefaultDocument());
        note.setText("Formatting is local. Images and active content are not loaded.");
        boolean rich=false;
        if(html!=null)try{formatted.setText(SafeMailHtml.sanitize(html));formatted.setCaretPosition(0);rich=true;}
        catch(Exception invalid){note.setText("Formatted view unavailable; use Plain text.");}
        views.setEnabledAt(0,rich);views.setSelectedIndex(rich?0:1);
    }
    void updateSecurity(String status){security.setText(status);security.setCaretPosition(0);}
    void clear(){showMessage("Open a message to see its verification status.","",null);}

    private void openLink(String target){
        URI uri=SafeMailHtml.link(target);if(uri==null)return;
        // Show the actual destination as plain text, not the sender's anchor
        // label. Only an explicit confirmation invokes the external browser.
        JTextArea description=new JTextArea("Open this website in your browser?\n\n"+uri.toASCIIString()+"\n\nThe website will receive your browser request.",6,55);description.setEditable(false);description.setLineWrap(true);description.setWrapStyleWord(true);
        if(JOptionPane.showConfirmDialog(this,new JScrollPane(description),"Open external link",JOptionPane.OK_CANCEL_OPTION,JOptionPane.QUESTION_MESSAGE)!=JOptionPane.OK_OPTION)return;
        try{if(!Desktop.isDesktopSupported()||!Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))throw new IOException("No browser is available");Desktop.getDesktop().browse(uri);}
        catch(Exception e){JOptionPane.showMessageDialog(this,"Could not open the browser.","Open link",JOptionPane.ERROR_MESSAGE);}
    }
}
