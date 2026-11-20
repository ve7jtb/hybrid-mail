package dev.hybridmail;

import java.awt.*;
import java.awt.event.ActionEvent;
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.text.html.*;

/** Small local rich-text editor. Clipboard data enters as text, never remote HTML. */
final class DesktopComposeBody extends JPanel {
    private final JTextArea plain;
    final JCheckBox formatting=new JCheckBox("Use formatting");
    final JTextPane rich=new JTextPane();
    final JPanel tools=new JPanel(new FlowLayout(FlowLayout.LEFT,4,0));
    private final JPanel cards=new JPanel(new CardLayout());
    DesktopComposeBody(JTextArea plain){
        super(new BorderLayout(0,6));this.plain=plain;
        HTMLEditorKit kit=new HTMLEditorKit();StyleSheet styles=new StyleSheet();styles.addStyleSheet(kit.getStyleSheet());styles.addRule("body { font-family: sans-serif; font-size: 14pt; color: #16383E; }");kit.setStyleSheet(styles);rich.setEditorKit(kit);rich.setMargin(new Insets(12,14,12,14));rich.getAccessibleContext().setAccessibleName("Formatted message editor");
        // Reject HTML/image/file clipboard flavors and drag-and-drop. A pasted
        // web page must not introduce image loading into the editable pane.
        rich.setTransferHandler(new TransferHandler(){
            @Override public boolean canImport(TransferSupport support){return support.isDataFlavorSupported(java.awt.datatransfer.DataFlavor.stringFlavor);}
            @Override public boolean importData(TransferSupport support){try{if(!canImport(support))return false;rich.replaceSelection((String)support.getTransferable().getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor));return true;}catch(Exception invalid){return false;}}
            @Override protected java.awt.datatransfer.Transferable createTransferable(JComponent c){return new java.awt.datatransfer.StringSelection(rich.getSelectedText()==null?"":rich.getSelectedText());}
            @Override public int getSourceActions(JComponent c){return COPY;}
        });
        // Drag is disabled by default; do not enable it.
        addAction("Bold",new StyledEditorKit.BoldAction());addAction("Italic",new StyledEditorKit.ItalicAction());addAction("Underline",new StyledEditorKit.UnderlineAction());
        addButton("Heading",()->insertBlock("h2","Heading"));addButton("Bullets",()->insertBlock("ul","List item"));addButton("Numbered list",()->insertBlock("ol","List item"));
        addButton("Link…",()->{String destination=JOptionPane.showInputDialog(this,"Website address (https://…)","Insert link",JOptionPane.PLAIN_MESSAGE);if(destination==null)return;if(SafeMailHtml.link(destination)==null){JOptionPane.showMessageDialog(this,"Enter a complete HTTP or HTTPS address without credentials.");return;}insertLink(destination);});
        JPanel top=new JPanel(new BorderLayout());top.add(formatting,BorderLayout.WEST);top.add(tools);add(top,BorderLayout.NORTH);tools.setVisible(false);
        cards.add(new JScrollPane(plain),"plain");cards.add(new JScrollPane(rich),"rich");add(cards);
        formatting.addActionListener(e->{
            if(formatting.isSelected()){
                rich.setText("<html><body><p>"+SafeMailHtml.escape(plain.getText()).replace("\n","<br>")+"</p></body></html>");rich.setCaretPosition(0);
            }else{
                if(JOptionPane.showConfirmDialog(this,"Keep the text and remove formatting?","Plain text",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION){formatting.setSelected(true);return;}
                plain.setText(richText());
            }
            ((CardLayout)cards.getLayout()).show(cards,formatting.isSelected()?"rich":"plain");tools.setVisible(formatting.isSelected());revalidate();
        });
    }
    private void addButton(String label,Runnable action){JButton button=new JButton(label);button.setFocusable(false);button.addActionListener(e->action.run());tools.add(button);}
    private void addAction(String label,Action action){addButton(label,()->{rich.requestFocusInWindow();action.actionPerformed(new ActionEvent(rich,ActionEvent.ACTION_PERFORMED,label));});}
    private String selected(String fallback){String selected=rich.getSelectedText();return selected==null||selected.isEmpty()?fallback:selected;}
    void insertBlock(String tag,String fallback){
        String label=selected(fallback),markup=SafeMailHtml.escape(label);
        if(tag.equals("ul")||tag.equals("ol"))markup="<li>"+markup.replace("\n","</li><li>")+"</li>";
        rich.replaceSelection("");rich.requestFocusInWindow();
        new HTMLEditorKit.InsertHTMLTextAction("Insert block","<"+tag+">"+markup+"</"+tag+">",HTML.Tag.BODY,HTML.getTag(tag)).actionPerformed(new ActionEvent(rich,ActionEvent.ACTION_PERFORMED,"insert"));
    }
    void insertLink(String destination){
        if(SafeMailHtml.link(destination)==null)return;
        String label=selected(destination);int start=rich.getSelectionStart();rich.replaceSelection("");
        try{((HTMLEditorKit)rich.getEditorKit()).insertHTML((HTMLDocument)rich.getDocument(),start,"<a href=\""+SafeMailHtml.escape(destination)+"\">"+SafeMailHtml.escape(label)+"</a>",0,0,HTML.Tag.A);}
        catch(Exception e){JOptionPane.showMessageDialog(this,"Could not insert link.");}
    }
    private String richText(){try{String text=rich.getDocument().getText(0,rich.getDocument().getLength());return text.startsWith("\n")?text.substring(1):text;}catch(BadLocationException e){throw new IllegalStateException(e);}}
    String text(){return formatting.isSelected()?richText():plain.getText();}
    String html()throws java.io.IOException{return formatting.isSelected()?SafeMailHtml.sanitize(rich.getText()):null;}
}
