package dev.hybridmail;

import java.awt.*;
import java.awt.event.HierarchyEvent;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

/** A prominent, accessible loading state shared by inbox operations and reconnects. */
final class DesktopLoadingOverlay extends JPanel {
    private final JTextArea message=new JTextArea(2,32);
    private final Spinner spinner=new Spinner();

    DesktopLoadingOverlay(){
        super(new GridBagLayout());setOpaque(false);
        JPanel card=new JPanel(new BorderLayout(0,16));card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0xDCEAE5)),new EmptyBorder(28,32,24,32)));
        JPanel icon=new JPanel(new FlowLayout(FlowLayout.CENTER,0,0));icon.setOpaque(false);icon.add(spinner);card.add(icon,BorderLayout.NORTH);
        message.setEditable(false);message.setFocusable(false);message.setOpaque(false);message.setLineWrap(true);message.setWrapStyleWord(true);
        message.setFont(UIManager.getFont("Label.font").deriveFont(Font.BOLD,17f));message.setForeground(DesktopMailShell.INK);
        message.getAccessibleContext().setAccessibleName("Current mail operation");card.add(message);
        JLabel note=new JLabel("Please wait…",SwingConstants.CENTER);note.setForeground(DesktopMailShell.TEAL);card.add(note,BorderLayout.SOUTH);
        getAccessibleContext().setAccessibleName("Mail loading status");add(card);setVisible(false);
        // A hidden page or disposed window must not keep a repaint timer alive.
        addHierarchyListener(e->{if((e.getChangeFlags()&HierarchyEvent.SHOWING_CHANGED)!=0)spinner.animate(isShowing());});
    }

    void showActivity(String text){
        // Plain text avoids Swing HTML interpretation of any future dynamic label.
        message.setText(text);setVisible(true);spinner.animate(isShowing());revalidate();repaint();
    }
    void clear(){spinner.animate(false);setVisible(false);message.setText("");}
    String activityText(){return message.getText();}

    @Override protected void paintComponent(Graphics graphics){
        // Retain the surrounding layout while making the loading state the focal point.
        Graphics2D g=(Graphics2D)graphics.create();
        try{g.setColor(new Color(241,247,245,235));g.fillRect(0,0,getWidth(),getHeight());}
        finally{g.dispose();}
        super.paintComponent(graphics);
    }

    private static final class Spinner extends JPanel {
        private int angle;
        private final Timer animation=new Timer(35,e->{angle=(angle+12)%360;repaint();});
        Spinner(){
            setOpaque(false);setPreferredSize(new Dimension(72,72));
            getAccessibleContext().setAccessibleName("Loading");
            getAccessibleContext().setAccessibleDescription("An operation is in progress; its description appears below.");
            animation.setCoalesce(true);
        }
        void animate(boolean running){if(running)animation.start();else animation.stop();}
        @Override protected void paintComponent(Graphics graphics){
            super.paintComponent(graphics);Graphics2D g=(Graphics2D)graphics.create();
            try{
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
                g.setStroke(new BasicStroke(6f,BasicStroke.CAP_ROUND,BasicStroke.JOIN_ROUND));
                g.setColor(new Color(0xDCEAE5));g.drawOval(9,9,54,54);
                g.setColor(DesktopMailShell.TEAL);g.drawArc(9,9,54,54,-angle,245);
                g.setColor(DesktopMailShell.LIME);g.drawArc(9,9,54,54,-angle+250,45);
            }finally{g.dispose();}
        }
        @Override public void removeNotify(){animation.stop();super.removeNotify();}
    }
}
