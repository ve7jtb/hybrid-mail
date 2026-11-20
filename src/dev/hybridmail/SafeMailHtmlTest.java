package dev.hybridmail;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;
import javax.swing.text.html.*;
import java.awt.image.BufferedImage;

/** Adversarial rendering tests use synthetic mail and an instrumented loopback server. */
public final class SafeMailHtmlTest {
    static void check(boolean condition,String reason){if(!condition)throw new AssertionError(reason);}
    public static void main(String[] args)throws Exception{
        for(String target:new String[]{"javascript:alert(1)","data:text/html,bad","file:///tmp/image","cid:image","//example.test","https://user@example.test/","https://example.test/\u202eevil","mailto:a@example.test"})check(SafeMailHtml.link(target)==null,"Unsafe link: "+target);
        check(SafeMailHtml.link("https://example.test/a?q=one&x=two")!=null,"Explicit HTTPS link");
        try{SafeMailHtml.sanitize("x".repeat(SafeMailHtml.LIMIT+1));throw new AssertionError("Unbounded HTML");}catch(IOException expected){}
        try{SafeMailHtml.sanitize("<p>x</p>".repeat(10000));throw new AssertionError("Unbounded element count");}catch(IOException expected){}
        AtomicInteger requests=new AtomicInteger();HttpServer server=HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(),0),0);
        server.createContext("/",exchange->{requests.incrementAndGet();exchange.sendResponseHeaders(204,-1);exchange.close();});server.start();
        try{
            String remote="http://localhost:"+server.getAddress().getPort()+"/resource";
            String input="<html><head><base href='"+remote+"'><link rel='stylesheet' href='"+remote+"'><style>@import url("+remote+");</style><meta http-equiv='refresh' content='0;url="+remote+"'></head><body background='"+remote+"' onload='alert(1)'><h1>Project update</h1><p style='background:url("+remote+")'>Hello <b>world</b> &amp; café</p><ul><li>One</li></ul><table><tr><th>Status</th><td>Ready</td></tr></table><blockquote>Quoted text</blockquote><img src='"+remote+"' alt='Tracking pixel'><img src='file:///tmp/private.png'><img src='cid:inline'><iframe src='"+remote+"'></iframe><object data='"+remote+"'></object><script>BAD_SCRIPT</script><form action='"+remote+"'><input type='submit'></form><a href='javascript:alert(1)'>Bad link</a><a href='https://example.test/?q=one&amp;x=two'>Example link</a></body></html>";
            String safe=SafeMailHtml.sanitize(input);
            check(!safe.contains(remote)&&!safe.contains("file:")&&!safe.contains("cid:")&&!safe.contains("BAD_SCRIPT")&&!safe.contains("javascript:")&&!safe.contains("<img")&&!safe.contains("<form")&&!safe.contains("onload"),"Active content leaked");
            check(safe.contains("<h1>Project update</h1>")&&safe.contains("<b>world</b>")&&safe.contains("<table>")&&safe.contains("href=\"https://example.test/?q=one&amp;x=two\""),"Basic formatting or safe links lost");
            SwingUtilities.invokeAndWait(()->{
                DesktopMessageView view=new DesktopMessageView();view.showMessage("SIGNER NOT TRUSTED", "Plain alternative",input);
                check(view.views.getSelectedIndex()==0&&view.security.getText().equals("SIGNER NOT TRUSTED"),"Separate security status");
                view.setSize(900,700);layout(view);BufferedImage image=new BufferedImage(900,700,BufferedImage.TYPE_INT_RGB);var g=image.createGraphics();view.paint(g);g.dispose();
                check(!view.formatted.isEditable()&&!view.security.isEditable(),"Read-only controls");
                HTMLDocument doc=(HTMLDocument)view.formatted.getDocument();check(!doc.getIterator(HTML.Tag.IMG).isValid()&&!doc.getIterator(HTML.Tag.OBJECT).isValid()&&!doc.getIterator(HTML.Tag.INPUT).isValid(),"Forbidden renderer objects");
                try{view.formatted.setPage(URI.create(remote).toURL());throw new AssertionError("Navigation allowed");}catch(IOException expected){}
                view.updateSecurity("SIGNER TRUSTED");check(view.plain.getText().equals("Plain alternative"),"Trust refresh changed body");
                view.showMessage("UNSIGNED", "Plain only",null);check(view.views.getSelectedIndex()==1&&!view.views.isEnabledAt(0)&&!view.formatted.getText().contains("Project update"),"Previous HTML retained");
                view.clear();check(view.plain.getText().isEmpty()&&!view.security.getText().contains("TRUSTED"),"Reader clear leaked previous message");
            });
            // Allow deferred Swing resource loading to run before checking the server.
            Thread.sleep(350);check(requests.get()==0,"Rendering contacted a website");
            String related="Content-Type: multipart/related; boundary=r; start=\"<root>\"\r\n\r\n--r\r\nContent-Type: text/html\r\nContent-ID: <other>\r\n\r\nWrong body\r\n--r\r\nContent-Type: text/html; charset=UTF-8\r\nContent-ID: <root>\r\n\r\n<b>Chosen body</b>\r\n--r--\r\n";
            check(VerifiedMime.body(related.getBytes(java.nio.charset.StandardCharsets.UTF_8)).html().contains("Chosen body"),"Related root selection");
            check(VerifiedMime.body("Content-Type: text/html\r\nContent-Disposition: attachment; filename=page.html\r\n\r\nNOT BODY".getBytes()).html()==null,"HTML attachment treated as body");
            System.out.println("PASS safe HTML: formatting, link policy, limits, MIME root/attachment selection, zero resource requests, separate trust, document clearing");
        }finally{server.stop(0);}
    }
    static void layout(java.awt.Container c){c.doLayout();for(var child:c.getComponents())if(child instanceof java.awt.Container container)layout(container);}
}
