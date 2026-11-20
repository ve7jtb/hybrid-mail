package dev.hybridmail;

import java.io.*;
import java.net.URI;
import java.util.*;
import javax.swing.text.*;
import javax.swing.text.html.*;
import javax.swing.text.html.parser.ParserDelegator;

/** Converts untrusted email HTML into a small, network-free formatting subset. */
final class SafeMailHtml {
    static final int LIMIT=1024*1024;
    private static final Set<String> TAGS=Set.of("p","div","span","b","strong","i","em","u","s","strike","blockquote","br","hr","ul","ol","li","table","tr","td","th","h1","h2","h3","h4","h5","h6","pre","code","a","sub","sup","dl","dt","dd");
    private static final Set<String> DROP=Set.of("head","script","style","iframe","object","applet","svg","math","template","form","textarea","select","button");

    static String escape(String value){return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}

    /** Only explicit web destinations are clickable. No files, data, cid, JS,
     * relative URLs, credentials in URLs, or mailto/form submission paths. */
    static URI link(String value){
        if(value==null||value.length()>2048||value.codePoints().anyMatch(c->Character.isISOControl(c)||Character.isWhitespace(c)||Character.getType(c)==Character.FORMAT))return null;
        try{URI uri=new URI(value);return ("https".equalsIgnoreCase(uri.getScheme())||"http".equalsIgnoreCase(uri.getScheme()))&&uri.getHost()!=null&&uri.getRawUserInfo()==null?uri:null;}catch(Exception e){return null;}
    }

    static String sanitize(String input)throws IOException{
        if(input.length()>LIMIT)throw new IOException("HTML body is too large for formatted view; use Plain text.");
        StringBuilder body=new StringBuilder();Deque<String> blocked=new ArrayDeque<>();int[] nodes={0};
        new ParserDelegator().parse(new StringReader(input),new HTMLEditorKit.ParserCallback(){
            private void count(){if(++nodes[0]>20000)return;}
            private String name(HTML.Tag tag){return tag.toString().toLowerCase(Locale.ROOT);}
            private void start(HTML.Tag tag,MutableAttributeSet attrs,boolean simple){
                count();if(nodes[0]>20000)return;String n=name(tag);
                // No source attributes survive except a separately validated
                // link destination. In particular CSS, event handlers, image
                // URLs, background URLs, base URLs and frame URLs are discarded.
                if(DROP.contains(n)){if(!simple)blocked.push(n);return;}
                if(!blocked.isEmpty())return;
                if(n.equals("img")){Object alt=attrs.getAttribute(HTML.Attribute.ALT);body.append("<span>[Image not loaded");if(alt!=null)body.append(": ").append(escape(alt.toString()));body.append("]</span>");return;}
                if(!TAGS.contains(n))return;
                body.append('<').append(n);
                if(n.equals("a")){Object href=attrs.getAttribute(HTML.Attribute.HREF);URI uri=link(href==null?null:href.toString());if(uri!=null)body.append(" href=\"").append(escape(uri.toASCIIString())).append('"');}
                body.append('>');
            }
            @Override public void handleStartTag(HTML.Tag tag,MutableAttributeSet attrs,int pos){start(tag,attrs,false);}
            @Override public void handleSimpleTag(HTML.Tag tag,MutableAttributeSet attrs,int pos){
                if(Boolean.TRUE.equals(attrs.getAttribute(HTML.Attribute.ENDTAG))||"true".equals(attrs.getAttribute(HTML.Attribute.ENDTAG)))handleEndTag(tag,pos);
                else start(tag,attrs,true);
            }
            @Override public void handleEndTag(HTML.Tag tag,int pos){
                count();if(nodes[0]>20000)return;String n=name(tag);
                if(!blocked.isEmpty()){if(blocked.peek().equals(n))blocked.pop();return;}
                if(TAGS.contains(n)&&!n.equals("br")&&!n.equals("hr"))body.append("</").append(n).append('>');
            }
            @Override public void handleText(char[] data,int pos){count();if(nodes[0]<=20000&&blocked.isEmpty())body.append(escape(new String(data)));}
            // Comments (including script payloads reported as comments), parser
            // errors and DOCTYPE declarations are never copied to the document.
        },true);
        if(nodes[0]>20000)throw new IOException("HTML has too many elements; use Plain text.");
        // Only application-owned, literal CSS is installed; sender styles can
        // neither hide content nor reference URLs or impersonate the app chrome.
        return "<html><head><style>body { font-family: sans-serif; font-size: 14pt; color: #16383E; margin: 18px; } p { margin-top: 8px; margin-bottom: 8px; } a { color: #00566B; text-decoration: underline; } blockquote { margin-left: 18px; color: #52666B; } table { border-collapse: collapse; } td, th { border: 1px solid #DCEAE5; padding: 7px; } pre, code { font-family: monospace; } h1, h2, h3 { color: #00566B; }</style></head><body>"+body+"</body></html>";
    }
}
