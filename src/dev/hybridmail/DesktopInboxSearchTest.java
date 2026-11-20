package dev.hybridmail;
import java.util.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.swing.*;
import java.awt.*;
public final class DesktopInboxSearchTest {
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);}
 static java.util.List<JButton> buttons(Component c){var out=new ArrayList<JButton>();if(c instanceof JButton b)out.add(b);if(c instanceof Container p)for(var child:p.getComponents())out.addAll(buttons(child));return out;}
 public static void main(String[] args)throws Exception{
  MailEngine.init();var requests=new ArrayList<String>();
  try(var api=new GmailApi(()->"synthetic".toCharArray(),(r,l)->{String q=r.uri().getRawQuery();requests.add(URLDecoder.decode(q,StandardCharsets.UTF_8));return GmailApiTest.json(q.contains("pageToken")?"{}":"{\"nextPageToken\":\"next/+\"}");})){
   api.setSearch("from:alice@example.test subject:hello & world");api.latest();api.older();check(api.pageNumber()==2&&api.hasNewer(),"Gmail search paging");check(requests.get(1).contains("q=from:alice@example.test subject:hello & world")&&requests.get(1).contains("pageToken=next/+"),"Gmail preserves encoded query/cursor");api.newer();api.setSearch("");api.latest();check(api.pageNumber()==1&&!requests.getLast().contains("&q="),"Gmail clear resets search/page");
  }
  requests.clear();try(var api=new MicrosoftGraph(()->"synthetic".toCharArray(),(r,l)->{String uri=r.uri().toString();requests.add(URLDecoder.decode(uri,StandardCharsets.UTF_8));return new MicrosoftGraph.Response(200,(uri.contains("skiptoken")?"{\"value\":[]}":"{\"value\":[],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?skiptoken=next\"}").getBytes(StandardCharsets.UTF_8));})){
   api.setSearch("Alice's & report");api.latest();check(requests.getFirst().contains("contains(subject,'Alice''s & report')"),"Outlook escapes quoted search");api.older();check(api.pageNumber()==2&&api.hasNewer(),"Outlook follows checked nextLink");api.newer();api.setSearch("");api.latest();check(api.pageNumber()==1&&requests.getLast().contains("$orderby=")&&!requests.getLast().contains("$filter="),"Outlook clear restores first inbox page");
  }
  var folder=new MailAccountTest.FakeFolder(25);try(var api=new ImapInbox(null,folder)){
   check(api.latest().getFirst().uid()==1025&&api.hasOlder()&&!api.hasNewer(),"IMAP first page");check(api.older().getFirst().uid()==1015&&api.hasNewer(),"IMAP older");check(api.newer().getFirst().uid()==1025,"IMAP newer");api.setSearch("Message 1");check(api.latest().size()==10&&api.hasOlder(),"IMAP subject search");check(api.older().size()==1&&!api.hasOlder(),"IMAP search paging");api.setSearch("sender@example.test");check(api.latest().size()==10&&api.hasOlder(),"IMAP sender search");api.setSearch("no-such-subject");check(api.latest().isEmpty()&&!api.hasOlder()&&!api.hasNewer(),"IMAP empty search");check(folder.bodies==0,"Search/paging must not download message bodies");api.setSearch("");api.latest();folder.messages.removeFirst();MailAccountTest.reject(api::older,"changed mailbox requires refresh before IMAP paging");
  }
  SwingUtilities.invokeAndWait(()->{
   var tabs=new JTabbedPane();for(String title:java.util.List.of("Compose","Read","Keys","Inbox","Certificates","OpenPGP","Mail accounts"))tabs.add(title,new JPanel());int[] connects={0,0,0};var shell=new DesktopMailShell(tabs,new JLabel(),()->connects[0]++,()->connects[1]++,()->connects[2]++,()->{});
   check(shell.isWelcome()&&Arrays.equals(connects,new int[3]),"Start screen must not connect automatically");var providers=buttons(shell).stream().filter(b->b.getText().equals("Sign in or reconnect")).toList();check(providers.size()==3,"Three consistent provider actions");for(var b:providers)b.doClick();check(Arrays.equals(connects,new int[]{1,1,1}),"Each provider routes correctly");shell.showPage(3);check(!shell.isWelcome()&&tabs.getSelectedIndex()==3,"Connected route to inbox");shell.showPage(2);check(tabs.getSelectedIndex()==2,"Keys settings available");shell.showWelcome();check(shell.isWelcome(),"Switch account returns to provider screen");shell.busy("Unlocking Google OAuth refresh token");check(shell.progress.isVisible()&&shell.activity.getText().contains("refresh token"),"Authentication reason and loading indicator");shell.idle();check(!shell.progress.isVisible(),"Loading indicator ends");
  });
  System.out.println("PASS provider navigation, explicit credential-unlock/loading status, Gmail/Outlook/IMAP search, paging, clear, empty results, query escaping and header-only reads; synthetic tests only");
 }
}
