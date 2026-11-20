package dev.hybridmail;

import java.io.*;
import java.time.Instant;
import java.util.*;
import jakarta.mail.*;
import jakarta.mail.internet.MimeMessage;

/** Read-only, session-scoped inbox. UIDs keep selections stable after expunges. */
public final class ImapInbox implements MailInbox {
    public record Entry(long uid,String sender,String subject,Instant received,long bytes){}
    private final Store store;
    private final Folder folder;
    private final UIDFolder uids;
    private final long validity;
    private String search="";private Message[] matches;private int snapshotCount,total,page;
    synchronized void setSearch(String query){search=query.trim();matches=null;total=0;page=0;}
    int pageNumber(){return page+1;}
    boolean hasOlder(){return (page+1)*10<total;}
    boolean hasNewer(){return page>0;}
    synchronized List<Entry> older()throws Exception{return hasOlder()?loadPage(page+1):List.of();}
    synchronized List<Entry> newer()throws Exception{return hasNewer()?loadPage(page-1):List.of();}
    ImapInbox(Store store,Folder folder)throws MessagingException{
        this.store=store;this.folder=folder;
        if(!(folder instanceof UIDFolder uidFolder))throw new MessagingException("Server does not provide stable message UIDs");
        uids=uidFolder;validity=uids.getUIDValidity();
    }
    public static ImapInbox connect(String host,int port,String user,String credential,boolean oauth)throws Exception{
        Store store=Session.getInstance(MailEngine.networkProperties("imaps",oauth)).getStore("imaps");
        try{store.connect(host,port,user,credential);Folder folder=store.getFolder("INBOX");folder.open(Folder.READ_ONLY);return new ImapInbox(store,folder);}
        catch(Exception e){try{store.close();}catch(Exception ignored){}throw e;}
    }
    public synchronized List<Entry> latest()throws Exception{
        ensureOpen();snapshotCount=folder.getMessageCount();
        matches=search.isEmpty()?null:folder.search(new jakarta.mail.search.OrTerm(new jakarta.mail.search.SubjectTerm(search),new jakarta.mail.search.FromStringTerm(search)));
        if(matches!=null)Arrays.sort(matches,Comparator.comparingInt(Message::getMessageNumber));total=matches==null?snapshotCount:matches.length;
        return loadPage(0);
    }
    private List<Entry> loadPage(int requested)throws Exception{
        ensureOpen();if(folder.getMessageCount()!=snapshotCount)throw new IOException("Inbox changed. Refresh before paging again.");
        if(total==0){page=0;return List.of();}int end=total-requested*10,start=Math.max(0,end-10);if(end<=0)throw new IOException("Refresh the inbox before paging.");
        Message[] messages=matches==null?folder.getMessages(start+1,end):Arrays.copyOfRange(matches,start,end);
        FetchProfile profile=new FetchProfile();profile.add(FetchProfile.Item.ENVELOPE);profile.add(FetchProfile.Item.SIZE);profile.add(UIDFolder.FetchProfileItem.UID);
        folder.fetch(messages,profile);List<Entry> result=new ArrayList<>();
        for(int i=messages.length-1;i>=0;i--){Message m=messages[i];if(m.isExpunged())continue;
            Address[] from=m.getFrom();String sender=from==null||from.length==0?"(unknown sender)":from[0].toString();
            Date date=m.getReceivedDate();if(date==null)date=m.getSentDate();long uid=uids.getUID(m);if(uid<=0)continue;
            result.add(new Entry(uid,sender,Objects.requireNonNullElse(m.getSubject(),"(no subject)"),date==null?null:date.toInstant(),m.getSizeLong()));
        }
        page=requested;return List.copyOf(result);
    }
    public synchronized MimeMessage message(long uid)throws Exception{
        ensureOpen();Message m=uids.getMessageByUID(uid);
        if(m==null||m.isExpunged())throw new IOException("Message is no longer in the inbox. Refresh the list.");
        if(m.getSizeLong()>MailEngine.MAX_MESSAGE)throw new IOException("Message exceeds 20 MiB limit");
        ByteArrayOutputStream out=new ByteArrayOutputStream(){
            public synchronized void write(byte[] bytes,int offset,int length){if(length>MailEngine.MAX_MESSAGE-count)throw new IllegalStateException("Message exceeds 20 MiB limit");super.write(bytes,offset,length);}
            public synchronized void write(int value){if(count>=MailEngine.MAX_MESSAGE)throw new IllegalStateException("Message exceeds 20 MiB limit");super.write(value);}
        };
        m.writeTo(out);return MailEngine.parse(out.toByteArray());
    }
    private void ensureOpen()throws Exception{
        if(!folder.isOpen())throw new IOException("IMAP session closed. Connect again.");
        if(uids.getUIDValidity()!=validity)throw new IOException("Inbox identifiers changed. Connect again.");
    }
    public synchronized void close()throws MessagingException{matches=null;total=0;page=0;try{if(folder.isOpen())folder.close(false);}finally{if(store!=null)store.close();}}
}
