package dev.hybridmail;

import jakarta.mail.*;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.search.*;
import java.util.*;

/** Read-only IMAP pages: fetch headers for the visible page, MIME only on open. */
final class AndroidImapMailbox implements AutoCloseable {
    private final Store store;
    private final Folder folder;
    private final UIDFolder uids;
    private final long validity;
    private long[] matches=new long[0];
    private int offset;
    static final int PAGE_SIZE=20;
    private AndroidImapMailbox(Store s,Folder f)throws Exception{store=s;folder=f;uids=(UIDFolder)f;validity=uids.getUIDValidity();}
    static AndroidImapMailbox connect(String host,String user,String password)throws Exception{
        Store s=Session.getInstance(MailEngine.networkProperties("imaps",false)).getStore("imaps");
        try{s.connect(host,993,user,password);Folder f=s.getFolder("INBOX");f.open(Folder.READ_ONLY);return new AndroidImapMailbox(s,f);}catch(Exception e){try{s.close();}catch(Exception ignored){}throw e;}
    }
    boolean hasNewer(){return offset>0;}
    boolean hasOlder(){return offset+PAGE_SIZE<matches.length;}
    int pageNumber(){return offset/PAGE_SIZE+1;}
    private void check()throws Exception{if(!folder.isOpen()||uids.getUIDValidity()!=validity)throw new java.io.IOException("Mailbox changed or disconnected. Reconnect to IMAP.");}
    synchronized List<ImapInbox.Entry> latest(String query)throws Exception{
        check();Message[] m=query.isBlank()?folder.getMessages():folder.search(new OrTerm(new SubjectTerm(query),new FromStringTerm(query)));
        FetchProfile p=new FetchProfile();p.add(UIDFolder.FetchProfileItem.UID);folder.fetch(m,p);
        long[] found=new long[m.length];int count=0;for(Message item:m)if(!item.isExpunged()){long uid=uids.getUID(item);if(uid>0)found[count++]=uid;}
        matches=Arrays.copyOf(found,count);Arrays.sort(matches);offset=0;return page();
    }
    synchronized List<ImapInbox.Entry> move(int direction)throws Exception{int previous=offset;if(direction>0&&hasOlder())offset+=PAGE_SIZE;if(direction<0&&hasNewer())offset-=PAGE_SIZE;try{return page();}catch(Exception e){offset=previous;throw e;}}
    private List<ImapInbox.Entry> page()throws Exception{
        check();List<Message> list=new ArrayList<>();for(int n=offset;n<Math.min(matches.length,offset+PAGE_SIZE);n++){Message m=uids.getMessageByUID(matches[matches.length-1-n]);if(m!=null&&!m.isExpunged())list.add(m);}
        FetchProfile p=new FetchProfile();p.add(FetchProfile.Item.ENVELOPE);p.add(FetchProfile.Item.SIZE);folder.fetch(list.toArray(new Message[0]),p);
        List<ImapInbox.Entry> result=new ArrayList<>();for(Message m:list){if(m.isExpunged())continue;Address[] from=m.getFrom();Date date=m.getReceivedDate();if(date==null)date=m.getSentDate();result.add(new ImapInbox.Entry(uids.getUID(m),from==null||from.length==0?"Unknown sender":from[0].toString(),Objects.requireNonNullElse(m.getSubject(),"(no subject)"),date==null?null:date.toInstant(),m.getSizeLong()));}return List.copyOf(result);
    }
    synchronized MimeMessage message(long uid)throws Exception{
        check();Message m=uids.getMessageByUID(uid);if(m==null||m.isExpunged())throw new java.io.IOException("Message removed. Refresh the inbox.");
        if(m.getSizeLong()>MailEngine.MAX_MESSAGE)throw new java.io.IOException("Message exceeds 20 MiB");
        var out=new java.io.ByteArrayOutputStream(){public synchronized void write(byte[] b,int o,int n){if(n>MailEngine.MAX_MESSAGE-count)throw new IllegalStateException("Message exceeds 20 MiB");super.write(b,o,n);}public synchronized void write(int b){if(count>=MailEngine.MAX_MESSAGE)throw new IllegalStateException("Message exceeds 20 MiB");super.write(b);}};
        m.writeTo(out);return MailEngine.parse(out.toByteArray());
    }
    public synchronized void close()throws Exception{try{if(folder.isOpen())folder.close(false);}finally{store.close();matches=new long[0];}}
}
