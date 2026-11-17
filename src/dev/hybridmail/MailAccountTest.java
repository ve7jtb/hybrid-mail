package dev.hybridmail;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.nio.file.*;
import java.net.*;
import java.net.http.*;
import java.util.*;
public final class MailAccountTest {
    interface Action{void run()throws Exception;}
    static void check(boolean value,String label){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
    static void reject(Action action,String label)throws Exception{try{action.run();}catch(Exception expected){if(label.startsWith("real loopback")&&!expected.getMessage().equals("Google sign-in was denied or cancelled"))throw expected;System.out.println("PASS "+label);return;}throw new AssertionError(label);}
    static final class FakeFolder extends Folder implements UIDFolder{
        List<Message> messages=new ArrayList<>();Map<Message,Long> ids=new IdentityHashMap<>();boolean opened=true;long validity=5;int bodies;
        FakeFolder(int count)throws Exception{super(MailEngine.session().getStore("imaps"));for(int i=1;i<=count;i++){final int number=i;MimeMessage m=new MimeMessage(MailEngine.session()){
            public void writeTo(java.io.OutputStream out)throws java.io.IOException,MessagingException{bodies++;super.writeTo(out);}
        };m.setFrom("sender@example.test");m.setSubject("Message "+i);m.setSentDate(new Date(i*1000L));m.setText("body "+number);m.saveChanges();messages.add(m);ids.put(m,1000L+i);}}
        public String getName(){return "INBOX";}public String getFullName(){return "INBOX";}public Folder getParent(){return null;}public boolean exists(){return true;}public Folder[] list(String pattern){return new Folder[0];}public char getSeparator(){return '/';}public int getType(){return HOLDS_MESSAGES;}public boolean create(int type){throw new AssertionError("write");}public boolean hasNewMessages(){return false;}public Folder getFolder(String name){return null;}public boolean delete(boolean recurse){throw new AssertionError("write");}public boolean renameTo(Folder folder){throw new AssertionError("write");}public void open(int mode){check(mode==READ_ONLY,"read-only folder");opened=true;}public void close(boolean expunge){check(!expunge,"close without expunge");opened=false;}public boolean isOpen(){return opened;}public Flags getPermanentFlags(){return new Flags();}public int getMessageCount(){return messages.size();}public Message getMessage(int number){return messages.get(number-1);}public void appendMessages(Message[] ms){throw new AssertionError("write");}public Message[] expunge(){throw new AssertionError("write");}
        public long getUIDValidity(){return validity;}public Message getMessageByUID(long id){return messages.stream().filter(m->ids.get(m)==id).findFirst().orElse(null);}public Message[] getMessagesByUID(long a,long b){throw new UnsupportedOperationException();}public Message[] getMessagesByUID(long[] ids){throw new UnsupportedOperationException();}public long getUID(Message m){return ids.get(m);}public long getUIDNext(){return 2000;}
    }
    public static void main(String[] args)throws Exception{
        for(int count:new int[]{0,1,9,10,25}){
            FakeFolder folder=new FakeFolder(count);try(ImapInbox inbox=new ImapInbox(null,folder)){
                var rows=inbox.latest();check(rows.size()==Math.min(count,10)&&folder.bodies==0,"inbox size "+count+" lists at most ten without fetching bodies");
                if(count>0){check(rows.getFirst().uid()==1000+count,"newest arrival first");var chosen=rows.getFirst();if(count>1)folder.messages.removeFirst();check(inbox.message(chosen.uid()).getSubject().equals("Message "+count),"selection follows UID after sequence shift");folder.messages.removeIf(m->folder.ids.get(m)==chosen.uid());reject(()->inbox.message(chosen.uid()),"removed message rejected");}
                folder.validity++;reject(inbox::latest,"changed UIDVALIDITY rejected");
            }
        }
        var imap=MailEngine.networkProperties("imaps",true);var smtp=MailEngine.networkProperties("smtp",true);
        check("XOAUTH2".equals(imap.getProperty("mail.imaps.auth.mechanisms"))&&"true".equals(imap.getProperty("mail.imaps.peek"))&&"true".equals(imap.getProperty("mail.imaps.ssl.checkserveridentity"))&&"XOAUTH2".equals(smtp.getProperty("mail.smtp.auth.mechanisms")),"OAuth-only auth, read-only peek, TLS hostname checks");
        check(GoogleOAuth.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").equals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),"PKCE RFC7636 S256 test vector");
        check(GoogleOAuth.code("state=expected&code=a%2Bb","expected").equals("a+b"),"matching callback decoded");
        reject(()->GoogleOAuth.code("state=other&code=secret","expected"),"OAuth state mismatch rejected");
        reject(()->GoogleOAuth.code("state=expected&state=expected&code=x","expected"),"duplicate callback rejected");
        reject(()->GoogleOAuth.code("state=expected&error=access_denied","expected"),"Google consent denial rejected");
        try(var token=GoogleOAuth.token("{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"https://mail.google.com/\"}")){
            check(token.valid()&&new String(token.credential()).equals("test-token"),"session token available");token.close();reject(token::credential,"sign-out clears token");
        }
        try(var expired=new GoogleOAuth.Token("expired-test-token",1)){reject(expired::credential,"expired token rejected");}
        try(var token=GoogleOAuth.token("{\"access_token\":\"test-access\",\"refresh_token\":\"test-refresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}")){
            check(token.refreshToken().equals("test-refresh"),"refresh token parsed without logging");token.close();check(token.refreshToken()==null,"closing session clears refresh token");
        }
        var refreshParams=GoogleOAuth.refreshParameters(new GoogleOAuth.Client("test.apps.googleusercontent.com","test-secret"),"test-refresh");
        check(refreshParams.get("grant_type").equals("refresh_token")&&refreshParams.get("refresh_token").equals("test-refresh")&&!refreshParams.containsKey("code"),"refresh grant uses saved token and correct client");
        reject(()->GoogleOAuth.token("{\"access_token\":\"secret-not-for-logs\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid\"}"),"insufficient OAuth scope rejected");
        Path config=Files.createTempFile("google-test-client-",".json");
        try{Files.writeString(config,"{\"web\":{\"client_id\":\"test.apps.googleusercontent.com\"}}");reject(()->GoogleOAuth.Client.read(config),"web OAuth client rejected");Files.writeString(config,"{\"installed\":{\"client_id\":\"test.apps.googleusercontent.com\",\"token_uri\":\"https://attacker.invalid\"}}");var client=GoogleOAuth.Client.read(config);var uri=GoogleOAuth.authorization(client,"user@example.test","http://127.0.0.1:1234/oauth2/callback","state","verifier");check(uri.getHost().equals("accounts.google.com")&&GoogleOAuth.query(uri.getRawQuery()).get("code_challenge_method").equals("S256")&&GoogleOAuth.query(uri.getRawQuery()).get("access_type").equals("offline")&&GoogleOAuth.query(uri.getRawQuery()).get("prompt").contains("consent"),"authorization endpoint fixed and PKCE mandatory");}
        finally{Files.delete(config);}
        var callbackReached=new java.util.concurrent.atomic.AtomicBoolean();
        var callbackClient=new GoogleOAuth.Client("test.apps.googleusercontent.com","");
        reject(()->GoogleOAuth.authorize(callbackClient,"user@example.test",uri->{
            try{
                var fields=GoogleOAuth.query(uri.getRawQuery());String redirect=fields.get("redirect_uri");
                HttpClient http=HttpClient.newHttpClient();
                int wrong=http.send(HttpRequest.newBuilder(URI.create(redirect+"?state=wrong&code=x")).GET().build(),HttpResponse.BodyHandlers.discarding()).statusCode();
                if(wrong!=400)throw new AssertionError("mismatched state callback accepted");
                http.send(HttpRequest.newBuilder(URI.create(redirect+"?"+GoogleOAuth.form(Map.of("state",fields.get("state"),"error","access_denied")))).GET().build(),HttpResponse.BodyHandlers.discarding());callbackReached.set(true);
            }catch(Exception e){throw new RuntimeException(e);}
        },()->false),"real loopback rejects mismatched state and handles browser consent denial");
        check(callbackReached.get(),"loopback callback exercised through HTTP");
        var probes=new java.util.concurrent.atomic.AtomicInteger();var prompts=new java.util.concurrent.atomic.AtomicInteger();
        TokenPresence.require(()->probes.getAndIncrement()==0?2:0,()->{prompts.incrementAndGet();return true;});check(probes.get()==2&&prompts.get()==1,"missing token prompts once and rechecks before PIN");
        reject(()->TokenPresence.require(()->2,()->false),"missing-token cancellation stops operation");
        reject(()->TokenPresence.require(()->1,()->{throw new AssertionError("configuration error must not prompt insertion");}),"module errors are distinct from missing token");
        MimeMessage unsigned=new MimeMessage(MailEngine.session());unsigned.setText("ordinary text");unsigned.saveChanges();check(MailPreview.display(unsigned).contains("UNSIGNED MESSAGE")&&MailPreview.display(unsigned).contains("ordinary text"),"unsigned text is labelled unverified");
        unsigned.setHeader("Content-Type","application/pkcs7-mime; smime-type=signed-data");check(!MailPreview.isOrdinary(unsigned),"S/MIME cannot fall back to unsigned preview");
    }
}
