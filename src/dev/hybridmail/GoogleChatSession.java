package dev.hybridmail;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.function.Consumer;

/** One Chat login, distinct from Gmail. Refresh tokens persist only through
 * GoogleChatVault; access tokens and verified account IDs stay in memory. */
final class GoogleChatSession implements AutoCloseable {
    static final Set<String> SCOPES;
    static {var scopes=new HashSet<>(GoogleChatExperiment.SCOPES);scopes.add("https://www.googleapis.com/auth/userinfo.email");SCOPES=Set.copyOf(scopes);}
    private final PrfVault vault;private final GoogleChatVault storage;private final GoogleOAuth.Client client;
    private GoogleOAuth.Token token;private GoogleChatApi.Account account;
    interface OAuth {
        GoogleOAuth.Token authorize(GoogleOAuth.Client c,String email,Consumer<URI> browser,java.util.function.BooleanSupplier cancelled)throws Exception;
        GoogleOAuth.Token refresh(GoogleOAuth.Client c,String refresh)throws Exception;
    }
    private final OAuth oauth;private final GoogleChatApi.Wire wire;
    private static final OAuth GOOGLE=new OAuth(){
        public GoogleOAuth.Token authorize(GoogleOAuth.Client c,String email,Consumer<URI> browser,java.util.function.BooleanSupplier cancelled)throws Exception{return GoogleOAuth.authorize(c,email,browser,cancelled,SCOPES);}
        public GoogleOAuth.Token refresh(GoogleOAuth.Client c,String refresh)throws Exception{return GoogleOAuth.refresh(c,refresh,SCOPES);}
    };
    GoogleChatSession(PrfVault vault,GoogleOAuth.Client client){this(vault,client,GOOGLE,GoogleChatApi::network);}
    GoogleChatSession(PrfVault vault,GoogleOAuth.Client client,OAuth oauth,GoogleChatApi.Wire wire){this.vault=vault;storage=new GoogleChatVault(vault);this.client=client;this.oauth=oauth;this.wire=wire;}
    static GoogleOAuth.Client client()throws IOException{
        try(var in=GoogleChatSession.class.getResourceAsStream("/google-chat-client.json")){
            if(in==null)throw new IOException("This build has no Chat test client configuration");
            var j=com.google.gson.JsonParser.parseString(new String(in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("installed");return new GoogleOAuth.Client(j.get("client_id").getAsString(),j.get("client_secret").getAsString());
        }
    }
    synchronized GoogleChatApi.Account connect(String email,boolean fresh,Consumer<URI> browser)throws Exception{
        requireUnlock();close();String expected=GoogleChatVault.email(email);GoogleOAuth.Token candidate;
        if(fresh||!storage.hasRefresh(client.id(),expected))candidate=oauth.authorize(client,expected,browser,()->!vault.unlocked()||Thread.currentThread().isInterrupted());
        else candidate=storage.withRefresh(client.id(),expected,r->oauth.refresh(client,new String(r)));
        try{
            // login_hint isn't an identity proof. Fetch the authenticated Google
            // account and reject account switching before persisting credentials.
            var actual=new GoogleChatApi(candidate::credential,wire).account();requireUnlock();
            if(!actual.email().equals(expected))throw new IOException("Google signed in a different account; choose "+expected);
            String refresh=candidate.refreshToken();if(refresh==null)throw new IOException("Google did not supply offline access; choose Sign in again");
            char[] chars=refresh.toCharArray();try{storage.saveRefresh(client.id(),expected,chars,SCOPES);}finally{Arrays.fill(chars,'\0');}
            token=candidate;account=actual;candidate=null;return account;
        }finally{if(candidate!=null)candidate.close();}
    }
    private void requireUnlock()throws IOException{if(!vault.unlocked()){close();throw new IOException("Unlock the PRF vault before using Chat");}}
    synchronized char[] credential()throws Exception{
        requireUnlock();if(account==null||token==null)throw new IOException("Sign in or reconnect to Google Chat first");
        if(!token.valid()){
            var next=storage.withRefresh(client.id(),account.email(),r->oauth.refresh(client,new String(r)));
            try{var actual=new GoogleChatApi(next::credential,wire).account();if(!actual.equals(account))throw new IOException("Chat account changed; sign in again");requireUnlock();token.close();token=next;next=null;}finally{if(next!=null)next.close();}
        }return token.credential();
    }
    synchronized GoogleChatApi.Account account()throws IOException{requireUnlock();if(account==null)throw new IOException("Connect Google Chat first");return account;}
    GoogleChatApi api(){return new GoogleChatApi(this::credential,wire);}
    synchronized void forget(String email)throws Exception{close();storage.forgetRefresh(client.id(),email);}
    public synchronized void close(){if(token!=null)token.close();token=null;account=null;}
}
