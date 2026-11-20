package dev.hybridmail;

import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Chat secrets and default-identity pins live exclusively inside the PRF vault.
 * There is deliberately no OS credential-store or plaintext fallback. */
final class GoogleChatVault {
    private final PrfVault vault;
    GoogleChatVault(PrfVault vault){this.vault=Objects.requireNonNull(vault);}
    static String email(String value)throws Exception{
        String address=value.trim().toLowerCase(Locale.ROOT);
        OpenPgp.validateEmail(address);
        // Preserve dots and plus suffixes: separate certified addresses are not
        // implicitly interchangeable, even if a mail provider delivers both.
        return address;
    }
    private static String key(String purpose,String client,String account)throws Exception{
        return "google-chat."+purpose+"."+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((client+"\n"+email(account)).getBytes(StandardCharsets.UTF_8)));
    }
    private void unlocked()throws IOException{if(!vault.unlocked())throw new IOException("Unlock the passkey vault for Google Chat credentials and identity settings.");}
    void saveRefresh(String client,String account,char[] refresh,Set<String> grantedScopes)throws Exception{
        unlocked();new GoogleOAuth.Client(client,"");String address=email(account);
        if(refresh==null||refresh.length==0||refresh.length>16384)throw new IOException("Invalid Google Chat refresh token");
        if(!grantedScopes.containsAll(GoogleChatExperiment.SCOPES))throw new IOException("Google Chat read/send permissions were not fully granted");
        JsonObject data=new JsonObject();data.addProperty("client",client);data.addProperty("email",address);data.addProperty("refresh",new String(refresh));
        JsonArray scopes=new JsonArray();grantedScopes.stream().sorted().forEach(scopes::add);data.add("scopes",scopes);
        // Only refresh credentials persist. Access tokens are never accepted by
        // this storage API. The caller owns and must clear its input PIN/token.
        vault.put(key("oauth",client,address),data.toString());
    }
    boolean hasRefresh(String client,String account)throws Exception{unlocked();return !vault.get(key("oauth",client,account)).isEmpty();}
    interface RefreshOperation<T>{T run(char[] refresh)throws Exception;}
    <T>T withRefresh(String client,String account,RefreshOperation<T> operation)throws Exception{
        unlocked();String address=email(account),saved=vault.get(key("oauth",client,address));
        if(saved.isEmpty())throw new IOException("Sign in to Google Chat for this account and client first");
        JsonObject data=JsonParser.parseString(saved).getAsJsonObject();
        if(!client.equals(data.get("client").getAsString())||!address.equals(data.get("email").getAsString()))throw new IOException("Google Chat credential binding mismatch");
        Set<String> scopes=new HashSet<>();data.getAsJsonArray("scopes").forEach(s->scopes.add(s.getAsString()));
        if(!scopes.containsAll(GoogleChatExperiment.SCOPES))throw new IOException("Sign in again to authorize Google Chat read/send access");
        char[] refresh=data.get("refresh").getAsString().toCharArray();
        try{return operation.run(refresh);}finally{Arrays.fill(refresh,'\0');}
    }
    void forgetRefresh(String client,String account)throws Exception{unlocked();vault.put(key("oauth",client,account),null);}
    record Pin(String email,String identityId,String fingerprint,String certificateDigest){}
    static OpenPgp.PublicIdentity eligible(DesktopState state,String account,Identity identity)throws Exception{
        String address=email(account),id=DesktopState.identityId(identity);
        if(state.identities().stream().noneMatch(saved->saved.id().equals(id)))throw new IOException("Save this identity before pinning it for Chat");
        // loadOwn validates public certificate bindings against the selected
        // software/YubiKey identity. Reparse to reevaluate expiry/revocation.
        var original=OpenPgp.loadOwn(state.directory(),identity);
        var cert=new OpenPgp.PublicIdentity(original.encoded);
        if(cert.version()!=6||(cert.v6!=null&&cert.v6.signers.isEmpty())||!cert.matchesEmail(address)||!cert.canEncrypt())throw new IOException("Select a usable v6 OpenPGP identity with signing/encryption keys and a certified email matching "+address);
        if(cert.signing==null||cert.signing.pq()==null||!cert.quantumEncryption())throw new IOException("The default Chat identity requires hybrid v6 signing and encryption");
        return cert;
    }
    private static String digest(OpenPgp.PublicIdentity cert)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.encoded));}
    Pin pin(DesktopState state,String account,Identity identity)throws Exception{
        unlocked();var cert=eligible(state,account,identity);String address=email(account);
        Pin pin=new Pin(address,DesktopState.identityId(identity),cert.fingerprint(),digest(cert));
        vault.put(key("identity","",address),new Gson().toJson(pin));return pin;
    }
    Pin pinned(String account)throws Exception{
        unlocked();String saved=vault.get(key("identity","",account));if(saved.isEmpty())return null;
        Pin pin=new Gson().fromJson(saved,Pin.class);if(!email(account).equals(pin.email()))throw new IOException("Chat identity account binding mismatch");return pin;
    }
    void unpin(String account)throws Exception{unlocked();vault.put(key("identity","",account),null);}
    OpenPgp.PublicIdentity requirePinned(DesktopState state,String authorizedAccount,Identity loaded)throws Exception{
        Pin pin=pinned(authorizedAccount);if(pin==null)throw new IOException("Pin a default v6 identity for this Google Chat account first");
        if(!pin.identityId().equals(DesktopState.identityId(loaded)))throw new IOException("Load the pinned Chat identity; the Compose selection is not a replacement");
        var cert=eligible(state,authorizedAccount,loaded);
        if(!pin.fingerprint().equals(cert.fingerprint())||!pin.certificateDigest().equals(digest(cert)))throw new IOException("The pinned OpenPGP certificate changed; review and pin it again");
        // Call this guard for both send/sign and receive/decrypt. A pin chooses
        // our own keys; it never grants trust to an incoming message's signer.
        return cert;
    }
}
