package dev.hybridmail;

import java.io.IOException;
import java.util.List;

/** Desktop boundary for the experimental transport. Reuses the vault-pinned
 * identity and email/fingerprint trust store rather than the Compose selection.
 * The transport must supply authenticated account/sender email mappings. */
final class GoogleChatBundles {
    private final DesktopState state;
    private final GoogleChatVault vault;
    private final String gmailClient;
    GoogleChatBundles(DesktopState state,GoogleChatVault vault,String gmailClient){this.state=state;this.vault=vault;this.gmailClient=gmailClient;}
    byte[] create(String account,Identity loaded,OpenPgp.PublicIdentity recipient,String to,String subject,String text,String html,
                  List<MailEngine.Attachment> files,ExternalMu.Backend backend)throws Exception{
        GoogleChatExperiment.requireEnabled(state,gmailClient);
        var own=vault.requirePinned(state,account,loaded);
        if(recipient!=null&&!state.isPgpTrusted(GoogleChatVault.email(to),recipient.fingerprint()))throw new IOException("Review and trust the recipient's email and full OpenPGP fingerprint before encrypting Chat");
        return ChatBundle.create(loaded,own,recipient,account,to,subject,text,html,files,backend);
    }
    record Received(ChatBundle.Opened bundle,boolean trusted){}
    Received open(String account,String transportSender,byte[] bytes,OpenPgp.PublicIdentity signer,Identity loaded,ExternalKem.Backend backend)throws Exception{
        GoogleChatExperiment.requireEnabled(state,gmailClient);
        var own=vault.requirePinned(state,account,loaded);
        var result=ChatBundle.open(bytes,signer,own,loaded,backend);
        if(!GoogleChatVault.email(result.to()).equals(GoogleChatVault.email(account))||!GoogleChatVault.email(result.from()).equals(GoogleChatVault.email(transportSender)))throw new IOException("Chat sender/recipient does not match the signed message");
        // Successful mathematics is not contact trust. Return both independently
        // so a future Chat UI can display untrusted signatures accurately.
        return new Received(result,state.isPgpTrusted(result.from(),result.signerFingerprint()));
    }
}
