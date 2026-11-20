package dev.hybridmail;

import java.io.IOException;
import java.util.List;

/** Default-off development boundary; it does not enable a Chat transport or
 * reuse Gmail authorization. The client ID is public configuration, not a token. */
final class GoogleChatExperiment {
    static final String FLAG="experimental.googleChat.enabled";
    static final String CLIENT="experimental.googleChat.clientId";
    // These names deliberately do not overlap with google-session/google-client.
    // Chat credentials must use GoogleChatVault and the unlocked PRF vault;
    // no credentials are written by this configuration class.
    static final String SESSION_NAMESPACE="google-chat-experimental-session";
    static final List<String> SCOPES=List.of(
        "https://www.googleapis.com/auth/chat.spaces.readonly",
        "https://www.googleapis.com/auth/chat.messages.readonly",
        "https://www.googleapis.com/auth/chat.messages.create");
    static boolean enabled(DesktopState state){return "true".equals(state.get(FLAG,"false"));}
    static String clientId(DesktopState state){return state.get(CLIENT,"");}
    static void configure(DesktopState state,boolean enabled,String clientId,String gmailClientId)throws IOException{
        String id=clientId.trim();
        // Validate every field before writing either preference. A disabled
        // experiment may retain its client ID without making any OAuth request.
        if(!id.isEmpty())validateSeparateClient(id,gmailClientId);
        if(enabled&&id.isEmpty())throw new IOException("Configure a separate Google Chat Desktop OAuth client before enabling this experiment.");
        state.set(CLIENT,id.isEmpty()?null:id);state.set(FLAG,Boolean.toString(enabled));state.save();
    }
    static void requireEnabled(DesktopState state,String gmailClientId)throws IOException{
        if(!enabled(state))throw new IOException("Experimental Google Chat is disabled.");
        validateSeparateClient(clientId(state),gmailClientId);
    }
    private static void validateSeparateClient(String id,String gmailClientId)throws IOException{
        try{new GoogleOAuth.Client(id,"");}catch(IllegalArgumentException e){throw new IOException("Enter a valid Google Chat Desktop OAuth client ID.");}
        if(id.equals(gmailClientId))throw new IOException("Use a separate development client for Chat; the Gmail client is reserved for mail.");
        // Different IDs alone cannot prove project separation. The setup UI
        // explicitly asks for a client from a dedicated development project.
    }
}
