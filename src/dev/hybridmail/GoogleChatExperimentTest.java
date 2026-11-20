package dev.hybridmail;

import java.nio.file.*;
import java.util.*;

/** Configuration boundaries are checked without a browser, account or network. */
public final class GoogleChatExperimentTest {
    static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    interface Operation{void run()throws Exception;}
    static void reject(Operation op)throws Exception{try{op.run();throw new AssertionError("Unexpected authorization");}catch(java.io.IOException expected){}}
    public static void main(String[] args)throws Exception{
        Path root=Files.createTempDirectory("chat-experiment-");String gmail="mail-test.apps.googleusercontent.com",chat="chat-test.apps.googleusercontent.com";
        try{
            DesktopState state=new DesktopState(root);state.set("google.email","synthetic@example.test");state.set("google.client.mode","shared");state.save();
            check(!GoogleChatExperiment.enabled(state),"Experiment must default off");reject(()->GoogleChatExperiment.requireEnabled(state,gmail));
            reject(()->GoogleChatExperiment.configure(state,true,"",gmail));reject(()->GoogleChatExperiment.configure(state,true,gmail,gmail));reject(()->GoogleChatExperiment.configure(state,true,"invalid",gmail));
            check(!GoogleChatExperiment.enabled(state)&&GoogleChatExperiment.clientId(state).isEmpty(),"Invalid setup mutated configuration");
            GoogleChatExperiment.configure(state,true,chat,gmail);DesktopState restored=new DesktopState(root);GoogleChatExperiment.requireEnabled(restored,gmail);
            check(GoogleChatExperiment.clientId(restored).equals(chat),"Client selection did not survive restart");
            GoogleChatExperiment.configure(restored,false,chat,gmail);reject(()->GoogleChatExperiment.requireEnabled(restored,gmail));
            check(restored.get("google.email","").equals("synthetic@example.test")&&restored.get("google.client.mode","").equals("shared"),"Changed Gmail configuration");
            check(GoogleChatExperiment.SCOPES.size()==3&&GoogleChatExperiment.SCOPES.stream().allMatch(s->s.contains("/auth/chat.")),"Unexpected Chat scopes");
            check(!GoogleOAuth.SCOPE.contains("chat.")&&GoogleOAuth.SCOPE.equals(GoogleOAuth.READ_SCOPE+" "+GoogleOAuth.SEND_SCOPE),"Chat permissions leaked into Gmail");
            System.out.println("PASS default-off Chat gate, separate client, validation, restart, disable and unchanged Gmail permissions/configuration; no network or credentials");
        }finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
