package dev.hybridmail;

import java.nio.file.*;
import java.util.*;

/** Uses a temporary encrypted vault and software keys; no OAuth or hardware. */
public final class GoogleChatVaultTest {
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    interface Op{void run()throws Exception;}
    static void reject(Op op)throws Exception{try{op.run();throw new AssertionError("Unexpected acceptance");}catch(AssertionError e){throw e;}catch(Exception expected){}}
    public static void main(String[] args)throws Exception{
        MailEngine.init();Path root=Files.createTempDirectory("chat-vault-");byte[] prf=PrfVault.random(32);String client="chat-test.apps.googleusercontent.com",email="chat@example.test";
        try(var vault=new PrfVault(root.resolve("vault.json"))){
            var store=new GoogleChatVault(vault);reject(()->store.withRefresh(client,email,s->null));vault.create("YWJj",PrfVault.random(32),prf);
            vault.put("credential.google-session","existing-gmail-marker");char[] refresh="synthetic-chat-refresh-token".toCharArray();Set<String> scopes=Set.copyOf(GoogleChatExperiment.SCOPES);
            reject(()->store.saveRefresh(client,email,refresh,Set.of(GoogleChatExperiment.SCOPES.getLast())));store.saveRefresh(client,email,refresh,scopes);
            check(!Files.readString(root.resolve("vault.json")).contains("synthetic-chat-refresh-token"),"Plaintext token on disk");char[][] delivered={null};store.withRefresh(client,email,s->{delivered[0]=s;check(Arrays.equals(s,refresh),"Refresh mismatch");return null;});check(Arrays.equals(delivered[0],new char[delivered[0].length]),"Temporary refresh not cleared");
            reject(()->store.withRefresh(client,"wrong@example.test",s->null));reject(()->store.withRefresh("other.apps.googleusercontent.com",email,s->null));
            reject(()->store.withRefresh(client,email,s->{delivered[0]=s;throw new java.io.IOException("Synthetic failure");}));check(Arrays.equals(delivered[0],new char[delivered[0].length]),"Failure leaked temporary refresh");
            var ids=SoftwareIdentityVault.addLevel5OpenPgp(Identity.generateSoftwareProfile(email,TokenProfile.LEVEL5,List.of("alias@example.test")));var id=ids.getLast();var own=id.softwareOpenPgp().own();
            Path p12=root.resolve("identity.p12");id.save(p12,"synthetic-only-password".toCharArray(),ids.getFirst());DesktopState state=new DesktopState(root.resolve("state"));state.rememberSoftwareProfiles(ids,p12,"Synthetic");
            var pin=store.pin(state,email,id);check(pin.fingerprint().equals(own.fingerprint()),"Wrong pin");store.requirePinned(state,email,id);reject(()->store.pin(state,"wrong@example.test",id));reject(()->store.requirePinned(state,email,ids.getFirst()));
            var contact=state.rememberPgp(own,email);var initial=GoogleChatContacts.inspect(state,email);check(initial.certificates().size()==1&&!initial.certificates().getFirst().trusted()&&initial.certificates().getFirst().version()==6,"Import implicitly trusted");state.setPgpTrusted(contact,true);
            var trusted=GoogleChatContacts.inspect(state,email);check(trusted.certificates().getFirst().trusted(),"Missing exact trust");check(!GoogleChatContacts.inspect(state,"alias@example.test").certificates().getFirst().trusted(),"Alias inherited trust");
            state.rememberPgp(own.compatibility,email);var mixed=GoogleChatContacts.inspect(state,email);check(mixed.certificates().size()==2&&mixed.certificates().getFirst().version()==6&&!mixed.certificates().getLast().trusted(),"v4/v6 trust conflated");
            var bundles=new GoogleChatBundles(state,store,"gmail-test.apps.googleusercontent.com");
            reject(()->bundles.create(email,id,own,email,"Chat","Hello",null,List.of(),null));
            GoogleChatExperiment.configure(state,true,client,"gmail-test.apps.googleusercontent.com");
            byte[] bundle=bundles.create(email,id,own,email,"Chat","Hello","<b>Hello</b>",List.of(),null);
            check(bundles.open(email,email,bundle,own,id,null).trusted(),"Trusted Chat bundle not recognized");
            reject(()->bundles.open(email,"wrong@example.test",bundle,own,id,null));
            state.setPgpTrusted(contact,false);reject(()->bundles.create(email,id,own,email,"Chat","Hello",null,List.of(),null));
            check(!bundles.open(email,email,bundle,own,id,null).trusted(),"Verification implicitly trusted signer");
            state.setPgpTrusted(contact,true);
            state.setTrusted(id.signingCert(),"signing",true);state.rememberContact(id.signingCert(),email,"signing");state.setPgpTrusted(contact,false);check(GoogleChatContacts.inspect(state,email).certificates().stream().filter(c->c.kind().equals("OpenPGP")).noneMatch(GoogleChatContacts.Certificate::trusted),"S/MIME trust leaked to OpenPGP");
            check(GoogleChatContacts.inspect(state,"").certificates().isEmpty()&&GoogleChatContacts.inspect(state,"unknown@example.test").certificates().isEmpty(),"Unknown user matched a key");
            vault.close();reject(()->store.pinned(email));reject(()->store.withRefresh(client,email,s->null));vault.unlock("YWJj",prf);store.requirePinned(state,email,id);check(store.pinned("other@example.test")==null,"Account pin leaked");
            state.set("identities","");state.save();reject(()->store.requirePinned(state,email,id));store.unpin(email);check(store.pinned(email)==null,"Unpin failed");store.forgetRefresh(client,email);reject(()->store.withRefresh(client,email,s->null));check(vault.get("credential.google-session").equals("existing-gmail-marker"),"Touched Gmail session");
            Arrays.fill(refresh,'\0');System.out.println("PASS vault-only Chat refresh storage, account/client/scope binding, lock and temporary-secret clearing; v6 identity pin/revalidation; per-email/fingerprint contact trust and v4/v6/S/MIME separation");
        }finally{Arrays.fill(prf,(byte)0);try(var files=Files.walk(root)){for(var path:files.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
