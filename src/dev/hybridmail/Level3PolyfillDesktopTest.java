package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Exercises the real desktop catalog and PGP/MIME entry points with a
 * synthetic card. There are no PC/SC calls, PIN dialogs, account reads or mail
 * sends. Only ciphertext and public metadata may persist in the test catalog. */
public final class Level3PolyfillDesktopTest {
    /** Match production's operation lifetime while substituting generated
     * hardware keys. Software PQ material is destroyed after every message. */
    static final class Operation implements ExternalMu.Backend,ExternalKem.Backend {
        final byte[] encoded;final Map<String,PublicKey> publicKeys;final Level3CompanionTest.Hardware card;
        Level3Companion companion;boolean ended;
        Operation(byte[] encoded,Map<String,PublicKey> keys,Level3CompanionTest.Hardware card){this.encoded=encoded;this.publicKeys=keys;this.card=card;}
        public Operation newOperation(){return new Operation(encoded,publicKeys,card);}
        private Level3Companion unlock()throws Exception{check(!ended,"Operation ended");if(companion==null)companion=Level3Companion.restore(encoded,123456,publicKeys,card);return companion;}
        public byte[] sign(PublicKey key,byte[] mu)throws Exception{return unlock().signComponent(key,mu);}
        public byte[] signEd25519(PublicKey key,byte[] digest)throws Exception{check(!ended,"Operation ended");return card.signEd25519(key,digest);}
        public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception{return unlock().decapsulate(key,ciphertext);}
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{check(!ended,"Operation ended");return card.derive(key,peer);}
        public void clearSecrets(){ended=true;if(companion!=null){companion.close();companion=null;}}
    }
    static void reject(Level5CompanionTest.Checked action)throws Exception{Level5CompanionTest.rejected(action);}
    public static void main(String[] args)throws Exception {
        MailEngine.init();Path directory=Files.createTempDirectory("level3-desktop-test-");
        var keys=Level3CompanionTest.hardware();var publics=new LinkedHashMap<String,PublicKey>();keys.forEach((slot,key)->publics.put(slot,key.getPublic()));var card=new Level3CompanionTest.Hardware(keys);
        try{
            byte[] encoded;Identity original;PublicIdentity own;
            try(var created=Level3Companion.create(123456,publics,List.of("desktop@example.test","alias@example.test"),card,card)){encoded=created.seal(card);original=created.anchors();own=created.own;}
            var state=new DesktopState(directory);var id=Level3PolyfillDesktop.install(state,new Level3PolyfillDesktop.Loaded(encoded,Level3Companion.inspect(encoded,123456,publics)));
            String catalog=DesktopState.identityId(id);check(id.level3Polyfill()&&OpenPgp.supported(id),"Companion is not a selectable OpenPGP identity");
            check(state.identities().size()==1&&!state.identities().getFirst().passwordRequired(),"Wrong catalog storage type");
            var restarted=new DesktopState(directory);id=restarted.loadIdentity(catalog,new char[0]);restarted.activateIdentity(id);
            // Invalid software component requests must be rejected before the
            // no-touch wrapping operation asks for its PIN. The deliberately
            // nonexistent adapter path catches any accidental process launch.
            int[] pinRequests={0};ExternalMu.PinSource forbiddenPin=()->{pinRequests[0]++;throw new GeneralSecurityException("Unexpected PIN request");};
            try(var invalid=new Level3PolyfillOperation(encoded,123456,publics,"/not-an-adapter","/not-an-adapter",Map.of(),forbiddenPin)){
                reject(()->invalid.sign(parseKey(own.primary,true).pq(),new byte[64]));
            }
            try(var invalid=new Level3PolyfillOperation(encoded,123456,publics,"/not-an-adapter","/not-an-adapter",Map.of(),forbiddenPin)){
                reject(()->invalid.sign(own.signing.pq(),new byte[63]));
            }
            try(var invalid=new Level3PolyfillOperation(encoded,123456,publics,"/not-an-adapter","/not-an-adapter",Map.of(),forbiddenPin)){
                reject(()->invalid.decapsulate(own.signing.pq(),new byte[1088]));
            }
            try(var invalid=new Level3PolyfillOperation(encoded,123456,publics,"/not-an-adapter","/not-an-adapter",Map.of(),forbiddenPin)){
                reject(()->invalid.decapsulate(own.encryption.pq(),new byte[1]));
            }
            try(var invalid=new Level3PolyfillOperation(encoded,123456,publics,"/not-an-adapter","/not-an-adapter",Map.of(),forbiddenPin)){
                reject(()->invalid.signEd25519(publics.get("82"),new byte[48]));
                reject(()->invalid.derive(publics.get("82"),publics.get("9d")));
                invalid.close();reject(()->invalid.sign(own.signing.pq(),new byte[64]));reject(()->invalid.signEd25519(publics.get("9c"),new byte[48]));reject(()->invalid.decapsulate(own.encryption.pq(),new byte[1088]));reject(()->invalid.derive(publics.get("83"),publics.get("83")));
            }
            check(pinRequests[0]==0,"Invalid or closed operation requested a PIN");
            check(DesktopState.activeTokenSerial().equals("123456"),"Hardware serial binding lost on restart");
            check(Arrays.equals(id.signingCert().getEncoded(),original.signingCert().getEncoded())&&Arrays.equals(id.encryptionCert().getEncoded(),original.encryptionCert().getEncoded()),"Carrier certificates changed across restart");
            var restoredOwn=OpenPgp.loadOwn(directory,id);check(Arrays.equals(own.encoded,restoredOwn.encoded),"OpenPGP certificate changed across restart");
            Path ciphertext=Level3PolyfillDesktop.path(directory,id);check(Arrays.equals(encoded,Files.readAllBytes(ciphertext)),"Ciphertext cache differs from card envelope");
            check(restarted.contacts().isEmpty()&&restarted.pgpContacts().isEmpty(),"Restoring own identity unexpectedly added or trusted contacts");
            Identity selected=id;var operation=new Operation(encoded,publics,card);
            reject(()->selected.signer(operation));
            reject(()->MailEngine.compose(selected,"desktop@example.test","desktop@example.test","Not S/MIME","test",null,operation));
            reject(()->Identity.validateCertificatePurpose(selected.signingCert(),"signing"));
            reject(()->Identity.validateCertificatePurpose(selected.encryptionCert(),"encryption"));
            reject(()->restarted.setTrusted(selected.signingCert(),"signing",true));
            reject(()->restarted.rememberContact(selected.encryptionCert(),"desktop@example.test","encryption"));
            reject(()->restarted.certificateBundle(selected));
            int wrap=card.wrappings,sign=card.signatures,decrypt=card.decryptions;
            for(boolean encrypted:new boolean[]{false,true}){
                byte[] mime=OpenPgp.composeForRecipient(id,restoredOwn,restoredOwn,encrypted,"desktop@example.test","desktop@example.test","Synthetic desktop test","Desktop companion test","<p>Desktop <b>companion</b> test</p>",operation);
                // Parsing through the mail engine exercises the same MIME
                // normalization used when a downloaded message is opened.
                var parsed=MailEngine.parse(mime);check(parsed.getSubject().equals("Synthetic desktop test"),"Message subject lost");
                var opened=OpenPgp.open(MailEngine.encode(parsed),restoredOwn,restoredOwn,id,operation);
                check(opened.encrypted()==encrypted&&opened.postQuantum()&&opened.text().contains("Desktop companion test")&&opened.html()!=null&&opened.html().contains("<b>companion</b>"),"Desktop PGP/MIME round trip failed");
            }
            check(card.signatures==sign+2&&card.decryptions==decrypt+1&&card.wrappings==wrap+3,"Unexpected private operations across two signatures and one decryption");card.wiped();
            // A valid companion belonging to another software primary must not
            // replace this selector's carrier, even on the same physical card.
            try(var other=Level3Companion.create(123456,publics,List.of("desktop@example.test"),card,card)){
                reject(()->OpenPgp.match(own,other.anchors()));reject(()->Level3PolyfillDesktop.saveLocal(directory,other.anchors(),encoded));
            }
            byte[] bad=encoded.clone();bad[bad.length/2]^=1;Files.write(ciphertext,bad);reject(()->OpenPgp.loadOwn(directory,selected));Files.write(ciphertext,encoded);
            // The old .asc cache is not an authority: loadOwn validates the
            // signed companion and returns its full certificate every time.
            Files.write(OpenPgp.ownPath(directory,id),new byte[]{1,2,3});check(Arrays.equals(OpenPgp.loadOwn(directory,id).encoded,own.encoded),"Unauthenticated .asc cache overrode companion");
            int privateCalls=card.wrappings+card.signatures+card.decryptions+card.certifications;
            restarted.forgetYubiKeyIdentity(catalog);check(new DesktopState(directory).identities().isEmpty()&&!Files.exists(ciphertext)&&!Files.exists(OpenPgp.ownPath(directory,id)),"Forget retained companion identity files");
            check(privateCalls==card.wrappings+card.signatures+card.decryptions+card.certifications,"Forget contacted the card");
            try(var files=Files.walk(directory)){check(files.noneMatch(p->p.getFileName().toString().endsWith(".p12")),"Plaintext P12 persisted in desktop catalog");}
            System.out.println("PASS Level 3 desktop: install/restart/load/activate, signed+encrypted HTML PGP/MIME, S/MIME and trust refusal, wrong-carrier/tampered-cache rejection, ciphertext-only persistence and local Forget");
        }finally{try(var paths=Files.walk(directory)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
    }
}
