package dev.hybridmail;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import java.io.*;
import java.util.*;
@RunWith(AndroidJUnit4.class)
public class OnKeyAndroidTest {
    static class Card implements OnKeyBundle.Card {
        Map<Integer,byte[]> objects=new HashMap<>();Map<String,byte[]> keys;int writes,fail=-1;
        public int serial(){return 123456;}public byte[] publicKey(String slot){return keys.get(slot);}
        public byte[] get(int tag){return objects.get(tag);}public void put(int tag,byte[] value)throws Exception{if(writes++==fail)throw new IOException("Interrupted");objects.put(tag,value);}
        public void authenticate(char[] management){}public void move9aTo83(){throw new AssertionError("No hardware operations in test");}
    }
    @Test public void allProfilesSignedStorageAndInterruptedWrite()throws Exception{
        java.security.Security.removeProvider("BC");java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);MailEngine.init();for(TokenProfile level:TokenProfile.values()){
            var ids=Identity.generateSoftwareProfile("test@example.com",level,List.of());var entries=new ArrayList<OnKeyBundle.Profile>();
            for(var id:ids)entries.add(new OnKeyBundle.Profile(new CertificateBundle.Entry(id,123456,"9c","83","9d","82"),OpenPgp.supported(id)?OpenPgp.create(id,null).encoded:new byte[0]));
            byte[] payload=OnKeyBundle.payload(entries);var signer=ids.get(1).signer(null);signer.getOutputStream().write(payload);var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.writeBytes("PQMAILS1");OnKeyBundle.blob(out,payload);out.writeInt(1);OnKeyBundle.blob(out,signer.getSignature());
            var bundle=OnKeyBundle.decode(bytes.toByteArray());var card=new Card();card.keys=OnKeyBundle.bindings(bundle.entries());OnKeyStorage.save(card,bundle.encoded(),new char[0]);
            card.fail=card.writes+1;try{OnKeyStorage.save(card,bundle.encoded(),new char[0]);fail("Expected interruption");}catch(IOException expected){}
            assertArrayEquals(bundle.encoded(),OnKeyStorage.load(card).encoded());byte[] tampered=bundle.encoded().clone();tampered[tampered.length-1]^=1;try{OnKeyBundle.decode(tampered);fail("Accepted tampering");}catch(Exception expected){}
        }
    }
}
