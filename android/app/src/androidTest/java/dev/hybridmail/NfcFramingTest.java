package dev.hybridmail;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.*;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import com.yubico.yubikit.core.Transport;
import java.io.*;
import java.util.*;
/** Exercises real YubiKit response assembly with non-256-byte continuation lengths. */
@RunWith(AndroidJUnit4.class)
public class NfcFramingTest extends YubiBackendTest {
 @Test public void largePublicKeysHonorAdvertisedContinuationLengths()throws Exception {
  for(var profile:TokenProfile.values()){
   Card card=new Card(profile){byte[] pending;int offset,expected;
    public Transport getTransport(){return Transport.NFC;}
    public byte[] sendAndReceive(byte[] a)throws IOException{
     if((a[1]&255)==0xc0){assertNotNull(pending);assertEquals(5,a.length);assertEquals(expected,a[4]&255);}
     else {byte[] full=super.sendAndReceive(a);pending=Arrays.copyOf(full,full.length-2);offset=0;}
     int n=Math.min(197,pending.length-offset);
     byte[] result=Arrays.copyOfRange(pending,offset,offset+n+2);offset+=n;
     int remaining=pending.length-offset;
     if(remaining>0){expected=Math.min(197,remaining);result[n]=0x61;result[n+1]=(byte)expected;}
     else {result[n]=(byte)0x90;result[n+1]=0;pending=null;}
     return result;
    }
   };
   assertTrue(PivReadTest.run(card,12345,card.publicKeys()).startsWith("PASS"));
   assertEquals(0,card.verifies);assertEquals(0,card.privateOps);
  }
 }
 @Test public void malformedAndUnknownStatusFailBeforePinWithoutReplay()throws Exception {
  for(byte[] response:new byte[][]{new byte[0],new byte[]{(byte)0x90},new byte[]{0x41,(byte)0x90},new byte[]{(byte)0xc4,3}}){
   Card card=new Card(TokenProfile.LEVEL3){int calls;
    public Transport getTransport(){return Transport.NFC;}
    public byte[] sendAndReceive(byte[] a){assertEquals(0,calls++);return response;}
   };
   var source=new YubiBackend.DeviceSource(){public com.yubico.yubikit.core.YubiKeyDevice get(){return card;}
    public boolean retryBeforePin(String d){fail("Framing/status errors must not trigger transport recovery");return false;}};
   var backend=new YubiBackend(source,l->"123456".toCharArray(),12345,card.publicKeys());
   try{backend.sign(card.keys.get(com.yubico.yubikit.piv.Slot.SIGNATURE).getPublic(),new byte[64]);fail();}
   catch(PivDiagnostic expected){assertFalse(expected.retryableBeforePin);}
   assertEquals(0,card.verifies);assertEquals(0,card.privateOps);
  }
 }
}
