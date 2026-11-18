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
  for(byte[] response:new byte[][]{new byte[0],new byte[]{(byte)0x90},new byte[]{0x41,(byte)0x90},new byte[]{(byte)0xc4,3},new byte[]{0x7e,(byte)0x84}}){
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
 @Test public void publicMetadataReadsAvoid253ByteTruncationBoundary()throws Exception {
  for(var profile:TokenProfile.values()){
   int[] truncated={0},continuations={0};
   Card card=new Card(profile){byte[] pending;int offset;
    public Transport getTransport(){return Transport.NFC;}
    public byte[] sendAndReceive(byte[] a)throws IOException{
     int ins=a[1]&255;
     if(ins!=0xf7 && ins!=0xc0)return super.sendAndReceive(a);
     if(ins==0xf7){byte[] full=super.sendAndReceive(a);pending=Arrays.copyOf(full,full.length-2);offset=0;}
     else continuations[0]++;
     int le=a[4]&255;if(le==0)le=256;
     int n=Math.min(le,pending.length-offset);
     byte[] response=Arrays.copyOfRange(pending,offset,offset+n+2);offset+=n;
     int remaining=pending.length-offset;
     response[n]=remaining>0?0x61:(byte)0x90;
     response[n+1]=remaining>0?(byte)(remaining>=256?0:remaining):0;
     if(response.length>253){truncated[0]++;return Arrays.copyOf(response,253);}
     return response;
    }
   };
   // Control without our wrapper: the synthetic transport truncates the large response.
   try{PivSessions.open(card).getSlotMetadata(com.yubico.yubikit.piv.Slot.SIGNATURE);fail("Unbounded read must not succeed");}catch(Exception expected){}
   assertTrue(truncated[0]>0);truncated[0]=0;
   assertTrue(PivReadTest.run(card,12345,card.publicKeys()).startsWith("PASS"));
   assertEquals(0,truncated[0]);assertTrue(continuations[0]>0);
   assertEquals(0,card.verifies);assertEquals(0,card.privateOps);
  }
 }
 @Test public void chunkLimitDoesNotAlterUsbOrPrivateResponses()throws Exception {
  for(var transport:new Transport[]{Transport.USB,Transport.NFC}){
   java.util.List<byte[]> sent=new ArrayList<>();
   Card card=new Card(TokenProfile.LEVEL3){
    public Transport getTransport(){return transport;}
    public byte[] sendAndReceive(byte[] a){sent.add(a.clone());return new byte[]{0x61,0};}
   };
   var connection=new PivDiagnostic.Connection(card);
   byte[] metadata={0,(byte)0xf7,0,(byte)0x9c,0};
   connection.sendAndReceive(metadata);
   assertEquals(transport==Transport.NFC?240:0,sent.get(0)[4]&255);
   assertEquals(0,metadata[4]); // Do not mutate YubiKit's command buffer.
   connection.sendAndReceive(new byte[]{0,(byte)0x87,0,0,0});
   connection.sendAndReceive(new byte[]{0,(byte)0xc0,0,0,0});
   assertEquals(0,sent.get(2)[4]);connection.close();
  }
 }

}
