package dev.hybridmail;
import org.junit.Test;
import static org.junit.Assert.*;
import com.yubico.yubikit.core.Transport;
import java.io.*;
import java.util.*;
public class OnKeyTransportTest extends YubiBackendTest {
 @Test public void certificateObjectReadHonorsNfcBoundary()throws Exception{
  for(boolean extended:new boolean[]{false,true}){
   byte[] object=new byte[2068];new java.security.SecureRandom().nextBytes(object);
   int[] reads={0},truncated={0};
   Card fake=new Card(TokenProfile.LEVEL3){byte[] pending;int offset;
    public Transport getTransport(){return Transport.NFC;}
    public boolean isExtendedLengthApduSupported(){return extended;}
    public byte[] sendAndReceive(byte[] a)throws IOException{
     int ins=a[1]&255;if(ins!=0xcb&&ins!=0xc0)return super.sendAndReceive(a);
     if(ins==0xcb){assertEquals(11,a.length);assertEquals(5,a[4]);assertEquals(0x5c,a[5]&255);assertEquals(240,a[10]&255);pending=tlv(0x53,object);offset=0;}
     int le=a[a.length-1]&255;if(le==0)le=256;int n=Math.min(le,pending.length-offset);byte[] answer=Arrays.copyOfRange(pending,offset,offset+n+2);offset+=n;int remaining=pending.length-offset;
     answer[n]=remaining==0?(byte)0x90:0x61;answer[n+1]=(byte)(remaining>=256?0:remaining);reads[0]++;
     if(answer.length>253){truncated[0]++;return Arrays.copyOf(answer,253);}return answer;
    }
   };
   try(var card=new OnKeyAndroid(fake)){assertArrayEquals(object,card.get(0x5f5001));}
   assertTrue(reads[0]>1);assertEquals(0,truncated[0]);assertEquals(0,fake.verifies);assertEquals(0,fake.privateOps);
  }
 }
}
