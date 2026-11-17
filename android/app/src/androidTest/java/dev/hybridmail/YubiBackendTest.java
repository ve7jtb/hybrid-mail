package dev.hybridmail;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.*;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import com.yubico.yubikit.core.*;
import com.yubico.yubikit.core.smartcard.*;
import com.yubico.yubikit.core.util.*;
import com.yubico.yubikit.piv.*;
import java.io.*;
import java.security.*;
import java.util.*;

/** Tests the REAL YubiKit PivSession against a fake APDU card, not physical hardware. */
@RunWith(AndroidJUnit4.class)
public class YubiBackendTest {
 @Before public void providers(){Security.removeProvider("BC");Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(),1);}
 static byte[] tlv(int tag,byte[] value){return new Tlv(tag,value).getBytes();}
 static byte[] join(byte[]... values)throws IOException{var out=new ByteArrayOutputStream();for(byte[] v:values)out.write(v);return out.toByteArray();}
 static class Card implements YubiKeyDevice,SmartCardConnection {
  Map<Slot,KeyPair> keys=new EnumMap<>(Slot.class);Map<Slot,KeyType> types=new EnumMap<>(Slot.class);int verifies,privateOps,closes;boolean rejectPin;int serial=12345;
  Card(TokenProfile p)throws Exception{
   keys.put(Slot.SIGNATURE,KeyPairGenerator.getInstance(p.ml,"BC").generateKeyPair());keys.put(Slot.KEY_MANAGEMENT,KeyPairGenerator.getInstance(p.kem,"BC").generateKeyPair());
   var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new java.security.spec.ECGenParameterSpec(p.curve));keys.put(Slot.AUTHENTICATION,g.generateKeyPair());keys.put(Slot.RETIRED1,g.generateKeyPair());
   types.put(Slot.SIGNATURE,p.category==2?KeyType.MLDSA44:p.category==3?KeyType.MLDSA65:KeyType.MLDSA87);types.put(Slot.KEY_MANAGEMENT,p.category==5?KeyType.MLKEM1024:KeyType.MLKEM768);types.put(Slot.AUTHENTICATION,p.category==2?KeyType.ECCP256:KeyType.ECCP384);types.put(Slot.RETIRED1,types.get(Slot.AUTHENTICATION));
  }
  Map<Slot,PublicKey> publicKeys(){Map<Slot,PublicKey> result=new EnumMap<>(Slot.class);keys.forEach((s,k)->result.put(s,k.getPublic()));return result;}
  public Transport getTransport(){return Transport.USB;}
  public boolean supportsConnection(Class<? extends YubiKeyConnection> c){return c==SmartCardConnection.class;}
  public <T extends YubiKeyConnection> T openConnection(Class<T> c){return c.cast(this);}
  public <T extends YubiKeyConnection> void requestConnection(Class<T> c,Callback<Result<T,IOException>> cb){cb.invoke(Result.success(c.cast(this)));}
  public boolean isExtendedLengthApduSupported(){return true;}
  public byte[] getAtr(){return new byte[0];}
  public void close(){closes++;}
  public byte[] sendAndReceive(byte[] a)throws IOException {
   try{return join(handle(a),new byte[]{(byte)0x90,0});}catch(PinFailure e){return new byte[]{0x63,(byte)0xc2};}catch(Exception e){throw new IOException(e);}
  }
  byte[] handle(byte[] a)throws Exception{
   int ins=a[1]&255,slot=a[3]&255;
   if(ins==0xa4)return new byte[0];if(ins==0xfd)return new byte[]{6,0,0};if(ins==0xf8)return java.nio.ByteBuffer.allocate(4).putInt(serial).array();
   if(ins==0xf7){if(slot==0x9b)return join(tlv(1,new byte[]{10}),tlv(2,new byte[]{0,1}),tlv(5,new byte[]{1}));
    Slot s=Slot.fromValue(slot);PublicKey key=keys.get(s).getPublic();byte[] raw=org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getBytes();int tag=s==Slot.SIGNATURE?0x87:s==Slot.KEY_MANAGEMENT?0x88:0x86;
    return join(tlv(1,new byte[]{types.get(s).value}),tlv(2,new byte[]{3,1}),tlv(3,new byte[]{1}),tlv(4,tlv(tag,raw)));
   }
   if(ins==0x20){verifies++;if(rejectPin)throw new PinFailure();return new byte[0];}
   if(ins!=0x87)throw new IOException("Unexpected APDU "+ins);
   privateOps++;Slot s=Slot.fromValue(slot);int start=a[4]==0?7:5;int length=a[4]==0?((a[5]&255)<<8)|(a[6]&255):a[4]&255;
   var operands=Tlvs.decodeMap(Tlvs.unpackValue(0x7c,Arrays.copyOfRange(a,start,start+length)));byte[] answer;
   if(s==Slot.SIGNATURE){byte[] mu=operands.get(0x88);assertNotNull(mu);assertEquals(64,mu.length);var signer=new org.bouncycastle.crypto.signers.MLDSASigner();signer.init(true,org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(keys.get(s).getPrivate().getEncoded()));answer=signer.generateMuSignature(mu);}
   else if(s==Slot.AUTHENTICATION){var sig=Signature.getInstance("NONEwithECDSA","BC");sig.initSign(keys.get(s).getPrivate());sig.update(operands.get(0x81));answer=sig.sign();}
   else if(s==Slot.KEY_MANAGEMENT){var priv=(org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(keys.get(s).getPrivate().getEncoded());answer=new org.bouncycastle.crypto.kems.MLKEMExtractor(priv).extractSecret(operands.get(0x86));}
   else {byte[] point=operands.get(0x85);var id=new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,types.get(s)==KeyType.ECCP384?org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1:org.bouncycastle.asn1.x9.X9ObjectIdentifiers.prime256v1);var peer=KeyFactory.getInstance("EC","BC").generatePublic(new java.security.spec.X509EncodedKeySpec(new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(id,point).getEncoded()));var dh=javax.crypto.KeyAgreement.getInstance("ECDH","BC");dh.init(keys.get(s).getPrivate());dh.doPhase(peer,true);answer=dh.generateSecret();}
   return tlv(0x7c,tlv(0x82,answer));
  }
 }
 static class PinFailure extends Exception{}
 @Test public void actualYubiKitProtocolAllProfiles()throws Exception{
  for(var p:TokenProfile.values()){
   Card card=new Card(p);List<char[]> pins=new ArrayList<>();YubiBackend backend=new YubiBackend(()->card,label->{char[] pin="123456".toCharArray();pins.add(pin);return pin;},12345,card.publicKeys());
   var k=card.publicKeys();var id=Identity.forTokenProfile("token@example.test",p,k.get(Slot.SIGNATURE),k.get(Slot.AUTHENTICATION),k.get(Slot.KEY_MANAGEMENT),k.get(Slot.RETIRED1),backend);
   var m=MailEngine.compose(id,"token@example.test","token@example.test","APDU test","USB/NFC adapter core",id.encryptionCert(),backend);
   assertEquals("USB/NFC adapter core",MailEngine.open(m,id,id.signingCert(),backend).text());
   assertEquals(4,pins.size());assertEquals(8,card.verifies);assertEquals(8,card.privateOps);assertEquals(4,card.closes);
   for(char[] pin:pins)assertArrayEquals(new char[6],pin);
  }
 }
 @Test public void wrongSerialMismatchAndRejectedPinFailClosed()throws Exception{
  Card card=new Card(TokenProfile.LEVEL2);int[] prompts={0};YubiBackend.PinSource pins=label->{prompts[0]++;return "123456".toCharArray();};
  var key=card.keys.get(Slot.SIGNATURE).getPublic();var wrongSerial=new YubiBackend(()->card,pins,999,card.publicKeys());
  try{wrongSerial.sign(key,new byte[64]);fail();}catch(GeneralSecurityException expected){}assertEquals(0,prompts[0]);assertEquals(0,card.verifies);
  var bound=card.publicKeys();bound.put(Slot.SIGNATURE,KeyPairGenerator.getInstance("ML-DSA-44","BC").generateKeyPair().getPublic());
  try{new YubiBackend(()->card,pins,12345,bound).sign(key,new byte[64]);fail();}catch(GeneralSecurityException expected){}assertEquals(0,prompts[0]);
  card.rejectPin=true;try{new YubiBackend(()->card,pins,12345,card.publicKeys()).sign(key,new byte[64]);fail();}catch(com.yubico.yubikit.core.application.InvalidPinException expected){}
  assertEquals(1,prompts[0]);assertEquals(1,card.verifies);assertEquals(0,card.privateOps);
 }
}
