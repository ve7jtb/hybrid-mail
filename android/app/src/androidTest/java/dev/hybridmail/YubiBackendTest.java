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
 @Test public void readOnlyConnectionTestNeverVerifiesPinOrUsesPrivateKeys()throws Exception{
  Card card=new Card(TokenProfile.LEVEL3);
  assertTrue(PivReadTest.run(card,12345,card.publicKeys()).startsWith("PASS read-only"));
  assertEquals(0,card.verifies);assertEquals(0,card.privateOps);assertEquals(1,card.closes);
 }
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
 @Test public void betaFirmwareResolvesQualifierOnSameCard()throws Exception{
  Card card=new Card(TokenProfile.LEVEL3){
   byte[] handle(byte[] a)throws Exception{
    int ins=a[1]&255;
    if(ins==0xfd)return new byte[]{0,0,1};
    if(ins==0xa4 && a.length>5 && a[4]==8)return "YubiKey 0.0.1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    if(ins==0x1d){byte[] qualifier=join(tlv(1,new byte[]{6,0,0}),tlv(2,new byte[]{1}),tlv(3,new byte[]{0,0,0,0}));byte[] data=tlv(0x19,qualifier);return join(new byte[]{(byte)data.length},data);}
    return super.handle(a);
   }
  };
  var session=PivSessions.open(card);assertEquals(new Version(6,0,0),session.getVersion());assertEquals(12345,session.getSerialNumber());
  assertEquals(new Version(0,0,1),com.yubico.yubikit.core.application.SessionVersionOverride.overrideOf(new Version(0,0,1)));
  assertEquals(0,card.verifies);
 }
 @Test public void unavailablePivShowsHeaderWithoutPin()throws Exception{
  Card card=new Card(TokenProfile.LEVEL2){public byte[] sendAndReceive(byte[] apdu)throws IOException{if((apdu[1]&255)==0xa4)return new byte[]{0x6a,(byte)0x82};return super.sendAndReceive(apdu);}};
  var backend=new YubiBackend(()->card,label->"123456".toCharArray(),12345,card.publicKeys());
  try{backend.sign(card.publicKeys().get(Slot.SIGNATURE),new byte[64]);fail("Expected PIV selection error");}
  catch(PivDiagnostic e){assertTrue(e.getMessage().contains("Selecting and initializing PIV"));assertTrue(e.getMessage().contains("INS=A4"));assertTrue(e.getMessage().contains("SW=6A82"));}
  assertEquals(0,card.verifies);assertEquals(0,card.privateOps);assertEquals(1,card.closes);
 }
 @Test public void pinCollectedBeforeConnectionAndClearedWhenCancelled()throws Exception{
  Card card=new Card(TokenProfile.LEVEL2);char[] pin="123456".toCharArray();boolean[] requested={false};
  var backend=new YubiBackend(()->{assertTrue(requested[0]);throw new java.util.concurrent.CancellationException("Tap cancelled");},label->{requested[0]=true;return pin;},12345,card.publicKeys());
  try{backend.sign(card.publicKeys().get(Slot.SIGNATURE),new byte[64]);fail();}catch(PivDiagnostic expected){}
  assertArrayEquals(new char[6],pin);assertEquals(0,card.verifies);
 }
 @Test public void wrongSerialMismatchAndRejectedPinFailClosed()throws Exception{
  Card card=new Card(TokenProfile.LEVEL2);int[] prompts={0};YubiBackend.PinSource pins=label->{prompts[0]++;return "123456".toCharArray();};
  var key=card.keys.get(Slot.SIGNATURE).getPublic();var wrongSerial=new YubiBackend(()->card,pins,999,card.publicKeys());
  try{wrongSerial.sign(key,new byte[64]);fail();}catch(GeneralSecurityException expected){}assertEquals(1,prompts[0]);assertEquals(0,card.verifies);
  var bound=card.publicKeys();bound.put(Slot.SIGNATURE,KeyPairGenerator.getInstance("ML-DSA-44","BC").generateKeyPair().getPublic());
  try{new YubiBackend(()->card,pins,12345,bound).sign(bound.get(Slot.SIGNATURE),new byte[64]);fail();}catch(GeneralSecurityException expected){}assertEquals(2,prompts[0]);
  card.rejectPin=true;try{new YubiBackend(()->card,pins,12345,card.publicKeys()).sign(key,new byte[64]);fail();}catch(com.yubico.yubikit.core.application.InvalidPinException expected){}
  assertEquals(3,prompts[0]);assertEquals(1,card.verifies);assertEquals(0,card.privateOps);
 } @Test public void rfc9980ExtraSlotsThroughYubiKitAndBundle()throws Exception {
  Card card=new Card(TokenProfile.LEVEL3){
   public Transport getTransport(){return Transport.NFC;}
   byte[] handle(byte[] a)throws Exception{
    Slot slot=(a[1]&255)==0x87?Slot.fromValue(a[3]&255):null;
    if(slot!=Slot.RETIRED3&&slot!=Slot.RETIRED4)return super.handle(a);
    privateOps++;int start=a[4]==0?7:5,length=a[4]==0?((a[5]&255)<<8)|(a[6]&255):a[4]&255;
    var operands=Tlvs.decodeMap(Tlvs.unpackValue(0x7c,Arrays.copyOfRange(a,start,start+length)));byte[] answer;
    if(slot==Slot.RETIRED3){var sign=Signature.getInstance("Ed25519","BC");sign.initSign(keys.get(slot).getPrivate());sign.update(operands.get(0x81));answer=sign.sign();}
    else{var peer=OpenPgp.curve25519(operands.get(0x85),false);answer=OpenPgp.derive(keys.get(slot).getPrivate(),peer);}
    return tlv(0x7c,tlv(0x82,answer));
   }
  };
  card.keys.put(Slot.RETIRED3,KeyPairGenerator.getInstance("Ed25519","BC").generateKeyPair());card.types.put(Slot.RETIRED3,KeyType.ED25519);
  card.keys.put(Slot.RETIRED4,KeyPairGenerator.getInstance("X25519","BC").generateKeyPair());card.types.put(Slot.RETIRED4,KeyType.X25519);
  int[] prompts={0};List<char[]> pins=new ArrayList<>();YubiBackend.PinSource source=label->{prompts[0]++;char[] pin="123456".toCharArray();pins.add(pin);return pin;};
  var backend=new YubiBackend(()->card,source,12345,card.publicKeys());var keys=card.publicKeys();
  var id=Identity.forTokenProfile("rfc@example.com",TokenProfile.LEVEL3,keys.get(Slot.SIGNATURE),keys.get(Slot.AUTHENTICATION),keys.get(Slot.KEY_MANAGEMENT),keys.get(Slot.RETIRED1),backend,List.of());
  var pure=Identity.forTokenProfile("rfc@example.com",TokenProfile.LEVEL3,keys.get(Slot.SIGNATURE),null,keys.get(Slot.KEY_MANAGEMENT),null,backend,List.of());
  var own=OpenPgp.createRfc9980(id,backend,keys.get(Slot.RETIRED3),keys.get(Slot.RETIRED4));
  var expected=YubiBackend.pgpKeys(id,new String[]{"9c","9a","9d","82"},own);assertEquals(Set.of(Slot.SIGNATURE,Slot.KEY_MANAGEMENT,Slot.RETIRED3,Slot.RETIRED4),expected.keySet());
  var pgpBackend=new YubiBackend(()->card,source,12345,expected);prompts[0]=0;int ops=card.privateOps;
  byte[] message=OpenPgp.compose(id,own,own,"rfc@example.com","rfc@example.com","Test","RFC NFC",pgpBackend);
  assertEquals("RFC NFC",OpenPgp.open(message,own,own,id,pgpBackend).text());assertEquals(2,prompts[0]);assertEquals(4,card.privateOps-ops);
  for(char[] pin:pins)assertArrayEquals(new char[6],pin);
  var profiles=List.of(new OnKeyBundle.Profile(new CertificateBundle.Entry(pure,12345,"9c","9a","9d","82"),new byte[0]),new OnKeyBundle.Profile(new CertificateBundle.Entry(id,12345,"9c","9a","9d","82"),own.encoded));
  var storage=new OnKeyAndroidTest.Card(){public int serial(){return 12345;}};storage.keys=OnKeyBundle.bindings(profiles.stream().map(OnKeyBundle.Profile::entry).toList());storage.keys.put("84",keys.get(Slot.RETIRED3).getEncoded());storage.keys.put("85",keys.get(Slot.RETIRED4).getEncoded());
  byte[] bundle=OnKeyBundle.sign(profiles,1,backend);OnKeyStorage.save(storage,bundle,new char[0]);var restored=OnKeyStorage.load(storage);assertArrayEquals(own.encoded,restored.profiles().get(1).pgp());
  java.nio.file.Path root=java.nio.file.Files.createTempDirectory(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath(),"rfc-restore-");
  restored.savePgp(root);assertEquals(own.fingerprint(),OpenPgp.loadOwn(root,id).fingerprint());
  storage.keys.remove("85");try{OnKeyStorage.load(storage);fail("Missing X25519 accepted");}catch(java.io.IOException expectedFailure){}
  var wrong=new EnumMap<Slot,PublicKey>(expected);wrong.put(Slot.RETIRED3,KeyPairGenerator.getInstance("Ed25519","BC").generateKeyPair().getPublic());int verifies=card.verifies;
  try{new YubiBackend(()->card,source,12345,wrong).signEd25519(wrong.get(Slot.RETIRED3),new byte[48]);fail("Wrong Ed25519 accepted");}catch(GeneralSecurityException expectedFailure){}assertEquals(verifies,card.verifies);
 }
 @Test public void openPgpUsesRealPivAdapter()throws Exception {
  Card card=new Card(TokenProfile.LEVEL3);int[] prompts={0};
  var backend=new YubiBackend(()->card,label->{prompts[0]++;return "123456".toCharArray();},12345,card.publicKeys());
  var keys=card.publicKeys();
  Identity identity=Identity.forTokenProfile("pgp@example.com",TokenProfile.LEVEL3,keys.get(Slot.SIGNATURE),keys.get(Slot.AUTHENTICATION),keys.get(Slot.KEY_MANAGEMENT),keys.get(Slot.RETIRED1),backend,List.of());
  prompts[0]=0;int start=card.privateOps;
  var own=OpenPgp.create(identity,backend);
  byte[] message=OpenPgp.compose(identity,own,own,"pgp@example.com","pgp@example.com","OpenPGP","YubiKit OpenPGP test",backend);
  var opened=OpenPgp.open(message,own,own,identity,backend);
  assertEquals("YubiKit OpenPGP test",opened.text());assertTrue(opened.encrypted());
  assertEquals(3,prompts[0]);assertEquals(10,card.privateOps-start);
 }

 @Test public void nfcSetupRecoveryRechecksCardAndReusesOnePin()throws Exception{
  Card card=new Card(TokenProfile.LEVEL3){int calls;
   public Transport getTransport(){return Transport.NFC;}
   public byte[] sendAndReceive(byte[] apdu)throws IOException{if(calls++==0)throw new IOException("Synthetic tag loss");return super.sendAndReceive(apdu);}
  };
  int[] prompts={0},retries={0};char[] pin="123456".toCharArray();
  var source=new YubiBackend.DeviceSource(){public YubiKeyDevice get(){return card;}public boolean retryBeforePin(String d){retries[0]++;assertEquals(0,card.verifies);return true;}};
  var backend=new YubiBackend(source,label->{prompts[0]++;return pin;},12345,card.publicKeys());
  assertTrue(backend.sign(card.keys.get(Slot.SIGNATURE).getPublic(),new byte[64]).length>0);backend.clearSecrets();
  assertEquals(1,prompts[0]);assertEquals(1,retries[0]);assertEquals(1,card.verifies);assertEquals(1,card.privateOps);assertEquals(2,card.closes);assertArrayEquals(new char[6],pin);
 }
 @Test public void persistentNfcFailureStopsAfterTwoFreshTapsAndClearsPin()throws Exception{
  Card card=new Card(TokenProfile.LEVEL3){public Transport getTransport(){return Transport.NFC;}public byte[] sendAndReceive(byte[] a)throws IOException{throw new IOException("Synthetic tag loss");}};
  int[] retries={0};char[] pin="123456".toCharArray();
  var source=new YubiBackend.DeviceSource(){public YubiKeyDevice get(){return card;}public boolean retryBeforePin(String d){retries[0]++;return true;}};
  var backend=new YubiBackend(source,l->pin,12345,card.publicKeys());
  try{backend.sign(card.keys.get(Slot.SIGNATURE).getPublic(),new byte[64]);fail();}catch(PivDiagnostic expected){}
  assertEquals(2,retries[0]);assertEquals(3,card.closes);assertEquals(0,card.verifies);assertArrayEquals(new char[6],pin);
 }
 @Test public void nfcNeverRetriesVerifyOrPrivateCommandTransportFailure()throws Exception{
  for(int instruction:new int[]{0x20,0x87}){
   Card card=new Card(TokenProfile.LEVEL3){public Transport getTransport(){return Transport.NFC;}public byte[] sendAndReceive(byte[] a)throws IOException{if((a[1]&255)==instruction)throw new IOException("Synthetic private-stage loss");return super.sendAndReceive(a);}};
   char[] pin="123456".toCharArray();
   var source=new YubiBackend.DeviceSource(){public YubiKeyDevice get(){return card;}public boolean retryBeforePin(String d){fail("Must never retry a PIN or private command");return true;}};
   var backend=new YubiBackend(source,l->pin,12345,card.publicKeys());
   try{backend.sign(card.keys.get(Slot.SIGNATURE).getPublic(),new byte[64]);fail();}catch(IOException expected){}
   assertEquals(1,card.closes);assertArrayEquals(new char[6],pin);
  }
 }

 @Test public void readDiagnosticKeepsOnePivSessionButReadsEveryKeyEachCycle()throws Exception {
  int[] selects={0},reads={0};
  Card card=new Card(TokenProfile.LEVEL3){
   byte[] handle(byte[] a)throws Exception {
    if((a[1]&255)==0xa4)selects[0]++;
    if((a[1]&255)==0xf7 && (a[3]&255)!=0x9b)reads[0]++;
    return super.handle(a);
   }
  };
  assertTrue(PivReadTest.run(card,12345,card.publicKeys()).startsWith("PASS"));
  assertEquals(1,selects[0]);assertEquals(40,reads[0]);assertEquals(0,card.verifies);
 }
 @Test public void metadataIsCheckedOncePerConnectionAndNeverAfterPin()throws Exception {
  int[] reads={0};boolean[] verified={false};
  Card card=new Card(TokenProfile.LEVEL3){
   byte[] handle(byte[] a)throws Exception {
    int ins=a[1]&255;
    if(ins==0xa4)verified[0]=false;
    if(ins==0x20)verified[0]=true;
    if(ins==0xf7 && (a[3]&255)!=0x9b){assertFalse("No redundant large metadata read after VERIFY",verified[0]);reads[0]++;}
    return super.handle(a);
   }
  };
  var backend=new YubiBackend(()->card,l->"123456".toCharArray(),12345,card.publicKeys());
  var key=card.keys.get(Slot.SIGNATURE).getPublic();
  backend.sign(key,new byte[64]);backend.signEcdsa(card.keys.get(Slot.AUTHENTICATION).getPublic(),new byte[48]);
  assertEquals(4,reads[0]);backend.clearSecrets();
  backend.sign(key,new byte[64]);assertEquals(8,reads[0]);backend.clearSecrets();
  // A replaced key must still be detected on the next connection, before VERIFY.
  card.keys.put(Slot.SIGNATURE,KeyPairGenerator.getInstance("ML-DSA-65","BC").generateKeyPair());
  int before=card.verifies;
  try{backend.sign(key,new byte[64]);fail("Must reject changed key");}catch(PivDiagnostic expected){}
  assertEquals(before,card.verifies);
 }

 @Test public void intermediateFailuresAreRecordedBeforeRecoveryWithoutExceptionPayloads()throws Exception {
  Card card=new Card(TokenProfile.LEVEL3){int calls;
   public Transport getTransport(){return Transport.NFC;}
   public byte[] sendAndReceive(byte[] a)throws IOException{if(calls++<2)throw new IOException("SECRET_SENTINEL");return super.sendAndReceive(a);}
  };
  List<Integer> attempts=new ArrayList<>();
  var source=new YubiBackend.DeviceSource(){
   public YubiKeyDevice get(){return card;}
   public void setupFailed(String op,int attempt,String frames){attempts.add(attempt);assertEquals(0,card.verifies);assertTrue(op.contains("signing"));assertTrue(frames.contains("INS=A4"));assertTrue(frames.contains("tx="));assertTrue(frames.contains("rx=-1"));assertFalse(frames.contains("SECRET_SENTINEL"));}
   public boolean retryBeforePin(String d){assertEquals(card.closes,attempts.size());return true;}
  };
  var backend=new YubiBackend(source,l->"123456".toCharArray(),12345,card.publicKeys());
  backend.sign(card.keys.get(Slot.SIGNATURE).getPublic(),new byte[64]);backend.clearSecrets();
  assertEquals(List.of(1,2),attempts);assertEquals(1,card.verifies);
 }
 @Test public void retryHistoryPersistsAndIsBounded()throws Exception {
  var context=androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getTargetContext();
  var prefs=context.getSharedPreferences("nfc-retries-test",0);prefs.edit().clear().commit();
  try{
   for(int i=1;i<=52;i++)NfcRetryHistory.append(prefs,12345,"profile","signing",i,"INS=F7");
   var saved=new org.json.JSONArray(context.getSharedPreferences("nfc-retries-test",0).getString("history","[]"));
   assertEquals(50,saved.length());assertEquals(3,saved.getJSONObject(0).getInt("attempt"));assertEquals(52,saved.getJSONObject(49).getInt("attempt"));assertTrue(saved.getJSONObject(49).getBoolean("beforePin"));
  }finally{prefs.edit().clear().commit();}
 }

}
