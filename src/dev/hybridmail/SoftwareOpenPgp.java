package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.util.*;

/** Software-only RFC 9980 Level 5 keys. Private components live exclusively in the encrypted PKCS#12. */
public final class SoftwareOpenPgp {
 private static final ASN1ObjectIdentifier METADATA=new ASN1ObjectIdentifier("2.25.302661978184745645819285730512635507321");
 private static final List<String> NAMES=List.of("cert-ml","cert-ed","sign-ml","sign-ed","kem-ml","kem-x","v4-sign","v4-ml","v4-x","v4-ec");
 private final Map<String,KeyPair> keys;private final byte[] modern,compat;
 private SoftwareOpenPgp(Map<String,KeyPair> keys,byte[] modern,byte[] compat){this.keys=Map.copyOf(keys);this.modern=modern.clone();this.compat=compat.clone();}
 static KeyPair generate(String algorithm)throws Exception{var g=KeyPairGenerator.getInstance(algorithm.equals("P521")?"EC":algorithm,"BC");if(algorithm.equals("P521"))g.initialize(new ECGenParameterSpec("secp521r1"),RANDOM);return g.generateKeyPair();}
 private static org.bouncycastle.crypto.params.AsymmetricKeyParameter component(KeyPair k,boolean priv)throws Exception{return priv?PrivateKeyFactory.createKey(k.getPrivate().getEncoded()):PublicKeyFactory.createKey(k.getPublic().getEncoded());}
 private static AsymmetricCipherKeyPair composite(KeyPair classical,KeyPair pq)throws Exception{return new AsymmetricCipherKeyPair(new BcPGPCompositeKeyParameters(false,component(classical,false),component(pq,false)),new BcPGPCompositeKeyParameters(true,component(classical,true),component(pq,true)));}
 private static PGPKeyPair pair(Map<String,KeyPair> k,String role,int version,int algorithm,Date date)throws Exception{
  return switch(role){case "cert","sign" -> new BcPGPKeyPair(version,algorithm,composite(k.get(role+"-ed"),k.get(role+"-ml")),date);
   case "kem" -> new BcPGPKeyPair(version,algorithm,composite(k.get("kem-x"),k.get("kem-ml")),date);
   case "v4-kem" -> new BcPGPKeyPair(version,algorithm,composite(k.get("v4-x"),k.get("v4-ml")),date);
   case "v4-ec" -> new JcaPGPKeyPair(version,algorithm,new PGPKdfParameters(10,9),k.get(role),date);
   default -> new JcaPGPKeyPair(version,algorithm,k.get(role),date);};
 }
 private static PGPSignatureSubpacketVector prefs(int flags){var s=new PGPSignatureSubpacketGenerator();s.setKeyFlags(false,flags);s.setPreferredSymmetricAlgorithms(false,new int[]{9});s.setPreferredHashAlgorithms(false,new int[]{10,9,8});s.setPreferredCompressionAlgorithms(false,new int[]{2,1,0});s.setFeature(false,(byte)9);return s.generate();}
 public static SoftwareOpenPgp generate(List<String> emails)throws Exception{
  var keys=new LinkedHashMap<String,KeyPair>();String[] alg={"ML-DSA-87","Ed448","ML-DSA-87","Ed448","ML-KEM-1024","X448","P521","ML-KEM-768","X25519","P521"};for(int i=0;i<NAMES.size();i++)keys.put(NAMES.get(i),generate(alg[i]));Date date=new Date(now()*1000);
  var primary=pair(keys,"cert",6,31,date);var signer=new BcPGPContentSignerBuilder(31,10);var digest=new BcPGPDigestCalculatorProvider().get(2);
  var g=new PGPKeyRingGenerator(primary,digest,prefs(1),null,signer,null);
  g.addSubKey(pair(keys,"sign",6,31,date),prefs(2),null,signer);g.addSubKey(pair(keys,"kem",6,36,date),prefs(12),null);
  var modern=g.generatePublicKeyRing();PGPPublicKey pub=modern.getPublicKey();
  for(String email:emails){validateEmail(email);var sig=new PGPSignatureGenerator(signer,pub);sig.init(19,primary.getPrivateKey());sig.setHashedSubpackets(prefs(1));pub=PGPPublicKey.addCertification(pub,email,sig.generateCertification(email,pub));}
  modern=PGPPublicKeyRing.insertPublicKey(modern,pub);
  var v4primary=pair(keys,"v4-sign",4,19,date);var v4signer=new BcPGPContentSignerBuilder(19,10);
  var old=new PGPKeyRingGenerator(19,v4primary,emails.get(0),digest,prefs(3),null,v4signer,null);
  old.addSubKey(pair(keys,"v4-kem",4,35,date),prefs(12),null);
  // Explicit SHA-512 / AES-256 KDF for P-521.
  old.addSubKey(new JcaPGPKeyPair(4,18,new PGPKdfParameters(10,9),keys.get("v4-ec"),date),prefs(12),null);
  var compatibility=old.generatePublicKeyRing();pub=compatibility.getPublicKey();
  for(String email:emails.subList(1,emails.size())){var sig=new PGPSignatureGenerator(v4signer,pub);sig.init(19,v4primary.getPrivateKey());sig.setHashedSubpackets(prefs(3));pub=PGPPublicKey.addCertification(pub,email,sig.generateCertification(email,pub));}
  compatibility=PGPPublicKeyRing.insertPublicKey(compatibility,pub);
  var result=new SoftwareOpenPgp(keys,modern.getEncoded(org.bouncycastle.bcpg.PacketFormat.CURRENT),compatibility.getEncoded(org.bouncycastle.bcpg.PacketFormat.CURRENT));result.own();return result;
 }
 public PublicIdentity own()throws Exception{var own=new PublicIdentity(modern);own.compatibility=new PublicIdentity(compat);return own;}
 static PGPPublicKeyRing ring(byte[] encoded)throws Exception{return new PGPPublicKeyRing(encoded,new BcKeyFingerprintCalculator());}
 private PGPPrivateKey privateKey(PGPPublicKey pub)throws Exception{
  String role=switch(pub.getAlgorithm()){case 31->pub.isMasterKey()?"cert":"sign";case 36->"kem";case 35->"v4-kem";case 19->"v4-sign";case 18->"v4-ec";default->throw new GeneralSecurityException("Unsupported software OpenPGP key");};
  var generated=pair(keys,role,pub.getVersion(),pub.getAlgorithm(),pub.getCreationTime());check(Arrays.equals(generated.getPublicKey().getFingerprint(),pub.getFingerprint()),"Software OpenPGP private/public mismatch");return generated.getPrivateKey();
 }
 void store(KeyStore ks,char[] password)throws Exception{
  byte[] metadata=new DERSequence(new ASN1Encodable[]{new DEROctetString(modern),new DEROctetString(compat)}).getEncoded();
  for(String name:NAMES){var pair=keys.get(name);var dn=new X500Name("CN=PQ Mail OpenPGP storage");var builder=new JcaX509v3CertificateBuilder(dn,new java.math.BigInteger(128,RANDOM).add(java.math.BigInteger.ONE),new Date(0),new Date(4102444800000L),dn,pair.getPublic());if(name.equals("cert-ed"))builder.addExtension(METADATA,false,new DEROctetString(metadata));var cert=new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("Ed448").setProvider("BC").build(keys.get("cert-ed").getPrivate())));ks.setKeyEntry("pgp5-"+name,pair.getPrivate(),password,new java.security.cert.Certificate[]{cert});}
 }
 static SoftwareOpenPgp load(KeyStore ks,char[] password)throws Exception{
  if(!ks.containsAlias("pgp5-cert-ed"))return null;var keys=new LinkedHashMap<String,KeyPair>();for(String name:NAMES){var cert=ks.getCertificate("pgp5-"+name);var key=ks.getKey("pgp5-"+name,password);check(cert!=null&&key instanceof PrivateKey,"Incomplete software OpenPGP keyset");keys.put(name,new KeyPair(cert.getPublicKey(),(PrivateKey)key));}
  byte[] ext=((X509Certificate)ks.getCertificate("pgp5-cert-ed")).getExtensionValue(METADATA.getId());check(ext!=null&&ext.length<256*1024,"Missing/oversized OpenPGP certificates");var outer=ASN1OctetString.getInstance(ext).getOctets();var seq=ASN1Sequence.getInstance(ASN1OctetString.getInstance(outer).getOctets());check(seq.size()==2,"Invalid OpenPGP metadata");var result=new SoftwareOpenPgp(keys,ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets(),ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());result.own();for(byte[] encoded:List.of(result.modern,result.compat)){var it=ring(encoded).getPublicKeys();while(it.hasNext())result.privateKey(it.next());}return result;
 }
 void match(PublicIdentity own)throws Exception{check(Arrays.equals(modern,own.encoded),"OpenPGP certificate does not match software identity");}
 /** Binary signed packets for transport-independent bundles. Keep private keys
  * inside this identity; never export a secret OpenPGP key to sign a file. */
 byte[] signPackets(PublicIdentity own,byte[] plain)throws Exception{
  match(own);check(plain.length<=LIMIT,"Message too large");
  var pub=own.v6.signers.values().stream().filter(k->k.getAlgorithm()==31).findFirst().orElseThrow(()->new IOException("No hybrid signing subkey"));
  var gen=new PGPSignatureGenerator(new BcPGPContentSignerBuilder(pub.getAlgorithm(),10),pub);gen.init(PGPSignature.BINARY_DOCUMENT,privateKey(pub));
  var out=new ByteArrayOutputStream();gen.generateOnePassVersion(false).encode(out);
  var literal=new PGPLiteralDataGenerator();try(var stream=literal.open(out,PGPLiteralData.BINARY,"",plain.length,new Date(0))){stream.write(plain);}
  gen.update(plain);gen.generate().encode(out);return out.toByteArray();
 }
 byte[] compose(PublicIdentity own,PublicIdentity recipient,boolean encrypted,String from,String to,String subject,String text)throws Exception{
        return compose(own,recipient,encrypted,from,to,subject,text,null);
    }
    byte[] compose(PublicIdentity own,PublicIdentity recipient,boolean encrypted,String from,String to,String subject,String text,String html)throws Exception{
  match(own);check(own.matchesEmail(from),"Sender address mismatch");validateEmail(to);check(recipient==null||recipient.matchesEmail(to),"Recipient address mismatch");check(!encrypted||recipient!=null,"Select recipient");check(text.length()<LIMIT/4,"Message too large");boolean v4=recipient!=null&&recipient.version()==4;
  var certificate=v4?own.compatibility:own;var pub=v4?ring(compat).getPublicKey():own.v6.signers.values().iterator().next();
  byte[] plain=MailEngine.messageBody(text,html);
  plain=withPublicCertificate(plain,own.compatibility,own);
  var gen=new PGPSignatureGenerator(new BcPGPContentSignerBuilder(pub.getAlgorithm(),10),pub);gen.init(0,privateKey(pub));
  var packets=new ByteArrayOutputStream();if(encrypted){gen.generateOnePassVersion(false).encode(packets);var literal=new PGPLiteralDataGenerator();try(var stream=literal.open(packets,PGPLiteralData.BINARY,"",plain.length,new Date(0))){stream.write(plain);}}
  gen.update(plain);byte[] signature=gen.generate().getEncoded();byte[] message;
  if(encrypted){packets.write(signature);message=mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),armor(encrypt(packets.toByteArray(),recipient),"MESSAGE")),true,from,to,subject);}
  else message=mimeWrap(plain,cat(bytes("Content-Type: application/pgp-signature\r\n\r\n"),armor(signature,"SIGNATURE")),false,from,to,subject);
  return new String(message,java.nio.charset.StandardCharsets.UTF_8).replace("micalg=pgp-sha384;","micalg=pgp-sha512;").getBytes(java.nio.charset.StandardCharsets.UTF_8);
 }
 byte[] decrypt(byte[] encoded)throws Exception{
  var objects=LegacyOpenPgp.objects(encoded);Object first=objects.nextObject();check(first instanceof PGPEncryptedDataList,"Expected encrypted OpenPGP data");var list=(PGPEncryptedDataList)first;check(list.size()==1,"Expected one recipient");var data=(PGPPublicKeyEncryptedData)list.get(0);PGPPublicKey pub=null;
  for(byte[] cert:List.of(modern,compat)){var it=ring(cert).getPublicKeys();while(it.hasNext()){var candidate=it.next();if(candidate.getKeyID()==data.getKeyID())pub=candidate;}}
  check(pub!=null,"Encrypted message is for another identity");check(data.isIntegrityProtected(),"Unprotected message rejected");byte[] plain=LegacyOpenPgp.bounded(data.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey(pub))));check(data.verify(),"Encrypted message integrity failed");check(objects.nextObject()==null,"Trailing encrypted message packets");return plain;
 }
}
