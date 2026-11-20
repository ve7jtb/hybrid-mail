package dev.hybridmail;
import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
/** Explicit local hardware runner: no key generation or mail transmission. */
public final class Rfc9980HardwareTest {
 public static void main(String[] args)throws Exception{
  MailEngine.init();int serial=Integer.parseInt(args[0]);Path out=Path.of(args[1]);Files.createDirectories(out);var state=DesktopState.open();Identity id=null;PublicKey ed,x;
  Map<String,byte[]> before=new LinkedHashMap<>();Map<Integer,byte[]> certs=new LinkedHashMap<>();
  try(var card=new OnKeyDesktop(serial)){
   if(card.serial()!=serial)throw new Exception("Wrong YubiKey");
   for(var saved:state.identities())if(!saved.passwordRequired()&&state.get("identity."+saved.id()+".token.serial","").equals(args[0])){
    var candidate=state.loadIdentity(saved.id(),new char[0]);if(!Identity.HYBRID_65_P384_SIGN.equals(candidate.signatureAlgorithm()))continue;
    try{OnKeyBundle.check(card,state.certificateBundle(candidate));}catch(Exception mismatch){continue;}
    if(id==null||candidate.signingCert().getNotBefore().after(id.signingCert().getNotBefore()))id=candidate;
   }
   if(id==null)throw new Exception("No matching saved Level 3 hybrid identity for this key");
   for(String slot:List.of("9c","9d","82","83","84","85")){byte[] key=card.publicKey(slot);if(key==null)throw new Exception("Missing key in "+slot);before.put(slot,key);Files.write(out.resolve("before-"+slot+".der"),key);}
   for(int tag:new int[]{0x5fc105,0x5fc10a,0x5fc10b,0x5fc101,0x5fc10d,0x5fc10e,0x5fc10f,0x5fc110})certs.put(tag,card.get(tag));
   ed=KeyFactory.getInstance("Ed25519","BC").generatePublic(new X509EncodedKeySpec(before.get("84")));x=KeyFactory.getInstance("X25519","BC").generatePublic(new X509EncodedKeySpec(before.get("85")));
   var old=OnKeyStorage.load(card);Files.write(out.resolve("previous-bundle.pqkey"),old.encoded());
  }
  if(args.length>2&&args[2].equals("check")){System.out.println("PASS read-only preflight: six keys, existing certificate identities and old on-key bundle match.");System.exit(0);}
  var console=System.console();if(console==null)throw new Exception("Run in Terminal for the management-key prompt");
  char[] management=console.readPassword("PIV AES-192 management key (48 hex characters; NOT YubiKey PIN): ");if(management==null)throw new Exception("Cancelled");
  boolean valid=management.length==48;for(char c:management)valid&=Character.digit(c,16)>=0;if(!valid){Arrays.fill(management,'\0');throw new Exception("Expected 48 hexadecimal characters for the AES-192 management key, not the PIN. No signing or writing attempted.");}
  try{
   state.activateIdentity(id);var signer=ExternalMu.executable(state.adapter(false));
   System.out.println("Creating RFC 9980 OpenPGP certificate: one PIN dialog for all three composite signatures.");
   var own=OpenPgp.createRfc9980(id,signer,ed,x);Files.write(out.resolve("rfc9980-public.asc"),own.export());
   System.out.println("Testing signed and encrypted OpenPGP locally: signing PIN, then decryption PIN. No email sent.");
   String email=OpenPgp.email(id);byte[] msg=OpenPgp.compose(id,own,own,email,email,"Local RFC 9980 test","RFC 9980 hardware round trip",signer);
   var opened=OpenPgp.open(msg,own,own,id,ExternalKem.executable(state.adapter(true)));if(!opened.text().equals("RFC 9980 hardware round trip"))throw new Exception("Round trip mismatch");
   Files.writeString(out.resolve("message-result.txt"),opened.display());
   OpenPgp.replaceOwn(state.directory(),id,own);var entries=state.certificateBundle(id);var profiles=OnKeyBundle.collect(entries,state.directory());int index=0;for(int i=0;i<entries.size();i++)if(entries.get(i).identity().signingCert().equals(id.signingCert()))index=i;
   System.out.println("Signing updated public certificate bundle: one PIN dialog, then writing custom bundle objects.");
   byte[] encoded=OnKeyBundle.sign(profiles,index,signer);Files.write(out.resolve("new-bundle.pqkey"),encoded);
   try(var card=new OnKeyDesktop(serial)){OnKeyStorage.save(card,encoded,management);}
   OnKeyBundle.Bundle restored;
   try(var card=new OnKeyDesktop(serial)){
    restored=OnKeyStorage.load(card);if(!Arrays.equals(encoded,restored.encoded()))throw new Exception("Bundle readback mismatch");
    for(var e:before.entrySet()){byte[] key=card.publicKey(e.getKey());if(!Arrays.equals(e.getValue(),key))throw new Exception("Key changed: "+e.getKey());Files.write(out.resolve("after-"+e.getKey()+".der"),key);}
    for(var e:certs.entrySet())if(!Arrays.equals(e.getValue(),card.get(e.getKey())))throw new Exception("PIV certificate changed");
   }
   var fresh=new DesktopState(out.resolve("restored"));fresh.importOnKey(restored);var loaded=OpenPgp.loadOwn(fresh.directory(),id);if(!loaded.fingerprint().equals(own.fingerprint()))throw new Exception("Restored OpenPGP identity mismatch");
   String result="PASS RFC 9980 composite certificate signatures and signed/encrypted message through PKCS#11.\nPASS backup readback, fresh-state import and OpenPGP fingerprint.\nPASS all six public keys and existing PIV certificate objects unchanged.\nNo email sent; no private keys exported.\n";Files.writeString(out.resolve("result.txt"),result);System.out.print(result);
  }finally{Arrays.fill(management,'\0');}
  System.exit(0);
 }
}
