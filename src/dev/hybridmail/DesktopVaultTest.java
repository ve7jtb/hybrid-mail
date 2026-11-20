package dev.hybridmail;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import com.google.gson.*;
/** Synthetic PRF inputs only: never opens a browser, Keychain, account or YubiKey. */
public final class DesktopVaultTest {
 static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
 interface Action{void run()throws Exception;}
 static void reject(Action action)throws Exception{try{action.run();throw new AssertionError("Expected rejection");}catch(Exception expected){}}
 static JsonObject reply(String challenge,byte[] prf)throws Exception{
  var c=new JsonObject();c.addProperty("challenge",challenge);c.addProperty("origin",DesktopPasskeyPrf.ORIGIN);c.addProperty("type","webauthn.get");
  byte[] auth=new byte[37];System.arraycopy(MessageDigest.getInstance("SHA-256").digest(PrfVault.RP.getBytes(StandardCharsets.UTF_8)),0,auth,0,32);auth[32]=5;
  var body=new JsonObject();body.addProperty("clientDataJSON",PrfVault.b64(c.toString().getBytes(StandardCharsets.UTF_8)));body.addProperty("authenticatorData",PrfVault.b64(auth));var result=new JsonObject();result.addProperty("first",PrfVault.b64(prf));var p=new JsonObject();p.add("results",result);var ext=new JsonObject();ext.add("prf",p);var r=new JsonObject();r.addProperty("type","public-key");r.addProperty("rawId","YWJj");r.add("response",body);r.add("clientExtensionResults",ext);return r;
 }
 public static void main(String[] args)throws Exception{
  MailEngine.init();Path root=Files.createTempDirectory("desktop-vault-test-");byte[] prf=PrfVault.random(32),second=PrfVault.random(32);var vault=new PrfVault(root.resolve("account-vault.json"));
  try{
   vault.create("YWJj",PrfVault.random(32),prf);vault.renamePasskey("YWJj","Mac test");vault.put("secret","synthetic-refresh-token");vault.addPasskey("ZGVm",PrfVault.random(32),second);vault.renamePasskey("ZGVm","Backup test");vault.close();
   check(!Files.readString(root.resolve("account-vault.json")).contains("synthetic-refresh-token"),"Plaintext secret");check(vault.passkeyName("YWJj").equals("Mac test"),"Locked name");reject(()->vault.unlock("YWJj",PrfVault.random(32)));vault.unlock("ZGVm",second);check(vault.get("secret").equals("synthetic-refresh-token"),"Backup passkey unlock");vault.removePasskey("ZGVm");reject(()->vault.removePasskey("YWJj"));
   var state=new DesktopState(root);state.set("imap.host","private.example.test");state.save();DesktopVault.configure(state,null);
   var field=DesktopVault.class.getDeclaredField("vault");field.setAccessible(true);field.set(null,vault);DesktopVault.migrateSettings();check(state.get("imap.host","").equals("private.example.test"),"Settings migration");check(!Files.readString(root.resolve("settings.properties")).contains("private.example.test"),"Plaintext legacy settings");state.set("smtp.password","synthetic-mail-password");state.save();check(vault.get("setting.smtp.password").equals("synthetic-mail-password"),"Encrypted server password");
   byte[] beforeDuplicate=Files.readAllBytes(root.resolve("account-vault.json"));
   check(DesktopVault.alreadyEnrolled("YWJj"),"Existing credential recognized without error");
   check(!DesktopVault.alreadyEnrolled("ZGVm"),"Removed credential can be enrolled again");
   check(Arrays.equals(beforeDuplicate,Files.readAllBytes(root.resolve("account-vault.json"))),"Duplicate must not change wrapper, salt, name or payload");
   vault.close();reject(()->DesktopVault.alreadyEnrolled("YWJj"));vault.unlock("YWJj",prf);
   check(vault.passkeyName("YWJj").equals("Mac test")&&vault.get("secret").equals("synthetic-refresh-token"),"Original PRF still unlocks unchanged vault");
   var ids=SoftwareIdentityVault.addLevel5OpenPgp(Identity.generateSoftwareProfile("test@example.test",TokenProfile.LEVEL5,List.of("alias@example.test")));state.rememberVaultProfiles(ids,"Test");check(state.identities().size()==2,"Two software views");
   var id=state.loadIdentity(DesktopState.identityId(ids.getLast()),new char[0]);var own=OpenPgp.loadOwn(root,id);var full=own.compatibility;var fallback=OpenPgp.classicalOnlyCompatibility(full);
   check(own.version()==6&&own.primary[5]==31&&own.subkey[5]==36&&own.separated(),"v6 separated keys");check(!Arrays.equals(own.primary,own.signingBody()),"Certification/signing separation");check(full.version()==4&&full.signingAlgorithms().equals("ECDSA P-521")&&full.quantumEncryption(),"v4 hybrid");check(fallback.encryptionAlgorithm().equals("ECDH P-521")&&!fallback.quantumEncryption(),"v4 fallback");
   for(var recipient:List.of(own,full,fallback))for(boolean encrypted:new boolean[]{false,true}){
    byte[] message=OpenPgp.composeForRecipient(id,own,recipient,encrypted,"test@example.test","test@example.test","Synthetic test","Level 5 desktop vault round trip",null);var signer=recipient.version()==6?own:full;
    var opened=OpenPgp.open(message,signer,own,id,null);check(opened.text().contains("Level 5 desktop vault round trip")&&opened.fromMatches()&&opened.encrypted()==encrypted&&opened.postQuantum()==(recipient.version()==6),"Sign/decrypt round trip");
    if(!encrypted){var parts=OpenPgp.parts(message);byte[] signature=OpenPgp.unarmor(OpenPgp.decoded(OpenPgp.mime(parts.second())),"SIGNATURE");signature[signature.length-1]^=1;reject(()->new LegacyOpenPgp(signer.encoded,signer.version()).verify(signature,parts.first()));}
   }
   Path stored=state.vaultIdentityPath(state.get("identity."+DesktopState.identityId(id)+".vault",""));char[] password="synthetic-portable-export-password".toCharArray();Path export=root.resolve("export.p12");Files.write(export,SoftwareIdentityVault.export(stored,vault,password));var portable=Identity.loadProfiles(export,password);check(portable.getLast().softwareOpenPgp().own().fingerprint().equals(own.fingerprint()),"Export v6 fingerprint");check(portable.getLast().softwareOpenPgp().own().compatibility.fingerprint().equals(full.fingerprint()),"Export v4 fingerprint");reject(()->Identity.loadProfiles(export,"wrong".toCharArray()));
   byte[] transfer=IdentityTransfer.create(ids,"YWJj",PrfVault.random(32),prf,root);var migrated=IdentityTransfer.open(transfer,"YWJj",prf,root);
   check(migrated.getLast().softwareOpenPgp().own().fingerprint().equals(own.fingerprint()),"Wrapped transfer v6 fingerprint");check(migrated.getLast().softwareOpenPgp().own().compatibility.fingerprint().equals(full.fingerprint()),"Wrapped transfer v4 fingerprint");
   reject(()->IdentityTransfer.open(transfer,"YWJj",second,root));reject(()->IdentityTransfer.open(transfer,"ZGVm",prf,root));var broken=IdentityTransfer.metadata(transfer);broken.addProperty("id",PrfVault.b64(PrfVault.random(32)));reject(()->IdentityTransfer.open(broken.toString().getBytes(StandardCharsets.UTF_8),"YWJj",prf,root));
   try(var destination=new PrfVault(root.resolve("destination-vault.json"))){destination.create("YWJj",PrfVault.random(32),second);Path destinationP12=root.resolve("destination.vault.p12");SoftwareIdentityVault.save(migrated,destinationP12,destination);var received=SoftwareIdentityVault.load(destinationP12,destination).getLast();check(received.softwareOpenPgp().own().fingerprint().equals(own.fingerprint()),"Destination rewrap");var message=OpenPgp.compose(received,own,own,"test@example.test","test@example.test","Transfer","wrapped transfer verified",null);check(OpenPgp.open(message,own,own,received,null).text().contains("wrapped transfer verified"),"Transfer signing/decryption");}
   DesktopVault.lock();reject(()->SoftwareIdentityVault.load(stored,vault));vault.unlock("YWJj",prf);check(SoftwareIdentityVault.load(stored,vault).getLast().softwareOpenPgp()!=null,"Vault reload");
   String challenge=PrfVault.b64(PrfVault.random(32));var reply=reply(challenge,prf);check(Arrays.equals(prf,DesktopPasskeyPrf.validate(reply,challenge,false,"YWJj")),"PRF response");reject(()->DesktopPasskeyPrf.validate(reply,"wrong",false,"YWJj"));reject(()->DesktopPasskeyPrf.validate(reply,challenge,false,"ZGVm"));
   var altered=reply.deepCopy();byte[] auth=PrfVault.decode(altered.getAsJsonObject("response").get("authenticatorData").getAsString());auth[32]=1;altered.getAsJsonObject("response").addProperty("authenticatorData",PrfVault.b64(auth));reject(()->DesktopPasskeyPrf.validate(altered,challenge,false,"YWJj"));
   var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));var client=generator.generateKeyPair();var server=generator.generateKeyPair();var agreement=KeyAgreement.getInstance("ECDH");agreement.init(client.getPrivate());agreement.doPhase(server.getPublic(),true);byte[] k=MessageDigest.getInstance("SHA-256").digest(agreement.generateSecret());var sealed=PrfVault.seal(k,reply.toString().getBytes(StandardCharsets.UTF_8),challenge);sealed.addProperty("publicKey",PrfVault.b64(client.getPublic().getEncoded()));check(DesktopPasskeyPrf.decrypt(server.getPrivate(),sealed,challenge).equals(reply),"Encrypted browser callback");reject(()->DesktopPasskeyPrf.decrypt(server.getPrivate(),sealed,"wrong nonce"));
   System.out.println("PASS: vault encryption, names, backup passkey, remove-last rejection, settings migration, 256-bit random PKCS12 passwords, pure/hybrid catalog restore, six v6/v4 OpenPGP round trips, signature tamper rejection, export/import, passkey-wrapped transfer/rewrap/tamper rejection, lock/reopen, WebAuthn context/UV validation and encrypted callback");
  }finally{vault.close();Arrays.fill(prf,(byte)0);Arrays.fill(second,(byte)0);try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
 }
}
