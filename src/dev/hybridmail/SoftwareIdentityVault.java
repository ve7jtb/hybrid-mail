package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
/** Separate random PKCS#12 passwords, wrapped only by the PRF vault. */
final class SoftwareIdentityVault {
 static List<Identity> addLevel5OpenPgp(List<Identity> profiles)throws Exception{
  Identity hybrid=profiles.get(profiles.size()-1);if(!Identity.HYBRID_87_SIGN.equals(hybrid.signatureAlgorithm())||hybrid.softwareOpenPgp()!=null)return profiles;
  var emails=CertificateBundle.emails(hybrid.signingCert());var pgp=SoftwareOpenPgp.generate(new ArrayList<>(emails));return profiles.stream().map(id->id.withSoftwareOpenPgp(pgp)).toList();
 }
 static boolean protectedBundle(String name){return name.endsWith(".vault.p12");}
 private static String key(Path path){return "software.p12."+path.getFileName();}
 static void save(List<Identity> profiles,Path path,PrfVault vault)throws Exception{
  if(!vault.unlocked())throw new IllegalStateException("Unlock the passkey vault first");
  if(Files.exists(path))throw new java.io.IOException("Identity already exists");
  byte[] random=PrfVault.random(32);char[] password=PrfVault.b64(random).toCharArray();Arrays.fill(random,(byte)0);
  Path temp=path.resolveSibling(path.getFileName()+".tmp");
  try{
   write(profiles,temp,password);
   try(var channel=java.nio.channels.FileChannel.open(temp,StandardOpenOption.WRITE)){channel.force(true);}
   // Persist recovery material first: a crash may leave an unused password, never an unreadable identity.
   vault.put(key(path),new String(password));
   Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE);
  }finally{Arrays.fill(password,'\0');Files.deleteIfExists(temp);}
 }
 static List<Identity> load(Path path,PrfVault vault)throws Exception{
  String saved=vault.get(key(path));if(saved.isEmpty())throw new java.io.IOException("This identity's password is missing from the vault. Restore a password-protected export.");
  char[] pass=saved.toCharArray();try{return Identity.loadProfiles(path,pass);}finally{Arrays.fill(pass,'\0');}
 }
 static void write(List<Identity> profiles,Path path,char[] password)throws Exception{
  if(profiles.isEmpty()||profiles.size()>2)throw new java.io.IOException("Unsupported identity profile bundle");
  profiles.get(profiles.size()-1).save(path,password,profiles.size()==2?profiles.get(0):null);
 }
 static byte[] export(Path path,PrfVault vault,char[] password)throws Exception{
  var profiles=load(path,vault);Path temp=path.getParent().resolve("identity-export-"+UUID.randomUUID()+".p12");
  try{write(profiles,temp,password);return Files.readAllBytes(temp);}finally{Files.deleteIfExists(temp);}
 }
}
