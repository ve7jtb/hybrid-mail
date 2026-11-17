package dev.hybridmail;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;

/** Per-user non-secret configuration and certificate identities; never saves PINs. */
public final class DesktopState {
    private static volatile Map<String,String> processConfig=Map.of();
    private final Path directory;
    private final Properties values=new Properties();
    public record SavedIdentity(String id,String name,boolean passwordRequired){public String toString(){return name;}}
    public DesktopState(Path directory)throws IOException{
        this.directory=directory;
        Path file=directory.resolve("settings.properties");
        if(Files.exists(file))try(InputStream in=Files.newInputStream(file)){values.load(in);}
    }
    public static DesktopState open()throws IOException{
        String override=System.getProperty("hybridmail.dataDir");
        return new DesktopState(override==null?Path.of(System.getProperty("user.home"),"Library","Application Support","Hybrid Mail"):Path.of(override));
    }
    public Path directory(){return directory;}
    public String get(String name,String fallback){return values.getProperty(name,fallback);}
    public void set(String name,String value){if(value==null)values.remove(name);else values.setProperty(name,value);}
    public void save()throws IOException{
        Files.createDirectories(directory);Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));
        ByteArrayOutputStream out=new ByteArrayOutputStream();values.store(out,"Hybrid Mail — non-secret preferences; no PINs or passwords");
        write(directory.resolve("settings.properties"),out.toByteArray());
    }
    private static void write(Path path,byte[] bytes)throws IOException{
        Files.createDirectories(path.getParent());Files.setPosixFilePermissions(path.getParent(),PosixFilePermissions.fromString("rwx------"));
        Path temporary=Files.createTempFile(path.getParent(),".save-",".tmp",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try{Files.write(temporary,bytes);Files.move(temporary,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
        finally{Files.deleteIfExists(temporary);}
    }
    public List<SavedIdentity> identities(){
        List<SavedIdentity> result=new ArrayList<>();
        for(String id:get("identities","").split(","))if(id.matches("[a-f0-9]{24}"))
            result.add(new SavedIdentity(id,get("identity."+id+".name",id),get("identity."+id+".type","token").equals("pkcs12")));
        return result;
    }
    private Path identityDirectory(String id){
        if(identities().stream().noneMatch(i->i.id().equals(id)))throw new IllegalArgumentException("Unknown saved identity");
        return directory.resolve("identities").resolve(id);
    }
    public Identity loadIdentity(String id,char[] password)throws Exception{
        Path folder=identityDirectory(id);
        if(get("identity."+id+".type","token").equals("pkcs12"))return Identity.load(folder.resolve("identity.p12"),password);
        X509Certificate signing=Identity.readCertificate(folder.resolve("signing.cer"));
        X509Certificate encryption=Files.exists(folder.resolve("encryption.cer"))?Identity.readCertificate(folder.resolve("encryption.cer")):null;
        String alg=signing.getPublicKey().getAlgorithm();
        if(!Set.of(Identity.PURE_SIGN,Identity.HYBRID_SIGN,Identity.HYBRID_RSA_SIGN).contains(alg))throw new IOException("Unsupported saved signing identity");
        if(encryption!=null)ExternalKem.validatePublicKey(encryption.getPublicKey());
        return new Identity(signing,null,encryption,null,null);
    }
    public String remember(Identity identity,String name,Path encryptedOriginal)throws Exception{
        MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(identity.signingCert().getEncoded());
        if(identity.encryptionCert()!=null)hash.update(identity.encryptionCert().getEncoded());
        String id=HexFormat.of().formatHex(hash.digest()).substring(0,24);
        Path folder=directory.resolve("identities").resolve(id);
        boolean token=identity.signingKey()==null&&identity.encryptionKey()==null&&identity.traditionalKey()==null;
        if(token){
            write(folder.resolve("signing.cer"),identity.signingCert().getEncoded());
            write(folder.resolve("signing.pem"),pem(identity.signingCert()));
            if(identity.encryptionCert()!=null){write(folder.resolve("encryption.cer"),identity.encryptionCert().getEncoded());write(folder.resolve("encryption.pem"),pem(identity.encryptionCert()));}
        }else{
            if(encryptedOriginal==null)throw new IOException("An encrypted PKCS12 file is needed to remember a software identity");
            write(folder.resolve("identity.p12"),Files.readAllBytes(encryptedOriginal));
        }
        LinkedHashSet<String> ids=new LinkedHashSet<>();for(var old:identities())ids.add(old.id());ids.add(id);
        set("identities",String.join(",",ids));set("identity."+id+".name",name);set("identity."+id+".type",token?"token":"pkcs12");set("selected.identity",id);save();return id;
    }
    public void saveCertificate(String role,X509Certificate certificate)throws Exception{
        if(!Set.of("recipient","pinned").contains(role))throw new IllegalArgumentException("Invalid certificate role");
        write(directory.resolve(role+".cer"),certificate.getEncoded());
    }
    public X509Certificate certificate(String role)throws Exception{
        if(!Set.of("recipient","pinned").contains(role))throw new IllegalArgumentException("Invalid certificate role");
        Path path=directory.resolve(role+".cer");return Files.exists(path)?Identity.readCertificate(path):null;
    }
    public record Contact(String id,String email,String role){}
    public List<Contact> contacts(){
        List<Contact> contacts=new ArrayList<>();
        for(String id:get("contacts","").split(","))if(id.matches("[a-f0-9]{64}"))contacts.add(new Contact(id,get("contact."+id+".email",""),get("contact."+id+".role","")));
        return List.copyOf(contacts);
    }
    public X509Certificate contactCertificate(Contact contact)throws Exception{
        if(!contacts().contains(contact))throw new IOException("Unknown certificate contact");
        return Identity.readCertificate(directory.resolve("contacts").resolve(contact.id()).resolve("certificate.cer"));
    }
    public Contact rememberContact(X509Certificate certificate,String email,String role)throws Exception{
        if(!Set.of("signing","encryption").contains(role))throw new IOException("Choose signing or encryption");
        new jakarta.mail.internet.InternetAddress(email,true).validate();
        if(!Identity.matchesEmail(certificate,email))throw new IOException("Certificate email SAN does not match the contact address");
        certificate.checkValidity();boolean[] usage=certificate.getKeyUsage();int bit=role.equals("signing")?0:2;
        if(usage==null||usage.length<=bit||!usage[bit])throw new IOException("Certificate does not permit "+role);
        if(role.equals("encryption"))ExternalKem.validatePublicKey(certificate.getPublicKey());
        MessageDigest digest=MessageDigest.getInstance("SHA-256");digest.update(certificate.getEncoded());digest.update(("\n"+email.toLowerCase(Locale.ROOT)+"\n"+role).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String id=HexFormat.of().formatHex(digest.digest());Path folder=directory.resolve("contacts").resolve(id);
        write(folder.resolve("certificate.cer"),certificate.getEncoded());write(folder.resolve("certificate.pem"),pem(certificate));
        var ids=new LinkedHashSet<String>();for(var contact:contacts())ids.add(contact.id());ids.add(id);
        set("contacts",String.join(",",ids));set("contact."+id+".email",email);set("contact."+id+".role",role);save();return new Contact(id,email,role);
    }
    public void removeContact(Contact contact)throws Exception{
        if(!contacts().contains(contact))throw new IOException("Unknown certificate contact");
        Path trash=directory.resolve("removed-contacts");Files.createDirectories(trash);Files.setPosixFilePermissions(trash,PosixFilePermissions.fromString("rwx------"));
        Files.move(directory.resolve("contacts").resolve(contact.id()),trash.resolve(contact.id()+"-"+System.currentTimeMillis()));
        var ids=new ArrayList<String>();for(var old:contacts())if(!old.id().equals(contact.id()))ids.add(old.id());
        set("contacts",String.join(",",ids));set("contact."+contact.id()+".email",null);set("contact."+contact.id()+".role",null);save();
    }
    public void clearCertificate(String role)throws IOException{
        if(!Set.of("recipient","pinned").contains(role))throw new IllegalArgumentException("Invalid certificate role");
        Files.deleteIfExists(directory.resolve(role+".cer"));
    }
    public void saveGoogleClient(GoogleOAuth.Client client)throws IOException{
        var installed=new com.google.gson.JsonObject();installed.addProperty("client_id",client.id());installed.addProperty("client_secret",client.secret());
        var root=new com.google.gson.JsonObject();root.add("installed",installed);
        write(directory.resolve("google-client.json"),root.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    public void importGoogleClient(Path source)throws IOException{
        GoogleOAuth.Client.read(source);
        write(directory.resolve("google-client.json"),Files.readAllBytes(source));
    }
    public static byte[] pem(X509Certificate certificate)throws Exception{
        return ("-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(certificate.getEncoded())+"\n-----END CERTIFICATE-----\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }
    public static Path resources(){
        try{
            Path location=Path.of(DesktopState.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            Path root=Files.isDirectory(location)?location:location.getParent();
            if(Files.isDirectory(root.resolve("adapters")))return root;
            if(root.getParent()!=null&&Files.isDirectory(root.getParent().resolve("adapters")))return root.getParent();
            return root;
        }catch(Exception e){throw new IllegalStateException("Cannot locate bundled resources",e);}
    }
    private String nativePath(String setting,String bundled,String fallback){
        String custom=get(setting,"");if(!custom.isBlank())return custom;
        Path candidate=resources().resolve(bundled);return Files.exists(candidate)?candidate.toString():fallback;
    }
    public Map<String,String> configuration(){
        Map<String,String> result=new HashMap<>();
        result.put("OPENSSL_BIN",nativePath("openssl.path","native/bin/openssl","/opt/homebrew/bin/openssl"));
        result.put("PKCS11_PROVIDER",nativePath("provider.path","native/lib/pkcs11.dylib",resources().resolve("native/pkcs11.dylib").toString()));
        result.put("PKCS11_MODULE",nativePath("module.path","native/lib/libykcs11.dylib",resources().resolve("native/libykcs11.dylib").toString()));
        result.put("PYTHON_BIN",get("python.path","/usr/bin/python3"));
        result.put("PKCS11_SERIAL",get("token.serial",""));result.put("PKCS11_TRADITIONAL_SLOT",get("token.rsaSlot","9a"));
        result.put("PKCS11_KEM_SLOT",get("token.kemSlot","9d"));result.put("PKCS11_ECDH_SLOT",get("token.ecdhSlot","82"));
        return Map.copyOf(result);
    }
    public void activate(){processConfig=configuration();}
    public static ProcessBuilder process(String executable){
        Map<String,String> config=processConfig;
        ProcessBuilder builder=executable.endsWith(".py")?new ProcessBuilder(config.getOrDefault("PYTHON_BIN","/usr/bin/python3"),executable):new ProcessBuilder(executable);
        builder.environment().putAll(config);builder.environment().put("PYTHONDONTWRITEBYTECODE","1");
        return builder;
    }
    public String adapter(boolean kem){
        String mode=get(kem?"decrypt.adapter":"sign.adapter","pkcs11");
        if(mode.equals("software"))return null;
        return mode.equals("pkcs11")?resources().resolve("adapters").resolve(kem?"pkcs11-kem.py":"pkcs11-mu.py").toString():mode;
    }
}
