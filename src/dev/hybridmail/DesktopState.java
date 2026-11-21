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
    public static boolean windows(){return System.getProperty("os.name").startsWith("Windows");}
    public static boolean linux(){return System.getProperty("os.name").equals("Linux");}
    public static String defaultPython(){return windows()?resources().resolve("native/python/python.exe").toString():"/usr/bin/python3";}
    public static DesktopState open()throws IOException{
        String override=System.getProperty("hybridmail.dataDir");
        return new DesktopState(override==null?(linux()?Path.of(System.getenv().getOrDefault("XDG_DATA_HOME",Path.of(System.getProperty("user.home"),".local","share").toString()),"pq-mail"):windows()?Path.of(System.getenv().getOrDefault("LOCALAPPDATA",System.getProperty("user.home")),"Hybrid Mail"):Path.of(System.getProperty("user.home"),"Library","Application Support","Hybrid Mail")):Path.of(override));
    }
    public Path directory(){return directory;}
    public String get(String name,String fallback){return DesktopVault.configured()&&DesktopVault.sensitive(name)?DesktopVault.setting(name,fallback):rawGet(name,fallback);}
    String rawGet(String name,String fallback){return values.getProperty(name,fallback);}
    void rawSet(String name,String value){if(value==null)values.remove(name);else values.setProperty(name,value);}
    public void set(String name,String value){if(DesktopVault.configured()&&DesktopVault.sensitive(name))DesktopVault.putSetting(name,value);else rawSet(name,value);}
    public void save()throws IOException{
        PrivateFiles.directory(directory);
        ByteArrayOutputStream out=new ByteArrayOutputStream();values.store(out,"PQ Mail — non-secret preferences; no PINs or passwords");
        write(directory.resolve("settings.properties"),out.toByteArray());
    }
    private static void write(Path path,byte[] bytes)throws IOException{
        PrivateFiles.directory(path.getParent());
        Path temporary=PrivateFiles.temporary(path.getParent());
        try{Files.write(temporary,bytes);Files.move(temporary,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
        finally{Files.deleteIfExists(temporary);}
    }
    public List<SavedIdentity> identities(){
        List<SavedIdentity> result=new ArrayList<>();
        for(String id:get("identities","").split(","))if(id.matches("[a-f0-9]{24}"))
            result.add(new SavedIdentity(id,get("identity."+id+".name",id)+(get("identity."+id+".type","token").equals("pkcs12")?" · software .p12":" · YubiKey "+get("identity."+id+".token.serial","unbound")),get("identity."+id+".type","token").equals("pkcs12")));
        return result;
    }
    /** Legacy RSA token demos remain on disk for reading old mail, but are not offered for outgoing use. */
    public List<SavedIdentity> selectableIdentities(){
        return identities().stream().filter(saved->{
            if(saved.passwordRequired())return true;
            try{return !Identity.HYBRID_RSA_SIGN.equals(Identity.readCertificate(directory.resolve("identities").resolve(saved.id()).resolve("signing.cer")).getPublicKey().getAlgorithm());}
            catch(Exception e){return true;} // Preserve the existing load-time error for damaged identities.
        }).toList();
    }
    private Path identityDirectory(String id){
        if(identities().stream().noneMatch(i->i.id().equals(id)))throw new IllegalArgumentException("Unknown saved identity");
        return directory.resolve("identities").resolve(id);
    }
    public Identity loadIdentity(String id,char[] password)throws Exception{
        Path folder=identityDirectory(id);
        if(get("identity."+id+".type","token").equals("pkcs12")){
            String stored=get("identity."+id+".vault","");if(!stored.isEmpty()){
                var profiles=SoftwareIdentityVault.load(vaultIdentityPath(stored),DesktopVault.vault());
                return profiles.stream().filter(p->{try{return identityId(p).equals(id);}catch(Exception e){return false;}}).findFirst().orElseThrow(()->new IOException("Vault identity does not match catalog"));
            }
            return Identity.load(folder.resolve("identity.p12"),password,get("identity."+id+".variant","").equals("pure"));
        }
        X509Certificate signing=Identity.readCertificate(folder.resolve("signing.cer"));
        X509Certificate encryption=Files.exists(folder.resolve("encryption.cer"))?Identity.readCertificate(folder.resolve("encryption.cer")):null;
        String alg=signing.getPublicKey().getAlgorithm();
        if(!Set.of(Identity.PURE_SIGN,Identity.HYBRID_SIGN,Identity.HYBRID_RSA_SIGN,Identity.PURE_87_SIGN,Identity.HYBRID_87_SIGN,Identity.PURE_44_SIGN,Identity.HYBRID_44_SIGN,Identity.HYBRID_65_P384_SIGN).contains(alg))throw new IOException("Unsupported saved signing identity");
        if(encryption!=null)Identity.validateEncryptionKey(encryption.getPublicKey());
        return new Identity(signing,null,encryption,null,null);
    }
    static String identityId(Identity identity)throws Exception{
        MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(identity.signingCert().getEncoded());if(identity.encryptionCert()!=null)hash.update(identity.encryptionCert().getEncoded());return HexFormat.of().formatHex(hash.digest()).substring(0,24);
    }
    public void bindToken(String id,String serial,String traditional,String kem,String ecdh)throws Exception{
        if(serial==null||serial.isBlank())throw new IOException("Specify the YubiKey serial for this identity");
        for(var entry:Map.of("serial",serial,"rsaSlot",traditional,"kemSlot",kem,"ecdhSlot",ecdh).entrySet())set("identity."+id+".token."+entry.getKey(),entry.getValue());save();
    }
    public void migrateTokenBindings()throws Exception{
        for(var saved:identities())if(!saved.passwordRequired()&&get("identity."+saved.id()+".token.serial","").isBlank()&&!get("token.serial","").isBlank())bindToken(saved.id(),get("token.serial",""),get("token.rsaSlot","9a"),get("token.kemSlot","9d"),get("token.ecdhSlot","82"));
    }
    public void activateIdentity(Identity identity)throws Exception{
        Map<String,String> config=new HashMap<>(configuration());
        if(identity.signingKey()==null){String id=identityId(identity);String serial=get("identity."+id+".token.serial","");
            if(serial.isBlank())throw new IOException("YubiKey identity has no saved device binding");
            config.put("PKCS11_SERIAL",serial);config.put("PKCS11_TRADITIONAL_SLOT",get("identity."+id+".token.rsaSlot","9a"));config.put("PKCS11_KEM_SLOT",get("identity."+id+".token.kemSlot","9d"));config.put("PKCS11_ECDH_SLOT",get("identity."+id+".token.ecdhSlot","82"));
        }processConfig=Map.copyOf(config);
    }
    public static String activeTokenSerial(){return processConfig.getOrDefault("PKCS11_SERIAL","");}
    public String remember(Identity identity,String name,Path encryptedOriginal)throws Exception{
        String id=identityId(identity);
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
        set("identities",String.join(",",ids));set("identity."+id+".name",name);set("identity."+id+".type",token?"token":"pkcs12");set("selected.identity",id);if(token&&get("identity."+id+".token.serial","").isBlank()&&!get("token.serial","").isBlank())bindToken(id,get("token.serial",""),get("token.rsaSlot","9a"),get("token.kemSlot","9d"),get("token.ecdhSlot","82"));save();return id;
    }
    /** Forget one local token record; never opens a token connection. */
    public void forgetYubiKeyIdentity(String id)throws Exception{
        var saved=identities().stream().filter(i->i.id().equals(id)).findFirst().orElseThrow(()->new IOException("Unknown saved identity"));
        if(saved.passwordRequired())throw new IOException("This action only forgets YubiKey identities");
        Path folder=identityDirectory(id);
        Identity identity=loadIdentity(id,new char[0]);
        Path pgp=OpenPgp.supported(identity)?OpenPgp.ownPath(directory,identity):null;
        Properties before=new Properties();before.putAll(values);
        set("identities",String.join(",",identities().stream().map(SavedIdentity::id).filter(other->!other.equals(id)).toList()));
        for(String key:new ArrayList<>(values.stringPropertyNames()))if(key.startsWith("identity."+id+"."))values.remove(key);
        if(id.equals(get("selected.identity","")))set("selected.identity",null);
        try{save();}catch(Exception e){values.clear();values.putAll(before);throw e;}
        for(String file:List.of("signing.cer","signing.pem","encryption.cer","encryption.pem"))Files.deleteIfExists(folder.resolve(file));
        if(pgp!=null)Files.deleteIfExists(pgp);
        if(identity.level3Polyfill())Files.deleteIfExists(Level3PolyfillDesktop.path(directory,identity));
        try(var files=Files.list(folder)){if(files.findAny().isEmpty())Files.delete(folder);}
    }
    public void rememberSoftwareProfiles(List<Identity> profiles,Path file,String name)throws Exception{
        for(int i=0;i<profiles.size();i++){
            var identity=profiles.get(i);String id=remember(identity,name+" · "+identity.signatureAlgorithm(),file);
            set("identity."+id+".variant",profiles.size()==2&&i==0?"pure":"");
        }save();
    }
    Path vaultIdentityPath(String filename)throws IOException{
        if(!filename.matches("[a-f0-9-]{36}\\.vault\\.p12"))throw new IOException("Invalid vault identity path");
        return directory.resolve("software-vault").resolve(filename);
    }
    boolean vaultIdentity(String id){return !get("identity."+id+".vault","").isEmpty();}
    void rememberVaultProfiles(List<Identity> profiles,String name)throws Exception{
        String filename=UUID.randomUUID()+".vault.p12";Path path=vaultIdentityPath(filename);PrivateFiles.directory(path.getParent());
        SoftwareIdentityVault.save(profiles,path,DesktopVault.vault());
        // Commit catalog pointers only after the encrypted file and its recovery password are durable.
        LinkedHashSet<String> ids=new LinkedHashSet<>();for(var saved:identities())ids.add(saved.id());
        for(var identity:profiles){String id=identityId(identity);ids.add(id);set("identity."+id+".name",name+" · "+identity.signatureAlgorithm());set("identity."+id+".type","pkcs12");set("identity."+id+".vault",filename);set("selected.identity",id);}
        set("identities",String.join(",",ids));save();
        // Old password-protected copies remain as recovery backups; never silently destroy user files.
    }
    public List<CertificateBundle.Entry> certificateBundle(Identity selected)throws Exception{
        if(selected!=null&&selected.level3Polyfill())throw new IOException("Use the Level 3 encrypted companion for restore, or export its OpenPGP public certificate for contacts");
        if(selected==null||selected.signingKey()!=null)throw new IOException("Select a saved YubiKey identity to share its pure/hybrid certificates");
        String serial=get("identity."+identityId(selected)+".token.serial","");if(serial.isBlank())throw new IOException("Selected identity has no YubiKey serial");
        List<CertificateBundle.Entry> result=new ArrayList<>();
        for(var saved:identities())if(!saved.passwordRequired()&&serial.equals(get("identity."+saved.id()+".token.serial",""))){
            Identity id=loadIdentity(saved.id(),new char[0]);if(!CertificateBundle.sameKeys(selected,id))continue;if(!CertificateBundle.emails(selected.signingCert()).equals(CertificateBundle.emails(id.signingCert()))||!CertificateBundle.emails(selected.encryptionCert()).equals(CertificateBundle.emails(id.encryptionCert())))continue;
            String prefix="identity."+saved.id()+".token.";
            result.add(new CertificateBundle.Entry(id,Integer.parseInt(serial),"9c",get(prefix+"rsaSlot","9a"),get(prefix+"kemSlot","9d"),get(prefix+"ecdhSlot","82")));
        }
        return CertificateBundle.decode(CertificateBundle.encode(result));
    }
    public void importCertificateBundle(List<CertificateBundle.Entry> entries,boolean own)throws Exception{
        entries=CertificateBundle.decode(CertificateBundle.encode(entries));
        for(var e:entries)if(own){String id=identityId(e.identity());
            if(identities().stream().anyMatch(old->old.id().equals(id))){
                String prefix="identity."+id+".token.";
                if(get("identity."+id+".type","").equals("pkcs12")||!get(prefix+"serial","").equals(Integer.toString(e.serial()))||!get(prefix+"rsaSlot","9a").equals(e.traditionalSlot())||!get(prefix+"kemSlot","9d").equals(e.kemSlot())||!get(prefix+"ecdhSlot","82").equals(e.ecdhSlot()))throw new IOException("Bundle conflicts with an existing identity; no bindings changed");
            }
        }
        String previous=get("selected.identity",null);
        for(var e:entries){if(own){String id=identityId(e.identity());if(identities().stream().noneMatch(old->old.id().equals(id))){remember(e.identity(),CertificateBundle.emails(e.identity().signingCert())+" · "+e.identity().signatureAlgorithm(),null);bindToken(id,Integer.toString(e.serial()),e.traditionalSlot(),e.kemSlot(),e.ecdhSlot());}}
            else for(String role:List.of("signing","encryption")){X509Certificate cert=role.equals("signing")?e.identity().signingCert():e.identity().encryptionCert();for(String email:CertificateBundle.emails(cert))rememberContact(cert,email,role);}
        }
        set("selected.identity",previous);save();
    }
    public void importOnKey(OnKeyBundle.Bundle bundle)throws Exception{
        for(var e:bundle.entries()){String id=identityId(e.identity()),prefix="identity."+id+".token.";
            if(e.traditionalSlot().equals("83")&&get(prefix+"serial","").equals(Integer.toString(e.serial()))&&get(prefix+"rsaSlot","9a").equals("9a"))bindToken(id,Integer.toString(e.serial()),"83",e.kemSlot(),e.ecdhSlot());
        }importCertificateBundle(bundle.entries(),true);bundle.savePgp(directory);
    }
    public void migrateTokenBindings(List<CertificateBundle.Entry> entries)throws Exception{
        for(var e:entries){String id=identityId(e.identity());bindToken(id,Integer.toString(e.serial()),"83",e.kemSlot(),e.ecdhSlot());}save();
    }
    public void saveCertificate(String role,X509Certificate certificate)throws Exception{
        if(!Set.of("recipient","pinned").contains(role))throw new IllegalArgumentException("Invalid certificate role");
        write(directory.resolve(role+".cer"),certificate.getEncoded());
    }
    public X509Certificate certificate(String role)throws Exception{
        if(!Set.of("recipient","pinned").contains(role))throw new IllegalArgumentException("Invalid certificate role");
        Path path=directory.resolve(role+".cer");return Files.exists(path)?Identity.readCertificate(path):null;
    }
    private static String trustKey(X509Certificate certificate,String role)throws Exception{
        if(!Set.of("signing","encryption").contains(role))throw new IllegalArgumentException("Invalid certificate trust role");
        return "trusted."+role+"."+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }
    private static void validateContactPurpose(X509Certificate cert,String role)throws Exception{
        try{Identity.validateCertificatePurpose(cert,role);}catch(java.security.GeneralSecurityException e){throw new IOException(e.getMessage(),e);}
    }
    public boolean isTrusted(X509Certificate certificate,String role)throws Exception{return Boolean.parseBoolean(get(trustKey(certificate,role),"false"));}
    public void setTrusted(X509Certificate certificate,String role,boolean trusted)throws Exception{
        if(trusted)validateContactPurpose(certificate,role);
        set(trustKey(certificate,role),trusted?"true":null);save();
    }
    public void migrateTrust()throws Exception{
        if(!get("trust.migrated","false").equals("true")){
            X509Certificate old=certificate("pinned");if(old!=null)set(trustKey(old,"signing"),"true");
            set("trust.migrated","true");save();
        }
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
        validateContactPurpose(certificate,role);
        if(role.equals("encryption"))Identity.validateEncryptionKey(certificate.getPublicKey());
        MessageDigest digest=MessageDigest.getInstance("SHA-256");digest.update(certificate.getEncoded());digest.update(("\n"+email.toLowerCase(Locale.ROOT)+"\n"+role).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String id=HexFormat.of().formatHex(digest.digest());Path folder=directory.resolve("contacts").resolve(id);
        write(folder.resolve("certificate.cer"),certificate.getEncoded());write(folder.resolve("certificate.pem"),pem(certificate));
        var ids=new LinkedHashSet<String>();for(var contact:contacts())ids.add(contact.id());ids.add(id);
        set("contacts",String.join(",",ids));set("contact."+id+".email",email);set("contact."+id+".role",role);save();return new Contact(id,email,role);
    }
    public void removeContact(Contact contact)throws Exception{
        if(!contacts().contains(contact))throw new IOException("Unknown certificate contact");
        setTrusted(contactCertificate(contact),contact.role(),false);
        Path trash=directory.resolve("removed-contacts");PrivateFiles.directory(trash);
        Files.move(directory.resolve("contacts").resolve(contact.id()),trash.resolve(contact.id()+"-"+System.currentTimeMillis()));
        var ids=new ArrayList<String>();for(var old:contacts())if(!old.id().equals(contact.id()))ids.add(old.id());
        set("contacts",String.join(",",ids));set("contact."+contact.id()+".email",null);set("contact."+contact.id()+".role",null);save();
    }
    private static String pgpId(String email,String fingerprint)throws Exception{
        OpenPgp.validateEmail(email);if(!fingerprint.matches("(?i)[0-9a-f]{40}|[0-9a-f]{64}"))throw new IOException("Invalid full OpenPGP fingerprint");
        return OpenPgp.hex(OpenPgp.hash("SHA-256",OpenPgp.bytes(email.toLowerCase(Locale.ROOT)+"\n"+fingerprint.toLowerCase(Locale.ROOT))));
    }
    public List<Contact> pgpContacts(){
        var result=new ArrayList<Contact>();for(String id:get("pgp.contacts","").split(","))if(id.matches("[a-f0-9]{64}"))result.add(new Contact(id,get("pgp."+id+".email",""),"OpenPGP"));return List.copyOf(result);
    }
    public String pgpFingerprint(Contact c)throws Exception{
        if(!pgpContacts().contains(c))throw new IOException("Unknown OpenPGP contact");String fp=get("pgp."+c.id()+".fingerprint","");
        if(!pgpId(c.email(),fp).equals(c.id()))throw new IOException("OpenPGP contact metadata mismatch");return fp;
    }
    public OpenPgp.PublicIdentity pgpCertificate(Contact c)throws Exception{
        String fp=pgpFingerprint(c);Path path=directory.resolve("openpgp-contacts").resolve(c.id()).resolve("public.asc");
        if(Files.size(path)>128*1024)throw new IOException("OpenPGP contact too large");var key=new OpenPgp.PublicIdentity(Files.readAllBytes(path));
        if(!key.fingerprint().equals(fp)||!key.matchesEmail(c.email()))throw new IOException("OpenPGP contact certificate mismatch");return key;
    }
    public Contact rememberPgp(OpenPgp.PublicIdentity supplied,String email)throws Exception{
        var key=new OpenPgp.PublicIdentity(supplied.export());email=email.trim().toLowerCase(Locale.ROOT);
        if(!key.matchesEmail(email))throw new IOException("Email is not certified by this OpenPGP key");Contact contact=rememberPgpChecked(key,email);save();return contact;
    }
    private Contact rememberPgpChecked(OpenPgp.PublicIdentity key,String email)throws Exception{
        String fp=key.fingerprint(),id=pgpId(email,fp);
        write(directory.resolve("openpgp-contacts").resolve(id).resolve("public.asc"),key.export());
        var ids=new LinkedHashSet<String>();for(var c:pgpContacts())ids.add(c.id());ids.add(id);set("pgp.contacts",String.join(",",ids));set("pgp."+id+".email",email);set("pgp."+id+".fingerprint",fp);return new Contact(id,email,"OpenPGP");
    }
    public boolean isPgpTrusted(String email,String fp)throws Exception{
        String id=pgpId(email,fp);var c=pgpContacts().stream().filter(v->v.id().equals(id)).findFirst().orElse(null);
        if(c==null||!Boolean.parseBoolean(get("pgp."+id+".trusted","false")))return false;
        pgpCertificate(c);return true; // Trust never overrides validity or certificate binding checks.
    }
    public void setPgpTrusted(Contact c,boolean trusted)throws Exception{
        pgpFingerprint(c);if(trusted)pgpCertificate(c);set("pgp."+c.id()+".trusted",trusted?"true":null);save();
    }
    public void setPgpTrustSelection(OpenPgp.PublicIdentity supplied,Set<String> selectedEmails)throws Exception{
        var key=new OpenPgp.PublicIdentity(supplied.export());var emails=key.certifiedEmails();
        var selected=new HashSet<String>();for(String email:selectedEmails)selected.add(email.trim().toLowerCase(Locale.ROOT));
        if(!emails.containsAll(selected))throw new IOException("Trust selection includes an email not certified by this key");
        Properties before=new Properties();before.putAll(values);
        try{
            for(String email:emails){String id=pgpId(email,key.fingerprint());
                if(selected.contains(email)||pgpContacts().stream().anyMatch(c->c.id().equals(id))){
                    var c=rememberPgpChecked(key,email);set("pgp."+c.id()+".trusted",selected.contains(email)?"true":null);
                }
            }
            save(); // One atomic settings replacement publishes the entire trust selection.
        }catch(Exception e){values.clear();values.putAll(before);throw e;}
    }
    void migratePgpTrust(OpenPgp.PublicIdentity previous,OpenPgp.PublicIdentity replacement,Set<String> trusted)throws Exception{
        var next=new OpenPgp.PublicIdentity(replacement.export());OpenPgp.check(next.certifiedEmails().containsAll(trusted),"Migration trust contains an uncertified address");
        Properties before=new Properties();before.putAll(values);
        try{
            var old=new ArrayList<Contact>();for(var c:pgpContacts())if(pgpFingerprint(c).equals(previous.fingerprint()))old.add(c);
            for(String email:next.certifiedEmails()){var c=rememberPgpChecked(next,email);set("pgp."+c.id()+".trusted",trusted.contains(email)?"true":null);}
            var currentIds=pgpContacts().stream().map(Contact::id).toList();var removed=new HashSet<String>();for(var c:old){removed.add(c.id());for(String suffix:List.of("email","fingerprint","trusted"))set("pgp."+c.id()+"."+suffix,null);}
            set("pgp.contacts",String.join(",",currentIds.stream().filter(k->!removed.contains(k)).toList()));save();
        }catch(Exception e){values.clear();values.putAll(before);throw e;}
    }
    public void removePgp(Contact c)throws Exception{
        pgpFingerprint(c);Path folder=directory.resolve("openpgp-contacts").resolve(c.id());
        Path removed=directory.resolve("removed-contacts");PrivateFiles.directory(removed);
        if(Files.exists(folder))Files.move(folder,removed.resolve("pgp-"+c.id()+"-"+System.nanoTime()));
        set("pgp.contacts",String.join(",",pgpContacts().stream().filter(v->!v.id().equals(c.id())).map(Contact::id).toList()));
        for(String suffix:List.of("email","fingerprint","trusted"))set("pgp."+c.id()+"."+suffix,null);save();
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
        result.put("OPENSSL_BIN",nativePath("openssl.path",windows()?"native/bin/openssl.exe":"native/bin/openssl",linux()?"/usr/bin/openssl":"/opt/homebrew/bin/openssl"));
        result.put("PKCS11_PROVIDER",nativePath("provider.path",windows()?"native/lib/pkcs11.dll":linux()?"native/lib/pkcs11.so":"native/lib/pkcs11.dylib",resources().resolve(linux()?"native/pkcs11.so":"native/pkcs11.dylib").toString()));
        result.put("PKCS11_MODULE",nativePath("module.path",windows()?"native/lib/ykcs11.dll":linux()?"native/lib/libykcs11.so":"native/lib/libykcs11.dylib",resources().resolve(linux()?"native/libykcs11.so":"native/libykcs11.dylib").toString()));
        result.put("PYTHON_BIN",get("python.path",defaultPython()));
        result.put("PKCS11_SERIAL",get("token.serial",""));result.put("PKCS11_TRADITIONAL_SLOT",get("token.rsaSlot","9a"));
        result.put("PKCS11_KEM_SLOT",get("token.kemSlot","9d"));result.put("PKCS11_ECDH_SLOT",get("token.ecdhSlot","82"));
        return Map.copyOf(result);
    }
    public void activate(){processConfig=configuration();}
    public static ProcessBuilder process(String executable){
        Map<String,String> config=processConfig;
        ProcessBuilder builder=executable.endsWith(".py")?new ProcessBuilder(config.getOrDefault("PYTHON_BIN",defaultPython()),executable):new ProcessBuilder(executable);
        builder.environment().putAll(config);builder.environment().put("PYTHONDONTWRITEBYTECODE","1");
        return builder;
    }
    public String adapter(boolean kem){
        return resources().resolve("adapters").resolve(kem?"pkcs11-kem.py":"pkcs11-mu.py").toString();
    }
}
