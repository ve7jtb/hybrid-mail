package dev.hybridmail;
import android.content.Context;
import org.json.*;
import java.nio.file.*;
import java.security.cert.X509Certificate;
import java.util.*;

/** App-private encrypted bundles and public-only token records. No passwords or PINs saved. */
final class AndroidStore {
    record Entry(String id,String label,String bundle,int serial,String sign,String encrypt) {
        public String toString(){return label+(serial==0?" • software":" • YubiKey "+serial);}
    }
    final Path root;
    final Context context;
    AndroidStore(Context context)throws Exception{this.context=context;root=context.getFilesDir().toPath();Files.createDirectories(root);}
    List<Entry> entries()throws Exception {
        var a=new JSONArray(context.getSharedPreferences("identities",0).getString("entries","[]"));
        List<Entry> result=new ArrayList<>();
        for(int i=0;i<a.length();i++){var o=a.getJSONObject(i);result.add(new Entry(o.getString("id"),o.getString("label"),o.optString("bundle"),o.optInt("serial"),o.optString("sign"),o.optString("encrypt")));}
        return result;
    }
    void add(Entry e)throws Exception {
        var a=new JSONArray(context.getSharedPreferences("identities",0).getString("entries","[]"));
        a.put(new JSONObject().put("id",e.id).put("label",e.label).put("bundle",e.bundle).put("serial",e.serial).put("sign",e.sign).put("encrypt",e.encrypt));
        if(!context.getSharedPreferences("identities",0).edit().putString("entries",a.toString()).commit())throw new java.io.IOException("Cannot save identity catalog");
    }
    void replaceSoftwareBundle(Entry entry,String bundle)throws Exception{
        var a=new JSONArray();boolean found=false;
        for(var e:entries()){if(e.id().equals(entry.id())){if(e.serial()!=0)throw new java.io.IOException("Not a software identity");found=true;e=new Entry(e.id(),e.label(),bundle,0,"","");}a.put(new JSONObject().put("id",e.id()).put("label",e.label()).put("bundle",e.bundle()).put("serial",e.serial()).put("sign",e.sign()).put("encrypt",e.encrypt()));}
        if(!found||!context.getSharedPreferences("identities",0).edit().putString("entries",a.toString()).commit())throw new java.io.IOException("Cannot update identity catalog");
    }
    Identity loadToken(Entry e)throws Exception{return new Identity(Identity.readCertificate(root.resolve(e.sign)),null,Identity.readCertificate(root.resolve(e.encrypt)),null,null);}
    void addToken(String label,int serial,Identity id)throws Exception {addToken(label,serial,id,"9a");}
    void addToken(String label,int serial,Identity id,String traditional)throws Exception {
        String key=UUID.randomUUID().toString();
        Files.write(root.resolve(key+"-sign.cer"),id.signingCert().getEncoded());
        Files.write(root.resolve(key+"-encrypt.cer"),id.encryptionCert().getEncoded());
        context.getSharedPreferences("slots",0).edit().putString(key,"9c,"+traditional+",9d,82").commit();
        add(new Entry(key,label,"",serial,key+"-sign.cer",key+"-encrypt.cer"));
    }
    String[] slots(Entry e){return context.getSharedPreferences("slots",0).getString(e.id(),"9c,9a,9d,82").split(",");}
    List<CertificateBundle.Entry> certificateBundle(Entry selected,Identity current)throws Exception{
        if(selected==null||selected.serial()==0)throw new java.io.IOException("Select a YubiKey identity first");
        List<CertificateBundle.Entry> result=new ArrayList<>();
        for(var e:entries())if(e.serial()==selected.serial()){
            Identity id=loadToken(e);if(!CertificateBundle.sameKeys(current,id))continue;if(!CertificateBundle.emails(current.signingCert()).equals(CertificateBundle.emails(id.signingCert()))||!CertificateBundle.emails(current.encryptionCert()).equals(CertificateBundle.emails(id.encryptionCert())))continue;String[] slots=slots(e);
            result.add(new CertificateBundle.Entry(id,e.serial(),slots[0],slots[1],slots[2],slots[3]));
        }return CertificateBundle.decode(CertificateBundle.encode(result));
    }
    void importCertificateBundle(List<CertificateBundle.Entry> bundle,boolean own)throws Exception{
        bundle=CertificateBundle.decode(CertificateBundle.encode(bundle));
        for(var incoming:bundle)if(own)for(var old:entries())if(old.serial()!=0){var id=loadToken(old);
            if(Arrays.equals(id.signingCert().getEncoded(),incoming.identity().signingCert().getEncoded())&&Arrays.equals(id.encryptionCert().getEncoded(),incoming.identity().encryptionCert().getEncoded())&&(old.serial()!=incoming.serial()||!Arrays.equals(slots(old),new String[]{incoming.signingSlot(),incoming.traditionalSlot(),incoming.kemSlot(),incoming.ecdhSlot()})))throw new java.io.IOException("Bundle conflicts with saved YubiKey mapping");
        }
        for(var e:bundle){if(own){boolean exists=false;for(var old:entries())if(old.serial()!=0){var id=loadToken(old);if(Arrays.equals(id.signingCert().getEncoded(),e.identity().signingCert().getEncoded())&&Arrays.equals(id.encryptionCert().getEncoded(),e.identity().encryptionCert().getEncoded()))exists=true;}if(exists)continue;
                String key=UUID.randomUUID().toString();Files.write(root.resolve(key+"-sign.cer"),e.identity().signingCert().getEncoded());Files.write(root.resolve(key+"-encrypt.cer"),e.identity().encryptionCert().getEncoded());
                if(!context.getSharedPreferences("slots",0).edit().putString(key,String.join(",",e.signingSlot(),e.traditionalSlot(),e.kemSlot(),e.ecdhSlot())).commit())throw new java.io.IOException("Cannot save slot mappings");
                add(new Entry(key,CertificateBundle.emails(e.identity().signingCert())+" • "+e.identity().signatureAlgorithm(),"",e.serial(),key+"-sign.cer",key+"-encrypt.cer"));
            }else for(String role:List.of("signing","encryption")){var cert=role.equals("signing")?e.identity().signingCert():e.identity().encryptionCert();Files.write(root.resolve("contact-"+role+"-"+Identity.fingerprint(cert).replace(":","")+".cer"),cert.getEncoded());}
        }
    }
    void importOnKey(OnKeyBundle.Bundle bundle)throws Exception{
        if(bundle.entries().stream().allMatch(e->e.traditionalSlot().equals("83")))migrateBindings(bundle.entries());
        importCertificateBundle(bundle.entries(),true);bundle.savePgp(root);
    }
    void migrateBindings(List<CertificateBundle.Entry> entries)throws Exception{
        var edit=context.getSharedPreferences("slots",0).edit();
        for(var old:entries())if(old.serial()==entries.get(0).serial())for(var e:entries)if(Arrays.equals(loadToken(old).signingCert().getEncoded(),e.identity().signingCert().getEncoded())){var slots=slots(old);slots[1]="83";edit.putString(old.id(),String.join(",",slots));}
        if(!edit.commit())throw new java.io.IOException("Key moved; local mapping save failed. Recover using public backup.");
    }
    /** Local-only removal; no YubiKey connection or key operation. */
    void forgetYubiKeyIdentity(String id)throws Exception{
        var all=entries();var entry=all.stream().filter(e->e.id().equals(id)).findFirst().orElseThrow(()->new java.io.IOException("Unknown identity"));
        if(entry.serial()==0)throw new java.io.IOException("Only YubiKey identities can be forgotten here");
        var identity=loadToken(entry);Path pgp=OpenPgp.supported(identity)?OpenPgp.ownPath(root,identity):null;
        var remaining=new JSONArray();for(var e:all)if(!e.id().equals(id))remaining.put(new JSONObject().put("id",e.id()).put("label",e.label()).put("bundle",e.bundle()).put("serial",e.serial()).put("sign",e.sign()).put("encrypt",e.encrypt()));
        if(!context.getSharedPreferences("identities",0).edit().putString("entries",remaining.toString()).commit())throw new java.io.IOException("Cannot save identity catalog");
        if(!context.getSharedPreferences("slots",0).edit().remove(id).commit())throw new java.io.IOException("Identity forgotten; could not remove local slot record");
        for(String file:List.of(entry.sign(),entry.encrypt())){
            Path path=root.resolve(file).normalize();
            if(!path.getParent().equals(root))throw new java.io.IOException("Invalid local certificate path");
            if(all.stream().noneMatch(e->!e.id().equals(id)&&(e.sign().equals(file)||e.encrypt().equals(file))))Files.deleteIfExists(path);
        }
        if(pgp!=null){boolean shared=false;for(var e:all)if(!e.id().equals(id)&&e.serial()!=0){var other=loadToken(e);if(OpenPgp.supported(other)&&OpenPgp.ownPath(root,other).equals(pgp))shared=true;}if(!shared)Files.deleteIfExists(pgp);}
    }
    void trust(X509Certificate cert)throws Exception{trust(cert,"signing");}
    void trust(X509Certificate cert,String role)throws Exception{
        Identity.validateCertificatePurpose(cert,role);
        Files.write(root.resolve("trusted-"+role+"-"+Identity.fingerprint(cert).replace(":","")+".cer"),cert.getEncoded());
        context.getSharedPreferences("trust",0).edit().putBoolean(role+":"+Identity.fingerprint(cert),true).apply();
    }
    List<X509Certificate> encryptionContacts()throws Exception{
        List<X509Certificate> result=new ArrayList<>();try(var paths=Files.newDirectoryStream(root,"*-encryption-*.cer")){for(var path:paths)result.add(Identity.readCertificate(path));}return result;
    }
    boolean trusted(String fingerprint){return context.getSharedPreferences("trust",0).getBoolean("signing:"+fingerprint,context.getSharedPreferences("trust",0).getBoolean(fingerprint,false));}
}
