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
    Identity loadToken(Entry e)throws Exception{return new Identity(Identity.readCertificate(root.resolve(e.sign)),null,Identity.readCertificate(root.resolve(e.encrypt)),null,null);}
    void addToken(String label,int serial,Identity id)throws Exception {
        String key=UUID.randomUUID().toString();
        Files.write(root.resolve(key+"-sign.cer"),id.signingCert().getEncoded());
        Files.write(root.resolve(key+"-encrypt.cer"),id.encryptionCert().getEncoded());
        add(new Entry(key,label,"",serial,key+"-sign.cer",key+"-encrypt.cer"));
    }
    String[] slots(Entry e){return context.getSharedPreferences("slots",0).getString(e.id(),"9c,9a,9d,82").split(",");}
    List<CertificateBundle.Entry> certificateBundle(Entry selected,Identity current)throws Exception{
        if(selected==null||selected.serial()==0)throw new java.io.IOException("Select a YubiKey identity first");
        List<CertificateBundle.Entry> result=new ArrayList<>();
        for(var e:entries())if(e.serial()==selected.serial()){
            Identity id=loadToken(e);if(!CertificateBundle.sameKeys(current,id))continue;String[] slots=slots(e);
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
