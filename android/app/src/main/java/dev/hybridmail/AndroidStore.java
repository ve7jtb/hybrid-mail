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
    void trust(X509Certificate cert)throws Exception{trust(cert,"signing");}
    void trust(X509Certificate cert,String role)throws Exception{
        Identity.validateCertificatePurpose(cert,role);
        Files.write(root.resolve("trusted-"+role+"-"+Identity.fingerprint(cert).replace(":","")+".cer"),cert.getEncoded());
        context.getSharedPreferences("trust",0).edit().putBoolean(role+":"+Identity.fingerprint(cert),true).apply();
    }
    List<X509Certificate> encryptionContacts()throws Exception{
        List<X509Certificate> result=new ArrayList<>();try(var paths=Files.newDirectoryStream(root,"trusted-encryption-*.cer")){for(var path:paths)result.add(Identity.readCertificate(path));}return result;
    }
    boolean trusted(String fingerprint){return context.getSharedPreferences("trust",0).getBoolean("signing:"+fingerprint,context.getSharedPreferences("trust",0).getBoolean(fingerprint,false));}
}
