package dev.hybridmail;

import java.security.*;
import java.util.*;
import com.google.gson.*;

/** Public, signed routing metadata. A serial selects a card, never an algorithm. */
final class KeyLayout {
    enum Profile {
        LEVEL3_NIST("Level 3 NIST — ML-DSA-65 / ML-KEM-768 + P-384"),
        LEVEL5_NIST("Level 5 NIST — ML-DSA-87 / ML-KEM-1024 + P-384"),
        LEVEL5_NATIVE("Level 5 RFC 9980 — native Ed448 / X448"),
        LEVEL5_COMPANION("Level 5 RFC 9980 — encrypted Ed448 / X448 companion");
        final String label;Profile(String label){this.label=label;}
        public String toString(){return label;}
    }
    record Component(String role,String algorithm,String storage,String slot,String sha256){}
    record Manifest(int version,int serial,String profile,List<Component> components){}
    static Manifest companion(int serial,Map<String,PublicKey> h,OpenPgp.PublicIdentity own)throws Exception{
        return companion(serial,h,OpenPgp.parseKey(own.primary,true),own.signing,own.encryption);
    }
    /** Ultra envelopes authenticate key packet bodies before any certificate
     * signatures are regenerated. The same canonical manifest must bind those
     * exact public components without requiring a usable certificate yet. */
    static Manifest companion(int serial,Map<String,PublicKey> h,OpenPgp.Keys certification,OpenPgp.Keys signing,OpenPgp.Keys encryption)throws Exception{
        var components=new ArrayList<Component>();
        for(String[] c:new String[][]{{"certification-pq","86","ML-DSA-87"},{"signing-pq","9c","ML-DSA-87"},{"decryption-pq","9d","ML-KEM-1024"},{"companion-wrap","82","P-384"}})components.add(component(c[0],c[2],"piv",c[1],h.get(c[1])));
        components.add(component("certification-classical","Ed448","companion","",certification.ec()));
        components.add(component("signing-classical","Ed448","companion","",signing.ec()));
        components.add(component("decryption-classical","X448","companion","",encryption.ec()));
        return new Manifest(1,serial,Profile.LEVEL5_COMPANION.name(),List.copyOf(components));
    }
    private static Component component(String role,String algorithm,String storage,String slot,PublicKey key)throws Exception{return new Component(role,algorithm,storage,slot,HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getEncoded())));}
    static byte[] encode(Manifest manifest){return new Gson().toJson(manifest).getBytes(java.nio.charset.StandardCharsets.UTF_8);}
    /** Require canonical metadata, which also rejects unknown/duplicate fields.
     * The surrounding envelope signature must already have been checked. */
    static Manifest companion(byte[] encoded,int serial,Map<String,PublicKey> h,OpenPgp.PublicIdentity own)throws Exception{
        Manifest expected=companion(serial,h,own);OpenPgp.check(Arrays.equals(encoded,encode(expected)),"Companion manifest does not match serial, algorithms, slots or certificate");return expected;
    }
    static Manifest companion(byte[] encoded,int serial,Map<String,PublicKey> h,UltraCertificate template)throws Exception{
        Manifest expected=companion(serial,h,template.certificationKeys(),template.signingKeys(),template.encryptionKeys());OpenPgp.check(Arrays.equals(encoded,encode(expected)),"Ultra manifest does not match serial, algorithms, slots or template");return expected;
    }
}
