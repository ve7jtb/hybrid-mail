package dev.hybridmail;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
/** Four-key provisioning profiles; category refers to the ML-DSA parameter set. */
enum TokenProfile {
 LEVEL2("level2",2,"ML-DSA-44","ML-KEM-768","secp256r1",IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256,IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256),
 LEVEL3("level3",3,"ML-DSA-65","ML-KEM-768","secp384r1",IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512,IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256),
 LEVEL5("level5",5,"ML-DSA-87","ML-KEM-1024","secp384r1",IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512,IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
 final String code,ml,kem,curve;final int category;final ASN1ObjectIdentifier signingOid,kemOid;
 TokenProfile(String code,int category,String ml,String kem,String curve,ASN1ObjectIdentifier signingOid,ASN1ObjectIdentifier kemOid){this.code=code;this.category=category;this.ml=ml;this.kem=kem;this.curve=curve;this.signingOid=signingOid;this.kemOid=kemOid;}
 static TokenProfile parse(String code){for(var p:values())if(p.code.equals(code))return p;throw new IllegalArgumentException("Unknown YubiKey profile");}
 public String toString(){return "Level "+category+" · "+ml+" + "+kem+" + "+(category==2?"P-256":"P-384");}
}
