#include "CNative.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <limits.h>
static PQBuffer allocbuf(size_t n) { PQBuffer b={OPENSSL_malloc(n?n:1),n}; if(!b.data)b.count=0; return b; }
static PQBuffer failbuf(void) { PQBuffer b={0};return b; }
void pq_buffer_free(PQBuffer b){ if(b.data)OPENSSL_clear_free(b.data,b.count); }
void pq_key_free(void *p){EVP_PKEY_free(p);}
const char *pq_version(void){return OpenSSL_version(OPENSSL_VERSION);}
void *pq_key_generate(const char *alg,const char *group){
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_name(NULL,alg,NULL); EVP_PKEY *p=NULL;
 if(!c||EVP_PKEY_keygen_init(c)<=0)goto done;
 if(group&&*group&&EVP_PKEY_CTX_set_group_name(c,group)<=0)goto done;
 if(EVP_PKEY_generate(c,&p)<=0){EVP_PKEY_free(p);p=NULL;}
 done:EVP_PKEY_CTX_free(c);return p;
}
void *pq_key_read(const unsigned char *der,size_t n,int priv){
 if(n>LONG_MAX)return NULL;const unsigned char *q=der;EVP_PKEY *p=NULL;
 if(priv){PKCS8_PRIV_KEY_INFO *i=d2i_PKCS8_PRIV_KEY_INFO(NULL,&q,n);if(i){p=EVP_PKCS82PKEY(i);PKCS8_PRIV_KEY_INFO_free(i);}}
 else p=d2i_PUBKEY(NULL,&q,n);
 if(q!=der+n){EVP_PKEY_free(p);return NULL;}
 if(p&&!priv&&EVP_PKEY_is_a(p,"EC")){
  EVP_PKEY_CTX *check=EVP_PKEY_CTX_new_from_pkey(NULL,p,NULL);
  int valid=check&&EVP_PKEY_public_check(check)==1;EVP_PKEY_CTX_free(check);
  if(!valid){EVP_PKEY_free(p);return NULL;}
 }
 return p;
}
PQBuffer pq_key_export(void *p,int priv){
 unsigned char *out=NULL;int n; if(priv){PKCS8_PRIV_KEY_INFO *i=EVP_PKEY2PKCS8(p);if(!i)return failbuf();n=i2d_PKCS8_PRIV_KEY_INFO(i,&out);PKCS8_PRIV_KEY_INFO_free(i);}else n=i2d_PUBKEY(p,&out);
 if(n<=0){OPENSSL_free(out);return failbuf();}PQBuffer b={out,(size_t)n};return b;
}
PQBuffer pq_digest(const char *name,const unsigned char *p,size_t n){
 EVP_MD *md=EVP_MD_fetch(NULL,name,NULL); if(!md)return failbuf();PQBuffer b=allocbuf(EVP_MD_get_size(md));unsigned int len=0;
 if(!b.data||!EVP_Digest(p,n,b.data,&len,md,NULL)){pq_buffer_free(b);b=failbuf();}EVP_MD_free(md);return b;
}
PQBuffer pq_random(size_t n){PQBuffer b=allocbuf(n);if(!b.data||RAND_bytes_ex(NULL,b.data,n,0)!=1){pq_buffer_free(b);return failbuf();}return b;}
static int siginit(EVP_MD_CTX *c,void *key,const char *md,const unsigned char *ctx,size_t n,int sign){
 EVP_PKEY_CTX *p=NULL; int ok=sign?EVP_DigestSignInit_ex(c,&p,md&&*md?md:NULL,NULL,NULL,key,NULL):EVP_DigestVerifyInit_ex(c,&p,md&&*md?md:NULL,NULL,NULL,key,NULL);
 if(ok<=0)return 0;
 if(n){OSSL_PARAM params[]={OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,(void*)ctx,n),OSSL_PARAM_END};if(EVP_PKEY_CTX_set_params(p,params)<=0)return 0;}return 1;
}
PQBuffer pq_sign(void *key,const char *md,const unsigned char *ctx,size_t cn,const unsigned char *msg,size_t n){
 EVP_MD_CTX *c=EVP_MD_CTX_new();PQBuffer b=failbuf();size_t len=0;
 if(c&&siginit(c,key,md,ctx,cn,1)&&EVP_DigestSign(c,NULL,&len,msg,n)>0){b=allocbuf(len);if(!b.data||EVP_DigestSign(c,b.data,&len,msg,n)<=0){pq_buffer_free(b);b=failbuf();}else b.count=len;}EVP_MD_CTX_free(c);return b;
}
int pq_verify(void *key,const char *md,const unsigned char *ctx,size_t cn,const unsigned char *msg,size_t n,const unsigned char *sig,size_t sn){
 EVP_MD_CTX *c=EVP_MD_CTX_new();int ok=c&&siginit(c,key,md,ctx,cn,0)&&EVP_DigestVerify(c,sig,sn,msg,n)==1;EVP_MD_CTX_free(c);return ok;
}
int pq_encapsulate(void *key,PQBuffer *ct,PQBuffer *ss){
 *ct=failbuf();*ss=failbuf();EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);size_t cn=0,sn=0;int ok=0;
 if(c&&EVP_PKEY_encapsulate_init(c,NULL)>0&&EVP_PKEY_encapsulate(c,NULL,&cn,NULL,&sn)>0){*ct=allocbuf(cn);*ss=allocbuf(sn);if(ct->data&&ss->data&&EVP_PKEY_encapsulate(c,ct->data,&cn,ss->data,&sn)>0){ct->count=cn;ss->count=sn;ok=1;}}
 EVP_PKEY_CTX_free(c);if(!ok){pq_buffer_free(*ct);pq_buffer_free(*ss);*ct=failbuf();*ss=failbuf();}return ok;
}
PQBuffer pq_decapsulate(void *key,const unsigned char *ct,size_t n){
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);PQBuffer b=failbuf();size_t len=0;
 if(c&&EVP_PKEY_decapsulate_init(c,NULL)>0&&EVP_PKEY_decapsulate(c,NULL,&len,ct,n)>0){b=allocbuf(len);if(!b.data||EVP_PKEY_decapsulate(c,b.data,&len,ct,n)<=0){pq_buffer_free(b);b=failbuf();}else b.count=len;}EVP_PKEY_CTX_free(c);return b;
}
PQBuffer pq_ecdh(void *key,void *peer){EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);PQBuffer b=failbuf();size_t n=0;
 if(c&&EVP_PKEY_derive_init(c)>0&&EVP_PKEY_derive_set_peer(c,peer)>0&&EVP_PKEY_derive(c,NULL,&n)>0){b=allocbuf(n);if(!b.data||EVP_PKEY_derive(c,b.data,&n)<=0){pq_buffer_free(b);b=failbuf();}else b.count=n;}EVP_PKEY_CTX_free(c);return b;}
PQBuffer pq_hkdf(const unsigned char *ss,size_t n,const unsigned char *info,size_t in){
 EVP_KDF *k=EVP_KDF_fetch(NULL,"HKDF",NULL);EVP_KDF_CTX *c=k?EVP_KDF_CTX_new(k):NULL;PQBuffer b=allocbuf(32);
 OSSL_PARAM p[]={OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,"SHA256",0),OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,(void*)ss,n),OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,(void*)info,in),OSSL_PARAM_END};
 if(!c||!b.data||EVP_KDF_derive(c,b.data,32,p)<=0){pq_buffer_free(b);b=failbuf();}EVP_KDF_CTX_free(c);EVP_KDF_free(k);return b;
}
PQBuffer pq_gcm(int enc,const unsigned char *key,const unsigned char *nonce,const unsigned char *aad,size_t an,const unsigned char *in,size_t n){
 if(n>INT_MAX-16||an>INT_MAX||(!enc&&n<16))return failbuf();EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();PQBuffer b=allocbuf(n+16);int l=0,total=0;int count=enc?(int)n:(int)n-16;
 if(!c||!b.data||EVP_CipherInit_ex(c,EVP_aes_256_gcm(),NULL,key,nonce,enc)<=0)goto fail;
 if(an&&EVP_CipherUpdate(c,NULL,&l,aad,(int)an)<=0)goto fail;
 if(EVP_CipherUpdate(c,b.data,&l,in,count)<=0)goto fail;total=l;
 if(!enc&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)(in+count))<=0)goto fail;
 if(EVP_CipherFinal_ex(c,b.data+total,&l)<=0)goto fail;total+=l;
 if(enc){if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,b.data+total)<=0)goto fail;total+=16;}
 b.count=total;EVP_CIPHER_CTX_free(c);return b;
 fail:EVP_CIPHER_CTX_free(c);pq_buffer_free(b);return failbuf();
}
PQBuffer pq_wrap(int enc,const unsigned char *key,const unsigned char *in,size_t n){
 if(n>INT_MAX-16||n<16||n%8)return failbuf();EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();PQBuffer b=allocbuf(n+16);int l=0,f=0;
 if(!c||!b.data)goto fail;EVP_CIPHER_CTX_set_flags(c,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 if(EVP_CipherInit_ex(c,EVP_aes_256_wrap(),NULL,key,NULL,enc)<=0||EVP_CipherUpdate(c,b.data,&l,in,(int)n)<=0||EVP_CipherFinal_ex(c,b.data+l,&f)<=0)goto fail;
 b.count=l+f;EVP_CIPHER_CTX_free(c);return b;
 fail:EVP_CIPHER_CTX_free(c);pq_buffer_free(b);return failbuf();
}

#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <string.h>
PQBuffer pq_key_seed(void *key){size_t n=0;if(!EVP_PKEY_get_octet_string_param(key,"seed",NULL,0,&n)||n>64)return failbuf();PQBuffer b=allocbuf(n);if(!b.data||!EVP_PKEY_get_octet_string_param(key,"seed",b.data,n,&n)){pq_buffer_free(b);return failbuf();}return b;}
PQBuffer pq_shake256(const unsigned char *in,size_t n,size_t on){if(on>128)return failbuf();EVP_MD_CTX *c=EVP_MD_CTX_new();PQBuffer b=allocbuf(on);if(!c||!b.data||!EVP_DigestInit_ex(c,EVP_shake256(),NULL)||!EVP_DigestUpdate(c,in,n)||!EVP_DigestFinalXOF(c,b.data,on)){pq_buffer_free(b);b=failbuf();}EVP_MD_CTX_free(c);return b;}
/* Private transport for bags: type(1) || nameLength(2) || DERLength(4) || name || DER.
 * PKCS#12 remains standard; this framing is only the in-process Swift/C bridge. */
static int append_record(PQBuffer *out,int type,const char *name,const unsigned char *der,size_t n){
 size_t nn=strlen(name);if(nn==0||nn>255||n>131072||out->count+7+nn+n>1048576)return 0;
 size_t old=out->count,total=old+7+nn+n;unsigned char *p=OPENSSL_realloc(out->data,total);if(!p)return 0;out->data=p;out->count=total;p+=old;
 p[0]=type;p[1]=nn>>8;p[2]=nn;p[3]=n>>24;p[4]=n>>16;p[5]=n>>8;p[6]=n;memcpy(p+7,name,nn);memcpy(p+7+nn,der,n);return 1;
}
PQBuffer pq_p12_pack(const unsigned char *records,size_t n,const char *pass){
 STACK_OF(PKCS12_SAFEBAG)*bags=sk_PKCS12_SAFEBAG_new_null();STACK_OF(PKCS7)*safes=NULL;PKCS12*p12=NULL;PQBuffer out=failbuf();size_t off=0;int count=0;
 while(off<n){
  if(n-off<7||++count>32)goto done;const unsigned char *r=records+off;int type=r[0];size_t nn=(r[1]<<8)|r[2],dn=((size_t)r[3]<<24)|((size_t)r[4]<<16)|(r[5]<<8)|r[6];
  if(nn==0||nn>255||dn>131072||nn+dn>n-off-7)goto done;char name[256];memcpy(name,r+7,nn);name[nn]=0;if(strlen(name)!=nn)goto done;
  const unsigned char *q=r+7+nn;PKCS12_SAFEBAG *bag=NULL;
  if(type==1){PKCS8_PRIV_KEY_INFO*i=d2i_PKCS8_PRIV_KEY_INFO(NULL,&q,dn);if(!i)goto done;bag=PKCS12_SAFEBAG_create_pkcs8_encrypt(NID_aes_256_cbc,pass,-1,NULL,16,200000,i);PKCS8_PRIV_KEY_INFO_free(i);}
  else if(type==2){X509*x=d2i_X509(NULL,&q,dn);if(!x)goto done;bag=PKCS12_SAFEBAG_create_cert(x);X509_free(x);}
  if(!bag||q!=r+7+nn+dn){PKCS12_SAFEBAG_free(bag);goto done;}
  if(!PKCS12_add_friendlyname_utf8(bag,name,-1)||!PKCS12_add_localkeyid(bag,(unsigned char*)name,nn)||!sk_PKCS12_SAFEBAG_push(bags,bag)){PKCS12_SAFEBAG_free(bag);goto done;}off+=7+nn+dn;
 }
 if(!count||!PKCS12_add_safe(&safes,bags,NID_aes_256_cbc,200000,pass))goto done;
 p12=PKCS12_add_safes(safes,NID_pkcs7_data);
 if(!p12||!PKCS12_set_mac(p12,pass,-1,NULL,16,200000,EVP_sha256()))goto done;
 unsigned char *p=NULL;int len=i2d_PKCS12(p12,&p);if(len>0){out.data=p;out.count=len;}else OPENSSL_free(p);
 done:PKCS12_free(p12);sk_PKCS7_pop_free(safes,PKCS7_free);sk_PKCS12_SAFEBAG_pop_free(bags,PKCS12_SAFEBAG_free);return out;
}
static int valid_iter(const ASN1_INTEGER*i){int64_t n;if(!i)return 1;return ASN1_INTEGER_get_int64(&n,i)&&n>=1&&n<=1000000;}
static int valid_pbe(const X509_ALGOR *alg){
 const ASN1_OBJECT*oid;const void *p;int type;X509_ALGOR_get0(&oid,&type,&p,alg);if(type!=V_ASN1_SEQUENCE)return 0;
 if(OBJ_obj2nid(oid)==NID_pbes2){PBE2PARAM*a=ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM),alg->parameter);if(!a)return 0;int ok=0;
  if(OBJ_obj2nid(a->keyfunc->algorithm)==NID_id_pbkdf2){PBKDF2PARAM*b=ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM),a->keyfunc->parameter);if(b){ok=valid_iter(b->iter);PBKDF2PARAM_free(b);}}
  PBE2PARAM_free(a);return ok;
 }
 int nid=OBJ_obj2nid(oid);if(nid!=NID_pbe_WithSHA1And3_Key_TripleDES_CBC&&nid!=NID_pbe_WithSHA1And40BitRC2_CBC&&nid!=NID_pbe_WithSHA1And128BitRC2_CBC)return 0;
 PBEPARAM*a=ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM),alg->parameter);if(!a)return 0;int ok=valid_iter(a->iter);PBEPARAM_free(a);return ok;
}
static CRYPTO_ONCE providers_once=CRYPTO_ONCE_STATIC_INIT;
static void load_p12_providers(void){(void)OSSL_PROVIDER_load(NULL,"default");(void)OSSL_PROVIDER_load(NULL,"legacy");}
PQBuffer pq_p12_unpack(const unsigned char *der,size_t n,const char *pass){
 if(n>1048576)return failbuf();CRYPTO_THREAD_run_once(&providers_once,load_p12_providers);
 const unsigned char *q=der;PKCS12*p12=d2i_PKCS12(NULL,&q,n);STACK_OF(PKCS7)*safes=NULL;PQBuffer out=failbuf();int ok=0,total=0;
 if(!p12||q!=der+n||!PKCS12_mac_present(p12))goto done;
 const ASN1_INTEGER*iter;const X509_ALGOR*macalg;PKCS12_get0_mac(NULL,&macalg,NULL,&iter,p12);
 int macnid=OBJ_obj2nid(macalg->algorithm);if((macnid!=NID_sha1&&macnid!=NID_sha256&&macnid!=NID_sha512)||!valid_iter(iter)||!PKCS12_verify_mac(p12,pass,-1))goto done;
 safes=PKCS12_unpack_authsafes(p12);if(!safes||sk_PKCS7_num(safes)>8)goto done;
 for(int i=0;i<sk_PKCS7_num(safes);i++){
  PKCS7*s=sk_PKCS7_value(safes,i);STACK_OF(PKCS12_SAFEBAG)*bags=NULL;
  if(PKCS7_type_is_data(s))bags=PKCS12_unpack_p7data(s);
  else if(PKCS7_type_is_encrypted(s)&&valid_pbe(s->d.encrypted->enc_data->algorithm))bags=PKCS12_unpack_p7encdata(s,pass,-1);
  if(!bags)goto done;int good=1;
  for(int j=0;j<sk_PKCS12_SAFEBAG_num(bags)&&good;j++){
   if(++total>32){good=0;break;}PKCS12_SAFEBAG*b=sk_PKCS12_SAFEBAG_value(bags,j);char*name=PKCS12_get_friendlyname(b);int nid=PKCS12_SAFEBAG_get_nid(b),type=0,len=0;unsigned char *data=NULL;
   if(nid==NID_pkcs8ShroudedKeyBag){const X509_SIG*x=PKCS12_SAFEBAG_get0_pkcs8(b);const X509_ALGOR*a;X509_SIG_get0(x,&a,NULL);PKCS8_PRIV_KEY_INFO*k=valid_pbe(a)?PKCS12_decrypt_skey(b,pass,-1):NULL;if(k){len=i2d_PKCS8_PRIV_KEY_INFO(k,&data);PKCS8_PRIV_KEY_INFO_free(k);}type=1;}
   else if(nid==NID_certBag){X509*x=PKCS12_SAFEBAG_get1_cert(b);if(x){len=i2d_X509(x,&data);X509_free(x);}type=2;}
   /* Unencrypted private bags are intentionally not accepted. */
   if(!name||!type||len<=0||!append_record(&out,type,name,data,len))good=0;
   OPENSSL_free(name);if(data)OPENSSL_clear_free(data,len>0?(size_t)len:0);
  }
  sk_PKCS12_SAFEBAG_pop_free(bags,PKCS12_SAFEBAG_free);if(!good)goto done;
 }
 ok=out.count>0;
 done:PKCS12_free(p12);sk_PKCS7_pop_free(safes,PKCS7_free);if(!ok){pq_buffer_free(out);return failbuf();}return out;
}

/* OpenPGP hashes the signature input itself; ECDSA consumes that digest directly. */
PQBuffer pq_ec_sign_digest(void *key,const unsigned char *in,size_t n) {
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);PQBuffer b=failbuf();size_t sn=0;
 if(c&&EVP_PKEY_is_a(key,"EC")&&(n==32||n==48||n==64)&&EVP_PKEY_sign_init(c)>0&&EVP_PKEY_CTX_set_signature_md(c,n==32?EVP_sha256():n==48?EVP_sha384():EVP_sha512())>0&&EVP_PKEY_sign(c,NULL,&sn,in,n)>0) {
  b=allocbuf(sn);if(!b.data||EVP_PKEY_sign(c,b.data,&sn,in,n)<=0){pq_buffer_free(b);b=failbuf();}else b.count=sn;
 }EVP_PKEY_CTX_free(c);return b;
}
int pq_ec_verify_digest(void *key,const unsigned char *in,size_t n,const unsigned char *sig,size_t sn) {
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);
 int ok=c&&EVP_PKEY_is_a(key,"EC")&&(n==32||n==48||n==64)&&EVP_PKEY_verify_init(c)>0&&EVP_PKEY_CTX_set_signature_md(c,n==32?EVP_sha256():n==48?EVP_sha384():EVP_sha512())>0&&EVP_PKEY_verify(c,sig,sn,in,n)==1;
 EVP_PKEY_CTX_free(c);return ok;
}
PQBuffer pq_hkdf_salt(const unsigned char *ss,size_t n,const unsigned char *salt,size_t salt_n,const unsigned char *info,size_t info_n,size_t out_n) {
 if(out_n>64)return failbuf();
 EVP_KDF *k=EVP_KDF_fetch(NULL,"HKDF",NULL);EVP_KDF_CTX *c=k?EVP_KDF_CTX_new(k):NULL;PQBuffer b=allocbuf(out_n);
 OSSL_PARAM p[]={OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,"SHA256",0),OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,(void*)ss,n),OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt,salt_n),OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,(void*)info,info_n),OSSL_PARAM_END};
 if(!c||!b.data||EVP_KDF_derive(c,b.data,out_n,p)<=0){pq_buffer_free(b);b=failbuf();}EVP_KDF_CTX_free(c);EVP_KDF_free(k);return b;
}
/* Protocol-test oracle: signs the external mu produced by the hardware adapter. */
PQBuffer pq_sign_mu(void *key,const unsigned char *mu,size_t n) {
 if(n!=64)return failbuf();int enabled=1;size_t sn=0;PQBuffer b=failbuf();
 OSSL_PARAM p[]={OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU,&enabled),OSSL_PARAM_END};
 EVP_MD_CTX *c=EVP_MD_CTX_new();
 if(c&&EVP_DigestSignInit_ex(c,NULL,NULL,NULL,NULL,key,p)>0&&EVP_DigestSign(c,NULL,&sn,mu,n)>0) {
  b=allocbuf(sn);if(!b.data||EVP_DigestSign(c,b.data,&sn,mu,n)<=0){pq_buffer_free(b);b=failbuf();}else b.count=sn;
 }EVP_MD_CTX_free(c);return b;
}

/* RFC 9580 SEIPD supports OCB as well as GCM; fixed AES-256 and 128-bit tags. */
PQBuffer pq_ocb(int enc,const unsigned char *key,const unsigned char *nonce,const unsigned char *aad,size_t an,const unsigned char *in,size_t n) {
 if(n>INT_MAX-16||an>INT_MAX||(!enc&&n<16))return failbuf();
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();PQBuffer b=allocbuf(n+16);int l=0,total=0;int count=enc?(int)n:(int)n-16;
 if(!c||!b.data||EVP_CipherInit_ex(c,EVP_aes_256_ocb(),NULL,NULL,NULL,enc)<=0)goto fail;
 if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_IVLEN,15,NULL)<=0)goto fail;
 if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,enc?NULL:(void*)(in+count))<=0)goto fail;
 if(EVP_CipherInit_ex(c,NULL,NULL,key,nonce,enc)<=0)goto fail;
 if(an&&EVP_CipherUpdate(c,NULL,&l,aad,(int)an)<=0)goto fail;
 if(EVP_CipherUpdate(c,b.data,&l,in,count)<=0)goto fail;total=l;
 if(EVP_CipherFinal_ex(c,b.data+total,&l)<=0)goto fail;total+=l;
 if(enc){if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,b.data+total)<=0)goto fail;total+=16;}
 b.count=total;EVP_CIPHER_CTX_free(c);return b;
 fail:EVP_CIPHER_CTX_free(c);pq_buffer_free(b);return failbuf();
}
