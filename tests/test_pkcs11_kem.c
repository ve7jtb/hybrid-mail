#define main helper_main
#include "../native-src/pkcs11-kem.c"
#undef main
#include <assert.h>
int main(void) {
 const char *algs[]={"ML-KEM-768","ML-KEM-1024","ECDH-P256","ECDH-P384","X25519"};
 for(size_t i=0;i<5;i++) {
  const char *alg=algs[i],*kind=i<2?alg:i==4?"X25519":"EC";
  EVP_PKEY *key=i==2?EVP_PKEY_Q_keygen(NULL,NULL,kind,"prime256v1"):i==3?EVP_PKEY_Q_keygen(NULL,NULL,kind,"secp384r1"):EVP_PKEY_Q_keygen(NULL,NULL,kind);
  assert(key);unsigned char input[2048],expected[64],actual[64];size_t n=sizeof(input),e=sizeof(expected),a=sizeof(actual);
  EVP_PKEY_CTX *ctx=NULL;EVP_PKEY *peer=NULL;
  if(i<2) {
   ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);assert(ctx);
   assert(EVP_PKEY_encapsulate_init(ctx,NULL)>0);assert(EVP_PKEY_encapsulate(ctx,input,&n,expected,&e)>0);
  } else {
   peer=i==2?EVP_PKEY_Q_keygen(NULL,NULL,kind,"prime256v1"):i==3?EVP_PKEY_Q_keygen(NULL,NULL,kind,"secp384r1"):EVP_PKEY_Q_keygen(NULL,NULL,kind);assert(peer);
   unsigned char *cursor=input;int size=i2d_PUBKEY(peer,&cursor);assert(size>0);n=(size_t)size;
   ctx=EVP_PKEY_CTX_new_from_pkey(NULL,peer,NULL);assert(ctx);
   assert(EVP_PKEY_derive_init(ctx)>0);assert(EVP_PKEY_derive_set_peer(ctx,key)>0);assert(EVP_PKEY_derive(ctx,expected,&e)>0);
  }
  assert(recover_secret(key,alg,input,n,actual,&a,"provider=default"));assert(e==a&&!CRYPTO_memcmp(actual,expected,e));
  a=sizeof(actual);assert(!recover_secret(key,alg,input,n-1,actual,&a,"provider=default"));
  assert(matches(key,key));assert(!valid_key(key,i<2?"X25519":"ML-KEM-768"));
  EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(peer);EVP_PKEY_free(key);
  OPENSSL_cleanse(expected,sizeof(expected));OPENSSL_cleanse(actual,sizeof(actual));
 }
 puts("PASS five decryption profiles: shared-secret equality, malformed input rejection, key-type checks");return 0;
}
