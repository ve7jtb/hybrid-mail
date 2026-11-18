#ifndef PQ_NATIVE_H
#define PQ_NATIVE_H
#include <stddef.h>
#include <stdint.h>
typedef struct { unsigned char *data; size_t count; } PQBuffer;
void pq_buffer_free(PQBuffer b);
void pq_key_free(void *key);
void *pq_key_generate(const char *algorithm, const char *group);
void *pq_key_read(const unsigned char *der, size_t n, int private_key);
PQBuffer pq_key_export(void *key, int private_key);
PQBuffer pq_digest(const char *name, const unsigned char *p, size_t n);
PQBuffer pq_random(size_t n);
PQBuffer pq_sign(void *key, const char *digest, const unsigned char *context, size_t context_len, const unsigned char *message, size_t n);
int pq_verify(void *key, const char *digest, const unsigned char *context, size_t context_len, const unsigned char *message, size_t n, const unsigned char *sig, size_t sn);
int pq_encapsulate(void *key, PQBuffer *ct, PQBuffer *secret);
PQBuffer pq_decapsulate(void *key, const unsigned char *ct, size_t n);
PQBuffer pq_ecdh(void *key, void *peer);
PQBuffer pq_hkdf(const unsigned char *secret, size_t n, const unsigned char *info, size_t info_n);
/* GCM output is ciphertext || 16-byte tag. Unauthenticated plaintext is never returned. */
PQBuffer pq_gcm(int encrypt, const unsigned char *key, const unsigned char *nonce, const unsigned char *aad, size_t an, const unsigned char *in, size_t n);
PQBuffer pq_wrap(int encrypt, const unsigned char *key, const unsigned char *in, size_t n);
const char *pq_version(void);
PQBuffer pq_key_seed(void *key);
PQBuffer pq_shake256(const unsigned char *in, size_t n, size_t out_n);
PQBuffer pq_p12_pack(const unsigned char *records, size_t n, const char *password);
PQBuffer pq_p12_unpack(const unsigned char *der, size_t n, const char *password);
PQBuffer pq_ec_sign_digest(void *key,const unsigned char *in,size_t n);
int pq_ec_verify_digest(void *key,const unsigned char *in,size_t n,const unsigned char *sig,size_t sn);
PQBuffer pq_hkdf_salt(const unsigned char *ss,size_t n,const unsigned char *salt,size_t salt_n,const unsigned char *info,size_t info_n,size_t out_n);
PQBuffer pq_sign_mu(void *key,const unsigned char *mu,size_t n);
PQBuffer pq_ocb(int encrypt,const unsigned char *key,const unsigned char *nonce,const unsigned char *aad,size_t an,const unsigned char *in,size_t n);
#endif
