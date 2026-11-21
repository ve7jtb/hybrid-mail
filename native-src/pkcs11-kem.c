/* Single-process PKCS#11 public-key check + secret recovery. No persistent session or PIN cache.
 * Usage: helper ALGORITHM pkcs11:serial=...;id=%XX;type= expected.der input.bin
 * PIN is a single stdin line, read only after checking the live public key.
 * OPENSSL_CONF selects the existing OpenSSL provider and Yubico module. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/err.h>

/* Opt-in phase durations only: never PINs, keys, messages, or APDU data. */
static void timing(const char *phase) {
    static double previous;
    if(!getenv("PQMAIL_KEM_TIMINGS"))return;
#ifdef _WIN32
    LARGE_INTEGER counter,frequency;
    if(!QueryPerformanceFrequency(&frequency)||!QueryPerformanceCounter(&counter))return;
    double now=(double)counter.QuadPart/frequency.QuadPart;
#else
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return;
    double now=ts.tv_sec+ts.tv_nsec/1e9;
#endif
    if(previous)fprintf(stderr,"PQMAIL_PHASE %s %.3f ms\n",phase,(now-previous)*1000);
    previous=now;
}
static int use_pin_callback(void) {
    /* Our patched provider otherwise opens its own terminal PIN prompt.
       This is a mode flag only; the PIN remains in this process/anonymous pipe. */
#ifdef _WIN32
    return _putenv_s("HYBRID_MAIL_PIN_STDIN","1")==0;
#else
    return setenv("HYBRID_MAIL_PIN_STDIN","1",1)==0;
#endif
}
struct secret { char pin[10]; int ready; unsigned int callbacks; };
static int pin_reader(UI *ui, UI_STRING *s) {
    struct secret *p = UI_get0_user_data(ui);
    if (!p || !p->ready || UI_get_string_type(s) != UIT_PROMPT) return 0;
    p->callbacks++;
    return UI_set_result(ui, s, p->pin) >= 0 ? 1 : 0;
}
static size_t read_file(const char *name, unsigned char *out, size_t cap) {
    FILE *f=fopen(name,"rb"); if(!f)return 0;
    size_t n=fread(out,1,cap,f); int extra=fgetc(f); int bad=ferror(f); fclose(f);
    return extra==EOF && !bad ? n : 0;
}
static EVP_PKEY *load_key(const char *uri, int type, UI_METHOD *ui, struct secret *pin) {
    OSSL_STORE_CTX *s=OSSL_STORE_open_ex(uri,NULL,"provider=pkcs11",ui,pin,NULL,NULL,NULL);
    EVP_PKEY *key=NULL; if(!s)return NULL;
    if(OSSL_STORE_expect(s,type)!=1)goto done;
    while(!OSSL_STORE_eof(s)) {
        OSSL_STORE_INFO *info=OSSL_STORE_load(s);
        if(!info)break;
        if(OSSL_STORE_INFO_get_type(info)==type) {
            key=type==OSSL_STORE_INFO_PUBKEY?OSSL_STORE_INFO_get1_PUBKEY(info):OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);break;
        }
        OSSL_STORE_INFO_free(info);
    }
 done: OSSL_STORE_close(s);return key;
}
static int matches(EVP_PKEY *token, EVP_PKEY *expected) {
    /* Export only public material, then compare with the default provider.
       This also tolerates equivalent RSA AlgorithmIdentifier encodings. */
    unsigned char *der=NULL;int n=i2d_PUBKEY(token,&der);if(n<=0)return 0;
    const unsigned char *cursor=der;EVP_PKEY *plain=d2i_PUBKEY_ex(NULL,&cursor,n,NULL,"provider=default");
    int ok=plain && EVP_PKEY_eq(plain,expected)==1;EVP_PKEY_free(plain);OPENSSL_free(der);return ok;
}

static int valid_key(EVP_PKEY *key,const char *alg) {
    if(!strncmp(alg,"ML-KEM-",7) || !strcmp(alg,"X25519"))return EVP_PKEY_is_a(key,alg);
    char group[80];size_t n=0;
    return EVP_PKEY_is_a(key,"EC") && EVP_PKEY_get_group_name(key,group,sizeof(group),&n)>0 &&
        !strcmp(group,!strcmp(alg,"ECDH-P256")?"prime256v1":"secp384r1");
}
static int recover_secret(EVP_PKEY *key,const char *alg,const unsigned char *input,size_t inlen,
        unsigned char *secret,size_t *length,const char *provider) {
    EVP_PKEY_CTX *ctx=NULL,*check=NULL;EVP_PKEY *peer=NULL;int ok=0;
    const char *step="key-type";
    if(!valid_key(key,alg))goto done;
    step="context";
    ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,provider);if(!ctx)goto done;
    if(!strncmp(alg,"ML-KEM-",7)) {
        step="ciphertext-length";
        if(inlen!=(!strcmp(alg,"ML-KEM-768")?1088u:1568u))goto done;
        step="decapsulate-init";if(EVP_PKEY_decapsulate_init(ctx,NULL)<=0)goto done;
        step="decapsulate";ok=EVP_PKEY_decapsulate(ctx,secret,length,input,inlen)>0;
    } else {
        const unsigned char *cursor=input;
        step="peer-decode";
        peer=d2i_PUBKEY_ex(NULL,&cursor,inlen,NULL,"provider=default");
        if(!peer || cursor!=input+inlen || !valid_key(peer,alg))goto done;
        step="peer-check";
        check=EVP_PKEY_CTX_new_from_pkey(NULL,peer,"provider=default");
        if(!check || EVP_PKEY_public_check(check)<=0)goto done;
        step="derive-init";if(EVP_PKEY_derive_init(ctx)<=0)goto done;
        step="derive-set-peer";if(EVP_PKEY_derive_set_peer(ctx,peer)<=0)goto done;
        step="derive";ok=EVP_PKEY_derive(ctx,secret,length)>0;
    }
    if(ok)step="secret-length";
    ok=ok && *length==(!strcmp(alg,"ECDH-P384")?48u:32u);
 done:
    /* This fixed label identifies local validation versus the token call even
     * when an EVP/provider failure did not put a reason on the error stack.
     * Do not print peer bytes, derived secret bytes, paths or PKCS#11 URIs. */
    if(!ok && !strcmp(provider,"provider=pkcs11"))fprintf(stderr,"PQMAIL_KEM_STEP %s\n",step);
    EVP_PKEY_CTX_free(check);EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(peer);return ok;
}
int main(int argc,char **argv) {
    timing("start");int rc=1;const char *stage="arguments";struct secret pin={{0},0,0};
    unsigned char der[8192],input[2048],secret[48]={0};size_t n=0,len=sizeof(secret);
    EVP_PKEY *expected=NULL,*pub=NULL,*priv=NULL;UI_METHOD *ui=NULL;
    OSSL_PROVIDER *def=NULL,*p11=NULL;char public_uri[256],private_uri[256];
    if(argc!=5 || strncmp(argv[2],"pkcs11:serial=",14) || strlen(argv[2])>220)goto done;
    const char *alg=argv[1];
    if(strcmp(alg,"ML-KEM-768") && strcmp(alg,"ML-KEM-1024") && strcmp(alg,"ECDH-P256") && strcmp(alg,"ECDH-P384") && strcmp(alg,"X25519"))goto done;
    snprintf(public_uri,sizeof(public_uri),"%spublic",argv[2]);snprintf(private_uri,sizeof(private_uri),"%sprivate",argv[2]);
    stage="input";n=read_file(argv[3],der,sizeof(der));size_t inlen=read_file(argv[4],input,sizeof(input));if(!n||!inlen)goto done;
    if(!strncmp(alg,"ML-KEM-",7) && inlen!=(!strcmp(alg,"ML-KEM-768")?1088u:1568u))goto done;
    timing("input");stage="PIN callback setup";if(!use_pin_callback())goto done;
    stage="providers";def=OSSL_PROVIDER_load(NULL,"default");p11=OSSL_PROVIDER_load(NULL,"pkcs11");if(!def||!p11)goto done;
    timing("provider-load");const unsigned char *cursor=der;
    expected=d2i_PUBKEY_ex(NULL,&cursor,n,NULL,"provider=default");
    if(!expected||cursor!=der+n||!valid_key(expected,alg))goto done;
    ui=UI_create_method("PQ Mail private PIN pipe");if(!ui||UI_method_set_reader(ui,pin_reader)!=0)goto done;
    timing("expected-key-decode");stage="public key check";
    pub=load_key(public_uri,OSSL_STORE_INFO_PUBKEY,ui,&pin);if(!pub||!matches(pub,expected))goto done;
    timing("public-key-check");stage="PIN input";if(!fgets(pin.pin,sizeof(pin.pin),stdin))goto done;
    n=strlen(pin.pin);if(n<7||n>9||pin.pin[n-1]!='\n')goto done;pin.pin[--n]=0;
    for(size_t i=0;i<n;i++)if((unsigned char)pin.pin[i]<32||(unsigned char)pin.pin[i]>126)goto done;
    pin.ready=1;timing("pin-input");stage="private key check";
    priv=load_key(private_uri,OSSL_STORE_INFO_PKEY,ui,&pin);if(!priv||!matches(priv,expected))goto done;
    timing("private-key-check");stage="recover";
    if(!recover_secret(priv,alg,input,inlen,secret,&len,"provider=pkcs11"))goto done;
    timing("recover");stage="output";
#ifdef _WIN32
    if(_setmode(_fileno(stdout),_O_BINARY)==-1)goto done;
#endif
    if(fwrite(secret,1,len,stdout)!=len || fflush(stdout))goto done;
    timing("output");rc=0;
 done:
    if(rc){
        fprintf(stderr,"PQ Mail single-session decryption failed at %s; no retry\n",stage);
        /* Keep diagnostics useful without dumping OpenSSL's error-data fields:
         * those can contain paths, identifiers, or application input. Only
         * numeric codes and library-owned reason strings leave this process.
         * The adapter applies a second bounded allowlist before showing them. */
        unsigned long error;unsigned count=0;
        while((error=ERR_get_error()) && count++<8){
            const char *reason=ERR_reason_error_string(error);
            fprintf(stderr,"PQMAIL_ERROR %08lX %s\n",error,reason?reason:"unknown");
        }
        fprintf(stderr,"PQMAIL_PIN_CALLBACKS %u\n",pin.callbacks);
    }
    if(getenv("PQMAIL_KEM_TIMINGS"))fprintf(stderr,"PQMAIL_PIN_CALLBACKS %u\n",pin.callbacks);
    OPENSSL_cleanse(&pin,sizeof(pin));OPENSSL_cleanse(secret,sizeof(secret));
    EVP_PKEY_free(pub);EVP_PKEY_free(priv);EVP_PKEY_free(expected);UI_destroy_method(ui);
    OSSL_PROVIDER_unload(p11);OSSL_PROVIDER_unload(def);OPENSSL_cleanup();timing("cleanup");return rc;
}
