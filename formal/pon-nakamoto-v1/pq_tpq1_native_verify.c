/* PQL9: independent native TPQ1 pure ML-DSA-65 verification oracle.
 * Research only / HOLD_NO_GO. Signature-valid != Chain transaction authority,
 * durable replay consumption, model release, VerifiedWork or Hepta FinalUse.
 * cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic pq_tpq1_native_verify.c \
 *    -lcrypto -o pq_tpq1_native_verify
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRAME_SIZE 3487u
#define STMT_SIZE 176u
#define SIG_SIZE 3309u
#define SPKI_SIZE 1974u
#define MAX_PEM 16384u
#define MAX_PAYLOAD (64u * 1024u * 1024u)
static const unsigned char KEY_DOMAIN[]="TRNM/PoN/PQKey/v1";
static const unsigned char AUTH_DOMAIN[]="TRNM/PoN/PQAuth/ML-DSA-65/v1";
/* sizeof the two domain arrays includes their mandatory NUL separators. */
static const unsigned char SPKI_PREFIX[]={
    0x30,0x82,0x07,0xb2,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,
    0x01,0x65,0x03,0x04,0x03,0x12,0x03,0x82,0x07,0xa1,0x00
};
static int reject(const char *why) {fprintf(stderr,"PQL9_REJECT %s\n",why);return 2;}
static int exact(const unsigned char *a,const unsigned char *b,size_t n) {
    return CRYPTO_memcmp(a,b,n)==0;
}
static uint64_t be64(const unsigned char *p) {
    uint64_t value=0;
    for(unsigned i=0;i<8;i++)value=(value<<8)|p[i];
    return value;
}
static void store64(unsigned char *p,uint64_t n) {
    for(int i=7;i>=0;i--){p[i]=(unsigned char)n;n>>=8;}
}
static int parse_u64(const char *text,uint64_t *out) {
    if(!text || !*text || (text[0]=='0' && text[1]))return 0;
    uint64_t n=0;
    for(const unsigned char *p=(const unsigned char*)text;*p;p++) {
        if(*p<'0'||*p>'9')return 0;
        unsigned digit=(unsigned)(*p-'0');
        if(n>(UINT64_MAX-digit)/10u)return 0;
        n=n*10u+digit;
    }
    *out=n;return 1;
}
static int hex32(const char *s,unsigned char out[32]) {
    if(!s || strlen(s)!=64)return 0;
    for(unsigned i=0;i<32;i++){
        int a=s[2*i],b=s[2*i+1];
        a=(a>='0'&&a<='9')?a-'0':((a>='a'&&a<='f')?a-'a'+10:-1);
        b=(b>='0'&&b<='9')?b-'0':((b>='a'&&b<='f')?b-'a'+10:-1);
        if(a<0 || b<0)return 0;
        out[i]=(unsigned char)((a<<4)|b);
    }
    return 1;
}
/* Only opened regular no-symlink, single-link files; size must stay unchanged. */
static int open_input(const char *path,size_t max,size_t *len) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_nlink!=1 || st.st_size<0
       || (uintmax_t)st.st_size>(uintmax_t)max){close(fd);return -1;}
    *len=(size_t)st.st_size;
    return fd;
}
static int read_exact(int fd,unsigned char *buf,size_t len) {
    size_t offset=0;
    while(offset<len){
        ssize_t got=read(fd,buf+offset,len-offset);
        if(got<0 && errno==EINTR)continue;
        if(got<=0)return 0;
        offset+=(size_t)got;
    }
    unsigned char extra;
    return read(fd,&extra,1)==0;
}
static int hash_payload(const char *path,unsigned char out[48]) {
    size_t len=0;int fd=open_input(path,MAX_PAYLOAD,&len);
    if(fd<0)return 0;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    unsigned char length[8],buffer[65536];unsigned actual=0;
    store64(length,(uint64_t)len);
    int ok=ctx!=NULL && EVP_DigestInit_ex(ctx,EVP_sha384(),NULL)==1
         && EVP_DigestUpdate(ctx,AUTH_DOMAIN,sizeof(AUTH_DOMAIN))==1
         && EVP_DigestUpdate(ctx,"payload",8)==1
         && EVP_DigestUpdate(ctx,length,sizeof(length))==1;
    size_t remaining=len;
    while(ok && remaining){
        size_t take=remaining<sizeof(buffer)?remaining:sizeof(buffer);
        ssize_t count=read(fd,buffer,take);
        if(count<0 && errno==EINTR)continue;
        if(count<=0){ok=0;break;}
        ok=EVP_DigestUpdate(ctx,buffer,(size_t)count)==1;
        remaining-=(size_t)count;
    }
    unsigned char extra;
    if(ok && read(fd,&extra,1)!=0)ok=0;
    if(ok)ok=EVP_DigestFinal_ex(ctx,out,&actual)==1 && actual==48;
    EVP_MD_CTX_free(ctx);close(fd);
    return ok;
}
static int load_key(const char *path,EVP_PKEY **key,unsigned char id[32]) {
    size_t len=0;int fd=open_input(path,MAX_PEM,&len);
    if(fd<0 || len==0){if(fd>=0)close(fd);return 0;}
    unsigned char pem[MAX_PEM];
    int ok=read_exact(fd,pem,len);close(fd);
    if(!ok)return 0;
    BIO *bio=BIO_new_mem_buf(pem,(int)len);
    if(!bio)return 0;
    EVP_PKEY *candidate=PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL);
    unsigned char tail[256];int n=0;
    while((n=BIO_read(bio,tail,(int)sizeof(tail)))>0){
        for(int i=0;i<n;i++)if(tail[i]!='\n' && tail[i]!='\r' && tail[i]!=' ' && tail[i]!='\t')ok=0;
    }
    BIO_free(bio);
    if(!candidate || !ok || EVP_PKEY_is_a(candidate,"ML-DSA-65")!=1){
        EVP_PKEY_free(candidate);return 0;
    }
    /* PEM_read_bio_PUBKEY silently skips preambles and ignores trailing DER
     * bytes within base64.  Never derive a trusted key ID by normalizing an
     * ambiguous source: demand one exact canonical OpenSSL SPKI PEM encoding.
     * This is input-format hardening, not authentication of who supplied it. */
    BIO *canonical=BIO_new(BIO_s_mem());
    char *canonical_bytes=NULL;
    long canonical_len=0;
    if(canonical && PEM_write_bio_PUBKEY(canonical,candidate)==1)
        canonical_len=BIO_get_mem_data(canonical,&canonical_bytes);
    ok=canonical_len==(long)len && canonical_bytes!=NULL &&
       exact((const unsigned char *)canonical_bytes,pem,len);
    BIO_free(canonical);
    if(!ok){EVP_PKEY_free(candidate);return 0;}
    int der_len=i2d_PUBKEY(candidate,NULL);
    if(der_len!=(int)SPKI_SIZE){EVP_PKEY_free(candidate);return 0;}
    unsigned char der[SPKI_SIZE],*cursor=der;
    if(i2d_PUBKEY(candidate,&cursor)!=der_len ||
       !exact(der,SPKI_PREFIX,sizeof(SPKI_PREFIX))){
        EVP_PKEY_free(candidate);return 0;
    }
    EVP_MD_CTX *hash=EVP_MD_CTX_new();unsigned actual=0;
    ok=hash!=NULL && EVP_DigestInit_ex(hash,EVP_sha256(),NULL)==1 &&
       EVP_DigestUpdate(hash,KEY_DOMAIN,sizeof(KEY_DOMAIN))==1 &&
       EVP_DigestUpdate(hash,der,sizeof(der))==1 &&
       EVP_DigestFinal_ex(hash,id,&actual)==1 && actual==32;
    EVP_MD_CTX_free(hash);
    if(!ok){EVP_PKEY_free(candidate);return 0;}
    *key=candidate;return 1;
}
int main(int argc,char **argv) {
    if(argc!=12){fprintf(stderr,"PQL9 usage: %s public.pem signed.tpq payload.bin network32 context32 keyid32 purpose generation sequence expiry now\n",argv[0]);return 2;}
    unsigned char net[32],context[32],expected_kid[32],payload_hash[48];
    uint64_t purpose=0,generation=0,sequence=0,expiry=0,now=0;
    if(!hex32(argv[4],net)||!hex32(argv[5],context)||!hex32(argv[6],expected_kid)
       ||!parse_u64(argv[7],&purpose)||purpose<1||purpose>6
       ||!parse_u64(argv[8],&generation)||!generation
       ||!parse_u64(argv[9],&sequence)||!sequence
       ||!parse_u64(argv[10],&expiry)||!expiry
       ||!parse_u64(argv[11],&now)||now>expiry)return reject("caller-owned context");
    size_t len=0;int fd=open_input(argv[2],FRAME_SIZE,&len);
    if(fd<0 || len!=FRAME_SIZE){if(fd>=0)close(fd);return reject("bounded TPQ1 frame");}
    unsigned char frame[FRAME_SIZE];int ok=read_exact(fd,frame,len);close(fd);
    if(!ok || memcmp(frame,"TPQ1",4)!=0 || frame[4]!=1||frame[5]!=0x65
       ||frame[6]!=purpose||frame[7]!=0||frame[176]!=0x0c||frame[177]!=0xed)
        return reject("TPQ1 grammar or signed purpose");
    if(!exact(frame+8,net,32)||!exact(frame+40,context,32)||
       !exact(frame+72,expected_kid,32)||be64(frame+104)!=generation||
       be64(frame+112)!=sequence||be64(frame+120)!=expiry)
        return reject("pinned transaction or release identity");
    if(!hash_payload(argv[3],payload_hash)||!exact(frame+128,payload_hash,48))
        return reject("payload commitment");
    EVP_PKEY *key=NULL;unsigned char actual_kid[32];
    if(!load_key(argv[1],&key,actual_kid))return reject("strict ML-DSA-65 SPKI");
    ok=exact(actual_kid,expected_kid,32);
    EVP_MD_CTX *sig=EVP_MD_CTX_new();
    if(ok && sig)ok=EVP_DigestVerifyInit(sig,NULL,NULL,NULL,key)==1 &&
       EVP_DigestVerify(sig,frame+178,SIG_SIZE,frame,STMT_SIZE)==1;
    else ok=0;
    EVP_MD_CTX_free(sig);EVP_PKEY_free(key);
    if(!ok)return reject("ML-DSA-65 signature or pinned signer");
    /* Valid signature is deliberately NOT a VerifiedTransaction or FinalUse. */
    puts("PQL9_RESEARCH_ONLY_CRYPTO_VALID_NO_AUTHORITY");
    return 0;
}
