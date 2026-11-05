/* PQN4: independent native PCC1/PCQ1/PCR1 + TPQ1 ML-DSA-65 verification.
 * Explicitly RESEARCH ONLY: no Chain/Hepta authority, custody reward or storage proof.
 * Requires caller-controlled, independently authenticated expected root/release/peer IDs.
 * cc -std=c11 -Wall -Wextra -Werror -O2 pq_cell_native_verify.c -lcrypto -o pq_cell_native_verify
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

#define CATALOG_SIZE 157u
#define CHALLENGE_SIZE 217u
#define SIGNED_SIZE 3487u
#define UNSIGNED_SIZE 176u
#define MAX_CHUNK (1u<<20)
#define MAX_CHUNKS 4096u
#define MAX_OBJECT (64u<<20)
#define MAX_RESPONSE (4u+4u+4u+MAX_CHUNK+1u+12u*48u+SIGNED_SIZE)
static const unsigned char domain[]="TRNM/PoN/PQCellCustody/v1";
static const unsigned char auth_domain[]="TRNM/PoN/PQAuth/ML-DSA-65/v1";
static const unsigned char key_domain[]="TRNM/PoN/PQKey/v1";
/* sizeof includes the terminating domain separator NUL. */
struct part { const unsigned char *p; size_t n; };
static int reject(const char *msg) { fprintf(stderr,"PQN4_REJECT:%s\n",msg);return 1; }
static uint64_t be64(const unsigned char *p){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static uint32_t be32(const unsigned char *p){uint32_t v=0;for(int i=0;i<4;i++)v=(v<<8)|p[i];return v;}
static void put32(unsigned char p[4],uint32_t n){for(int i=3;i>=0;i--){p[i]=(unsigned char)n;n>>=8;}}
static void put64(unsigned char p[8],uint64_t n){for(int i=7;i>=0;i--){p[i]=(unsigned char)n;n>>=8;}}
static int nonzero(const unsigned char *p,size_t n){unsigned char v=0;for(size_t i=0;i<n;i++)v|=p[i];return v!=0;}
static int equal(const unsigned char *a,const unsigned char *b,size_t n){return CRYPTO_memcmp(a,b,n)==0;}
static int hash_parts(const EVP_MD *md,const struct part *parts,size_t n,unsigned char *out,size_t expected){
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned actual=0;
    if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,md,NULL)==1;
    for(size_t i=0;i<n && ok;i++)ok=EVP_DigestUpdate(ctx,parts[i].p,parts[i].n)==1;
    if(ok)ok=EVP_DigestFinal_ex(ctx,out,&actual)==1 && actual==expected;
    EVP_MD_CTX_free(ctx);return ok;
}
static int h48(const unsigned char *tag,size_t tn,const struct part *v,size_t n,unsigned char out[48]){
    if(n>8)return 0;
    struct part p[10]={{domain,sizeof(domain)},{tag,tn}};
    for(size_t i=0;i<n;i++)p[i+2]=v[i];
    return hash_parts(EVP_sha384(),p,n+2,out,48);
}
static int sha256_parts(const struct part *p,size_t n,unsigned char out[32]){
    return hash_parts(EVP_sha256(),p,n,out,32);
}
static int read_regular(const char *path,size_t max,unsigned char **out,size_t *len){
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 0;
    struct stat st;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<1 || (uintmax_t)st.st_size>max){close(fd);return 0;}
    size_t n=(size_t)st.st_size;unsigned char *buf=malloc(n+1);
    if(!buf){close(fd);return 0;}
    size_t off=0;
    while(off<n){ssize_t got=read(fd,buf+off,n-off);if(got<=0){free(buf);close(fd);return 0;}off+=(size_t)got;}
    unsigned char extra;int tail=read(fd,&extra,1);close(fd);
    if(tail!=0){free(buf);return 0;}
    buf[n]=0;*out=buf;*len=n;return 1;
}
static int parse_hex(const char *s,unsigned char *out,size_t len){
    if(strlen(s)!=len*2)return 0;
    for(size_t i=0;i<len;i++){
        int a=s[2*i],b=s[2*i+1];
        a=(a>='0'&&a<='9')?a-'0':((a>='a'&&a<='f')?a-'a'+10:-1);
        b=(b>='0'&&b<='9')?b-'0':((b>='a'&&b<='f')?b-'a'+10:-1);
        if(a<0||b<0)return 0;
        out[i]=(unsigned char)((a<<4)|b);
    }
    return 1;
}
static int parse_now(const char *text,uint64_t *out){
    if(!*text||*text<'0'||*text>'9')return 0;
    errno=0;char *end=NULL;unsigned long long v=strtoull(text,&end,10);
    if(errno || !end || *end || end==text)return 0;
    *out=(uint64_t)v;return 1;
}
static int verify_public_key(const unsigned char *pem,size_t n,EVP_PKEY **out,unsigned char key_id[32]){
    BIO *bio=BIO_new_mem_buf(pem,(int)n);if(!bio)return 0;
    EVP_PKEY *key=PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL);
    int valid_tail=1;unsigned char tail[128];int got;
    while((got=BIO_read(bio,tail,sizeof(tail)))>0){
        for(int i=0;i<got;i++)if(tail[i]!=' '&&tail[i]!='\t'&&tail[i]!='\r'&&tail[i]!='\n')valid_tail=0;
    }
    BIO_free(bio);
    if(!key || !valid_tail || EVP_PKEY_is_a(key,"ML-DSA-65")!=1){EVP_PKEY_free(key);return 0;}
    int dn=i2d_PUBKEY(key,NULL);
    if(dn<1||dn>4096){EVP_PKEY_free(key);return 0;}
    unsigned char *der=OPENSSL_malloc((size_t)dn);
    if(!der){EVP_PKEY_free(key);return 0;}
    unsigned char *cursor=der;
    static const unsigned char prefix[]={0x30,0x82,0x07,0xb2,0x30,0x0b,0x06,0x09,
       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12,0x03,0x82,0x07,0xa1,0x00};
    int valid=dn==(int)(sizeof(prefix)+1952u) && i2d_PUBKEY(key,&cursor)==dn
             && equal(der,prefix,sizeof(prefix));
    if(valid){struct part p[]={{key_domain,sizeof(key_domain)},{der,(size_t)dn}};
        valid=sha256_parts(p,2,key_id);}
    OPENSSL_free(der);
    if(!valid){EVP_PKEY_free(key);return 0;}
    *out=key;return 1;
}
static int native_verify(const unsigned char *c,size_t cn,const unsigned char *q,size_t qn,
                         const unsigned char *r,size_t rn,EVP_PKEY *key,
                         const unsigned char kid[32],const unsigned char release[48],
                         const unsigned char catalog_expected[48],const unsigned char requester[32],
                         const unsigned char nonce[32],uint64_t now){
    if(cn!=CATALOG_SIZE||qn!=CHALLENGE_SIZE || rn<4u+4u+4u+1u+SIGNED_SIZE)return 0;
    if(memcmp(c,"PCC1\1",5)||memcmp(q,"PCQ1\1",5)||memcmp(r,"PCR1",4))return 0;
    if(!nonzero(c+5,32)||!nonzero(c+37,48)||!nonzero(c+109,48)
       ||!nonzero(q+85,32)||!nonzero(q+117,32)||!nonzero(q+149,32))return 0;
    if(!equal(c+37,release,48)||!equal(c+5,q+5,32)
       ||!equal(q+117,requester,32)||!equal(q+85,nonce,32)||!equal(q+149,kid,32))return 0;
    uint64_t gen=be64(c+85),total=be64(c+93),qgen=be64(q+181),seq=be64(q+189);
    uint32_t size=be32(c+101),count=be32(c+105),index=be32(q+197);
    uint64_t issue=be64(q+201),expiry=be64(q+209);
    if(gen==0||gen!=qgen||seq==0||count==0||count>MAX_CHUNKS||size==0||size>MAX_CHUNK
      ||total==0||total>MAX_OBJECT||total<=(uint64_t)(count-1)*size
      ||total>(uint64_t)count*size||index>=count
      ||!expiry||expiry<issue||expiry-issue>300||now<issue||now>expiry)return 0;
    unsigned char catalog_id[48];
    struct part cv[]={{c,cn}};
    if(!h48((const unsigned char*)"catalog\0",8,cv,1,catalog_id)
      ||!equal(catalog_id,catalog_expected,48)||!equal(q+37,catalog_id,48))return 0;
    uint32_t read_index=be32(r+4),chunk_len=be32(r+8);
    uint64_t required=(index+1<count)?size:total-(uint64_t)(count-1)*size;
    if(read_index!=index||chunk_len!=required||chunk_len>MAX_CHUNK)return 0;
    size_t off=12u+(size_t)chunk_len;
    if(off>=rn)return 0;
    unsigned levels=0;uint32_t w=count;
    while(w>1){levels++;w=(w+1)/2;}
    if(levels>12||r[off]!=levels)return 0;
    const unsigned char *siblings=r+off+1;size_t frame_at=off+1+(size_t)levels*48;
    if(frame_at+SIGNED_SIZE!=rn)return 0;
    unsigned char num[4],cnt[4],blen[4],leaf[48],step[48],next[48];
    put32(num,index);put32(cnt,count);put32(blen,chunk_len);
    struct part lv[]={{num,4},{cnt,4},{blen,4},{r+12,(size_t)chunk_len}};
    if(!h48((const unsigned char*)"leaf\0",5,lv,4,leaf))return 0;
    memcpy(step,leaf,48);
    uint32_t position=index;
    w=count;
    for(unsigned i=0;i<levels;i++){
        const unsigned char *sib=siblings+48*i;
        if((position^1u)>=w && !equal(sib,step,48))return 0;
        struct part nv[]={{(position&1)?sib:step,48},{(position&1)?step:sib,48}};
        if(!h48((const unsigned char*)"node\0",5,nv,2,next))return 0;
        memcpy(step,next,48);position>>=1;w=(w+1)/2;
    }
    if(!equal(step,c+109,48))return 0;
    const unsigned char *frame=r+frame_at;
    if(memcmp(frame,"TPQ1",4)||frame[4]!=1||frame[5]!=0x65||frame[6]!=5||frame[7]!=0
       ||frame[UNSIGNED_SIZE]!=0x0c||frame[UNSIGNED_SIZE+1]!=0xed)return 0;
    unsigned char challenge_digest[48],context[32],payload_digest[48];
    struct part qv[]={{q,qn}};
    if(!h48((const unsigned char*)"challenge\0",10,qv,1,challenge_digest))return 0;
    struct part context_parts[]={{domain,sizeof(domain)},{(const unsigned char*)"context\0",8},
                                 {catalog_id,48},{q,qn}};
    if(!sha256_parts(context_parts,4,context))return 0;
    unsigned char payload[1024];size_t at=0;
#define APPEND(p,n) do {if((n)>sizeof(payload)-at)return 0;memcpy(payload+at,(p),(n));at+=(n);}while(0)
    APPEND(domain,sizeof(domain));
    APPEND((const unsigned char*)"signed-retrieval\0",17);
    APPEND(catalog_id,48);APPEND(challenge_digest,48);APPEND(leaf,48);
    unsigned char b=(unsigned char)levels;APPEND(&b,1);APPEND(siblings,(size_t)levels*48);
#undef APPEND
    unsigned char plen[8];put64(plen,(uint64_t)at);
    struct part pv[]={{auth_domain,sizeof(auth_domain)},{(const unsigned char*)"payload\0",8},
                      {plen,8},{payload,at}};
    if(!hash_parts(EVP_sha384(),pv,4,payload_digest,48))return 0;
    unsigned char expected[UNSIGNED_SIZE]={0};
    memcpy(expected,"TPQ1",4);expected[4]=1;expected[5]=0x65;expected[6]=5;
    memcpy(expected+8,c+5,32);memcpy(expected+40,context,32);memcpy(expected+72,kid,32);
    memcpy(expected+104,q+181,8);memcpy(expected+112,q+189,8);memcpy(expected+120,q+209,8);
    memcpy(expected+128,payload_digest,48);
    if(!equal(expected,frame,UNSIGNED_SIZE))return 0;
    EVP_MD_CTX *verify=EVP_MD_CTX_new();if(!verify)return 0;
    int ok=EVP_DigestVerifyInit(verify,NULL,NULL,NULL,key)==1 &&
           EVP_DigestVerify(verify,frame+UNSIGNED_SIZE+2,3309,frame,UNSIGNED_SIZE)==1;
    EVP_MD_CTX_free(verify);return ok;
}
int main(int argc,char **argv){
    if(argc!=11)return reject("usage catalog challenge response public.pem expected-release48 expected-catalog48 expected-requester32 expected-nonce32 now");
    unsigned char release[48],catalog[48],requester[32],nonce[32];uint64_t now=0;
    if(!parse_hex(argv[5],release,48)||!parse_hex(argv[6],catalog,48)
      ||!parse_hex(argv[7],requester,32)||!parse_hex(argv[8],nonce,32)||!parse_now(argv[9],&now))
        return reject("caller expected identity/time framing");
    /* argv[10] is independently pinned expected provider key-id, not copied from peer frame. */
    unsigned char expected_kid[32];if(!parse_hex(argv[10],expected_kid,32))return reject("expected provider identity");
    unsigned char *c=NULL,*q=NULL,*r=NULL,*pem=NULL;size_t cn=0,qn=0,rn=0,kn=0;
    EVP_PKEY *key=NULL;unsigned char kid[32];int ok=0;
    if(!read_regular(argv[1],CATALOG_SIZE,&c,&cn) ||
       !read_regular(argv[2],CHALLENGE_SIZE,&q,&qn) ||
       !read_regular(argv[3],MAX_RESPONSE,&r,&rn) ||
       !read_regular(argv[4],8192,&pem,&kn)){
       reject("bounded no-follow regular input");goto done;}
    if(!verify_public_key(pem,kn,&key,kid)||!equal(kid,expected_kid,32)){
       reject("strict authenticated ML-DSA-65 identity");goto done;}
    if(!native_verify(c,cn,q,qn,r,rn,key,kid,release,catalog,requester,nonce,now)){
       reject("canonical context/merkle/real signature");goto done;}
    puts("PQN4_VALID_RESEARCH_OBSERVATION_ONLY");ok=1;
 done:
    EVP_PKEY_free(key);free(c);free(q);free(r);free(pem);
    return ok?0:1;
}
