/*
 * Native, read-only QTX1/TPQ1 ML-DSA-65 conformance verifier (PQN1).
 * OFFLINE RESEARCH ONLY. No transaction acceptance, chain authority, account state,
 * final use, or network service is created by a successful verification.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror pq_qtx1_verify.c -lcrypto -o pq_qtx1_verify
 */
#define _POSIX_C_SOURCE 200809L
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

#define MAX_TX 8192U
#define MAX_PEM 16384U
#define TPQ_UNSIGNED 176U
#define TPQ_SIGNATURE 3309U
#define TPQ_FRAME (TPQ_UNSIGNED + 2U + TPQ_SIGNATURE)
#define QTX_HEAD 144U
#define MAX_MEMO 512U
#define MLDSA_PUB_BYTES 1952U

static const unsigned char CONTEXT_DOM[] = "TRNM/PoN/QTX1Context/v1";
static const unsigned char KEY_DOM[] = "TRNM/PoN/PQKey/v1";
static const unsigned char PAYLOAD_DOM[] = "TRNM/PoN/PQAuth/ML-DSA-65/v1";
static const unsigned char ID_DOM[] = "TRNM/PoN/QTX1Identity/v1";
static const unsigned char OID_MLDSA65[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};

static int fail(const char *s) {fprintf(stderr,"PQN1_REJECT %s\n",s);return 2;}
static uint64_t be64(const unsigned char *p) {
    uint64_t v=0;for(size_t i=0;i<8;i++)v=(v<<8)|p[i];return v;
}
static void put_be64(unsigned char p[8],uint64_t x){for(int i=7;i>=0;i--){p[i]=(unsigned char)x;x>>=8;}}
static void put_be32(unsigned char p[4],uint32_t x){for(int i=3;i>=0;i--){p[i]=(unsigned char)x;x>>=8;}}
static int parse_u64(const char *s, uint64_t *result){
    if (!s||!*s) return 0;
    if(s[0]=='0'&&s[1])return 0;
    uint64_t v=0;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++) {
        if(*p<'0'||*p>'9')return 0;
        unsigned d=*p-'0';if(v>(UINT64_MAX-d)/10)return 0;v=v*10+d;
    }
    *result=v;return 1;
}
static int hex32(const char *s,unsigned char out[32]) {
    if(!s||strlen(s)!=64)return 0;
    for(size_t i=0;i<32;i++){
        unsigned char a=(unsigned char)s[i*2],b=(unsigned char)s[i*2+1];
        if(!((a>='0'&&a<='9')||(a>='a'&&a<='f'))||
           !((b>='0'&&b<='9')||(b>='a'&&b<='f')))return 0;
        a=(unsigned char)(a<='9'?a-'0':a-'a'+10);
        b=(unsigned char)(b<='9'?b-'0':b-'a'+10);
        out[i]=(unsigned char)((a<<4)|b);
    }return 1;
}
static int any_nonzero(const unsigned char *p,size_t n){
    unsigned char v=0;for(size_t i=0;i<n;i++)v|=p[i];return v!=0;
}
static int read_file(const char *path, unsigned char *out, size_t max, size_t *size) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0)return 0;
    struct stat st;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<=0||(uintmax_t)st.st_size>max){close(fd);return 0;}
    size_t required=(size_t)st.st_size,total=0;
    while(total<required){ssize_t n=read(fd,out+total,required-total);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){close(fd);return 0;}
        total+=(size_t)n;
    }
    unsigned char extra;ssize_t r=read(fd,&extra,1);close(fd);
    if(r!=0)return 0;
    *size=total;return 1;
}
static int digest_segments(const EVP_MD *md,const unsigned char *const *parts,
                           const size_t *lens,size_t n,unsigned char *out,unsigned want) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned size=0;int ok=ctx!=NULL;
    if(ok)ok=EVP_DigestInit_ex(ctx,md,NULL)==1;
    for(size_t i=0;ok&&i<n;i++)ok=EVP_DigestUpdate(ctx,parts[i],lens[i])==1;
    if(ok)ok=EVP_DigestFinal_ex(ctx,out,&size)==1&&size==want;
    EVP_MD_CTX_free(ctx);return ok;
}
static int sha256(const unsigned char *const *p,const size_t *l,size_t n,unsigned char out[32]) {
    return digest_segments(EVP_sha256(),p,l,n,out,32);
}
static int sha384(const unsigned char *const *p,const size_t *l,size_t n,unsigned char out[48]) {
    return digest_segments(EVP_sha384(),p,l,n,out,48);
}
static int asn_len(const unsigned char *p,size_t n,size_t *pos,size_t *value) {
    if(*pos>=n)return 0;
    unsigned char c=p[(*pos)++];if(c<128){*value=c;return 1;}
    size_t k=c&127;if(k==0||k>4||n-*pos<k||p[*pos]==0)return 0;
    size_t v=0;for(size_t i=0;i<k;i++)v=(v<<8)|p[(*pos)++];
    if(v<128||v>n-*pos)return 0;
    *value=v;
    return 1;
}
static int exact_mldsa_spki(const unsigned char *p,size_t n) {
    size_t at=0,outer=0,alg=0,bits=0;
    if(at>=n||p[at++]!=0x30||!asn_len(p,n,&at,&outer)||outer!=n-at)return 0;
    if(at>=n||p[at++]!=0x30||!asn_len(p,n,&at,&alg)||alg!=sizeof(OID_MLDSA65)||
       alg>n-at||memcmp(p+at,OID_MLDSA65,alg))return 0;
    at+=alg;
    if(at>=n||p[at++]!=0x03||!asn_len(p,n,&at,&bits)||bits!=MLDSA_PUB_BYTES+1||
       bits!=n-at||p[at]!=0)return 0;
    return 1;
}
int main(int argc, char **argv) {
    if(argc!=13){fprintf(stderr,"PQN1 usage: %s public.pem signed.qtx network_hex sender_hex signer_id_hex generation nonce now balance base_fee byte_fee active(1)\n",argv[0]);return 2;}
    uint64_t generation,nonce,now,balance,base_fee,byte_fee,active;
    if(!parse_u64(argv[6],&generation)||!parse_u64(argv[7],&nonce)||
       !parse_u64(argv[8],&now)||!parse_u64(argv[9],&balance)||
       !parse_u64(argv[10],&base_fee)||!parse_u64(argv[11],&byte_fee)||
       !parse_u64(argv[12],&active)||active!=1||generation==0||nonce==0)return fail("caller state/time/number");
    unsigned char expected_net[32],expected_sender[32],expected_key[32];
    if(!hex32(argv[3],expected_net)||!hex32(argv[4],expected_sender)||
       !hex32(argv[5],expected_key))return fail("noncanonical pinned identity");
    unsigned char raw[MAX_TX],pem[MAX_PEM];size_t raw_len=0,pem_len=0;
    if(!read_file(argv[2],raw,sizeof(raw),&raw_len)||
       !read_file(argv[1],pem,sizeof(pem),&pem_len))return fail("bounded regular file required");
    if(raw_len<QTX_HEAD+TPQ_FRAME)return fail("QTX1 short");
    const unsigned char *body=raw,*frame=NULL;
    if(memcmp(body,"QTX1",4)||body[4]!=1||body[5]!=1)return fail("QTX1 version/type");
    size_t memo=((size_t)body[142]<<8)|body[143];
    if(memo>MAX_MEMO||QTX_HEAD+memo+TPQ_FRAME!=raw_len)return fail("QTX1 size/framing");
    size_t body_len=QTX_HEAD+memo;frame=raw+body_len;
    const unsigned char *net=body+6,*sender=body+38,*recipient=body+70;
    uint64_t gen=be64(body+102),tx_nonce=be64(body+110),expiry=be64(body+118),
             amount=be64(body+126),max_fee=be64(body+134);
    if(!any_nonzero(sender,32)||!any_nonzero(recipient,32)||
       memcmp(sender,recipient,32)==0||gen==0||tx_nonce==0||expiry==0||amount==0)return fail("QTX1 invalid values");
    if(memcmp(net,expected_net,32)||memcmp(sender,expected_sender,32)||
       gen!=generation||tx_nonce!=nonce||now>expiry)return fail("caller expected current context");
    if(memcmp(frame,"TPQ1",4)||frame[4]!=1||frame[5]!=0x65||frame[6]!=1||frame[7]!=0)return fail("TPQ1 version/algorithm/purpose");
    if(memcmp(frame+8,net,32)||be64(frame+104)!=gen||be64(frame+112)!=tx_nonce||
       be64(frame+120)!=expiry)return fail("TPQ1 transaction binding");
    if(frame[176]!=0x0c||frame[177]!=0xed)return fail("TPQ1 signature length");
    unsigned char context[32];const unsigned char *const cp[]={CONTEXT_DOM,net,sender};
    const size_t cl[]={sizeof(CONTEXT_DOM),32,32};
    if(!sha256(cp,cl,3,context)||memcmp(frame+40,context,32))return fail("TPQ1 context digest");
    unsigned char size8[8],payload_hash[48];put_be64(size8,body_len);
    const unsigned char *const dp[]={PAYLOAD_DOM,(const unsigned char*)"payload",size8,body};
    const size_t dl[]={sizeof(PAYLOAD_DOM),8,8,body_len};
    if(!sha384(dp,dl,4,payload_hash)||memcmp(frame+128,payload_hash,48))return fail("TPQ1 payload digest");
    /* Offline only: loaded PEM is not treated as trusted without the caller's exact key ID. */
    /* Cheap fee and account preflight MUST run before public-key decoding or ML-DSA verification. */
    if(byte_fee>0&&raw_len>(UINT64_MAX-base_fee)/byte_fee)return fail("fee overflow");
    uint64_t fee=base_fee+byte_fee*(uint64_t)raw_len;
    if(fee>max_fee||amount>UINT64_MAX-fee||balance<fee+amount)return fail("fee/balance");
    BIO *bio=BIO_new_mem_buf(pem,(int)pem_len);
    EVP_PKEY *key=bio?PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL):NULL;
    BIO_free(bio);
    if(!key)return fail("public PEM parse");
    int ok=EVP_PKEY_is_a(key,"ML-DSA-65");
    unsigned char *der=NULL;int dlen=ok?i2d_PUBKEY(key,&der):0;
    if(dlen<=0||!exact_mldsa_spki(der,(size_t)(dlen>0?dlen:0)))ok=0;
    unsigned char id[32];const unsigned char *const kp[]={KEY_DOM,der};
    const size_t kl[]={sizeof(KEY_DOM),(size_t)(dlen>0?dlen:0)};
    if(ok)ok=sha256(kp,kl,2,id)&&memcmp(id,expected_key,32)==0&&memcmp(id,frame+72,32)==0;
    OPENSSL_free(der);
    if(!ok){EVP_PKEY_free(key);return fail("untrusted signer key/algorithm");}
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();ok=ctx!=NULL;
    if(ok)ok=EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1;
    if(ok)ok=EVP_DigestVerify(ctx,frame+178,TPQ_SIGNATURE,frame,TPQ_UNSIGNED)==1;
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);
    if(!ok)return fail("ML-DSA-65 signature");
    unsigned char size4[4],txid[48];put_be32(size4,(uint32_t)body_len);
    const unsigned char *const ip[]={ID_DOM,size4,body,id};
    const size_t il[]={sizeof(ID_DOM),4,body_len,32};
    if(!sha384(ip,il,4,txid))return fail("identity digest");
    /* A result cannot be converted to Chain admission or user permission. */
    printf("PQN1_RESEARCH_ONLY_SIGNATURE_VALID identity=");
    for(size_t i=0;i<48;i++)printf("%02x",txid[i]);
    printf(" fee=%" PRIu64 " remaining=%" PRIu64 " bytes=%zu\n",fee,balance-fee-amount,raw_len);
    return 0;
}
