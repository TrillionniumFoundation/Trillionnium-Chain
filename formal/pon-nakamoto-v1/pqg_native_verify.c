/* PQN2: offline read-only native verifier for one PQG1 dual-possession claim.
 * Research only. No ledger import, authority, FinalUse or consensus activation.
 * Compile: cc -std=c11 -Wall -Wextra -Werror -O2 pqg_native_verify.c -lcrypto -o pqg_native_verify
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SNAPSHOT 65536u
#define MAX_PEM 8192u
#define ANCHOR_SIZE 292u
#define PROOF_SIZE (4u + 32u + 32u + 8u + 64u + 3309u)
static const unsigned char src_domain[] = "TRNM/PQ/GenesisSource/v1";
static const unsigned char mig_domain[] = "TRNM/PQ/GenesisMigration/v1";
static const unsigned char key_domain[] = "TRNM/PoN/PQKey/v1";
/* domain constants include their terminal NUL in the framing */
static int failed(const char *error) { fprintf(stderr, "PQN2_REJECT:%s\n", error); return 1; }
static uint64_t read64(const unsigned char *p) {
    uint64_t v=0; for (int i=0;i<8;i++) v=(v<<8)|p[i]; return v;
}
static unsigned read16(const unsigned char *p) { return (unsigned)p[0]*256u+(unsigned)p[1]; }
static void put64(unsigned char *out,uint64_t v) {
    for(int i=7;i>=0;i--){out[i]=(unsigned char)v;v>>=8;}
}
static int regular_bytes(const char *name,size_t limit,unsigned char **out,size_t *n) {
    int fd=open(name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return 0;
    struct stat st;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<1 || (uintmax_t)st.st_size>limit){close(fd);return 0;}
    size_t size=(size_t)st.st_size;
    unsigned char *buf=malloc(size+1);
    if(!buf){close(fd);return 0;}
    size_t pos=0;
    while(pos<size){ssize_t got=read(fd,buf+pos,size-pos); if(got<=0){free(buf);close(fd);return 0;}pos+=(size_t)got;}
    unsigned char extra;
    if(read(fd,&extra,1)!=0){free(buf);close(fd);return 0;}
    close(fd);buf[size]=0;*out=buf;*n=size;return 1;
}
static int hash384_frame(const unsigned char *domain,size_t domain_size,
                          const unsigned char *data,size_t len,unsigned char out[48]) {
    unsigned char be_len[8];put64(be_len,(uint64_t)len);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned outlen=0;
    if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha384(),NULL)==1
      && EVP_DigestUpdate(ctx,domain,domain_size)==1
      && EVP_DigestUpdate(ctx,be_len,8)==1
      && EVP_DigestUpdate(ctx,data,len)==1
      && EVP_DigestFinal_ex(ctx,out,&outlen)==1 && outlen==48;
    EVP_MD_CTX_free(ctx);return ok;
}
static int hash_key_id(const unsigned char *pem,size_t pemlen,EVP_PKEY **key,unsigned char out[32]) {
    BIO *b=BIO_new_mem_buf(pem,(int)pemlen);
    if(!b)return 0;
    EVP_PKEY *p=PEM_read_bio_PUBKEY(b,NULL,NULL,NULL);
    int trailing_ok=1;unsigned char tail[128];int count;
    while((count=BIO_read(b,tail,sizeof(tail)))>0){
        for(int i=0;i<count;i++) if(tail[i]!=' '&&tail[i]!='\n'&&tail[i]!='\r'&&tail[i]!='\t')trailing_ok=0;
    }
    BIO_free(b);
    if(!p||!trailing_ok){EVP_PKEY_free(p);return 0;}
    if(EVP_PKEY_is_a(p,"ML-DSA-65")!=1){EVP_PKEY_free(p);return 0;}
    int n=i2d_PUBKEY(p,NULL);
    if(n<=0||n>4096){EVP_PKEY_free(p);return 0;}
    unsigned char *der=OPENSSL_malloc((size_t)n);
    if(!der){EVP_PKEY_free(p);return 0;}
    unsigned char *dest=der;
    int ok=(i2d_PUBKEY(p,&dest)==n);
    /* Exact canonical SubjectPublicKeyInfo: SEQ(SEQ(ML-DSA-65 OID),BIT STRING) */
    static const unsigned char prefix[]={0x30,0x82,0x07,0xb2,0x30,0x0b,0x06,0x09,
       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12,0x03,0x82,0x07,0xa1,0x00};
    if(n!=((int)sizeof(prefix)+1952)||memcmp(der,prefix,sizeof(prefix))!=0)ok=0;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned olen=0;
    if(!ctx)ok=0;
    if(ok) ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1
      && EVP_DigestUpdate(ctx,key_domain,sizeof(key_domain))==1
      && EVP_DigestUpdate(ctx,der,(size_t)n)==1
      && EVP_DigestFinal_ex(ctx,out,&olen)==1 && olen==32;
    EVP_MD_CTX_free(ctx);OPENSSL_free(der);
    if(!ok){EVP_PKEY_free(p);return 0;}
    *key=p;return 1;
}
static int verify_raw(EVP_PKEY *key,const unsigned char *message,size_t msglen,
                      const unsigned char *sig,size_t siglen) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return 0;
    int ok=EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1
        && EVP_DigestVerify(ctx,sig,siglen,message,msglen)==1;
    EVP_MD_CTX_free(ctx);return ok;
}

/* RFC 8032 strict public point/R validation. This is public-input finite-field
 * arithmetic only. Reject noncanonical y, negative zero, nonpoints and 8-torsion.
 * The private signing operation remains entirely within the OpenSSL provider. */
static int strict_ed_point(const unsigned char point[32]) {
    unsigned char encoded[32];memcpy(encoded,point,32);
    int sign=(encoded[31]>>7)&1;encoded[31]&=127;
    BN_CTX *ctx=BN_CTX_new();if(!ctx)return 0;
    BN_CTX_start(ctx);
    BIGNUM *p=BN_CTX_get(ctx),*y=BN_CTX_get(ctx),*x=BN_CTX_get(ctx),
      *d=BN_CTX_get(ctx),*inverse=BN_CTX_get(ctx),*u=BN_CTX_get(ctx),
      *v=BN_CTX_get(ctx),*x2=BN_CTX_get(ctx),*zero=BN_CTX_get(ctx),
      *X=BN_CTX_get(ctx),*Y=BN_CTX_get(ctx),*Z=BN_CTX_get(ctx),
      *A=BN_CTX_get(ctx),*B=BN_CTX_get(ctx),*C=BN_CTX_get(ctx),
      *D=BN_CTX_get(ctx),*E=BN_CTX_get(ctx),*F=BN_CTX_get(ctx),
      *G=BN_CTX_get(ctx),*H=BN_CTX_get(ctx),*tmp=BN_CTX_get(ctx);
    int ok=(tmp!=NULL);
#define MUST(expr) do{if(ok && !(expr))ok=0;}while(0)
    if(ok){BN_zero(zero);BN_one(p);MUST(BN_lshift(p,p,255));MUST(BN_sub_word(p,19));
        MUST(BN_lebin2bn(encoded,32,y)!=NULL);if(BN_cmp(y,p)>=0)ok=0;}
    if(ok){
        MUST(BN_set_word(d,121666));
        MUST(BN_mod_inverse(inverse,d,p,ctx)!=NULL);
        MUST(BN_set_word(d,121665));
        MUST(BN_mod_mul(d,d,inverse,p,ctx));
        MUST(BN_mod_sub(d,zero,d,p,ctx));
        MUST(BN_mod_sqr(tmp,y,p,ctx));
        MUST(BN_mod_sub(u,tmp,BN_value_one(),p,ctx));
        MUST(BN_mod_mul(v,d,tmp,p,ctx));
        MUST(BN_mod_add(v,v,BN_value_one(),p,ctx));
        MUST(BN_mod_inverse(inverse,v,p,ctx)!=NULL);
        MUST(BN_mod_mul(x2,u,inverse,p,ctx));
        MUST(BN_mod_sqrt(x,x2,p,ctx)!=NULL);
        if(BN_is_zero(x)&&sign)ok=0;
        if(ok && BN_is_odd(x)!=sign)MUST(BN_sub(x,p,x));
    }
    if(ok){
        MUST(BN_copy(X,x)!=NULL);MUST(BN_copy(Y,y)!=NULL);BN_one(Z);
        for(int i=0;i<3&&ok;i++){
            MUST(BN_mod_sqr(A,X,p,ctx));MUST(BN_mod_sqr(B,Y,p,ctx));
            MUST(BN_mod_sqr(C,Z,p,ctx));MUST(BN_mod_add(C,C,C,p,ctx));
            MUST(BN_mod_sub(D,zero,A,p,ctx));
            MUST(BN_mod_add(tmp,X,Y,p,ctx));MUST(BN_mod_sqr(E,tmp,p,ctx));
            MUST(BN_mod_sub(E,E,A,p,ctx));MUST(BN_mod_sub(E,E,B,p,ctx));
            MUST(BN_mod_add(G,D,B,p,ctx));MUST(BN_mod_sub(F,G,C,p,ctx));
            MUST(BN_mod_sub(H,D,B,p,ctx));
            MUST(BN_mod_mul(X,E,F,p,ctx));MUST(BN_mod_mul(Y,G,H,p,ctx));
            MUST(BN_mod_mul(Z,F,G,p,ctx));
        }
        if(ok && BN_is_zero(X)&&BN_cmp(Y,Z)==0)ok=0;
    }
#undef MUST
    BN_CTX_end(ctx);BN_CTX_free(ctx);return ok;
}
static int strict_ed_scalar(const unsigned char scalar[32]) {
    static const unsigned char l[32]={
      0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10};
    for(int i=31;i>=0;i--){if(scalar[i]<l[i])return 1;if(scalar[i]>l[i])return 0;}
    return 0;
}

static int is_zero(const unsigned char *p,size_t n){unsigned char v=0;for(size_t i=0;i<n;i++)v|=p[i];return v==0;}
static int verify_source(const unsigned char *s,size_t len,const unsigned char *a,
                         const unsigned char *proof,const unsigned char **account) {
    if(len<233 || len>MAX_SNAPSHOT || memcmp(s,"PQG1\1",5)!=0)return 0;
    if(memcmp(a,"PQA1",4)!=0 || memcmp(proof,"PQM1",4)!=0)return 0;
    if(is_zero(s+5,32)||is_zero(s+37,32)||memcmp(s+5,s+37,32)==0||
       is_zero(s+69,32)||is_zero(s+101,32)||is_zero(s+133,32))return 0;
    if(memcmp(s+5,a+52,32)||memcmp(s+37,a+84,32)||memcmp(s+69,a+116,32)||
       memcmp(s+101,a+148,32)||memcmp(s+133,a+180,32))return 0;
    unsigned ac=read16(s+173),lc=read16(s+175);
    if(ac<1||ac>128||lc>256||len!=177u+(size_t)ac*56u+(size_t)lc*81u)return 0;
    if(memcmp(a+220,proof+4,32)||memcmp(a+252,proof+36,32)||is_zero(proof+4,32)
        ||is_zero(proof+36,32))return 0;
    uint64_t total=0,issued=read64(s+165);*account=NULL;
    for(unsigned i=0;i<ac;i++){
        const unsigned char *e=s+177u+(size_t)i*56u;
        if(is_zero(e,32)||read64(e+40)==0||read64(e+48)==0||read64(e+48)==UINT64_MAX)return 0;
        if(i && memcmp(e-56,e,32)>=0)return 0;
        uint64_t value=read64(e+32);if(total>UINT64_MAX-value)return 0;total+=value;
        if(memcmp(e,proof+4,32)==0)*account=e;
    }
    for(unsigned i=0;i<lc;i++){
        const unsigned char *e=s+177u+(size_t)ac*56u+(size_t)i*81u;
        if(is_zero(e,32)||is_zero(e+32,32)||!read64(e+64)||e[80]<1||e[80]>4)return 0;
        if(i && memcmp(e-81,e,32)>=0)return 0;
        int found=0;
        for(unsigned j=0;j<ac;j++)if(!memcmp(e+32,s+177u+(size_t)j*56u,32)){found=1;break;}
        if(!found)return 0;
        uint64_t value=read64(e+64);if(total>UINT64_MAX-value)return 0;total+=value;
    }
    return total==issued && issued==read64(a+212) && *account!=NULL;
}
int main(int argc,char **argv){
    if(argc!=5)return failed("usage: snapshot anchor one-migration pq-public-pem");
    unsigned char *s=NULL,*a=NULL,*proof=NULL,*pem=NULL,*msg=NULL;
    size_t sn=0,an=0,pn=0,kn=0;EVP_PKEY *pq=NULL,*ed=NULL;int code=1;
    if(!regular_bytes(argv[1],MAX_SNAPSHOT,&s,&sn)||
       !regular_bytes(argv[2],ANCHOR_SIZE,&a,&an)||
       !regular_bytes(argv[3],PROOF_SIZE,&proof,&pn)||
       !regular_bytes(argv[4],MAX_PEM,&pem,&kn)||an!=ANCHOR_SIZE||pn!=PROOF_SIZE){
        failed("bounded regular file / wire length");goto done;}
    unsigned char digest[48],kid[32];
    if(!hash384_frame(src_domain,sizeof(src_domain),s,sn,digest)||
       CRYPTO_memcmp(digest,a+4,48)!=0){failed("externally pinned source mismatch");goto done;}
    const unsigned char *account=NULL;
    if(!verify_source(s,sn,a,proof,&account)){failed("source bounds/supply/context/account");goto done;}
    if(!hash_key_id(pem,kn,&pq,kid)||CRYPTO_memcmp(kid,proof+36,32)!=0){
        failed("strict ML-DSA-65 public key identity");goto done;}
    uint64_t expiry=read64(proof+68),now=read64(a+284);
    if(!expiry||now>expiry){failed("expired proof");goto done;}
    /* Sign exactly the Python PQG1 MigrationStatement; no arbitrary bytes or caller-selected domains. */
    size_t ml=sizeof(mig_domain)+48+5u*32u+56+32+8+8;
    msg=malloc(ml);if(!msg){failed("allocation");goto done;}
    size_t at=0;
#define ADD(ptr,n) do{memcpy(msg+at,(ptr),(n));at+=(n);}while(0)
    ADD(mig_domain,sizeof(mig_domain));ADD(digest,48);
    ADD(s+5,160);ADD(account,56);ADD(kid,32);
    unsigned char n64[8];put64(n64,read64(account+48)+1);ADD(n64,8);
    ADD(proof+68,8);
#undef ADD
    if(at!=ml){failed("statement length");goto done;}
    if(!strict_ed_point(proof+4)||!strict_ed_point(proof+76)||
       !strict_ed_scalar(proof+108)){
        failed("strict Ed25519 point/R/scalar rejected");goto done;
    }
    ed=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,proof+4,32);
    if(!ed||!verify_raw(ed,msg,ml,proof+76,64)){
        failed("invalid Ed25519 old-key possession");goto done;}
    if(!verify_raw(pq,msg,ml,proof+140,3309)){
        failed("invalid ML-DSA-65 new-key possession");goto done;}
    puts("PQN2_VALID_RESEARCH_OBSERVATION_ONLY");code=0;
 done:
    EVP_PKEY_free(ed);EVP_PKEY_free(pq);
    if(msg){OPENSSL_cleanse(msg,sizeof(mig_domain)+48+160+56+32+16);free(msg);}
    free(s);free(a);free(proof);free(pem);
    return code;
}
