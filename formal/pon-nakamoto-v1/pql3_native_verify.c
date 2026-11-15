/* PQL3: independent, bounded C11 verifier of PQG1/PQS1/PQL2 projection bytes.
 * RESEARCH / HOLD_NO_GO. No keys, signatures, Chain account import, state mutations,
 * FinalUse, chainwork, or source-authority decisions. Caller-supplied pins MUST be
 * independently authenticated by the old-chain/source and withdrawal owners.
 * Requires OpenSSL 3+ for EVP SHA-256 and SHA-384; no cryptographic bypass.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

#define LIMIT 65536u
#define PIN_BYTES 365u
#define SOURCE_HEADER 177u
#define SOURCE_ACCOUNT 56u
#define LIABILITY 81u
#define TARGET_ACCOUNT 129u
#define MAX_ACCOUNTS 128u
#define MAX_LIABILITIES 256u
#define STATE_HEADER 71u
#define PQL2_HEADER 231u

typedef unsigned char U8;
typedef struct { U8 *p; size_t n; } Bytes;
typedef struct { const U8 *src, *pqs, *pql, *pin; size_t sn,pn,ln; } Input;

static uint64_t get64(const U8 *p) {
    uint64_t x=0; for (size_t i=0;i<8;i++) x=(x<<8)|p[i]; return x;
}
static unsigned get16(const U8 *p) { return ((unsigned)p[0]<<8)|(unsigned)p[1]; }
static void set64(U8 *p,uint64_t n) { for(int i=7;i>=0;i--){p[i]=(U8)n;n>>=8;} }
static int zero(const U8 *p,size_t n) {
    U8 combined=0; for(size_t i=0;i<n;i++)combined|=p[i];return combined==0;
}
static int eq(const U8 *a,const U8 *b,size_t n){return memcmp(a,b,n)==0;}
static int add(U8 *buf,size_t *len,size_t cap,const U8 *p,size_t n){
    if(n>cap-*len)return 0;
    memcpy(buf+*len,p,n);*len+=n;return 1;
}
static int digest_parts(const EVP_MD *algorithm,const U8 *domain,size_t domain_len,
                        const U8 *a,size_t na,const U8 *b,size_t nb,
                        const U8 *c,size_t nc,U8 *out,unsigned expected_len,int frame) {
    U8 length[8]; set64(length,(uint64_t)na);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned actual=0;
    if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,algorithm,NULL)==1
       &&EVP_DigestUpdate(ctx,domain,domain_len)==1
       &&(!frame||EVP_DigestUpdate(ctx,length,sizeof(length))==1)
       &&EVP_DigestUpdate(ctx,a,na)==1
       &&(nb==0||EVP_DigestUpdate(ctx,b,nb)==1)
       &&(nc==0||EVP_DigestUpdate(ctx,c,nc)==1)
       &&EVP_DigestFinal_ex(ctx,out,&actual)==1 && actual==expected_len;
    EVP_MD_CTX_free(ctx);return ok;
}
static int commit_sha384(const U8 *dom,size_t dom_len,const U8 *p,size_t n,U8 out[48]) {
    return digest_parts(EVP_sha384(),dom,dom_len,p,n,NULL,0,NULL,0,out,48,1);
}
static int id_sha256(const U8 *domain,size_t domain_len,
                     const U8 *network,const U8 *oldkey,const U8 *pqkey,
                     int migrated,U8 out[32]){
    return digest_parts(EVP_sha256(),domain,domain_len,network,32,oldkey,32,
                        migrated?pqkey:NULL,migrated?32:0,out,32,0);
}
static int take_file(const char *path,size_t max,Bytes *out){
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 0;
    struct stat st;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<=0||(uint64_t)st.st_size>max){close(fd);return 0;}
    size_t n=(size_t)st.st_size;
    U8 *data=(U8*)malloc(n);
    if(!data){close(fd);return 0;}
    size_t got=0;
    while(got<n){ssize_t k=read(fd,data+got,n-got);if(k<0&&errno==EINTR)continue;
        if(k<=0){free(data);close(fd);return 0;}got+=(size_t)k;}
    U8 extra;
    ssize_t after=read(fd,&extra,1);int close_ok=close(fd)==0;
    if(after!=0||!close_ok){free(data);return 0;}
    out->p=data;out->n=n;return 1;
}
static const U8 SRC_DOMAIN[]="TRNM/PQ/GenesisSource/v1";
static const U8 STATE_DOMAIN[]="TRNM/PQ/GenesisState/v1";
static const U8 GEN_DOMAIN[]="TRNM/PQ/GenesisID/v1";
static const U8 OUT_DOMAIN[]="TRNM/PQ/PQL2State/v1";
static const U8 ACCOUNT_DOMAIN[]="TRNM/PQ/Account/v1";
static const U8 QUARANTINE_DOMAIN[]="TRNM/PQ/Quarantine/v1";

static int verify(const Input *v){
    const U8 *s=v->src,*t=v->pqs,*o=v->pql,*p=v->pin;
    /* PQLP/v1 is an external pin CONTRACT, not an authenticated certificate. */
    if(v->sn<SOURCE_HEADER+SOURCE_ACCOUNT||v->pn<STATE_HEADER+TARGET_ACCOUNT+10
       ||v->ln<PQL2_HEADER+TARGET_ACCOUNT+26||!eq(p,(const U8*)"PQLP\x01",5))return 0;
    if(!eq(s,(const U8*)"PQG1\x01",5)||!eq(t,(const U8*)"PQS1\x01",5)
       ||!eq(o,(const U8*)"PQL2\x01",5))return 0;
    const U8 *src_digest=p+5,*target_root=p+53,*genesis=p+101,*pqlroot=p+149;
    const U8 *oldnet=p+197,*newnet=p+229,*oldhead=p+261,*withdrawal=p+293,*protocol=p+325;
    uint64_t issued=get64(p+357);
    if(zero(oldnet,32)||zero(newnet,32)||eq(oldnet,newnet,32)
       ||zero(oldhead,32)||zero(withdrawal,32)||zero(protocol,32)
       ||zero(src_digest,48)||zero(target_root,48)||zero(genesis,48)||zero(pqlroot,48))return 0;
    if(!eq(s+5,oldnet,32)||!eq(s+37,newnet,32)||!eq(s+69,oldhead,32)
       ||!eq(s+101,withdrawal,32)||!eq(s+133,protocol,32)||get64(s+165)!=issued)return 0;
    unsigned ac=get16(s+173),lc=get16(s+175);
    if(ac<1||ac>MAX_ACCOUNTS||lc>MAX_LIABILITIES
       ||v->sn!=SOURCE_HEADER+(size_t)ac*SOURCE_ACCOUNT+(size_t)lc*LIABILITY)return 0;
    U8 digest[48];
    if(!commit_sha384(SRC_DOMAIN,sizeof(SRC_DOMAIN),s,v->sn,digest)||!eq(digest,src_digest,48))return 0;
    if(!commit_sha384(STATE_DOMAIN,sizeof(STATE_DOMAIN),t,v->pn,digest)||!eq(digest,target_root,48))return 0;
    U8 genesis_statement[160],gid[48];
    memcpy(genesis_statement,newnet,32);memcpy(genesis_statement+32,protocol,32);
    memcpy(genesis_statement+64,src_digest,48);memcpy(genesis_statement+112,target_root,48);
    if(!commit_sha384(GEN_DOMAIN,sizeof(GEN_DOMAIN),genesis_statement,sizeof(genesis_statement),gid)
       ||!eq(gid,genesis,48))return 0;
    if(!eq(t+5,newnet,32)||!eq(t+37,protocol,32)||get16(t+69)!=ac
       ||v->pn!=STATE_HEADER+(size_t)ac*TARGET_ACCOUNT+2+(size_t)lc*LIABILITY+8)return 0;
    if(get16(t+STATE_HEADER+(size_t)ac*TARGET_ACCOUNT)!=lc)return 0;
    const U8 *source_accounts=s+SOURCE_HEADER,*source_liabilities=source_accounts+(size_t)ac*SOURCE_ACCOUNT;
    const U8 *target_accounts=t+STATE_HEADER,*target_liabilities=target_accounts+(size_t)ac*TARGET_ACCOUNT+2;
    if(!eq(target_liabilities,source_liabilities,(size_t)lc*LIABILITY)
       ||get64(target_liabilities+(size_t)lc*LIABILITY)!=issued)return 0;
    uint64_t balance=0,locked=0,quarantined=0;
    for(unsigned i=0;i<ac;i++){
        const U8 *a=source_accounts+(size_t)i*SOURCE_ACCOUNT;
        const U8 *ta=target_accounts+(size_t)i*TARGET_ACCOUNT;
        if(zero(a,32)||(i>0&&memcmp(a,a-SOURCE_ACCOUNT,32)<=0)||get64(a+40)==0||get64(a+48)==0
           ||get64(a+48)==UINT64_MAX||!eq(a,ta+65,SOURCE_ACCOUNT))return 0;
        uint64_t bal=get64(a+32);
        if(bal>issued-balance)return 0;
        balance+=bal;
        unsigned status=ta[0];
        if(status>1||get64(ta+121)!=get64(a+48)+1)return 0;
        if(status==0){
            if(!zero(ta+33,32)||bal>issued-quarantined)return 0;
            quarantined+=bal;
        }else if(zero(ta+33,32))return 0;
        U8 id[32];
        if(!id_sha256(status?ACCOUNT_DOMAIN:QUARANTINE_DOMAIN,
                      status?sizeof(ACCOUNT_DOMAIN):sizeof(QUARANTINE_DOMAIN),
                      newnet,a,ta+33,status,id)||!eq(id,ta+1,32))return 0;
        for(unsigned j=0;j<i;j++){
            const U8 *prior=target_accounts+(size_t)j*TARGET_ACCOUNT;
            if(eq(prior+1,ta+1,32)|| (status==1&&prior[0]==1&&eq(prior+33,ta+33,32)))return 0;
        }
    }
    for(unsigned i=0;i<lc;i++){
        const U8 *l=source_liabilities+(size_t)i*LIABILITY;
        if(zero(l,32)||zero(l+32,32)||(i>0&&memcmp(l,l-LIABILITY,32)<=0)
           ||get64(l+64)==0||l[80]<1||l[80]>4)return 0;
        int owner=0;
        for(unsigned j=0;j<ac;j++){
            if(eq(l+32,source_accounts+(size_t)j*SOURCE_ACCOUNT,32)){owner=1;break;}
        }
        if(!owner)return 0;
        uint64_t amount=get64(l+64);
        if(amount>issued-locked)return 0;
        locked+=amount;
    }
    if(balance!=issued-locked)return 0;
    U8 expected[LIMIT];size_t n=0;
    U8 ac_bytes[2]={(U8)(ac>>8),(U8)ac},lc_bytes[2]={(U8)(lc>>8),(U8)lc};
    U8 quarantine_bytes[8],locked_bytes[8];
    set64(quarantine_bytes,quarantined);set64(locked_bytes,locked);
    if(!add(expected,&n,LIMIT,(const U8*)"PQL2\x01",5)
       ||!add(expected,&n,LIMIT,newnet,32)||!add(expected,&n,LIMIT,protocol,32)
       ||!add(expected,&n,LIMIT,oldhead,32)||!add(expected,&n,LIMIT,withdrawal,32)
       ||!add(expected,&n,LIMIT,src_digest,48)||!add(expected,&n,LIMIT,genesis,48)
       ||!add(expected,&n,LIMIT,ac_bytes,2)
       ||!add(expected,&n,LIMIT,target_accounts,(size_t)ac*TARGET_ACCOUNT)
       ||!add(expected,&n,LIMIT,lc_bytes,2)
       ||!add(expected,&n,LIMIT,source_liabilities,(size_t)lc*LIABILITY)
       ||!add(expected,&n,LIMIT,s+165,8)
       ||!add(expected,&n,LIMIT,quarantine_bytes,8)
       ||!add(expected,&n,LIMIT,locked_bytes,8)
       ||n!=v->ln||!eq(expected,o,n))return 0;
    if(!commit_sha384(OUT_DOMAIN,sizeof(OUT_DOMAIN),o,v->ln,digest)||!eq(digest,pqlroot,48))return 0;
    return 1;
}
int main(int argc,char **argv){
    Bytes files[4]={{0},{0},{0},{0}};
    if(argc!=5)goto reject;
    const size_t cap[4]={LIMIT,LIMIT,LIMIT,PIN_BYTES};
    for(size_t i=0;i<4;i++)if(!take_file(argv[i+1],cap[i],&files[i]))goto reject;
    if(files[3].n!=PIN_BYTES)goto reject;
    Input in={files[0].p,files[1].p,files[2].p,files[3].p,
              files[0].n,files[1].n,files[2].n};
    if(!verify(&in))goto reject;
    for(size_t i=0;i<4;i++)free(files[i].p);
    puts("PQL3_VALID_RESEARCH_OBSERVATION_ONLY");return 0;
reject:
    for(size_t i=0;i<4;i++)free(files[i].p);
    fputs("PQL3_REJECT\n",stderr);return 2;
}
