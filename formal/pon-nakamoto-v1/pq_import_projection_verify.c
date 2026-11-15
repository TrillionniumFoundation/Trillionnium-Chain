/* PQN5 — exact PQG1 -> PQS1 whole-roster projection; research-only.
 * No signer/proof/Chain import, checkpoint, account or Final-use authority.
 * Caller pins PQA3 separately. Self-signed/self-supplied anchors are NOT trust.
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

#define SOURCE_LIMIT 65536u
#define TARGET_LIMIT 65536u
#define ANCHOR_LEN 317u
#define SOURCE_HEAD 177u
#define PQS_HEAD 71u
#define ACCOUNT_LEN 56u
#define PROJECTED_ACCOUNT_LEN 129u
#define LIABILITY_LEN 81u
#define MAX_ACCOUNTS 128u
#define MAX_LIABILITIES 256u
#define U64_MAX_VALUE UINT64_MAX

static const unsigned char SOURCE_DOMAIN[] = "TRNM/PQ/GenesisSource/v1\0";
static const unsigned char STATE_DOMAIN[] = "TRNM/PQ/GenesisState/v1\0";
static const unsigned char GENESIS_ID_DOMAIN[] = "TRNM/PQ/GenesisID/v1\0";
static const unsigned char QUARANTINE_DOMAIN[] = "TRNM/PQ/Quarantine/v1\0";
static const unsigned char ACCOUNT_DOMAIN[] = "TRNM/PQ/Account/v1\0";

static uint16_t be16(const unsigned char *p) { return ((uint16_t)p[0]<<8)|p[1]; }
static uint64_t be64(const unsigned char *p) {
    uint64_t n=0; for (int i=0;i<8;i++) n=(n<<8)|p[i]; return n;
}
static void put_be64(unsigned char *p, uint64_t n) {
    for (int i=7;i>=0;i--) {p[i]=(unsigned char)n;n >>= 8;}
}
static int eq(const void *a,const void *b,size_t n) {return memcmp(a,b,n)==0;}
static int nonzero(const unsigned char *p,size_t n) {
    unsigned char v=0;for(size_t i=0;i<n;i++)v|=p[i];return v!=0;
}
static int hash_many(const EVP_MD *md, unsigned char *out,
                     const unsigned char **parts, const size_t *lengths, size_t count) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); unsigned int digest_len=0;
    if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,md,NULL)==1;
    for(size_t i=0;ok && i<count;i++)ok=EVP_DigestUpdate(ctx,parts[i],lengths[i])==1;
    if(ok)ok=EVP_DigestFinal_ex(ctx,out,&digest_len)==1;
    EVP_MD_CTX_free(ctx);
    return ok && digest_len==(unsigned int)EVP_MD_get_size(md);
}
static int sha256_parts(unsigned char out[32], const unsigned char **p, const size_t *n,size_t c) {
    return hash_many(EVP_sha256(),out,p,n,c);
}
static int sha384_framed(unsigned char out[48],const unsigned char *domain,size_t domain_len,
                         const unsigned char *data,size_t n) {
    unsigned char len[8]; put_be64(len,(uint64_t)n);
    const unsigned char *parts[]={domain,len,data};
    const size_t lens[]={domain_len,8,n};
    return hash_many(EVP_sha384(),out,parts,lens,3);
}

static int read_exact_regular(const char *path,unsigned char *buf,size_t limit,size_t *n) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 0;
    struct stat s;
    if(fstat(fd,&s)!=0||!S_ISREG(s.st_mode)||s.st_size<=0||(uint64_t)s.st_size>limit){close(fd);return 0;}
    size_t want=(size_t)s.st_size;size_t total=0;
    while(total<want){ssize_t got=read(fd,buf+total,want-total);
        if(got<=0){close(fd);return 0;}total+=(size_t)got;}
    unsigned char tail;
    int no_trailing=read(fd,&tail,1)==0;
    close(fd);
    if(!no_trailing)return 0;
    *n=want;return 1;
}

/* Anchor PQA3 layout: magic4/version1, source digest48, state root48,
 * genesis id48, old/new networks32 each, old/withdrawal heads32 each,
 * new protocol32, issued units8 = 317 bytes. None is signed here.
 */
static int check(const unsigned char *source,size_t slen,
                 const unsigned char *state,size_t tlen,
                 const unsigned char *anchor,size_t alen) {
    if(alen!=ANCHOR_LEN||!eq(anchor,"PQA3\x01",5))return 0;
    const unsigned char *expected_source=anchor+5;
    const unsigned char *expected_root=anchor+53;
    const unsigned char *expected_genesis=anchor+101;
    const unsigned char *old_net=anchor+149;
    const unsigned char *new_net=anchor+181;
    const unsigned char *old_head=anchor+213;
    const unsigned char *withdraw_head=anchor+245;
    const unsigned char *profile=anchor+277;
    const uint64_t issued=be64(anchor+309);
    if(!nonzero(expected_source,48)||!nonzero(expected_root,48)||
       !nonzero(expected_genesis,48)||!nonzero(old_net,32)||
       !nonzero(new_net,32)||eq(old_net,new_net,32)||
       !nonzero(old_head,32)||!nonzero(withdraw_head,32)||!nonzero(profile,32))return 0;
    if(slen<SOURCE_HEAD+ACCOUNT_LEN||slen>SOURCE_LIMIT||
       !eq(source,"PQG1\x01",5))return 0;
    if(!eq(source+5,old_net,32)||!eq(source+37,new_net,32)||
       !eq(source+69,old_head,32)||!eq(source+101,withdraw_head,32)||
       !eq(source+133,profile,32)||be64(source+165)!=issued)return 0;
    unsigned ac=be16(source+173),lc=be16(source+175);
    if(ac<1||ac>MAX_ACCOUNTS||lc>MAX_LIABILITIES||
       slen!=SOURCE_HEAD+(size_t)ACCOUNT_LEN*ac+(size_t)LIABILITY_LEN*lc)return 0;
    unsigned char source_digest[48],root[48],genesis[48];
    if(!sha384_framed(source_digest,SOURCE_DOMAIN,sizeof(SOURCE_DOMAIN)-1,source,slen)||
       !eq(source_digest,expected_source,48))return 0;
    if(tlen!=PQS_HEAD+(size_t)PROJECTED_ACCOUNT_LEN*ac+2+(size_t)LIABILITY_LEN*lc+8||
       tlen>TARGET_LIMIT||!eq(state,"PQS1\x01",5)||!eq(state+5,new_net,32)||
       !eq(state+37,profile,32)||be16(state+69)!=ac)return 0;
    const size_t liability_base=SOURCE_HEAD+(size_t)ACCOUNT_LEN*ac;
    const size_t target_liability_count=PQS_HEAD+(size_t)PROJECTED_ACCOUNT_LEN*ac;
    if(be16(state+target_liability_count)!=lc)return 0;
    if(!eq(source+liability_base,state+target_liability_count+2,(size_t)LIABILITY_LEN*lc)||
       be64(state+tlen-8)!=issued)return 0;
    uint64_t total=0;
    for(unsigned i=0;i<ac;i++){
        const unsigned char *a=source+SOURCE_HEAD+(size_t)ACCOUNT_LEN*i;
        const unsigned char *p=state+PQS_HEAD+(size_t)PROJECTED_ACCOUNT_LEN*i;
        if(!nonzero(a,32)||be64(a+40)==0||be64(a+48)==0||be64(a+48)==U64_MAX_VALUE||
           !eq(p+65,a,ACCOUNT_LEN)||be64(p+121)!=be64(a+48)+1)return 0;
        if(i>0 && memcmp(source+SOURCE_HEAD+(size_t)ACCOUNT_LEN*(i-1),a,32)>=0)return 0;
        if(total>U64_MAX_VALUE-be64(a+32))return 0;
        total+=be64(a+32);
        if(p[0]!=0 && p[0]!=1)return 0;
        unsigned char calculated[32];
        if(p[0]==0){
            if(nonzero(p+33,32))return 0;
            const unsigned char *parts[]={QUARANTINE_DOMAIN,new_net,a};
            const size_t lengths[]={sizeof(QUARANTINE_DOMAIN)-1,32,32};
            if(!sha256_parts(calculated,parts,lengths,3))return 0;
        }else{
            if(!nonzero(p+33,32))return 0;
            const unsigned char *parts[]={ACCOUNT_DOMAIN,new_net,a,p+33};
            const size_t lengths[]={sizeof(ACCOUNT_DOMAIN)-1,32,32,32};
            if(!sha256_parts(calculated,parts,lengths,4))return 0;
            for(unsigned j=0;j<i;j++){
                const unsigned char *prev=state+PQS_HEAD+(size_t)PROJECTED_ACCOUNT_LEN*j;
                if(prev[0]==1 && eq(prev+33,p+33,32))return 0;
            }
        }
        if(!eq(p+1,calculated,32))return 0;
        for(unsigned j=0;j<i;j++){
            const unsigned char *prev=state+PQS_HEAD+(size_t)PROJECTED_ACCOUNT_LEN*j;
            if(eq(prev+1,p+1,32))return 0;
        }
    }
    for(unsigned i=0;i<lc;i++){
        const unsigned char *liab=source+liability_base+(size_t)LIABILITY_LEN*i;
        if(!nonzero(liab,32)||!nonzero(liab+32,32)||be64(liab+64)==0||
           liab[80]<1||liab[80]>4)return 0;
        if(i>0 && memcmp(liab-LIABILITY_LEN,liab,32)>=0)return 0;
        int has_owner=0;
        for(unsigned j=0;j<ac;j++)
            if(eq(liab+32,source+SOURCE_HEAD+(size_t)ACCOUNT_LEN*j,32)){has_owner=1;break;}
        if(!has_owner)return 0;
        if(total>U64_MAX_VALUE-be64(liab+64))return 0;
        total+=be64(liab+64);
    }
    if(total!=issued)return 0;
    if(!sha384_framed(root,STATE_DOMAIN,sizeof(STATE_DOMAIN)-1,state,tlen)||
       !eq(root,expected_root,48))return 0;
    unsigned char genesis_input[32+32+48+48];
    memcpy(genesis_input,new_net,32);memcpy(genesis_input+32,profile,32);
    memcpy(genesis_input+64,source_digest,48);memcpy(genesis_input+112,root,48);
    if(!sha384_framed(genesis,GENESIS_ID_DOMAIN,sizeof(GENESIS_ID_DOMAIN)-1,
                      genesis_input,sizeof(genesis_input))||
       !eq(genesis,expected_genesis,48))return 0;
    return 1;
}
int main(int argc,char **argv) {
    if(argc!=4){fputs("usage: pq_import_projection_verify <PQG1> <PQS1> <PQA3>\n",stderr);return 2;}
    unsigned char source[SOURCE_LIMIT],state[TARGET_LIMIT],anchor[ANCHOR_LEN];
    size_t ns=0,nt=0,na=0;
    if(!read_exact_regular(argv[1],source,sizeof(source),&ns)||
       !read_exact_regular(argv[2],state,sizeof(state),&nt)||
       !read_exact_regular(argv[3],anchor,sizeof(anchor),&na)||
       !check(source,ns,state,nt,anchor,na)){
        fputs("PQN5_REJECTED_NO_AUTHORITY\n",stderr);return 1;}
    puts("PQN5_VALID_STRUCTURAL_PROJECTION_ONLY");
    return 0;
}
