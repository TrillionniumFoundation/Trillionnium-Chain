/* PQI1: bounded native read-only PQG1/PQS1 -> PQI1 projection.
 * Research only. No ledger, signer, work, account import or FinalUse authority.
 * Externally pinned source/state/genesis digests are UNTRUSTED AS TO PROVENANCE.
 * cc -std=c11 -Wall -Wextra -Werror -O2 pqi1_native.c -lcrypto -o pqi1_native
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_BYTES 65536u
#define MAX_ACCOUNTS 128u
#define MAX_LIABILITIES 256u
#define ACCOUNT_SIZE 129u
#define LIABILITY_SIZE 81u
static const unsigned char state_domain[] = "TRNM/PQ/GenesisState/v1";
static const unsigned char genesis_domain[] = "TRNM/PQ/GenesisID/v1";
static const unsigned char account_domain[] = "TRNM/PQ/Account/v1";
static const unsigned char quarantine_domain[] = "TRNM/PQ/Quarantine/v1";

static int reject(const char *msg) {
    fprintf(stderr,"PQI1_REJECT:%s\n",msg);
    return 1;
}
static int zeros(const unsigned char *p,size_t n) {
    unsigned char r=0;for(size_t i=0;i<n;i++)r|=p[i];return r==0;
}
static uint64_t be64(const unsigned char *p) {
    uint64_t x=0;for(size_t i=0;i<8;i++)x=(x<<8)|p[i];return x;
}
static unsigned be16(const unsigned char *p) {
    return ((unsigned)p[0]<<8)|(unsigned)p[1];
}
static void put64(unsigned char *out,uint64_t x) {
    for(int i=7;i>=0;i--){out[i]=(unsigned char)x;x>>=8;}
}
static int parse_hex(const char *s,unsigned char *dst,size_t n) {
    if(strlen(s)!=2*n)return 0;
    for(size_t i=0;i<n;i++) {
        unsigned hi,lo;char a=s[2*i],b=s[2*i+1];
        if(a>='0'&&a<='9')hi=(unsigned)(a-'0');
        else if(a>='a'&&a<='f')hi=(unsigned)(a-'a'+10);
        else return 0;
        if(b>='0'&&b<='9')lo=(unsigned)(b-'0');
        else if(b>='a'&&b<='f')lo=(unsigned)(b-'a'+10);
        else return 0;
        dst[i]=(unsigned char)(hi*16u+lo);
    }
    return !zeros(dst,n);
}
static int sha384_framed(const unsigned char *domain,size_t domain_size,
                         const unsigned char *buf,size_t n,unsigned char out[48]) {
    EVP_MD_CTX *m=EVP_MD_CTX_new();if(!m)return 0;
    unsigned char len[8];unsigned z=0;put64(len,(uint64_t)n);
    int ok=EVP_DigestInit_ex(m,EVP_sha384(),NULL)==1 &&
        EVP_DigestUpdate(m,domain,domain_size)==1 &&
        EVP_DigestUpdate(m,len,8)==1 &&
        EVP_DigestUpdate(m,buf,n)==1 &&
        EVP_DigestFinal_ex(m,out,&z)==1 && z==48u;
    EVP_MD_CTX_free(m);return ok;
}
static int account_hash(const unsigned char *domain,size_t domain_size,
                        const unsigned char *network,const unsigned char *old,
                        const unsigned char *kid,int active,unsigned char result[32]) {
    EVP_MD_CTX *m=EVP_MD_CTX_new();if(!m)return 0;
    unsigned outlen=0;
    int ok=EVP_DigestInit_ex(m,EVP_sha256(),NULL)==1 &&
        EVP_DigestUpdate(m,domain,domain_size)==1 &&
        EVP_DigestUpdate(m,network,32)==1 &&
        EVP_DigestUpdate(m,old,32)==1;
    if(active)ok=ok && EVP_DigestUpdate(m,kid,32)==1;
    ok=ok && EVP_DigestFinal_ex(m,result,&outlen)==1 && outlen==32u;
    EVP_MD_CTX_free(m);return ok;
}
static int read_regular(const char *path,unsigned char *dst,size_t *length) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 0;
    struct stat st;
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<1||(uintmax_t)st.st_size>MAX_BYTES){close(fd);return 0;}
    size_t count=(size_t)st.st_size;size_t n=0;
    while(n<count) {
        ssize_t got=read(fd,dst+n,count-n);
        if(got<=0){close(fd);return 0;}
        n+=(size_t)got;
    }
    unsigned char extra;
    if(read(fd,&extra,1)!=0){close(fd);return 0;}
    close(fd);*length=count;return 1;
}
static int checked_add(uint64_t *total,uint64_t value) {
    if(UINT64_MAX-*total<value)return 0;
    *total+=value;
    return 1;
}
int main(int argc,char **argv) {
    /* Args: immutable file, network32, profile32, source48, state_root48, genesis48 */
    if(argc!=7)return reject("ARGUMENTS");
    unsigned char net[32],profile[32],source[48],state_root[48],genesis[48];
    if(!parse_hex(argv[2],net,32)||!parse_hex(argv[3],profile,32)||
       !parse_hex(argv[4],source,48)||!parse_hex(argv[5],state_root,48)||
       !parse_hex(argv[6],genesis,48))return reject("PINS");
    unsigned char raw[MAX_BYTES],out[MAX_BYTES];size_t length=0;
    if(!read_regular(argv[1],raw,&length))return reject("SOURCE_FILE");
    if(length<71u+ACCOUNT_SIZE+2u+8u || memcmp(raw,"PQS1\x01",5)!=0 ||
       memcmp(raw+5,net,32)!=0||memcmp(raw+37,profile,32)!=0)return reject("CONTEXT");
    unsigned num=be16(raw+69);
    if(num==0u||num>MAX_ACCOUNTS)return reject("ACCOUNT_COUNT");
    size_t pos=71u;
    if(pos+(size_t)num*ACCOUNT_SIZE+2u+8u>length)return reject("ACCOUNTS_LENGTH");
    uint64_t sum=0;unsigned char last_old[32]={0};int has_old=0;
    for(unsigned i=0;i<num;i++) {
        const unsigned char *a=raw+pos;
        const unsigned char *aid=a+1,*kid=a+33,*old=a+65;
        uint64_t bal=be64(a+97),nonce=be64(a+105),prior=be64(a+113),current=be64(a+121);
        if(a[0]>1||zeros(old,32)||(has_old&&memcmp(old,last_old,32)<=0)||
           nonce==0||prior==0||prior==UINT64_MAX||current!=prior+1||
           !checked_add(&sum,bal))return reject("ACCOUNT_FIELDS");
        unsigned char expected[32];
        if(a[0]==0) {
            if(!zeros(kid,32)||!account_hash(quarantine_domain,sizeof(quarantine_domain),net,old,kid,0,expected))return reject("QUARANTINE");
        } else {
            if(zeros(kid,32)||!account_hash(account_domain,sizeof(account_domain),net,old,kid,1,expected))return reject("PQ_KEY");
            for(unsigned j=0;j<i;j++){
                const unsigned char *prev=raw+71u+(size_t)j*ACCOUNT_SIZE;
                if(prev[0]==1 && memcmp(prev+33,kid,32)==0)return reject("PQ_KEY_REUSE");
            }
        }
        if(memcmp(aid,expected,32)!=0)return reject("ACCOUNT_ID");
        memcpy(last_old,old,32);has_old=1;pos+=ACCOUNT_SIZE;
    }
    unsigned nliab=be16(raw+pos);pos+=2;
    if(nliab>MAX_LIABILITIES||pos+(size_t)nliab*LIABILITY_SIZE+8u!=length)return reject("LIABILITY_LENGTH");
    unsigned char last_id[32]={0};int has_id=0;
    for(unsigned i=0;i<nliab;i++){
        const unsigned char *v=raw+pos;
        uint64_t amount=be64(v+64);
        if(zeros(v,32)||(has_id&&memcmp(v,last_id,32)<=0)||amount==0||
           v[80]<1||v[80]>4||!checked_add(&sum,amount))return reject("LIABILITY_FIELDS");
        int owner=0;
        for(unsigned j=0;j<num;j++){
            const unsigned char *a=raw+71u+(size_t)j*ACCOUNT_SIZE;
            if(memcmp(a+65,v+32,32)==0){owner=1;break;}
        }
        if(!owner)return reject("LIABILITY_OWNER");
        memcpy(last_id,v,32);has_id=1;pos+=LIABILITY_SIZE;
    }
    if(be64(raw+pos)!=sum)return reject("ISSUANCE");
    unsigned char actual_root[48];
    if(!sha384_framed(state_domain,sizeof(state_domain),raw,length,actual_root)||
       memcmp(actual_root,state_root,48)!=0)return reject("STATE_ROOT");
    unsigned char payload[32+32+48+48],actual_genesis[48];
    memcpy(payload,net,32);memcpy(payload+32,profile,32);
    memcpy(payload+64,source,48);memcpy(payload+112,state_root,48);
    if(!sha384_framed(genesis_domain,sizeof(genesis_domain),payload,sizeof(payload),actual_genesis)||
       memcmp(actual_genesis,genesis,48)!=0)return reject("GENESIS_ID");
    /* Never rewrite account or liability payloads: retain nonce, quarantine & due. */
    size_t out_len=225u+(size_t)num*ACCOUNT_SIZE+(size_t)nliab*LIABILITY_SIZE;
    if(out_len>MAX_BYTES)return reject("OUTPUT_LIMIT");
    memcpy(out,"PQI1\x01",5);memcpy(out+5,net,32);memcpy(out+37,profile,32);
    memcpy(out+69,source,48);memcpy(out+117,state_root,48);
    memcpy(out+165,genesis,48);put64(out+213,sum);
    out[221]=(unsigned char)(num>>8);out[222]=(unsigned char)num;
    out[223]=(unsigned char)(nliab>>8);out[224]=(unsigned char)nliab;
    memcpy(out+225,raw+71,(size_t)num*ACCOUNT_SIZE);
    memcpy(out+225+(size_t)num*ACCOUNT_SIZE,raw+71u+(size_t)num*ACCOUNT_SIZE+2u,
           (size_t)nliab*LIABILITY_SIZE);
    if(fwrite(out,1,out_len,stdout)!=out_len||fflush(stdout)!=0)return reject("OUTPUT");
    return 0;
}
