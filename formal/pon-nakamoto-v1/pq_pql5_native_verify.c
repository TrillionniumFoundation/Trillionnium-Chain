/* PQL5N: independent read-only ML-DSA-65 quorum verifier (research only).
 * No ledger, checkpoint update, non-rewindable anchor, Node or FinalUse authority.
 * Requires caller-pinned network/import/genesis/challenge/latest frontier and keys.
 * Two compromised witnesses and a rewound external head can still authorize a clone.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define KEY_LIMIT 16384u
#define PUB_SIZE 1952u
#define RAW_SIZE 269u
#define SIG_SIZE 3309u
#define RESPONSE_SIZE (RAW_SIZE+2u+SIG_SIZE)
#define MAX_REPLIES 3u
#define RETURN_REJECT 2
#define KEY_PREFIX "TRNM/PoN/PQKey/v1\0"
#define SIGN_PREFIX "TRNM/PQ/PQL5Witness/v1\0"

struct Witness {
    EVP_PKEY *key;
    unsigned char key_id[32];
    int seen;
};
struct Reply {
    uint64_t seq;
    unsigned char fid[48];
    int witness_index;
};

static int reject(const char *message) {
    fprintf(stderr, "PQL5N_REJECT: %s\n", message);
    return RETURN_REJECT;
}
static int all_zero(const unsigned char *bytes, size_t n) {
    unsigned char any = 0;
    for (size_t i=0; i<n; i++) any |= bytes[i];
    return any == 0;
}
static int decode_hex(const char *src, size_t exact_bytes, unsigned char *out) {
    if (strlen(src) != exact_bytes * 2u) return 0;
    for (size_t i=0; i<exact_bytes; i++) {
        unsigned int a, b;
        unsigned char x=(unsigned char)src[2*i], y=(unsigned char)src[2*i+1];
        a=(x>='0'&&x<='9')?(unsigned int)(x-'0'):(x>='a'&&x<='f')?(unsigned int)(x-'a'+10):16u;
        b=(y>='0'&&y<='9')?(unsigned int)(y-'0'):(y>='a'&&y<='f')?(unsigned int)(y-'a'+10):16u;
        if (a>15u || b>15u) return 0;
        out[i]=(unsigned char)((a<<4)|b);
    }
    return 1;
}
static int decimal_u64(const char *text, uint64_t *out) {
    if (!text || !text[0] || (text[0]=='0' && text[1])) return 0;
    uint64_t n=0;
    for (const unsigned char *p=(const unsigned char *)text; *p; p++) {
        if (*p<'0'||*p>'9') return 0;
        unsigned int d=(unsigned int)(*p-'0');
        if (n > (UINT64_MAX-d)/10u) return 0;
        n=n*10u+d;
    }
    *out=n;
    return 1;
}
static uint64_t be64(const unsigned char *p) {
    uint64_t n=0;
    for (int i=0;i<8;i++) n=(n<<8)|(uint64_t)p[i];
    return n;
}
static int read_owned_regular(const char *path, unsigned char *buf, size_t cap, size_t *n) {
    int fd=open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) return 0;
    struct stat st;
    if (fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<1 ||
        (uint64_t)st.st_size > (uint64_t)cap) { close(fd); return 0; }
    size_t used=0;
    while (used<=cap) {
        ssize_t k=read(fd,buf+used,cap+1-used);
        if (k<0) { if (errno==EINTR) continue; close(fd); return 0; }
        if (k==0) break;
        used+=(size_t)k;
        if (used>cap) { close(fd); return 0; }
    }
    close(fd);
    if (used == 0) return 0;
    *n=used;
    return 1;
}
static int domain_hash_sha256(unsigned char out[32], const char *domain,
                              size_t domain_len, const unsigned char *bytes, size_t length) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    unsigned int n=0;
    if (!ctx) return 0;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1 &&
           EVP_DigestUpdate(ctx,domain,domain_len)==1 &&
           EVP_DigestUpdate(ctx,bytes,length)==1 &&
           EVP_DigestFinal_ex(ctx,out,&n)==1 && n==32u;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static int verify_mldsa65(EVP_PKEY *key, const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok=EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1 &&
           EVP_DigestVerify(ctx,sig,SIG_SIZE,msg,msg_len)==1;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static int load_key(const char *path, struct Witness *out) {
    unsigned char source[KEY_LIMIT+1];
    size_t n=0;
    if (!read_owned_regular(path,source,KEY_LIMIT,&n) || n > (size_t)INT_MAX) return 0;
    BIO *mem=BIO_new_mem_buf(source,(int)n);
    if (!mem) return 0;
    EVP_PKEY *key=PEM_read_bio_PUBKEY(mem,NULL,NULL,NULL);
    BIO_free(mem);
    if (!key || !EVP_PKEY_is_a(key,"ML-DSA-65")) { EVP_PKEY_free(key); return 0; }
    /* Require the *exact* canonical OpenSSL public PEM, including no appended data. */
    BIO *canon=BIO_new(BIO_s_mem());
    if (!canon || PEM_write_bio_PUBKEY(canon,key)!=1) {
        BIO_free(canon); EVP_PKEY_free(key); return 0;
    }
    BUF_MEM *encoded=NULL;
    BIO_get_mem_ptr(canon,&encoded);
    int same=encoded && encoded->length==n && memcmp(encoded->data,source,n)==0;
    BIO_free(canon);
    if (!same) { EVP_PKEY_free(key); return 0; }
    int size=i2d_PUBKEY(key,NULL);
    if (size<=0 || size>4096) { EVP_PKEY_free(key); return 0; }
    unsigned char der[4096],*write=der;
    if (i2d_PUBKEY(key,&write)!=size) { EVP_PKEY_free(key); return 0; }
    const unsigned char *read=der;
    X509_PUBKEY *spki=d2i_X509_PUBKEY(NULL,&read,size);
    if (!spki || read!=der+size) { X509_PUBKEY_free(spki); EVP_PKEY_free(key); return 0; }
    ASN1_OBJECT *obj=NULL;
    const unsigned char *key_bytes=NULL;
    int raw_len=0;
    X509_ALGOR *alg=NULL;
    const int structure_ok=X509_PUBKEY_get0_param(&obj,&key_bytes,&raw_len,&alg,spki)==1;
    const ASN1_OBJECT *alg_obj=NULL;
    const void *alg_val=NULL;
    int param_type=0;
    if (structure_ok && alg) X509_ALGOR_get0(&alg_obj,&param_type,&alg_val,alg);
    char oid[80]={0};
    if (obj) OBJ_obj2txt(oid,sizeof(oid),obj,1);
    int valid=structure_ok && strcmp(oid,"2.16.840.1.101.3.4.3.18")==0 &&
              param_type==V_ASN1_UNDEF && alg_val==NULL && raw_len==(int)PUB_SIZE;
    X509_PUBKEY_free(spki);
    if (!valid || !domain_hash_sha256(out->key_id,KEY_PREFIX,sizeof(KEY_PREFIX)-1,der,(size_t)size)) {
        EVP_PKEY_free(key); return 0;
    }
    out->key=key;
    out->seen=0;
    return 1;
}
static int verify_reply(const char *path, struct Witness roster[3],
                        const unsigned char network[32], const unsigned char root[48],
                        const unsigned char genesis[48], const unsigned char challenge[32],
                        uint64_t now, struct Reply *out) {
    unsigned char b[RESPONSE_SIZE+1];
    size_t n=0;
    if (!read_owned_regular(path,b,RESPONSE_SIZE,&n) || n!=RESPONSE_SIZE ||
        memcmp(b,"PQL5\x01",5)!=0 ||
        b[RAW_SIZE]!=(SIG_SIZE>>8) || b[RAW_SIZE+1]!=(SIG_SIZE&255) ||
        memcmp(b+37,network,32)!=0 || memcmp(b+69,root,48)!=0 ||
        memcmp(b+117,genesis,48)!=0 || memcmp(b+221,challenge,32)!=0) return 0;
    int wi=-1;
    for (int i=0;i<3;i++) {
        if (memcmp(b+5,roster[i].key_id,32)==0) { wi=i; break; }
    }
    if (wi<0 || roster[wi].seen) return 0;
    uint64_t seq=be64(b+165), observed=be64(b+253), expiry=be64(b+261);
    if (observed>now || expiry<now || observed>UINT64_MAX-30u || expiry!=observed+30u ||
        ((seq==0)!=(all_zero(b+173,48)!=0))) return 0;
    unsigned char msg[(sizeof(SIGN_PREFIX)-1)+RAW_SIZE];
    memcpy(msg,SIGN_PREFIX,sizeof(SIGN_PREFIX)-1);
    memcpy(msg+sizeof(SIGN_PREFIX)-1,b,RAW_SIZE);
    if (!verify_mldsa65(roster[wi].key,msg,sizeof(msg),b+RAW_SIZE+2)) return 0;
    out->seq=seq;
    memcpy(out->fid,b+173,48);
    out->witness_index=wi;
    roster[wi].seen=1;
    return 1;
}
int main(int argc, char **argv) {
    if (argc!=13 && argc!=14) return reject("usage: NETWORK ROOT GENESIS CHALLENGE NOW SEQ FID W0.pem W1.pem W2.pem reply0 reply1 [reply2]");
    unsigned char net[32],root[48],genesis[48],challenge[32],expected_fid[48];
    uint64_t now=0,expected_seq=0;
    if (!decode_hex(argv[1],32,net) || !decode_hex(argv[2],48,root) ||
        !decode_hex(argv[3],48,genesis) || !decode_hex(argv[4],32,challenge) ||
        !decimal_u64(argv[5],&now) || !decimal_u64(argv[6],&expected_seq) ||
        !decode_hex(argv[7],48,expected_fid) || expected_seq==0 ||
        all_zero(net,32) || all_zero(root,48) || all_zero(genesis,48) ||
        all_zero(challenge,32) || all_zero(expected_fid,48)) return reject("caller context / latest pin invalid");
    struct Witness witnesses[3]={{0}};
    struct Reply replies[MAX_REPLIES]={{0}};
    int code=RETURN_REJECT;
    for (int i=0;i<3;i++) {
        if (!load_key(argv[8+i],&witnesses[i])) {
            reject("public key / algorithm / trusted roster input invalid"); goto done;
        }
        for (int j=0;j<i;j++) if (memcmp(witnesses[i].key_id,witnesses[j].key_id,32)==0) {
            reject("witness roster duplicated"); goto done;
        }
    }
    int n=argc-11;
    for (int i=0;i<n;i++) {
        if (!verify_reply(argv[11+i],witnesses,net,root,genesis,challenge,now,&replies[i])) {
            reject("signed witness reply invalid or duplicated"); goto done;
        }
    }
    uint64_t highest=0;
    for (int i=0;i<n;i++) if (replies[i].seq>highest) highest=replies[i].seq;
    int votes=0;
    unsigned char winner[48]={0};
    for (int i=0;i<n;i++) {
        if (replies[i].seq!=highest) continue;
        int count=0;
        for (int j=0;j<n;j++) if (replies[j].seq==highest &&
                memcmp(replies[i].fid,replies[j].fid,48)==0) count++;
        if (count>=2) {
            if (!votes) memcpy(winner,replies[i].fid,48);
            if (memcmp(winner,replies[i].fid,48)!=0) { reject("conflicting high quorums"); goto done; }
            votes=count;
        }
    }
    if (highest!=expected_seq || votes<2 || memcmp(winner,expected_fid,48)!=0) {
        reject("no latest externally pinned 2-of-3 frontier quorum"); goto done;
    }
    printf("PQL5N_VALID_RESEARCH_OBSERVATION_ONLY sequence=%" PRIu64 " signers=%d frontier=",highest,votes);
    for(size_t i=0;i<48;i++) printf("%02x",winner[i]);
    puts("");
    code=0;
done:
    for(int i=0;i<3;i++) EVP_PKEY_free(witnesses[i].key);
    return code;
}
