/* Standalone experimental PoN ASERT oracle; NO consensus authority.
 * C11 with GCC/Clang __int128. No Rust, Python, Go or model imports.
 * Reject unrepresentable i128 intermediate values before saturation.
 * CLI emits canonical exact 256-bit targets, or a refusal error.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

typedef unsigned __int128 u128;
typedef struct { uint64_t limb[4]; } u256;
typedef struct { uint64_t limb[9]; } u576;

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static int hex256(const char *s, u256 *out) {
    if (strlen(s) != 64) return 0;
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < 32; ++i) {
        int a = hex_digit(s[2*i]), b = hex_digit(s[2*i+1]);
        if (a < 0 || b < 0) return 0;
        int reverse = 31-i;
        out->limb[reverse / 8] |= ((uint64_t)((a << 4) | b)) << ((reverse % 8)*8);
    }
    return 1;
}
static void print256(const u256 *v) {
    const char *alphabet="0123456789abcdef";
    char buf[65];
    for (int i=0;i<32;i++) {
        int rev=31-i;
        uint8_t b=(uint8_t)(v->limb[rev/8] >> ((rev%8)*8));
        buf[2*i]=alphabet[b>>4]; buf[2*i+1]=alphabet[b&15];
    }
    buf[64]='\0'; puts(buf);
}
static int cmp256(const u256 *a,const u256 *b) {
    for (int i=3;i>=0;i--) {
        if (a->limb[i]>b->limb[i]) return 1;
        if (a->limb[i]<b->limb[i]) return -1;
    }
    return 0;
}
static int is_zero256(const u256 *x) {
    return !(x->limb[0]|x->limb[1]|x->limb[2]|x->limb[3]);
}
static void multiply_factor(u576 *dst,const u256 *src,uint64_t factor) {
    memset(dst,0,sizeof(*dst));
    u128 carry=0;
    for (int i=0;i<4;i++) {
        u128 t=(u128)src->limb[i]*factor+carry;
        dst->limb[i]=(uint64_t)t;
        carry=t>>64;
    }
    dst->limb[4]=(uint64_t)carry;
}
static void left_shift(u576 *dst,const u576 *src,unsigned bits) {
    memset(dst,0,sizeof(*dst));
    unsigned words=bits/64, rem=bits%64;
    for (unsigned i=0;i<9;i++) {
        if (i+words>=9) break;
        dst->limb[i+words]|=src->limb[i]<<rem;
        if (rem && i+words+1<9) dst->limb[i+words+1]|=src->limb[i]>>(64-rem);
    }
}
static void right_shift(u576 *dst,const u576 *src,unsigned bits) {
    memset(dst,0,sizeof(*dst));
    unsigned words=bits/64, rem=bits%64;
    for (unsigned i=words;i<9;i++) {
        dst->limb[i-words]|=src->limb[i]>>rem;
        if (rem && i>=words+1) dst->limb[i-words-1]|=src->limb[i]<<(64-rem);
    }
}
static int parse_u64(const char *s,uint64_t *out) {
    if (!s || !*s) return 0;
    uint64_t n=0;
    for (const char *p=s;*p;p++) {
        if (*p<'0'||*p>'9') return 0;
        unsigned v=(unsigned)(*p-'0');
        if (n>(UINT64_MAX-v)/10) return 0;
        n=n*10+v;
    }
    *out=n; return 1;
}
/* 0 success, 1 parameters, 2 bounded i128 range. */
static int asert(const u256 *anchor, uint64_t anchor_time,uint64_t parent_time,
                 uint64_t anchor_height,uint64_t height,uint64_t spacing,
                 uint64_t half_life,const u256 *cap,u256 *out) {
    if (is_zero256(anchor)||is_zero256(cap)||cmp256(anchor,cap)>0 ||
        !anchor_height||height<=anchor_height||!spacing||!half_life) return 1;
    u128 max128=(((u128)1)<<127)-1;
    u128 ideal=(u128)(height-anchor_height)*spacing;
    if(ideal>max128) return 2;
    u128 magnitude;
    int negative;
    if(parent_time>=anchor_time) {
        u128 elapsed=(u128)(parent_time-anchor_time);
        if (ideal>elapsed) { negative=1; magnitude=ideal-elapsed; }
        else { negative=0; magnitude=elapsed-ideal; }
    } else {
        negative=1;
        magnitude=ideal+(u128)(anchor_time-parent_time);
    }
    if(magnitude>(negative ? (((u128)1)<<127) : max128)) return 2;
    if(magnitude>(negative ? ((((u128)1)<<127)>>16) : (max128>>16))) return 2;
    u128 q=(magnitude<<16)/half_life;
    long shifts;
    uint32_t fractional;
    if(!negative) {
        if(q>=((u128)256<<16)) { *out=*cap;return 0; }
        shifts=(long)(q>>16);
        fractional=(uint32_t)(q&65535);
    } else {
        if(q>=((u128)512<<16)) { memset(out,0,sizeof(*out));out->limb[0]=1;return 0; }
        uint64_t small=(uint64_t)q;
        shifts=-(long)((small+65535)/65536);
        fractional=(uint32_t)((65536-(small&65535))&65535);
        if(shifts<=-512) { memset(out,0,sizeof(*out));out->limb[0]=1;return 0; }
    }
    u128 f=fractional, f2=f*f, f3=f2*f;
    u128 poly=(u128)195766423245049ULL*f+(u128)971821376ULL*f2+
              (u128)5127ULL*f3+(((u128)1)<<47);
    uint64_t factor=(uint64_t)(poly>>48)+65536;
    if(factor<65536||factor>131072) return 1;
    u576 expanded,shifted,reduced;
    multiply_factor(&expanded,anchor,factor);
    if(shifts>=0) left_shift(&shifted,&expanded,(unsigned)shifts);
    else right_shift(&shifted,&expanded,(unsigned)(-shifts));
    right_shift(&reduced,&shifted,16);
    for(int i=4;i<9;i++) if(reduced.limb[i]) { *out=*cap;return 0; }
    for(int i=0;i<4;i++) out->limb[i]=reduced.limb[i];
    if(cmp256(out,cap)>0) *out=*cap;
    if(is_zero256(out)) out->limb[0]=1;
    return 0;
}
int main(int argc,char **argv) {
    const char *keys[8]={"--anchor","--limit","--anchor-parent-time","--parent-time",
                        "--anchor-height","--height","--spacing","--half-life"};
    const char *vals[8]={0};
    if(argc!=17) { fputs("ASERT_RESEARCH_PARAMETERS\n",stderr);return 2; }
    for (int i=1;i<argc;i+=2) {
        int hit=-1;
        for(int j=0;j<8;j++) if(strcmp(argv[i],keys[j])==0){hit=j;break;}
        if(hit<0||vals[hit]) { fputs("ASERT_RESEARCH_PARAMETERS\n",stderr);return 2; }
        vals[hit]=argv[i+1];
    }
    for(int i=0;i<8;i++) if(!vals[i]) { fputs("ASERT_RESEARCH_PARAMETERS\n",stderr);return 2; }
    u256 anchor,cap,target;
    uint64_t at,pt,ah,h,spacing,half;
    if(!hex256(vals[0],&anchor)||!hex256(vals[1],&cap)||
       !parse_u64(vals[2],&at)||!parse_u64(vals[3],&pt)||
       !parse_u64(vals[4],&ah)||!parse_u64(vals[5],&h)||
       !parse_u64(vals[6],&spacing)||!parse_u64(vals[7],&half)) {
        fputs("ASERT_RESEARCH_PARAMETERS\n",stderr);return 2;
    }
    int ret=asert(&anchor,at,pt,ah,h,spacing,half,&cap,&target);
    if(ret!=0) { fputs(ret==2?"ASERT_RESEARCH_RANGE\n":"ASERT_RESEARCH_PARAMETERS\n",stderr);return 2; }
    print256(&target);
    return 0;
}
