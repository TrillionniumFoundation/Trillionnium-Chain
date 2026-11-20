/* Qualification-only allocation census. No control-guard behavior is implemented
 * here: the original emitted f0 symbol performs every operation. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern void *__libc_calloc(size_t, size_t);
extern void __libc_free(void *);
static int active;
static uint64_t calls, denied, live, fail_at;
static void *owned[8];
void *calloc(size_t n, size_t size) {
    if (active) {
        calls++;
        if (calls == fail_at) { denied++; return NULL; }
    }
    void *p = __libc_calloc(n, size);
    if (active && p) {
        size_t i;
        for (i=0; i<8; i++) if (!owned[i]) { owned[i]=p; live++; break; }
        if (i==8) abort();
    }
    return p;
}
void free(void *p) {
    if (active && p) {
        size_t i;
        for (i=0; i<8; i++) if (owned[i]==p) { owned[i]=NULL; live--; break; }
        if (i==8) abort();
    }
    __libc_free(p);
}
static void word(uint64_t value) {
    unsigned char bytes[8];
    for (size_t i=0; i<8; i++) bytes[i]=(unsigned char)(value>>(8*i));
    if (fwrite(bytes,1,8,stdout)!=8) exit(8);
}
int main(int argc,char **argv) {
    if (argc!=5) return 2;
    FILE *input=fopen(argv[2],"rb");
    if (!input || fseek(input,0,SEEK_END)!=0) return 3;
    long end=ftell(input);
    if (end<0 || end>1024*1024 || fseek(input,0,SEEK_SET)!=0) return 3;
    size_t n=(size_t)end;
    char *tail=NULL;
    errno=0;
    unsigned long long parsed=strtoull(argv[3],&tail,10);
    if (errno || !tail || *tail || parsed>1024*1024) return 3;
    size_t output_size=(size_t)parsed;
    errno=0; parsed=strtoull(argv[4],&tail,10);
    if (errno || !tail || *tail || parsed>4) return 3;
    fail_at=(uint64_t)parsed;
    unsigned char *source=malloc(n?n:1), *output=malloc(output_size?output_size:1);
    size_t workspace_size=65536+3*n;
    if (workspace_size<140800) workspace_size=140800;
    workspace_size+=13;
    unsigned char *workspace=malloc(workspace_size);
    if (!source || !output || !workspace || fread(source,1,n,input)!=n || fclose(input)!=0) return 4;
    memset(output,0xa5,output_size); memset(workspace,0x6d,workspace_size);
    void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!library) { fputs(dlerror(),stderr); return 5; }
    void *symbol=dlsym(library,"f0");
    if (!symbol) return 5;
    typedef uint64_t (*entry)(void *,size_t,void *,size_t,void *,size_t);
    entry function;
    memcpy(&function,&symbol,sizeof(function));
    active=1;
    uint64_t result=function(source,n,output,output_size,workspace,workspace_size);
    active=0;
    word(result);word(calls);word(denied);word(live);
    if (fwrite(output,1,output_size,stdout)!=output_size) return 8;
    free(source);free(output);free(workspace);dlclose(library);
    return fflush(stdout)==0?0:8;
}
