/* Test observer only: allocation interception returns real NULL at an exact
 * boundary; all admitted descriptors and SQLite objects are real resources. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void *trnm_task_provider_new(void);
void trnm_task_provider_free(void *);
uint64_t trnm_task_provider_reset(void *);
uint64_t trnm_task_provider(void *, uint64_t, const unsigned char *, uint64_t, unsigned char *, uint64_t);
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
int __real_open(const char *,int,...);
int __real_close(int);
ssize_t __real_read(int,void *,size_t);
int __real_sqlite3_finalize(void *);
int __real_sqlite3_close_v2(void *);

static _Atomic int64_t fail_malloc=-1;
static _Atomic int fail_calloc_after_open=0;
static _Atomic uint64_t malloc_calls=0,open_calls=0,close_calls=0,finalize_calls=0,close_db_calls=0;
static _Atomic uint64_t read_calls=0;
static _Atomic int last_open=-1;
void * __wrap_malloc(size_t size) {
    uint64_t index=malloc_calls++;
    if (fail_malloc>=0 && index==(uint64_t)fail_malloc) return NULL;
    return __real_malloc(size);
}
void * __wrap_calloc(size_t count,size_t size) {
    if (fail_calloc_after_open && open_calls) {fail_calloc_after_open=0;return NULL;}
    return __real_calloc(count,size);
}
int __wrap_open(const char *path,int flags,...) {
    mode_t mode=0;
    if ((flags&O_CREAT) || (flags&O_TMPFILE)==O_TMPFILE) {
        va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args);
    }
    int fd=__real_open(path,flags,mode);open_calls++;last_open=fd;return fd;
}
int __wrap_close(int fd) {close_calls++;return __real_close(fd);}
ssize_t __wrap_read(int fd,void *buffer,size_t count) {read_calls++;return __real_read(fd,buffer,count);}
int __wrap_sqlite3_finalize(void *stmt) {finalize_calls++;return __real_sqlite3_finalize(stmt);}
int __wrap_sqlite3_close_v2(void *db) {close_db_calls++;return __real_sqlite3_close_v2(db);}
void trnm_test_fd_fault(int64_t nth,int after_open) {
    fail_malloc=nth;malloc_calls=0;open_calls=0;close_calls=0;last_open=-1;
    finalize_calls=0;close_db_calls=0;fail_calloc_after_open=after_open;
    read_calls=0;
}
uint64_t trnm_test_fd_observation(int key) {
    switch(key) {
    case 0:return malloc_calls;case 1:return open_calls;case 2:return close_calls;
    case 3:return (uint64_t)(int64_t)last_open;case 4:return finalize_calls;case 5:return close_db_calls;
    case 6:return read_calls;
    default:return UINT64_MAX;
    }
}

#ifndef TRNM_OBSERVER_NO_MAIN
static void need(int value,const char *message) {
    if (!value) {fprintf(stderr,"assertion failed: %s; errno=%d\n",message,errno);exit(2);}
}
static void wr(unsigned char *p,uint64_t n) {for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(i*8));}
static uint64_t rd(const unsigned char *p) {uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)p[i]<<(i*8);return n;}
static uint64_t invoke(void *ctx,uint64_t op,uint64_t a,unsigned char *out) {
    unsigned char raw[8];wr(raw,a);return trnm_task_provider(ctx,op,raw,8,out,24);
}
static uint64_t open_fd(void *ctx,const char *path,unsigned char *out,uint64_t capacity) {
    size_t n=strlen(path);unsigned char raw[4096];need(n<=sizeof(raw)-24,"fixture path extent");
    wr(raw,O_CREAT|O_RDWR|O_CLOEXEC);wr(raw+8,0600);wr(raw+16,n);memcpy(raw+24,path,n);
    return trnm_task_provider(ctx,17,raw,n+24,out,capacity);
}
static int closed(int fd) {errno=0;return fcntl(fd,F_GETFD)==-1 && errno==EBADF;}
static void pass(const char *name) {printf("{\"case\":\"%s\",\"status\":\"PASS\",\"malloc_calls\":%llu,\"open_calls\":%llu,\"close_calls\":%llu}\n",name,(unsigned long long)malloc_calls,(unsigned long long)open_calls,(unsigned long long)close_calls);fflush(stdout);}
int main(int argc,char **argv) {
    need(argc==2,"one actual output path");unsigned char out[64]={0};
    void *a=trnm_task_provider_new(),*b=trnm_task_provider_new();need(a&&b,"real contexts");
    trnm_test_fd_fault(-1,0);
    need(open_fd(a,argv[1],out,23)==24 && open_calls==0,"capacity refused before syscall");pass("capacity-no-side-effect");
    need(open_fd(a,argv[1],out,24)==24 && rd(out)==0,"actual open");int fd=(int)rd(out+8);need(fd>=0&&!closed(fd),"retained real fd");
    need(invoke(b,19,fd,out)==UINT64_MAX,"cross-context fsync rejected");
    need(invoke(b,18,fd,out)==UINT64_MAX&&!closed(fd),"cross-context close rejected without effect");
    need(invoke(a,19,fd,out)==24&&rd(out)==0,"retained actual fsync");pass("cross-context-capability");
    need(invoke(a,18,fd,out)==24&&rd(out)==0&&closed(fd),"actual close");
    int external=__real_open(argv[1],O_RDWR|O_CLOEXEC);need(external>=0,"external real fd");
    need(invoke(a,18,external,out)==UINT64_MAX&&!closed(external),"unretained fd refused");
    need(invoke(a,19,external,out)==UINT64_MAX&&!closed(external),"unretained fsync refused");
    need(invoke(a,18,fd,out)==UINT64_MAX&&!closed(external),"repeat close refused even after OS reuse");
    __real_close(external);pass("forged-and-repeated-descriptors");
    for(int64_t fail=0;fail<2;fail++) {
        trnm_test_fd_fault(fail,0);
        need(open_fd(a,argv[1],out,24)==UINT64_MAX-1,"real private allocation failure sentinel");
        need(open_calls==(uint64_t)fail,"actual open before retention failure only");
        need(close_calls==(uint64_t)fail,"actual close of just-opened descriptor");
        if(fail)need(last_open>=0&&closed(last_open),"failed retention leaves no descriptor");
        need(trnm_task_provider_reset(a)==0,"no retained resource after allocation failure");
        pass(fail?"retention-allocation-null-closes-real-fd":"path-allocation-null-no-open");
    }
    trnm_test_fd_fault(-1,0);
    need(open_fd(a,argv[1],out,24)==24&&rd(out)==0,"first reset fd");int fd1=(int)rd(out+8);
    need(open_fd(a,argv[1],out,24)==24&&rd(out)==0,"second reset fd");int fd2=(int)rd(out+8);
    unsigned char raw[128];wr(raw,0x02000006);wr(raw+8,8);memcpy(raw+16,":memory:",8);
    need(trnm_task_provider(a,2,raw,24,out,24)==24&&rd(out)==0,"actual SQLite database");uint64_t db=rd(out+8);
    wr(raw,db);wr(raw+8,8);memcpy(raw+16,"SELECT 1",8);
    need(trnm_task_provider(a,5,raw,24,out,24)==24&&rd(out)==0,"actual SQLite statement");
    uint64_t close_before=close_calls,finalize_before=finalize_calls,db_before=close_db_calls;
    need(trnm_task_provider_reset(a)==4,"all four actual resources reset");
    printf("{\"observation\":\"reset\",\"fd1_closed\":%d,\"fd2_closed\":%d,\"close_before\":%llu,\"close_after\":%llu,\"finalize_before\":%llu,\"finalize_after\":%llu,\"db_before\":%llu,\"db_after\":%llu}\n",closed(fd1),closed(fd2),(unsigned long long)close_before,(unsigned long long)close_calls,(unsigned long long)finalize_before,(unsigned long long)finalize_calls,(unsigned long long)db_before,(unsigned long long)close_db_calls);
    need(closed(fd1)&&closed(fd2)&&close_calls-close_before==2&&finalize_calls-finalize_before==1&&close_db_calls-db_before==1,"actual reset closes descriptors and SQLite");
    need(trnm_task_provider_reset(a)==0,"reset idempotent");pass("reset-real-mixed-resources");
    trnm_test_fd_fault(-1,0);
    need(open_fd(a,argv[1],out,24)==24&&rd(out)==0,"fd before owner drop");fd=(int)rd(out+8);
    trnm_task_provider_free(a);need(closed(fd)&&close_calls==1,"actual owner free closes fd");pass("owner-drop-closes-real-fd");
    trnm_task_provider_free(b);
    a=trnm_task_provider_new();need(a!=NULL,"zero descriptor context");
    (void)__real_close(0);trnm_test_fd_fault(-1,0);
    need(open_fd(a,argv[1],out,24)==24&&rd(out)==0&&rd(out+8)==0,"actual descriptor zero retained");
    need(invoke(a,19,0,out)==24&&rd(out)==0,"descriptor zero fsync");
    need(trnm_task_provider_reset(a)==1&&closed(0),"descriptor zero cleanup");
    trnm_task_provider_free(a);pass("descriptor-zero-owned");
    puts("{\"status\":\"PASS\",\"cases\":8}");return 0;
}
#endif
