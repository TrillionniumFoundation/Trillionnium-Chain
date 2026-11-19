#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void *trnm_task_provider_new(void);
void trnm_task_provider_free(void *);
uint64_t trnm_task_provider_reset(void *);
uint64_t trnm_task_provider(void *,uint64_t,const unsigned char *,uint64_t,unsigned char *,uint64_t);
void trnm_test_fd_fault(int64_t,int);
uint64_t trnm_test_fd_observation(int);
static volatile sig_atomic_t interrupted;
static void alarm_handler(int signal) {(void)signal;interrupted++;}
static void need(int yes,const char *message){if(!yes){fprintf(stderr,"assertion failed: %s; errno=%d\n",message,errno);exit(2);}}
static void wr(unsigned char *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(8*i));}
static uint64_t rd(const unsigned char *p){uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)p[i]<<(8*i);return n;}
static int opened(void *ctx,const char *path,int flags){
    unsigned char input[4096],out[24];size_t n=strlen(path);need(n<=sizeof(input)-24,"fixture path extent");
    wr(input,(uint64_t)flags);wr(input+8,0600);wr(input+16,n);memcpy(input+24,path,n);
    need(trnm_task_provider(ctx,17,input,n+24,out,24)==24&&rd(out)==0,"actual owned open");return (int)rd(out+8);
}
static uint64_t read_case(const char *name,void *ctx,int fd,uint64_t count,uint64_t cap,unsigned char *output){
    unsigned char input[16];wr(input,(uint64_t)fd);wr(input+8,count);memset(output,0xa5,4096);
    uint64_t result=trnm_task_provider(ctx,29,input,16,output,cap);
    printf("{\"case\":\"%s\",\"fd\":%d,\"requested\":%llu,\"capacity\":%llu,\"return\":%llu,\"input\":\"",name,fd,(unsigned long long)count,(unsigned long long)cap,(unsigned long long)result);
    for(unsigned i=0;i<16;i++){printf("%02x",input[i]);}
    printf("\",\"actual_output\":\"");
    for(uint64_t i=0;i<cap;i++){printf("%02x",output[i]);}
    printf("\",\"actual_read_calls\":%llu}\n",(unsigned long long)trnm_test_fd_observation(6));fflush(stdout);
    return result;
}
int main(int argc,char **argv){
    need(argc==2,"one fixture directory");char file[4096],fifo[4096];
    need(snprintf(file,sizeof(file),"%s/read-file",argv[1])>0,"file name");need(snprintf(fifo,sizeof(fifo),"%s/read-fifo",argv[1])>0,"fifo name");
    const char seed[]="0123456789abcdefghijklmnopqrstuv";int setup=open(file,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);need(setup>=0,"actual seed file open");need(write(setup,seed,sizeof(seed)-1)==(ssize_t)(sizeof(seed)-1),"actual seed write");need(close(setup)==0,"actual seed close");
    void *a=trnm_task_provider_new(),*b=trnm_task_provider_new();need(a&&b,"actual contexts");int fd=opened(a,file,O_RDONLY|O_CLOEXEC);unsigned char out[4096];trnm_test_fd_fault(-1,0);
    need(read_case("capacity-before-read",a,fd,20,43,out)==44,"required capacity");
    need(trnm_test_fd_observation(6)==0&&lseek(fd,0,SEEK_CUR)==0,"capacity no syscall or offset movement");for(unsigned i=0;i<4096;i++)need(out[i]==0xa5,"capacity no output write");
    need(read_case("first-five",a,fd,5,29,out)==29&&rd(out)==0&&rd(out+8)==5&&!memcmp(out+24,seed,5),"actual first five");
    need(read_case("next-seven",a,fd,7,31,out)==31&&rd(out)==0&&rd(out+8)==7&&!memcmp(out+24,seed+5,7),"actual sequential offset");
    need(lseek(fd,0,SEEK_CUR)==12,"read is sequential, not pread");
    need(read_case("short-read",a,fd,100,124,out)==24+sizeof(seed)-1-12&&rd(out)==0&&rd(out+8)==sizeof(seed)-1-12&&!memcmp(out+24,seed+12,sizeof(seed)-1-12),"actual short read");
    need(read_case("eof",a,fd,100,124,out)==24&&rd(out)==0&&rd(out+8)==0,"actual EOF");
    need(read_case("zero-length",a,fd,0,24,out)==24&&rd(out)==0&&rd(out+8)==0,"actual zero request");
    uint64_t calls=trnm_test_fd_observation(6);need(read_case("cross-context",b,fd,1,25,out)==UINT64_MAX&&trnm_test_fd_observation(6)==calls,"cross context no read");
    int external=open(file,O_RDONLY|O_CLOEXEC);need(external>=0,"actual foreign descriptor");need(read_case("foreign-descriptor",a,external,1,25,out)==UINT64_MAX&&lseek(external,0,SEEK_CUR)==0&&trnm_test_fd_observation(6)==calls,"foreign descriptor rejected without offset change");close(external);
    unsigned char close_request[8],small[24];wr(close_request,(uint64_t)fd);need(trnm_task_provider(a,18,close_request,8,small,24)==24&&rd(small)==0,"owned close");
    need(read_case("already-closed",a,fd,1,25,out)==UINT64_MAX&&trnm_test_fd_observation(6)==calls,"closed descriptor no read");
    int directory=opened(a,argv[1],O_RDONLY|O_CLOEXEC);need(read_case("actual-directory-error",a,directory,1,25,out)==24&&rd(out)==EISDIR&&rd(out+8)==0,"real EISDIR preserved");
    need(mkfifo(fifo,0600)==0,"actual FIFO");int pipe_fd=opened(a,fifo,O_RDWR|O_CLOEXEC);
    struct sigaction action={0},old={0};action.sa_handler=alarm_handler;sigemptyset(&action.sa_mask);need(sigaction(SIGALRM,&action,&old)==0,"actual nonrestart signal handler");
    ualarm(100000,0);need(read_case("actual-fifo-eintr",a,pipe_fd,1,25,out)==24&&rd(out)==EINTR&&rd(out+8)==0&&interrupted==1,"real interrupted blocking read returned unchanged");ualarm(0,0);need(sigaction(SIGALRM,&old,NULL)==0,"restore signal handler");
    need(write(pipe_fd,"xyz",3)==3,"actual pipe input");need(read_case("actual-pipe-short-read",a,pipe_fd,8,32,out)==27&&rd(out)==0&&rd(out+8)==3&&!memcmp(out+24,"xyz",3),"actual pipe short read");
    need(trnm_task_provider_reset(a)==2,"directory and FIFO cleanup");need(unlink(fifo)==0,"fixture FIFO cleanup");
    close(0);int zero=opened(a,file,O_RDONLY|O_CLOEXEC);need(zero==0,"actual owned fd zero");need(read_case("descriptor-zero",a,0,2,26,out)==26&&rd(out)==0&&rd(out+8)==2&&!memcmp(out+24,seed,2),"fd zero read");need(trnm_task_provider_reset(a)==1,"zero cleanup");trnm_task_provider_free(a);trnm_task_provider_free(b);
    puts("{\"status\":\"PASS\",\"cases\":13,\"real_signal_interruptions\":1}");return 0;
}
