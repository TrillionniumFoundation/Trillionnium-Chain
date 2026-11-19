/* Qualification-only allocator observer. No store, SQL, codec or crypto logic.
 * The original HIA objects are relinked with --wrap=calloc/free. Their calls
 * still reach the real libc allocator. The shared provider DSO is unchanged. */
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

void *__real_calloc(size_t,size_t);
void __real_free(void *);
struct allocation { void *pointer; size_t size; };
static struct allocation allocated[65536];
static pthread_mutex_t guard=PTHREAD_MUTEX_INITIALIZER;
static uint64_t calls,frees,live,bytes,fail_at,failures,bad_frees;

void *__wrap_calloc(size_t count,size_t size) {
    pthread_mutex_lock(&guard);
    uint64_t ordinal=++calls;
    if (ordinal==fail_at) { ++failures;pthread_mutex_unlock(&guard);return NULL; }
    pthread_mutex_unlock(&guard);
    void *pointer=__real_calloc(count,size);
    if (!pointer) { pthread_mutex_lock(&guard);++failures;pthread_mutex_unlock(&guard);return NULL; }
    if (size && count>SIZE_MAX/size) abort();
    pthread_mutex_lock(&guard);
    size_t index=0;
    while(index<65536 && allocated[index].pointer)++index;
    if(index==65536)abort();
    allocated[index].pointer=pointer;allocated[index].size=count*size;
    ++live;bytes+=count*size;
    pthread_mutex_unlock(&guard);
    return pointer;
}
void __wrap_free(void *pointer) {
    if (!pointer) { __real_free(pointer);return; }
    pthread_mutex_lock(&guard);
    size_t index=0;
    while(index<65536 && allocated[index].pointer!=pointer)++index;
    if(index==65536) { ++bad_frees;pthread_mutex_unlock(&guard);abort(); }
    --live;bytes-=allocated[index].size;++frees;
    allocated[index].pointer=NULL;allocated[index].size=0;
    pthread_mutex_unlock(&guard);
    __real_free(pointer);
}
uint64_t trnm_task_test_alloc_calls(void){pthread_mutex_lock(&guard);uint64_t v=calls;pthread_mutex_unlock(&guard);return v;}
uint64_t trnm_task_test_alloc_frees(void){pthread_mutex_lock(&guard);uint64_t v=frees;pthread_mutex_unlock(&guard);return v;}
uint64_t trnm_task_test_alloc_live(void){pthread_mutex_lock(&guard);uint64_t v=live;pthread_mutex_unlock(&guard);return v;}
uint64_t trnm_task_test_alloc_bytes(void){pthread_mutex_lock(&guard);uint64_t v=bytes;pthread_mutex_unlock(&guard);return v;}
uint64_t trnm_task_test_alloc_failures(void){pthread_mutex_lock(&guard);uint64_t v=failures;pthread_mutex_unlock(&guard);return v;}
uint64_t trnm_task_test_alloc_bad_frees(void){pthread_mutex_lock(&guard);uint64_t v=bad_frees;pthread_mutex_unlock(&guard);return v;}
void trnm_task_test_alloc_fail_after(uint64_t ordinal){pthread_mutex_lock(&guard);fail_at=ordinal?calls+ordinal:0;pthread_mutex_unlock(&guard);}
