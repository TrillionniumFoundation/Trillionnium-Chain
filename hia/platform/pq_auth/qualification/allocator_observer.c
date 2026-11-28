/* Qualification only: the unchanged HIA objects are linked with --wrap.
 * No parsing, cryptography, acceptance or ownership decisions live here. */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void *__real_calloc(size_t, size_t);
void __real_free(void *);
struct allocation { void *pointer; size_t size; };
static struct allocation allocated[65536];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t calls, frees, live, live_bytes, fail_at, failures;
static uint64_t unknown_frees, unwiped_frees, unwiped_bytes, cleared_bytes;

void *__wrap_calloc(size_t count, size_t width) {
    pthread_mutex_lock(&mutex);
    uint64_t ordinal = ++calls;
    if (ordinal == fail_at) {
        ++failures;
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    pthread_mutex_unlock(&mutex);
    void *pointer = __real_calloc(count, width);
    if (!pointer) {
        pthread_mutex_lock(&mutex);
        ++failures;
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    if (width && count > SIZE_MAX / width) abort();
    pthread_mutex_lock(&mutex);
    size_t index = 0;
    while (index < 65536 && allocated[index].pointer) ++index;
    if (index == 65536) abort();
    allocated[index].pointer = pointer;
    allocated[index].size = count * width;
    ++live;
    live_bytes += count * width;
    pthread_mutex_unlock(&mutex);
    return pointer;
}

void __wrap_free(void *pointer) {
    if (!pointer) return;
    pthread_mutex_lock(&mutex);
    size_t index = 0;
    while (index < 65536 && allocated[index].pointer != pointer) ++index;
    if (index == 65536) {
        ++unknown_frees;
        pthread_mutex_unlock(&mutex);
        abort();
    }
    size_t nonzero = 0;
    volatile const unsigned char *raw = pointer;
    for (size_t at = 0; at < allocated[index].size; ++at) {
        if (raw[at] != 0) ++nonzero;
    }
    if (nonzero) ++unwiped_frees;
    unwiped_bytes += nonzero;
    cleared_bytes += allocated[index].size - nonzero;
    --live;
    live_bytes -= allocated[index].size;
    ++frees;
    allocated[index].pointer = NULL;
    allocated[index].size = 0;
    pthread_mutex_unlock(&mutex);
    __real_free(pointer);
}

uint64_t trnm_pq_test_stat(uint64_t index) {
    pthread_mutex_lock(&mutex);
    uint64_t values[] = {calls, frees, live, live_bytes, failures,
        unknown_frees, unwiped_frees, unwiped_bytes, cleared_bytes};
    uint64_t result = index < 9 ? values[index] : UINT64_MAX;
    pthread_mutex_unlock(&mutex);
    return result;
}

void trnm_pq_test_fail_after(uint64_t ordinal) {
    pthread_mutex_lock(&mutex);
    fail_at = ordinal ? calls + ordinal : 0;
    pthread_mutex_unlock(&mutex);
}

void trnm_pq_test_probe(uint64_t clear) {
    volatile unsigned char *pointer = __wrap_calloc(1, 32);
    if (!pointer) abort();
    for (size_t at = 0; at < 32; ++at) pointer[at] = 0xa5;
    if (clear) for (size_t at = 0; at < 32; ++at) pointer[at] = 0;
    __wrap_free((void *)pointer);
}
