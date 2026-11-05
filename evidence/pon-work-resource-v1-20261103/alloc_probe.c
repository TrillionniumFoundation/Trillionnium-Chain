/* Local process-wide allocation observation. No runtime code is modified.
 * Time measurements must be taken separately without LD_PRELOAD. Counters cover
 * complete process setup, valid-proof preparation, observation and teardown.
 * Requested bytes are cumulative malloc/calloc/realloc requests, not peak RSS.
 */
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

static _Atomic unsigned long long calls;
static _Atomic unsigned long long requested;

static void observed(size_t bytes) {
    atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&requested, bytes, memory_order_relaxed);
}

void *malloc(size_t n) {
    void *p = __libc_malloc(n);
    if (p) observed(n);
    return p;
}

void *calloc(size_t n, size_t width) {
    void *p = __libc_calloc(n, width);
    if (p) observed(n * width);
    return p;
}

void *realloc(void *old, size_t n) {
    void *p = __libc_realloc(old, n);
    if (p) observed(n);
    return p;
}

__attribute__((destructor)) static void report(void) {
    unsigned long long c = atomic_load_explicit(&calls, memory_order_relaxed);
    unsigned long long b = atomic_load_explicit(&requested, memory_order_relaxed);
    char line[192];
    int length = snprintf(line, sizeof(line),
        "{\"schema\":\"w1-process-alloc-observation-v1\",\"successful_allocation_requests\":%llu,\"requested_bytes\":%llu}\n", c, b);
    if (length > 0 && (size_t)length < sizeof(line)) {
        ssize_t written = write(STDERR_FILENO, line, (size_t)length);
        if (written != length) _exit(126);
    }
}
