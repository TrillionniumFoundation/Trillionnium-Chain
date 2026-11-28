/* Qualification-only observer. Real SQLite, libc allocations and descriptors
 * remain the subjects. Exact allocation failures and Linux close error reports
 * are injected only at the actual foreign call boundary. No provider behavior
 * is implemented here and this file is excluded from every runtime DSO. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sqlite3.h"

void *trnm_task_provider_new(void);
int trnm_task_provider_enter(void *);
int trnm_task_provider_leave(void *);
void trnm_task_provider_free(void *);
uint64_t trnm_task_provider_reset(void *);
uint64_t trnm_task_provider(void *, uint64_t, const unsigned char *, uint64_t,
                            unsigned char *, uint64_t);
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
int __real_close(int);
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __real_pthread_mutex_destroy(pthread_mutex_t *);
int __real_sqlite3_finalize(sqlite3_stmt *);
int __real_sqlite3_close_v2(sqlite3 *);

static int armed, fail_calloc, fail_mutex, close_error, hit;
static int64_t failure = -1;
static uint64_t calls, close_calls, mutex_destroy_calls, owner_frees;
static void *tracked[8192], *watched_owner;
static char cleanup[256];
static unsigned cleanup_count;

static void forget(void *pointer) {
    if (!pointer) return;
    for (unsigned i = 0; i < 8192; ++i)
        if (tracked[i] == pointer) { tracked[i] = NULL; return; }
}
static void remember(void *pointer) {
    if (!pointer || !armed) return;
    for (unsigned i = 0; i < 8192; ++i)
        if (!tracked[i]) { tracked[i] = pointer; return; }
    _exit(90);
}
static unsigned live(void) {
    unsigned count = 0;
    for (unsigned i = 0; i < 8192; ++i) count += tracked[i] != NULL;
    return count;
}
void *__wrap_malloc(size_t size) {
    if (armed && calls++ == (uint64_t)failure) { hit = 1; return NULL; }
    void *result = __real_malloc(size); remember(result); return result;
}
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_calloc) { fail_calloc = 0; hit = 1; return NULL; }
    if (armed && calls++ == (uint64_t)failure) { hit = 1; return NULL; }
    void *result = __real_calloc(count, size); remember(result); return result;
}
void *__wrap_realloc(void *pointer, size_t size) {
    if (armed && calls++ == (uint64_t)failure) { hit = 1; return NULL; }
    void *result = __real_realloc(pointer, size);
    if (result || !size) { forget(pointer); remember(result); }
    return result;
}
void __wrap_free(void *pointer) {
    if (pointer && pointer == watched_owner) ++owner_frees;
    forget(pointer); __real_free(pointer);
}
int __wrap_close(int descriptor) {
    ++close_calls;
    int result = __real_close(descriptor);
    if (close_error) { errno = close_error; return -1; }
    return result;
}
int __wrap_pthread_mutex_init(pthread_mutex_t *lock, const pthread_mutexattr_t *attr) {
    if (fail_mutex) { fail_mutex = 0; watched_owner = (char *)lock - 8; return EAGAIN; }
    return __real_pthread_mutex_init(lock, attr);
}
int __wrap_pthread_mutex_destroy(pthread_mutex_t *lock) {
    ++mutex_destroy_calls; return __real_pthread_mutex_destroy(lock);
}
int __wrap_sqlite3_finalize(sqlite3_stmt *statement) {
    if (cleanup_count < sizeof(cleanup) - 1) cleanup[cleanup_count++] = 'S';
    return __real_sqlite3_finalize(statement);
}
int __wrap_sqlite3_close_v2(sqlite3 *database) {
    if (cleanup_count < sizeof(cleanup) - 1) cleanup[cleanup_count++] = 'D';
    return __real_sqlite3_close_v2(database);
}
static void need(int yes, const char *message) {
    if (!yes) { fprintf(stderr, "observer failed: %s; errno=%d\n", message, errno); exit(2); }
}
static void wr(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> (8 * i));
}
static uint64_t rd(const unsigned char *p) {
    uint64_t value = 0; for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (8 * i); return value;
}
static uint64_t database(void *owner) {
    unsigned char input[24], out[24]; wr(input, 6); wr(input + 8, 8); memcpy(input + 16, ":memory:", 8);
    need(trnm_task_provider(owner, 2, input, 24, out, 24) == 24 && rd(out) == 0, "fixture database"); return rd(out + 8);
}
static uint64_t prepare(void *owner, uint64_t db, const char *sql) {
    unsigned char input[256], out[24]; size_t size = strlen(sql);
    need(size <= sizeof(input) - 16, "fixture SQL extent"); wr(input, db); wr(input + 8, size); memcpy(input + 16, sql, size);
    need(trnm_task_provider(owner, 5, input, 16 + size, out, 24) == 24 && rd(out) == 0, "fixture statement"); return rd(out + 8);
}
static void sql(void *owner, uint64_t db, const char *statement) {
    uint64_t handle = prepare(owner, db, statement); unsigned char input[8], out[24]; wr(input, handle);
    need(trnm_task_provider(owner, 7, input, 8, out, 24) == 24 && rd(out) == SQLITE_DONE, "fixture step");
    need(trnm_task_provider(owner, 9, input, 8, out, 24) == 24 && rd(out) == SQLITE_OK, "fixture finalize");
}
int main(int argc, char **argv) {
    need(argc == 4, "scenario, allocation index and actual path required");
    const char *scenario = argv[1]; failure = strtoll(argv[2], NULL, 10);
    unsigned char input[4096], out[8192]; memset(out, 0xa5, sizeof(out));
    if (!strcmp(scenario, "new-calloc") || !strcmp(scenario, "new-mutex")) {
        fail_calloc = !strcmp(scenario, "new-calloc"); fail_mutex = !fail_calloc;
        void *owner = trnm_task_provider_new(); need(!owner, "failed construction returned owner");
        need(owner_frees == (uint64_t)!strcmp(scenario, "new-mutex"), "failed mutex owner freed exactly once");
        need(mutex_destroy_calls == 0, "uninitialized mutex was destroyed");
        printf("{\"scenario\":\"%s\",\"status\":\"PASS\",\"null\":true,\"owner_frees\":%llu}\n", scenario, (unsigned long long)owner_frees); return 0;
    }
    need(sqlite3_initialize() == SQLITE_OK, "real SQLite initialization");
    void *owner = trnm_task_provider_new(); need(owner != NULL, "real provider owner");
    uint64_t db = 0, stmt = 0, op = 0, size = 0;
    if (!strcmp(scenario, "open")) {
        op = 2; wr(input, 6); wr(input + 8, 8); memcpy(input + 16, ":memory:", 8); size = 24;
    } else if (!strcmp(scenario, "prepare")) {
        db = database(owner); const char *source = "SELECT ?1, printf('%080d',1), zeroblob(19)";
        op = 5; size = strlen(source); wr(input, db); wr(input + 8, size); memcpy(input + 16, source, size); size += 16;
    } else if (!strcmp(scenario, "column")) {
        db = database(owner); sql(owner, db, "PRAGMA encoding='UTF-16le'"); sql(owner, db, "CREATE TABLE t(x TEXT)");
        sql(owner, db, "INSERT INTO t VALUES(hex(zeroblob(4096)))");
        stmt = prepare(owner, db, "SELECT x FROM t"); wr(input, stmt);
        need(trnm_task_provider(owner, 7, input, 8, out, sizeof(out)) == 24 && rd(out) == SQLITE_ROW, "fixture row");
        need(sqlite3_column_text16((sqlite3_stmt *)(uintptr_t)stmt, 0) != NULL,
             "real SQLite UTF16 representation before UTF8 allocation failure");
        op = 8; wr(input + 8, 0); size = 16;
    } else if (!strcmp(scenario, "invalid-path-flags")) {
        op = 17; size = strlen(argv[3]); need(size < sizeof(input) - 24, "fixture path extent");
        wr(input, UINT64_C(2147483648)); wr(input + 8, 0600); wr(input + 16, size); memcpy(input + 24, argv[3], size); size += 24;
    } else if (!strcmp(scenario, "close-eintr") || !strcmp(scenario, "close-eio")) {
        size = strlen(argv[3]); need(size < sizeof(input) - 24, "fixture path extent");
        wr(input, O_CREAT | O_RDWR | O_CLOEXEC); wr(input + 8, 0600); wr(input + 16, size); memcpy(input + 24, argv[3], size);
        need(trnm_task_provider(owner, 17, input, size + 24, out, sizeof(out)) == 24 && rd(out) == 0, "real owned descriptor");
        int fd = (int)rd(out + 8); wr(input, (uint64_t)fd); close_error = !strcmp(scenario, "close-eintr") ? EINTR : EIO; close_calls = 0;
        need(trnm_task_provider(owner, 18, input, 8, out, sizeof(out)) == 24 && rd(out) == (uint64_t)close_error, "actual close error preserved");
        need(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "close actually consumed descriptor"); close_error = 0;
        need(trnm_task_provider(owner, 18, input, 8, out, sizeof(out)) == UINT64_MAX && close_calls == 1, "no retry after consumed close");
        need(trnm_task_provider_reset(owner) == 0, "close removed ownership"); trnm_task_provider_free(owner);
        need(sqlite3_shutdown() == SQLITE_OK, "SQLite shutdown");
        printf("{\"scenario\":\"%s\",\"status\":\"PASS\",\"actual_close_calls\":1,\"consumed\":true}\n", scenario); return 0;
    } else { need(0, "unknown scenario"); }
    memset(out, 0xa5, sizeof(out)); calls = 0; hit = 0; cleanup_count = 0; memset(cleanup, 0, sizeof(cleanup)); armed = 1;
    uint64_t result = trnm_task_provider(owner, op, input, size, out, sizeof(out)); armed = 0;
    uint64_t code = result <= sizeof(out) && result >= 24 ? rd(out) : 0;
    uint64_t value_kind = result <= sizeof(out) && result >= 24 && op == 8 ? rd(out + 8) : 0;
    int has_handle = result == 24 && (op == 2 || op == 5) && rd(out + 8) != 0;
    if (result == UINT64_MAX || result == UINT64_MAX - 1)
        for (unsigned i = 0; i < sizeof(out); ++i) need(out[i] == 0xa5, "failure published output");
    uint64_t count = trnm_task_provider_reset(owner); need(trnm_task_provider_reset(owner) == 0, "reset idempotence");
    trnm_task_provider_free(owner); need(sqlite3_shutdown() == SQLITE_OK, "SQLite shutdown");
    need(sqlite3_memory_used() == 0 && live() == 0, "allocation/resource leak after owner drop");
    for (unsigned i = 0; i + 1 < cleanup_count; ++i)
        need(!(cleanup[i] == 'D' && cleanup[i + 1] == 'S'), "statement must precede database cleanup");
    printf("{\"scenario\":\"%s\",\"status\":\"PASS\",\"failure_index\":%lld,\"allocation_calls\":%llu,\"actual_failure_hit\":%s,\"return\":%llu,\"code\":%llu,\"value_kind\":%llu,\"handle_returned\":%s,\"reset_resources\":%llu,\"cleanup\":\"%s\",\"live_allocations\":0,\"sqlite_memory\":0}\n", scenario, (long long)failure, (unsigned long long)calls, hit ? "true" : "false", (unsigned long long)result, (unsigned long long)code, (unsigned long long)value_kind, has_handle ? "true" : "false", (unsigned long long)count, cleanup);
    return 0;
}
