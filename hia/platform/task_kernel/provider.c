/* Mechanical provider only. All SQL, schema, policy, authentication, transaction
 * ordering and private receipts belong to the HIA owner. This translation unit
 * neither names a task-kernel table nor accepts a caller's validation result.
 * Build exclusively through the independently fenced build_provider.py.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "sqlite3.h"

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__BYTE_ORDER__) \
    || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The task-kernel native provider admits Linux x86_64 little-endian only"
#endif
#if SQLITE_VERSION_NUMBER != 3054001
#error "The task-kernel native provider requires bundled SQLite 3.54.1"
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8 && sizeof(int) == 4,
               "Unsupported native primitive layout");

uint64_t trnm_io_witness_layout(int key);
const char *trnm_io_witness_compileoption(int index);
int trnm_io_witness_version(void);
const char *trnm_io_witness_source_id(void);

/* Private foreign resources contain no chain state or task policy. The HIA
 * driver retains this opaque provider capability and never publishes it in a
 * result. The list supports mechanical cleanup if a native allocation fails. */
struct resource {
    void *pointer;
    int kind; /* 0 database, 1 statement, 2 owned descriptor encoded as fd+1 */
    struct resource *next;
};
struct provider {
    struct resource *resources;
    pthread_mutex_t lock;
};

void *trnm_task_provider_new(void) {
    struct provider *owner = calloc(1, sizeof(*owner));
    if (!owner) return NULL;
    if (pthread_mutex_init(&owner->lock, NULL)) {
        free(owner);
        return NULL;
    }
    return owner;
}

int trnm_task_provider_enter(void *opaque) {
    return pthread_mutex_lock(&((struct provider *)opaque)->lock);
}

int trnm_task_provider_leave(void *opaque) {
    return pthread_mutex_unlock(&((struct provider *)opaque)->lock);
}

static int contains(struct provider *owner, void *pointer, int kind) {
    for (struct resource *r = owner->resources; r; r = r->next)
        if (r->pointer == pointer && r->kind == kind) return 1;
    return 0;
}

static int retain(struct provider *owner, void *pointer, int kind) {
    if (!pointer) return 0;
    struct resource *r = malloc(sizeof(*r));
    if (!r) return -1;
    r->pointer = pointer;
    r->kind = kind;
    r->next = owner->resources;
    owner->resources = r;
    return 0;
}

static void release(struct provider *owner, void *pointer, int kind) {
    struct resource **slot = &owner->resources;
    while (*slot && ((*slot)->pointer != pointer || (*slot)->kind != kind)) slot = &(*slot)->next;
    if (*slot) {
        struct resource *r = *slot;
        *slot = r->next;
        free(r);
    }
}

uint64_t trnm_task_provider_reset(void *opaque) {
    struct provider *owner = opaque;
    uint64_t count = 0;
    struct resource **slot = &owner->resources;
    while (*slot) {
        struct resource *r = *slot;
        if (r->kind == 1) {
            (void)sqlite3_finalize(r->pointer);
            *slot = r->next;
            free(r);
            ++count;
        } else slot = &r->next;
    }
    while (owner->resources) {
        struct resource *r = owner->resources;
        owner->resources = r->next;
        if (r->kind == 2) (void)close((int)((uintptr_t)r->pointer - 1));
        else (void)sqlite3_close_v2(r->pointer);
        free(r);
        ++count;
    }
    return count;
}

void trnm_task_provider_free(void *opaque) {
    if (!opaque) return;
    struct provider *owner = opaque;
    (void)trnm_task_provider_reset(owner);
    (void)pthread_mutex_destroy(&owner->lock);
    free(owner);
}

static uint64_t rd(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static void wr(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> (i * 8));
}

static uint64_t scalar(unsigned char *out, uint64_t cap, uint64_t code,
                       uint64_t first, uint64_t second) {
    if (cap >= 24) {
        wr(out, code);
        wr(out + 8, first);
        wr(out + 16, second);
    }
    return 24;
}

static uint64_t bytes(unsigned char *out, uint64_t cap, uint64_t kind,
                      const void *data, uint64_t size) {
    if (size > UINT64_MAX - 24) return UINT64_MAX;
    uint64_t need = 24 + size;
    if (cap >= need) {
        wr(out, 0);
        wr(out + 8, kind);
        wr(out + 16, size);
        if (size) memcpy(out + 24, data, (size_t)size);
    }
    return need;
}

static uint64_t text(unsigned char *out, uint64_t cap, const char *value) {
    return bytes(out, cap, SQLITE_TEXT, value, value ? strlen(value) : 0);
}

/* The output is allocated by the native HIA driver. Insufficient space causes
 * no side effect: all mutating operations have a fixed 24-byte response, while
 * variable responses only inspect an already retained C object.
 * UINT64_MAX means an invalid provider frame, distinct from all SQLite/errno
 * results and from every task-kernel business error. UINT64_MAX-1 means a
 * failed private bridge allocation; the native driver returns its allocation
 * failure and resets all foreign resources, never inventing a SQLite/OS error.
 */
uint64_t trnm_task_provider(void *opaque, uint64_t op, const unsigned char *request,
                            uint64_t size, unsigned char *out, uint64_t cap) {
    if (!opaque || (size && !request) || (cap && !out) || size > SIZE_MAX || cap > SIZE_MAX)
        return UINT64_MAX;
    if (cap < 24) return 24;
    uint64_t a = size >= 8 ? rd(request) : 0;
    uint64_t b = size >= 16 ? rd(request + 8) : 0;
    uint64_t c = size >= 24 ? rd(request + 16) : 0;
    sqlite3 *db = (sqlite3 *)(uintptr_t)a;
    sqlite3_stmt *stmt = (sqlite3_stmt *)(uintptr_t)a;
    struct provider *owner = opaque;
    int code;

    if ((op == 3 || op == 4 || op == 5 || op == 10 || op == 25 || op == 27) && !contains(owner, db, 0))
        return UINT64_MAX;
    if ((op == 11 || op == 12) && db && !contains(owner, db, 0)) return UINT64_MAX;
    if ((op == 6 || op == 7 || op == 8 || op == 9 || op == 13 || op == 14 || op == 26) &&
        !contains(owner, stmt, 1)) return UINT64_MAX;
    if ((op == 18 || op == 19 || op == 29) &&
        (a > INT_MAX || !contains(owner, (void *)(uintptr_t)(a + 1), 2))) return UINT64_MAX;

    switch (op) {
    case 1: /* Independent compile-time witness/runtime identity observation. */
        if (size != 16 || b > INT_MAX) return UINT64_MAX;
        switch (a) {
        case 0: return scalar(out, cap, 0, sqlite3_libversion_number(), sqlite3_threadsafe());
        case 1: return text(out, cap, sqlite3_sourceid());
        case 2: return text(out, cap, sqlite3_compileoption_get((int)b));
        case 3: return scalar(out, cap, 0, trnm_io_witness_version(), trnm_io_witness_layout((int)b));
        case 4: return text(out, cap, trnm_io_witness_source_id());
        case 5: return text(out, cap, trnm_io_witness_compileoption((int)b));
        default: return UINT64_MAX;
        }
    case 2: { /* sqlite3_open_v2(flags, exact NUL-free path bytes). */
        if (size < 16 || a > INT_MAX || b != size - 16 || b >= SIZE_MAX ||
            memchr(request + 16, 0, (size_t)b)) return UINT64_MAX;
        char *path = malloc((size_t)b + 1);
        if (!path) return UINT64_MAX - 1;
        memcpy(path, request + 16, (size_t)b);
        path[b] = 0;
        sqlite3 *opened = NULL;
        code = sqlite3_open_v2(path, &opened, (int)a, NULL);
        free(path);
        if (retain(owner, opened, 0)) {
            (void)sqlite3_close(opened);
            return UINT64_MAX - 1;
        }
        return scalar(out, cap, (uint64_t)code, (uint64_t)(uintptr_t)opened, 0);
    }
    case 3: /* sqlite3_close, with actual SQLite failure returned. */
        if (size != 8) return UINT64_MAX;
        code = sqlite3_close(db);
        if (code == SQLITE_OK) release(owner, db, 0);
        return scalar(out, cap, (uint64_t)code, 0, 0);
    case 4:
        if (size != 16 || b > INT_MAX) return UINT64_MAX;
        return scalar(out, cap, (uint64_t)sqlite3_busy_timeout(db, (int)b), 0, 0);
    case 5: { /* Prepare exact SQL bytes; caller owns statement/finalization. */
        if (size < 16 || b != size - 16 || b > INT_MAX) return UINT64_MAX;
        sqlite3_stmt *prepared = NULL;
        const char *start = (const char *)request + 16;
        const char *tail = start;
        code = sqlite3_prepare_v3(db, start, (int)b, 0, &prepared, &tail);
        if (retain(owner, prepared, 1)) {
            (void)sqlite3_finalize(prepared);
            return UINT64_MAX - 1;
        }
        return scalar(out, cap, (uint64_t)code, (uint64_t)(uintptr_t)prepared,
                      tail && tail >= start && tail <= start + b ? (uint64_t)(tail - start) : 0);
    }
    case 6: /* Bind a typed value; SQLite copies non-scalar storage. */
        if (size < 24 || b == 0 || b > INT_MAX) return UINT64_MAX;
        if (c == SQLITE_NULL && size == 24) code = sqlite3_bind_null(stmt, (int)b);
        else if (c == SQLITE_INTEGER && size == 32)
            code = sqlite3_bind_int64(stmt, (int)b, (sqlite3_int64)rd(request + 24));
        else if (c == SQLITE_FLOAT && size == 32) {
            double value;
            memcpy(&value, request + 24, sizeof(value));
            code = sqlite3_bind_double(stmt, (int)b, value);
        } else if (c == SQLITE_BLOB)
            code = sqlite3_bind_blob64(stmt, (int)b, request + 24, size - 24, SQLITE_TRANSIENT);
        else if (c == SQLITE_TEXT)
            code = sqlite3_bind_text64(stmt, (int)b, (const char *)request + 24,
                                       size - 24, SQLITE_TRANSIENT, SQLITE_UTF8);
        else return UINT64_MAX;
        return scalar(out, cap, (uint64_t)code, 0, 0);
    case 7:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, (uint64_t)sqlite3_step(stmt), 0, 0);
    case 8: { /* Current row's typed column, without stepping again. */
        if (size != 16 || b > INT_MAX || b >= (uint64_t)sqlite3_column_count(stmt))
            return UINT64_MAX;
        int kind = sqlite3_column_type(stmt, (int)b);
        if (kind == SQLITE_NULL) return bytes(out, cap, (uint64_t)kind, NULL, 0);
        if (kind == SQLITE_INTEGER) {
            unsigned char value[8];
            wr(value, (uint64_t)sqlite3_column_int64(stmt, (int)b));
            return bytes(out, cap, (uint64_t)kind, value, sizeof(value));
        }
        if (kind == SQLITE_FLOAT) {
            double value = sqlite3_column_double(stmt, (int)b);
            return bytes(out, cap, (uint64_t)kind, &value, sizeof(value));
        }
        const void *value = kind == SQLITE_TEXT
            ? (const void *)sqlite3_column_text(stmt, (int)b) : sqlite3_column_blob(stmt, (int)b);
        int count = sqlite3_column_bytes(stmt, (int)b);
        if (!value && (count || sqlite3_errcode(sqlite3_db_handle(stmt)) == SQLITE_NOMEM))
            return scalar(out, cap, SQLITE_NOMEM, 0, 0);
        return bytes(out, cap, (uint64_t)kind, value, (uint64_t)count);
    }
    case 9:
        if (size != 8) return UINT64_MAX;
        code = sqlite3_finalize(stmt);
        release(owner, stmt, 1);
        return scalar(out, cap, (uint64_t)code, 0, 0);
    case 10:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)sqlite3_changes64(db), 0);
    case 11:
        if (size != 8) return UINT64_MAX;
        return text(out, cap, sqlite3_errmsg(db));
    case 12:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)sqlite3_extended_errcode(db), 0);
    case 13:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)sqlite3_column_count(stmt), 0);
    case 14:
        if (size != 16 || b > INT_MAX || b >= (uint64_t)sqlite3_column_count(stmt))
            return UINT64_MAX;
        return text(out, cap, sqlite3_column_name(stmt, (int)b));
    case 18: {
        if (size != 8 || a > INT_MAX) return UINT64_MAX;
        code = close((int)a);
        int cause = code < 0 ? errno : 0;
        /* On the admitted Linux target, close releases the descriptor even
         * when reporting EINTR or delayed I/O errors. Never close it twice. */
        release(owner, (void *)(uintptr_t)(a + 1), 2);
        return scalar(out, cap, (uint64_t)cause, 0, 0);
    }
    case 19:
        if (size != 8 || a > INT_MAX) return UINT64_MAX;
        code = fsync((int)a);
        return scalar(out, cap, code < 0 ? (uint64_t)errno : 0, 0, 0);
    case 22: {
        if (size) return UINT64_MAX;
        struct timespec value;
        code = clock_gettime(CLOCK_REALTIME, &value);
        if (code < 0) return scalar(out, cap, (uint64_t)errno, 0, 0);
        return scalar(out, cap, 0, (uint64_t)value.tv_sec, (uint64_t)value.tv_nsec);
    }
    case 23:
        if (size) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)getpid(), 0);
    case 24:
        if (size != 8 || a > INT_MAX) return UINT64_MAX;
        return text(out, cap, strerror((int)a));
    case 25:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)(int64_t)sqlite3_error_offset(db), 0);
    case 26:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)sqlite3_bind_parameter_count(stmt), 0);
    case 27:
        if (size != 8) return UINT64_MAX;
        return scalar(out, cap, 0, (uint64_t)sqlite3_errcode(db), 0);
    case 28:
        if (size != 8 || a > INT_MAX) return UINT64_MAX;
        return text(out, cap, sqlite3_errstr((int)a));
    case 29: { /* One actual owned-fd read; short reads, EOF and EINTR remain visible. */
        if (size != 16 || b > SIZE_MAX - 24) return UINT64_MAX;
        if (b > cap - 24) return b + 24; /* no read before sufficient capacity */
        ssize_t count = read((int)a, out + 24, (size_t)b);
        if (count < 0) return scalar(out, cap, (uint64_t)errno, 0, 0);
        wr(out, 0);
        wr(out + 8, (uint64_t)count);
        wr(out + 16, 0);
        return 24 + (uint64_t)count;
    }
    default: break;
    }

    /* Filesystem operations preserve raw path bytes and errno. Parent walking,
     * sidecar order, file-type checks, retry limits and commit uncertainty are
     * exclusively HIA policy decisions. */
    if (op != 15 && op != 16 && op != 17 && op != 20 && op != 21) return UINT64_MAX;
    if (size < 24 || c > size - 24 || c >= SIZE_MAX || memchr(request + 24, 0, (size_t)c))
        return UINT64_MAX;
    uint64_t rest = size - 24 - c;
    if ((op != 20 && rest) || (op == 20 && memchr(request + 24 + c, 0, (size_t)rest)))
        return UINT64_MAX;
    char *path = malloc((size_t)c + 1);
    if (!path) return UINT64_MAX - 1;
    memcpy(path, request + 24, (size_t)c);
    path[c] = 0;
    uint64_t result;
    if (op == 15) {
        struct stat observed;
        if (a > 1) result = UINT64_MAX;
        else {
            code = a ? stat(path, &observed) : lstat(path, &observed);
            result = code < 0 ? scalar(out, cap, (uint64_t)errno, 0, 0)
                             : scalar(out, cap, 0, (uint64_t)observed.st_mode, (uint64_t)observed.st_size);
        }
    } else if (op == 16) {
        if (a > UINT_MAX) result = UINT64_MAX;
        else {
            code = mkdir(path, (mode_t)a);
            result = scalar(out, cap, code < 0 ? (uint64_t)errno : 0, 0, 0);
        }
    } else if (op == 17) {
        if (a > INT_MAX || b > UINT_MAX) result = UINT64_MAX;
        else {
            code = open(path, (int)a, (mode_t)b);
            if (code >= 0 && retain(owner, (void *)(uintptr_t)((uint64_t)code + 1), 2)) {
                (void)close(code);
                result = UINT64_MAX - 1;
            } else {
                result = scalar(out, cap, code < 0 ? (uint64_t)errno : 0,
                                (uint64_t)(int64_t)code, 0);
            }
        }
    } else if (op == 21) {
        code = unlink(path);
        result = scalar(out, cap, code < 0 ? (uint64_t)errno : 0, 0, 0);
    } else {
        char *target = malloc((size_t)rest + 1);
        if (!target) result = UINT64_MAX - 1;
        else {
            memcpy(target, request + 24 + c, (size_t)rest);
            target[rest] = 0;
            code = link(path, target);
            result = scalar(out, cap, code < 0 ? (uint64_t)errno : 0, 0, 0);
            free(target);
        }
    }
    free(path);
    return result;
}
