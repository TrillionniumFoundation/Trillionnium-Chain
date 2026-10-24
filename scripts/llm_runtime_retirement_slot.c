/* PN4 preparation only: original O's one preborn, fixed-stack worker.
 * No deletion, effect-activation, root-clear or resource-return API exists yet.
 * Compiled after the unchanged spawn source in the same sealed native owner. */
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>

#define TRNM_RETIRE_STACK (1024U * 1024U)
#define TRNM_RETIRE_WORDS 24U
enum { TRNM_RETIRE_EMPTY, TRNM_RETIRE_OWNED, TRNM_RETIRE_STARTING,
       TRNM_RETIRE_READY, TRNM_RETIRE_EXPIRED, TRNM_RETIRE_UNKNOWN };
_Static_assert(ATOMIC_INT_LOCK_FREE == 2 && sizeof(_Atomic unsigned) == 4,
               "retirement-futex-requires-lock-free-u32");
static struct {
    _Atomic unsigned phase, command, expired;
    _Atomic int error, tid, wait_finished;
    _Atomic uintptr_t stack_sample;
    pid_t pid, owner_tid;
    uint64_t observer[3], deadline;
    uint64_t *output;
    void *mapping, *stack;
    size_t mapping_size, page;
    int membership[4], created;
    char expected[4097];
    size_t expected_size;
    pthread_attr_t attributes;
    pthread_t worker;
} trnm_retirement;

static int trnm_retirement_membership(void) {
    char raw[4097], extra;
    int *slot = trnm_retirement.membership;
    slot[1] = open("/proc/thread-self/cgroup", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (slot[1] < 0) return errno;
    ssize_t size = read(slot[1], raw, sizeof(raw));
    int error = size < 0 ? errno : 0;
    if (!error && ((size_t)size != trnm_retirement.expected_size ||
        memcmp(raw, trnm_retirement.expected, (size_t)size) || read(slot[1], &extra, 1) != 0))
        error = EINVAL;
    int closed = trnm_kernel_release_owned_v1(slot);
    return error ? error : closed;
}

static void *trnm_retirement_worker(void *unused) {
    (void)unused;
    unsigned char stack_sample;
    atomic_store(&trnm_retirement.stack_sample, (uintptr_t)&stack_sample);
    atomic_store(&trnm_retirement.tid, (int)syscall(SYS_gettid));
    int error = getpid() != trnm_retirement.pid ? EPERM : trnm_retirement_membership();
    if (!error && (!trnm_before(trnm_retirement.deadline) || atomic_load(&trnm_retirement.expired)))
        error = ETIMEDOUT;
    if (!error) {
        atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_READY, memory_order_release);
        struct timespec cutoff = {.tv_sec = (time_t)(trnm_retirement.deadline / UINT64_C(1000000000)),
            .tv_nsec = (long)(trnm_retirement.deadline % UINT64_C(1000000000))};
        /* No command producer exists in this preparation slice. One original
         * absolute monotonic wait, no queue, retry or later-born helper. */
        if (syscall(SYS_futex, &trnm_retirement.command, FUTEX_WAIT_BITSET_PRIVATE,
            0, &cutoff, NULL, FUTEX_BITSET_MATCH_ANY) < 0) error = errno;
        else error = EPROTO;
    }
    int no_error = 0;
    atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, error);
    atomic_store_explicit(&trnm_retirement.phase,
        atomic_load(&trnm_retirement.error) == ETIMEDOUT ? TRNM_RETIRE_EXPIRED : TRNM_RETIRE_UNKNOWN,
        memory_order_release);
    atomic_store_explicit(&trnm_retirement.wait_finished, 1, memory_order_release);
    return NULL; /* Original custom stack/map/root are deliberately retained. */
}

int trnm_kernel_retirement_snapshot_v1(uint64_t output[TRNM_RETIRE_WORDS]) {
    if (!output || output != trnm_retirement.output || getpid() != trnm_retirement.pid ||
        syscall(SYS_gettid) != trnm_retirement.owner_tid) return EPERM;
    unsigned phase = atomic_load_explicit(&trnm_retirement.phase, memory_order_acquire);
    if ((phase == TRNM_RETIRE_STARTING || phase == TRNM_RETIRE_READY) &&
        !trnm_before(trnm_retirement.deadline)) {
        atomic_store(&trnm_retirement.expired, 1);
        int no_error = 0;
        atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, ETIMEDOUT);
    }
    memset(output, 0, TRNM_RETIRE_WORDS * sizeof(*output));
    output[0] = atomic_load(&trnm_retirement.expired) ? TRNM_RETIRE_EXPIRED : phase;
    output[1] = (uint64_t)atomic_load(&trnm_retirement.error);
    output[2] = (uint64_t)trnm_retirement.pid; output[3] = (uint64_t)trnm_retirement.owner_tid;
    output[4] = (uint64_t)atomic_load(&trnm_retirement.tid);
    for (unsigned i = 0; i < 3; i++) output[5+i] = trnm_retirement.observer[i];
    output[8] = trnm_retirement.deadline; output[9] = (uintptr_t)trnm_retirement.mapping;
    output[10] = trnm_retirement.mapping_size; output[11] = (uintptr_t)trnm_retirement.stack;
    output[12] = TRNM_RETIRE_STACK; output[13] = trnm_retirement.page;
    /* The membership slot is stable only after worker membership IO ends. */
    if (phase == TRNM_RETIRE_READY || phase == TRNM_RETIRE_EXPIRED || phase == TRNM_RETIRE_UNKNOWN) {
        output[14] = (uint64_t)trnm_retirement.membership[0];
        output[15] = (uint64_t)trnm_retirement.membership[1];
    }
    output[16] = (uint64_t)trnm_retirement.created;
    output[17] = (uint64_t)atomic_load_explicit(&trnm_retirement.wait_finished, memory_order_acquire);
    output[18] = atomic_load(&trnm_retirement.stack_sample);
    return 0;
}

int trnm_kernel_retirement_prepare_v1(int observer, const uint64_t identity[3],
        const char *membership, size_t membership_size, uint64_t deadline,
        uint64_t output[TRNM_RETIRE_WORDS]) {
    uint64_t now = trnm_now_ns();
    struct stat meta; struct statfs fs;
    if (!output || !identity || !membership || !membership_size || membership_size > 4096 ||
        membership[membership_size-1] != '\n' || memchr(membership, 0, membership_size) ||
        !now || deadline <= now || deadline-now > UINT64_C(8000000000) ||
        fstat(observer, &meta) || fstatfs(observer, &fs) || fs.f_type != TRNM_CGROUP2_MAGIC ||
        !S_ISDIR(meta.st_mode) || (uint64_t)meta.st_dev != identity[0] ||
        (uint64_t)meta.st_ino != identity[1] || (uint64_t)meta.st_mode != identity[2]) return EINVAL;
    for (unsigned i = 0; i < TRNM_RETIRE_WORDS; i++) if (output[i]) return EINVAL;
    unsigned empty = TRNM_RETIRE_EMPTY;
    if (!atomic_compare_exchange_strong(&trnm_retirement.phase, &empty, TRNM_RETIRE_OWNED))
        return EALREADY;
    trnm_retirement.output = output; trnm_retirement.pid = getpid();
    trnm_retirement.owner_tid = (pid_t)syscall(SYS_gettid); trnm_retirement.deadline = deadline;
    for (unsigned i = 0; i < 3; i++) trnm_retirement.observer[i] = identity[i];
    memcpy(trnm_retirement.expected, membership, membership_size);
    trnm_retirement.expected_size = membership_size;
    trnm_retirement.membership[1] = trnm_retirement.membership[2] = trnm_retirement.membership[3] = -1;
    int error = trnm_retirement_membership();
    long page = sysconf(_SC_PAGESIZE);
    if (!error && (page < 4096 || page > 65536 || (page & (page-1)) ||
        TRNM_RETIRE_STACK % (size_t)page)) error = EINVAL;
    if (!error) {
        trnm_retirement.page = (size_t)page;
        trnm_retirement.mapping_size = TRNM_RETIRE_STACK + 2 * (size_t)page;
        void *mapping = mmap(NULL, trnm_retirement.mapping_size, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) error = errno;
        else {
            trnm_retirement.mapping = mapping;
            trnm_retirement.stack = (unsigned char *)mapping + page;
            if (mprotect(trnm_retirement.stack, TRNM_RETIRE_STACK, PROT_READ | PROT_WRITE)) error = errno;
        }
    }
    if (!error) error = pthread_attr_init(&trnm_retirement.attributes);
    if (!error) error = pthread_attr_setstack(&trnm_retirement.attributes,
        trnm_retirement.stack, TRNM_RETIRE_STACK);
    if (!error) error = pthread_attr_setdetachstate(&trnm_retirement.attributes, PTHREAD_CREATE_DETACHED);
    if (!error && !trnm_before(deadline)) error = ETIMEDOUT;
    if (!error) {
        atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_STARTING, memory_order_release);
        error = pthread_create(&trnm_retirement.worker, &trnm_retirement.attributes,
            trnm_retirement_worker, NULL);
        if (!error) trnm_retirement.created = 1;
    }
    if (error) {
        atomic_store(&trnm_retirement.error, error);
        atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_UNKNOWN, memory_order_release);
    }
    int observed = trnm_kernel_retirement_snapshot_v1(output);
    return error ? error : observed;
}
