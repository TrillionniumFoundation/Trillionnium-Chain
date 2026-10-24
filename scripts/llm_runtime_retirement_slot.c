/* PN4 original O's one preborn, fixed-stack, one-effect retirement worker.
 * Private mechanism only: no root-clear or resource-return authority.
 * Compiled after the unchanged spawn source in the same sealed native owner. */
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>

#define TRNM_RETIRE_STACK (1024U * 1024U)
#define TRNM_RETIRE_WORDS 24U
enum { TRNM_RETIRE_EMPTY, TRNM_RETIRE_OWNED, TRNM_RETIRE_STARTING,
       TRNM_RETIRE_READY, TRNM_RETIRE_EXPIRED, TRNM_RETIRE_UNKNOWN,
       TRNM_RETIRE_RUNNING, TRNM_RETIRE_DONE };
_Static_assert(ATOMIC_INT_LOCK_FREE == 2 && sizeof(_Atomic unsigned) == 4,
               "retirement-futex-requires-lock-free-u32");
static struct {
    _Atomic unsigned phase, command, expired, claimed, progress, effect_finished;
    _Atomic int error, tid, wait_finished, pidfd_close_error;
    _Atomic uintptr_t stack_sample;
    pid_t pid, owner_tid;
    uint64_t observer[3], deadline;
    uint64_t *output;
    void *mapping, *stack;
    size_t mapping_size, page;
    int membership[4], created;
    char expected[4097];
    size_t expected_size;
    int parent, *aggregate, *controller, *child;
    uint64_t identities[12];
    pthread_attr_t attributes;
    pthread_t worker;
} trnm_retirement;

static int trnm_retirement_check_membership(int slot[4]) {
    char raw[4097], extra;
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

/* Original held-object checks; names and order are fixed, never caller paths.
 * The namespace is the original administrator-controlled closed world. Linux
 * unlinkat has no expected-inode argument: unexpected replacement fails closed
 * before/after the effect, without claiming atomic hostile-rename protection. */
static int trnm_retirement_identity(int fd, const uint64_t id[3]) {
    struct stat meta;
    if (fd < 3 || fstat(fd, &meta)) return EBADF;
    return (uint64_t)meta.st_dev == id[0] && (uint64_t)meta.st_ino == id[1] &&
        (uint64_t)meta.st_mode == id[2] ? 0 : ESTALE;
}
static int trnm_retirement_named(int parent, const char *name, int *slot, const uint64_t id[3]) {
    struct stat meta;
    int error = trnm_retirement_identity(slot[1], id);
    if (error) return error;
    if (slot[0] || slot[2] != -1 || slot[3] != -1 || !S_ISDIR(id[2])) return EINVAL;
    if (fstatat(parent, name, &meta, AT_SYMLINK_NOFOLLOW)) return errno;
    return (uint64_t)meta.st_dev == id[0] && (uint64_t)meta.st_ino == id[1] &&
        (uint64_t)meta.st_mode == id[2] ? 0 : ESTALE;
}
static int trnm_retirement_timely(void) {
    return !atomic_load(&trnm_retirement.error) && !atomic_load(&trnm_retirement.expired) &&
        trnm_before(trnm_retirement.deadline);
}
static int trnm_retirement_remove(const char *name, int *slot, const uint64_t id[3], unsigned bit) {
    if (!trnm_retirement_timely()) return ETIMEDOUT;
    int error = trnm_retirement_named(trnm_retirement.parent, name, slot, id);
    if (error) return error;
    if (unlinkat(trnm_retirement.parent, name, AT_REMOVEDIR)) return errno;
    atomic_fetch_or_explicit(&trnm_retirement.progress, bit, memory_order_release);
    /* Record the irreversible removal even when it returned after the cutoff.
     * Never start the next effect on a late/unknown result. */
    if (!trnm_retirement_timely()) return ETIMEDOUT;
    struct stat meta;
    if (!fstatat(trnm_retirement.parent, name, &meta, AT_SYMLINK_NOFOLLOW)) return ESTALE;
    if (errno != ENOENT) return errno;
    error = trnm_retirement_identity(slot[1], id);
    if (error) return error;
    if (!trnm_retirement_timely()) return ETIMEDOUT;
    error = trnm_kernel_release_owned_v1(slot);
    atomic_fetch_or_explicit(&trnm_retirement.progress, bit << 1, memory_order_release);
    return error ? error : trnm_retirement_timely() ? 0 : ETIMEDOUT;
}
static int trnm_retirement_effect(void) {
    int membership[4] = {0, -1, -1, -1};
    int error = trnm_retirement_timely() ? trnm_retirement_check_membership(membership) : ETIMEDOUT;
    if (!error) error = trnm_retirement_identity(trnm_retirement.parent, trnm_retirement.identities);
    if (!error) error = trnm_retirement_named(trnm_retirement.parent, "aggregate",
        trnm_retirement.aggregate, trnm_retirement.identities + 3);
    if (!error) error = trnm_retirement_named(trnm_retirement.parent, "controller",
        trnm_retirement.controller, trnm_retirement.identities + 6);
    if (!error) error = trnm_retirement_identity(trnm_retirement.child[1], trnm_retirement.identities + 9);
    if (!error) error = trnm_retirement_remove("aggregate", trnm_retirement.aggregate,
        trnm_retirement.identities + 3, 1U);
    if (!error) error = trnm_retirement_remove("controller", trnm_retirement.controller,
        trnm_retirement.identities + 6, 4U);
    if (!error && !trnm_retirement_timely()) error = ETIMEDOUT;
    if (!error) {
        error = trnm_kernel_close_v1(trnm_retirement.child, 2U);
        atomic_store(&trnm_retirement.pidfd_close_error, error);
        atomic_fetch_or_explicit(&trnm_retirement.progress, 16U, memory_order_release);
        if (!error && !trnm_retirement_timely()) error = ETIMEDOUT;
    }
    return error;
}

static void *trnm_retirement_worker(void *unused) {
    (void)unused;
    unsigned char stack_sample;
    atomic_store(&trnm_retirement.stack_sample, (uintptr_t)&stack_sample);
    atomic_store(&trnm_retirement.tid, (int)syscall(SYS_gettid));
    int error = getpid() != trnm_retirement.pid ? EPERM : trnm_retirement_check_membership(trnm_retirement.membership);
    if (!error && (!trnm_before(trnm_retirement.deadline) || atomic_load(&trnm_retirement.expired)))
        error = ETIMEDOUT;
    if (!error) {
        atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_READY, memory_order_release);
        struct timespec cutoff = {.tv_sec = (time_t)(trnm_retirement.deadline / UINT64_C(1000000000)),
            .tv_nsec = (long)(trnm_retirement.deadline % UINT64_C(1000000000))};
        /* One absolute wait. A command already published before futex enters
         * yields EAGAIN; acquire its payload, without another wait or retry. */
        int waited = (int)syscall(SYS_futex, &trnm_retirement.command, FUTEX_WAIT_BITSET_PRIVATE,
            0, &cutoff, NULL, FUTEX_BITSET_MATCH_ANY);
        int wait_error = waited < 0 ? errno : 0;
        unsigned command = atomic_load_explicit(&trnm_retirement.command, memory_order_acquire);
        if (command == 1 && (!wait_error || wait_error == EAGAIN)) {
            atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_RUNNING, memory_order_release);
            error = trnm_retirement_effect();
            atomic_store_explicit(&trnm_retirement.effect_finished, 1, memory_order_release);
        } else error = wait_error ? wait_error : EPROTO;
    }
    int no_error = 0;
    atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, error);
    atomic_store_explicit(&trnm_retirement.phase,
        atomic_load(&trnm_retirement.error) == ETIMEDOUT ? TRNM_RETIRE_EXPIRED :
        atomic_load(&trnm_retirement.error) ? TRNM_RETIRE_UNKNOWN : TRNM_RETIRE_DONE,
        memory_order_release);
    atomic_store_explicit(&trnm_retirement.wait_finished, 1, memory_order_release);
    return NULL; /* Original custom stack/map/root are deliberately retained. */
}

int trnm_kernel_retirement_snapshot_v1(uint64_t output[TRNM_RETIRE_WORDS]) {
    /* OWNED is still initializing ordinary fields. Acquire the publication
     * before even comparing its stored output/PID/TID, including on refusal. */
    unsigned phase = atomic_load_explicit(&trnm_retirement.phase, memory_order_acquire);
    if (phase == TRNM_RETIRE_EMPTY || phase == TRNM_RETIRE_OWNED) return EAGAIN;
    if (!output || output != trnm_retirement.output || getpid() != trnm_retirement.pid ||
        syscall(SYS_gettid) != trnm_retirement.owner_tid) return EPERM;
    if ((phase == TRNM_RETIRE_STARTING || phase == TRNM_RETIRE_READY || phase == TRNM_RETIRE_RUNNING) &&
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
    if (phase == TRNM_RETIRE_READY || phase == TRNM_RETIRE_EXPIRED || phase == TRNM_RETIRE_UNKNOWN ||
        phase == TRNM_RETIRE_RUNNING || phase == TRNM_RETIRE_DONE) {
        output[14] = (uint64_t)trnm_retirement.membership[0];
        output[15] = (uint64_t)trnm_retirement.membership[1];
    }
    output[16] = (uint64_t)trnm_retirement.created;
    output[17] = (uint64_t)atomic_load_explicit(&trnm_retirement.wait_finished, memory_order_acquire);
    output[18] = atomic_load(&trnm_retirement.stack_sample);
    output[19] = atomic_load(&trnm_retirement.claimed);
    output[20] = atomic_load_explicit(&trnm_retirement.progress, memory_order_acquire);
    output[21] = atomic_load_explicit(&trnm_retirement.effect_finished, memory_order_acquire);
    output[22] = (uint64_t)atomic_load(&trnm_retirement.pidfd_close_error);
    return 0;
}

int trnm_kernel_retirement_prepare_v1(int observer, const uint64_t identity[3],
        const char *membership, size_t membership_size, uint64_t deadline,
        uint64_t output[TRNM_RETIRE_WORDS]) {
    /* An occupied slot never inspects caller buffers, which may be the output
     * currently written by its original owner's snapshot. Immutable identity/
     * membership inputs are validated only while the slot still appears empty. */
    if (atomic_load_explicit(&trnm_retirement.phase, memory_order_acquire) != TRNM_RETIRE_EMPTY)
        return EALREADY;
    uint64_t now = trnm_now_ns();
    struct stat meta; struct statfs fs;
    if (!output || !identity || !membership || !membership_size || membership_size > 4096 ||
        membership[membership_size-1] != '\n' || memchr(membership, 0, membership_size) ||
        !now || deadline <= now || deadline-now > UINT64_C(8000000000) ||
        fstat(observer, &meta) || fstatfs(observer, &fs) || fs.f_type != TRNM_CGROUP2_MAGIC ||
        !S_ISDIR(meta.st_mode) || (uint64_t)meta.st_dev != identity[0] ||
        (uint64_t)meta.st_ino != identity[1] || (uint64_t)meta.st_mode != identity[2]) return EINVAL;
    unsigned empty = TRNM_RETIRE_EMPTY;
    if (!atomic_compare_exchange_strong(&trnm_retirement.phase, &empty, TRNM_RETIRE_OWNED))
        return EALREADY;
    /* Only the winning initializer can read this shared output. All snapshots
     * refuse OWNED and every competing prepare loses before its output scan. */
    int error = 0;
    for (unsigned i = 0; i < TRNM_RETIRE_WORDS; i++) if (output[i]) { error = EINVAL; break; }
    trnm_retirement.output = output; trnm_retirement.pid = getpid();
    trnm_retirement.owner_tid = (pid_t)syscall(SYS_gettid); trnm_retirement.deadline = deadline;
    for (unsigned i = 0; i < 3; i++) trnm_retirement.observer[i] = identity[i];
    memcpy(trnm_retirement.expected, membership, membership_size);
    trnm_retirement.expected_size = membership_size;
    trnm_retirement.membership[1] = trnm_retirement.membership[2] = trnm_retirement.membership[3] = -1;
    if (!error) error = trnm_retirement_check_membership(trnm_retirement.membership);
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

/* Private producer: original O's verified exact-terminal owner supplies only
 * its original arrays. This is not a public acquisition/funding/Whole-U API. */
int trnm_kernel_retirement_activate_v1(int parent, int aggregate[4], int controller[4],
        int child[4], const uint64_t identities[12], uint64_t deadline,
        uint64_t output[TRNM_RETIRE_WORDS]) {
    unsigned phase = atomic_load_explicit(&trnm_retirement.phase, memory_order_acquire);
    if (phase == TRNM_RETIRE_EMPTY || phase == TRNM_RETIRE_OWNED) return EAGAIN;
    if (!output || output != trnm_retirement.output || getpid() != trnm_retirement.pid ||
        syscall(SYS_gettid) != trnm_retirement.owner_tid) return EPERM;
    if (atomic_load(&trnm_retirement.claimed)) return EALREADY;
    if (phase != TRNM_RETIRE_READY || atomic_load(&trnm_retirement.error) ||
        !trnm_retirement_timely() || deadline != trnm_retirement.deadline) return ETIMEDOUT;
    unsigned empty = 0;
    if (!atomic_compare_exchange_strong(&trnm_retirement.claimed, &empty, 1)) return EALREADY;
    int error = 0;
    struct statfs fs;
    if (!aggregate || !controller || !child || !identities || aggregate == controller ||
        aggregate == child || controller == child || child[0] <= 0 || child[2] != -1 || child[3] != -1)
        error = EINVAL;
    if (!error) error = trnm_retirement_identity(parent, identities);
    if (!error && fstatfs(parent, &fs)) error = errno;
    if (!error && fs.f_type != TRNM_CGROUP2_MAGIC) error = EINVAL;
    if (!error) error = trnm_retirement_named(parent, "aggregate", aggregate, identities + 3);
    if (!error) error = trnm_retirement_named(parent, "controller", controller, identities + 6);
    if (!error) error = trnm_retirement_identity(child[1], identities + 9);
    if (!error && (parent == aggregate[1] || parent == controller[1] ||
        aggregate[1] == controller[1] || child[1] == aggregate[1] ||
        child[1] == controller[1] || child[1] == parent)) error = EINVAL;
    if (!error && !trnm_retirement_timely()) error = ETIMEDOUT;
    if (error) {
        int no_error = 0;
        atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, error);
        atomic_store_explicit(&trnm_retirement.phase, TRNM_RETIRE_UNKNOWN, memory_order_release);
        return error; /* Slot stays claimed; no effect or second activation. */
    }
    trnm_retirement.parent = parent; trnm_retirement.aggregate = aggregate;
    trnm_retirement.controller = controller; trnm_retirement.child = child;
    memcpy(trnm_retirement.identities, identities, sizeof(trnm_retirement.identities));
    atomic_store_explicit(&trnm_retirement.command, 1, memory_order_release);
    if (syscall(SYS_futex, &trnm_retirement.command, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) < 0) {
        error = errno;
        int no_error = 0;
        atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, error);
        atomic_store(&trnm_retirement.expired, 1); /* Worker must not begin/continue effects. */
    }
    return error;
}

/* Retention only, bound to the same original O/output. This cannot clear a
 * slot, create work, cancel an in-kernel syscall or grant another attempt. */
int trnm_kernel_retirement_retain_v1(uint64_t output[TRNM_RETIRE_WORDS]) {
    unsigned phase = atomic_load_explicit(&trnm_retirement.phase, memory_order_acquire);
    if (phase == TRNM_RETIRE_EMPTY || phase == TRNM_RETIRE_OWNED) return EAGAIN;
    if (!output || output != trnm_retirement.output || getpid() != trnm_retirement.pid ||
        syscall(SYS_gettid) != trnm_retirement.owner_tid) return EPERM;
    if (phase != TRNM_RETIRE_READY && phase != TRNM_RETIRE_RUNNING) return EALREADY;
    int no_error = 0;
    atomic_compare_exchange_strong(&trnm_retirement.error, &no_error, ECANCELED);
    return 0;
}
