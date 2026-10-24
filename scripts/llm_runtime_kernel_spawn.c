/* Controlled ABI1: called inside the original Python wait4 owner. No reaper. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

int trnm_kernel_spawn_v1(int group, int output, const char *exe,
                        char *const argv[], char *const env[], int result[4]) {
    int ack[2] = {-1,-1}, error[2] = {-1,-1}, input = -1, pidfd = -1;
    input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (input < 0 || pipe2(ack, O_CLOEXEC) || pipe2(error, O_CLOEXEC)) goto refused;
    /* Never let dup2 overwrite a gate/error FD when caller stdio is closed. */
    if (input < 3 || output < 3 || ack[0] < 3 || ack[1] < 3 || error[0] < 3 || error[1] < 3) {
        errno = EBADF;
        goto refused;
    }
    struct clone_args args = {0};
    args.flags = CLONE_INTO_CGROUP | CLONE_PIDFD;
    args.pidfd = (uint64_t)(uintptr_t)&pidfd;
    args.exit_signal = SIGCHLD;
    args.cgroup = (uint64_t)group;
    long pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0) goto refused;
    if (!pid) {
        /* No Python callback, allocator, fork wrapper or interpreter return. */
        close(ack[1]); close(error[0]);
        if (dup2(input, 0) < 0 || dup2(output, 1) < 0 || dup2(output, 2) < 0) goto child_error;
        close(input);
        char permission;
        ssize_t count;
        do { count = read(ack[0], &permission, 1); } while (count < 0 && errno == EINTR);
        close(ack[0]);
        if (count != 1 || permission != 'G') _exit(126);
        execve(exe, argv, env);
child_error:;
        int code = errno;
        ssize_t sent;
        do { sent = write(error[1], &code, sizeof(code)); } while (sent < 0 && errno == EINTR);
        _exit(sent == sizeof(code) ? 127 : 125);
    }
    close(input); close(ack[0]); close(error[1]);
    result[0] = (int)pid; result[1] = pidfd;
    result[2] = ack[1]; result[3] = error[0];
    return 0;
refused:;
    int code = errno;
    if (input >= 0) close(input);
    for (int i=0; i<2; i++) { if (ack[i]>=0) close(ack[i]); if (error[i]>=0) close(error[i]); }
    return code;
}

/* Close and clear under one native call: Python signals cannot split them. */
int trnm_kernel_close_v1(int result[4], unsigned int mask) {
    int error = 0;
    for (int i = 1; i < 4; i++) {
        if ((mask & (1U << i)) && result[i] >= 0) {
            if (close(result[i]) < 0 && !error) error = errno;
            result[i] = -1;
        }
    }
    return error;
}

/* Private FD owner slots: persist errno before Python can receive a signal.
 * These are never child handoff slots, whose result[0] remains the owned PID. */
int trnm_kernel_release_owned_v1(int owner[4]) {
    owner[0] = trnm_kernel_close_v1(owner, 2U);
    return owner[0];
}

/* Private evidence-pipe ABI1. Slots/identity/status belong to the original
 * controller before entry; Python cannot lose output at a pending signal. */
int trnm_kernel_evidence_pipe_v1(int read_owner[4], int write_owner[4],
                               uint64_t identity[6], int *status) {
    *status = 0;
    if (read_owner == write_owner || read_owner[0] || write_owner[0] ||
        read_owner[1] != -1 || write_owner[1] != -1) {
        *status = EINVAL;
        return *status;
    }
    int ends[2];
    if (pipe2(ends, O_CLOEXEC | O_NONBLOCK) < 0) {
        *status = errno;
        return *status;
    }
    read_owner[1] = ends[0]; write_owner[1] = ends[1];
    struct stat before[2];
    if (ends[0] < 3 || ends[1] < 3) *status = EBADF;
    else if (fstat(ends[0], &before[0]) || fstat(ends[1], &before[1])) *status = errno;
    else if (!S_ISFIFO(before[0].st_mode) || !S_ISFIFO(before[1].st_mode)) *status = EINVAL;
    if (*status) {
        trnm_kernel_release_owned_v1(read_owner);
        trnm_kernel_release_owned_v1(write_owner);
        return *status;
    }
    for (int index = 0; index < 2; index++) {
        identity[3*index] = (uint64_t)before[index].st_dev;
        identity[3*index+1] = (uint64_t)before[index].st_ino;
        identity[3*index+2] = (uint64_t)before[index].st_mode;
    }
    return 0;
}

/* Private PN4 native controller. It never returns to the inherited interpreter.
 * The original ABI above remains the only A birth primitive. The caller still
 * owns C through its original four slots and exact Python wait4. This 64-byte
 * pipe record is bounded transport, never a whole-U/retirement/refund receipt. */
#define TRNM_CONTROLLER_MAGIC UINT64_C(0x31574134544e5243)
#define TRNM_CGROUP2_MAGIC 0x63677270

static uint64_t trnm_now_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int trnm_before(uint64_t deadline) {
    uint64_t now = trnm_now_ns();
    return now && now < deadline;
}

static int trnm_group_text(int group, const char *name, const char *expected) {
    char value[128];
    int fd = openat(group, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    ssize_t count = read(fd, value, sizeof(value));
    int error = count < 0 ? errno : 0;
    if (close(fd) && !error) error = errno;
    size_t length = __builtin_strlen(expected);
    if (!error && (count != (ssize_t)length || __builtin_memcmp(value, expected, length))) error = EINVAL;
    return error;
}

static int trnm_controller_sanitize(int aggregate, int record) {
    /* Duplicate sources above all targets before replacing either target. */
    int a = fcntl(aggregate, F_DUPFD_CLOEXEC, 5);
    if (a < 0) return errno;
    int r = fcntl(record, F_DUPFD_CLOEXEC, 5);
    if (r < 0) { int error = errno; close(a); return error; }
    if (dup3(a, 3, O_CLOEXEC) < 0 || dup3(r, 4, O_CLOEXEC) < 0) return errno;
    /* No inherited O/manager/funding/ancestor handles remain in C. Refuse on
     * unsupported close_range; never enumerate an unbounded FD namespace. */
    if (syscall(SYS_close_range, 5U, UINT_MAX, 0U)) return errno;
    return 0;
}

static int trnm_controller_wait4(int pid, int pidfd, uint64_t deadline, uint64_t record[8]) {
    struct rusage usage = {0};
    int status = 0, error = 0;
    for (;;) {
        long got = wait4(pid, &status, WNOHANG, &usage);
        if (got == pid) break;
        if (got < 0 && errno != EINTR) return errno;
        if (!trnm_before(deadline)) {
            error = ETIMEDOUT;
            /* Only the pidfd from this C's original clone is signalled. A
             * blocking cleanup wait cannot renew the original O deadline or
             * produce a successful record. If kernel cleanup stalls, C remains
             * the actual A wait owner; O still retains U and its C pidfd. */
            if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) && errno != ESRCH) return errno;
            do { got = wait4(pid, &status, 0, &usage); } while (got < 0 && errno == EINTR);
            if (got != pid) return got < 0 ? errno : ECHILD;
            break;
        }
        struct pollfd descriptor = {.fd = pidfd, .events = POLLIN};
        if (poll(&descriptor, 1, 1) < 0 && errno != EINTR) return errno;
    }
    if (!WIFEXITED(status) && !WIFSIGNALED(status)) return ECHILD;
    if (usage.ru_utime.tv_sec < 0 || usage.ru_utime.tv_usec < 0 || usage.ru_utime.tv_usec >= 1000000 ||
        usage.ru_stime.tv_sec < 0 || usage.ru_stime.tv_usec < 0 || usage.ru_stime.tv_usec >= 1000000 ||
        (uint64_t)usage.ru_utime.tv_sec > UINT64_MAX / 1000000 - 1 ||
        (uint64_t)usage.ru_stime.tv_sec > UINT64_MAX / 1000000 - 1) return EOVERFLOW;
    record[3] |= 1; /* Actual exact wait4, not pidfd readiness or waitpid. */
    record[4] = (uint64_t)status;
    record[5] = (uint64_t)usage.ru_utime.tv_sec * 1000000 + (uint64_t)usage.ru_utime.tv_usec;
    record[6] = (uint64_t)usage.ru_stime.tv_sec * 1000000 + (uint64_t)usage.ru_stime.tv_usec;
    return error;
}

static void trnm_controller_record(int fd, uint64_t record[8]) {
    unsigned char bytes[64];
    for (unsigned int i = 0; i < 8; i++)
        for (unsigned int j = 0; j < 8; j++) bytes[8*i+j] = (unsigned char)(record[i] >> (8*j));
    /* One <= PIPE_BUF write, nonblocking, and no retry/extra lifetime window. */
    if (write(fd, bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes)) _exit(125);
}

static void trnm_controller_run(int aggregate, int record_fd, const char *exe,
        char *const argv[], char *const env[], uint64_t deadline) {
    uint64_t record[8] = {TRNM_CONTROLLER_MAGIC, (uint64_t)getpid(), 0, 0, 0, 0, 0, 0};
    int error = trnm_controller_sanitize(aggregate, record_fd);
    if (error) _exit(125); /* Original write FD may have been overwritten. */
    if (!trnm_before(deadline)) error = ETIMEDOUT;
    if (!error) error = trnm_group_text(3, "cgroup.procs", "");
    if (!error) error = trnm_group_text(3, "pids.current", "0\n");
    if (!error) error = trnm_group_text(3, "cgroup.subtree_control", "");
    int slots[4] = {-1, -1, -1, -1}; /* C's one persistent A handoff. */
    int output = -1;
    if (!error) { output = fcntl(1, F_DUPFD_CLOEXEC, 5); if (output < 0) error = errno; }
    if (!error && !trnm_before(deadline)) error = ETIMEDOUT;
    if (!error) error = trnm_kernel_spawn_v1(3, output, exe, argv, env, slots);
    if (output >= 0) close(output);
    if (slots[0] > 0) {
        record[2] = (uint64_t)slots[0];
        char expected[32];
        /* No formatting allocator/libc stdio after clone: bounded PID decimal. */
        unsigned int pid = (unsigned int)slots[0], length = 0;
        char reverse[16];
        do { reverse[length++] = (char)('0' + pid % 10); pid /= 10; } while (pid);
        for (unsigned int i = 0; i < length; i++) expected[i] = reverse[length-i-1];
        expected[length++] = '\n'; expected[length] = 0;
        if (!error) error = trnm_group_text(3, "cgroup.procs", expected);
        if (!error && !trnm_before(deadline)) error = ETIMEDOUT;
        if (!error && write(slots[2], "G", 1) != 1) error = errno ? errno : EIO;
        if (!error) {
            struct pollfd descriptor = {.fd = slots[3], .events = POLLIN};
            for (;;) {
                if (!trnm_before(deadline)) { error = ETIMEDOUT; break; }
                int ready = poll(&descriptor, 1, 1);
                if (ready < 0 && errno != EINTR) { error = errno; break; }
                if (ready > 0) {
                    int exec_error = 0;
                    ssize_t count = read(slots[3], &exec_error, sizeof(exec_error));
                    /* EOF reports no exec errno; a pre-exec signal can also
                     * close this pipe. It never proves payload execution. */
                    if (!count) record[3] |= 2;
                    else error = count == sizeof(exec_error) && exec_error > 0 ? exec_error : EIO;
                    break;
                }
            }
        }
        trnm_kernel_close_v1(slots, 12U);
        if (error) {
            if (syscall(SYS_pidfd_send_signal, slots[1], SIGKILL, NULL, 0) && errno != ESRCH) record[7] = (uint64_t)errno;
        }
        int waited = trnm_controller_wait4(slots[0], slots[1], deadline, record);
        if (!error) error = waited;
        trnm_kernel_close_v1(slots, 2U);
    }
    if (!trnm_before(deadline) && !error) error = ETIMEDOUT;
    if (!record[7]) record[7] = (uint64_t)error;
    trnm_controller_record(4, record);
    _exit(error || record[7] || record[3] != 3 ? 124 : 0);
}

/* Private entry, no public authorization/funding producer. Same C four-slot
 * ABI, with a fixed native C body rather than exec of a Python interpreter. */
int trnm_kernel_controller_v1(int controller, int aggregate, int output, int record_fd,
        const char *exe, char *const argv[], char *const env[], uint64_t deadline, int result[4]) {
    struct statfs fs;
    uint64_t now = trnm_now_ns();
    if (!now || deadline <= now || deadline-now > UINT64_C(8000000000) ||
        !exe || exe[0] != '/' || !argv || !env || !result ||
        result[0] != -1 || result[1] != -1 || result[2] != -1 || result[3] != -1) return EINVAL;
    if (fstatfs(controller, &fs) || fs.f_type != TRNM_CGROUP2_MAGIC ||
        fstatfs(aggregate, &fs) || fs.f_type != TRNM_CGROUP2_MAGIC) return EINVAL;
    struct stat cmeta, ameta, rmeta;
    int record_flags = fcntl(record_fd, F_GETFL);
    int record_fd_flags = fcntl(record_fd, F_GETFD);
    if (fstat(controller, &cmeta) || fstat(aggregate, &ameta) || fstat(record_fd, &rmeta) ||
        !S_ISDIR(cmeta.st_mode) || !S_ISDIR(ameta.st_mode) || !S_ISFIFO(rmeta.st_mode) ||
        (cmeta.st_dev == ameta.st_dev && cmeta.st_ino == ameta.st_ino) || record_flags < 0 ||
        (record_flags & O_ACCMODE) != O_WRONLY || !(record_flags & O_NONBLOCK) ||
        record_fd_flags < 0 || !(record_fd_flags & FD_CLOEXEC)) return EINVAL;
    int ack[2] = {-1,-1}, error[2] = {-1,-1}, input = -1, pidfd = -1;
    input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (input < 0 || pipe2(ack, O_CLOEXEC) || pipe2(error, O_CLOEXEC)) goto refused;
    if (input < 3 || output < 3 || record_fd < 3 || controller < 3 || aggregate < 3 ||
        ack[0] < 3 || ack[1] < 3 || error[0] < 3 || error[1] < 3) { errno = EBADF; goto refused; }
    struct clone_args args = {0};
    args.flags = CLONE_INTO_CGROUP | CLONE_PIDFD;
    args.pidfd = (uint64_t)(uintptr_t)&pidfd;
    args.exit_signal = SIGCHLD;
    args.cgroup = (uint64_t)controller;
    long pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0) goto refused;
    if (!pid) {
        close(ack[1]); close(error[0]);
        if (dup2(input, 0) < 0 || dup2(output, 1) < 0 || dup2(output, 2) < 0) goto child_error;
        close(input);
        char permission;
        ssize_t count;
        do { count = read(ack[0], &permission, 1); } while (count < 0 && errno == EINTR);
        close(ack[0]);
        if (count != 1 || permission != 'G') _exit(126);
        close(error[1]); /* Native C gate admitted; this is not an exec receipt. */
        trnm_controller_run(aggregate, record_fd, exe, argv, env, deadline);
child_error:;
        int code = errno;
        ssize_t sent = write(error[1], &code, sizeof(code));
        _exit(sent == sizeof(code) ? 127 : 125);
    }
    close(input); close(ack[0]); close(error[1]);
    result[0] = (int)pid; result[1] = pidfd; result[2] = ack[1]; result[3] = error[0];
    return 0;
refused:;
    int code = errno;
    if (input >= 0) close(input);
    for (int i=0; i<2; i++) { if (ack[i]>=0) close(ack[i]); if (error[i]>=0) close(error[i]); }
    return code;
}
