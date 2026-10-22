/* Controlled ABI1: called inside the original Python wait4 owner. No reaper. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
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
