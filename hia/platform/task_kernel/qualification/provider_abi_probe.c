/* Build-time ABI probe only. Never linked into the provider runtime. */
#define _GNU_SOURCE 1
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

struct owner_layout { void *resources; pthread_mutex_t lock; };
int main(void) {
    printf("{\"pointer_bytes\":%zu,\"size_t_bytes\":%zu,\"int_bytes\":%zu,"
           "\"long_bytes\":%zu,\"ssize_t_bytes\":%zu,\"mode_t_bytes\":%zu,"
           "\"mutex_bytes\":%zu,\"mutex_alignment\":%zu,\"owner_bytes\":%zu,"
           "\"owner_lock_offset\":%zu,\"stat_bytes\":%zu,\"stat_mode_offset\":%zu,"
           "\"stat_mode_bytes\":%zu,\"stat_size_offset\":%zu,\"stat_size_bytes\":%zu,"
           "\"timespec_bytes\":%zu,\"timespec_seconds_offset\":%zu,"
           "\"timespec_nanoseconds_offset\":%zu,\"clock_realtime\":%d}\n",
           sizeof(void *), sizeof(size_t), sizeof(int), sizeof(long), sizeof(ssize_t), sizeof(mode_t),
           sizeof(pthread_mutex_t), _Alignof(pthread_mutex_t), sizeof(struct owner_layout),
           offsetof(struct owner_layout, lock), sizeof(struct stat), offsetof(struct stat, st_mode),
           sizeof(((struct stat *)0)->st_mode), offsetof(struct stat, st_size),
           sizeof(((struct stat *)0)->st_size), sizeof(struct timespec), offsetof(struct timespec, tv_sec),
           offsetof(struct timespec, tv_nsec), CLOCK_REALTIME);
    return 0;
}
