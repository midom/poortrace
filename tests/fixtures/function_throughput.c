#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_int done;
static pthread_barrier_t ready;

__attribute__((noinline)) long throughput_hit(long value) {
    __asm__ __volatile__("" ::: "memory");
    return value + 1;
}

static void *sleeper(void *unused) {
    (void)unused;
    pthread_barrier_wait(&ready);
    while (!atomic_load(&done)) usleep(1000);
    return NULL;
}

int main(int argc, char **argv) {
    long hits = argc > 1 ? strtol(argv[1], NULL, 10) : 500;
    int threads = argc > 2 ? atoi(argv[2]) : 1;
    if (hits < 1 || threads < 1 || threads > 512) return 2;
    pthread_t siblings[511];
    if (pthread_barrier_init(&ready, NULL, threads)) return 3;
    for (int i = 0; i < threads - 1; i++)
        if (pthread_create(&siblings[i], NULL, sleeper, NULL)) return 4;
    pthread_barrier_wait(&ready);
    volatile long total = 0;
    for (long i = 0; i < hits; i++) total += throughput_hit(i);
    atomic_store(&done, 1);
    for (int i = 0; i < threads - 1; i++) pthread_join(siblings[i], NULL);
    printf("total=%ld\n", total);
    return 0;
}
