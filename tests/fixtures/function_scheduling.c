#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static atomic_uint_fast64_t heartbeat;
static atomic_uint_fast64_t *counter = &heartbeat;
static volatile uint64_t completions;
static volatile sig_atomic_t requested;

static void request(int sig) { (void)sig; requested = 1; }
static void *writer(void *unused) {
    (void)unused;
    for (;;) atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
    return NULL;
}
__attribute__((noinline)) uintptr_t observed(uintptr_t value) {
    __asm__ __volatile__("" ::: "memory");
    return value + 1;
}
__attribute__((noinline)) void dormant(void) { __asm__ __volatile__("" ::: "memory"); }
int main(int argc, char **argv) {
    (void)argv;
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    signal(SIGUSR1, request);
    pid_t child = 0;
    if (argc > 1) {
        counter = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (counter == MAP_FAILED) return 2;
        child = fork();
        if (child < 0) return 2;
        if (!child) writer(NULL);
    } else {
        pthread_t threads[3];
        for (int i = 0; i < 3; i++)
            if (pthread_create(&threads[i], NULL, writer, NULL)) return 2;
    }
    printf("%p %p %x\n", (void *)counter, (void *)&completions, child);
    fflush(stdout);
    for (;;) {
        if (requested) {
            requested = 0;
            observed((uintptr_t)counter);
            completions++;
        }
        syscall(SYS_getpid);
        usleep(1000);
    }
}
