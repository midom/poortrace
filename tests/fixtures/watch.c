#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/prctl.h>
volatile uint64_t watched = 0;
int main(void) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    printf("%llx\n", (unsigned long long)(uintptr_t)&watched);
    fflush(stdout);
    while (1) { watched++; usleep(1000); }
}
