#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
volatile unsigned short poortrace_semaphore;
static void fire(long value) {
    signed char small=-5; volatile long memory=-99;
    __asm__ __volatile__(
        "991: nop\n"
        ".pushsection .note.stapsdt,\"\",@note\n"
        ".balign 4\n.4byte 8\n.4byte 993f-992f\n.4byte 3\n"
        ".asciz \"stapsdt\"\n.balign 4\n992:\n"
        ".8byte 991b\n.8byte 0\n.8byte poortrace_semaphore\n"
        ".asciz \"poortrace\"\n.asciz \"work\"\n.asciz \"-8@%0 -1@%1 -8@%2\"\n993:\n.balign 4\n.popsection\n"
        : : "r"(value), "r"(small), "m"(memory) : "memory");
}
int main(int argc,char **argv) {
    (void)argv;
    if(argc>1) {
        prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
        printf("%llx\n",(unsigned long long)(unsigned long)&poortrace_semaphore);fflush(stdout);
        while(1){if(poortrace_semaphore)fire(1);usleep(1000);}
    }

    for (long i=1;i<=3;i++) if(poortrace_semaphore) fire(i);
    printf("semaphore=%d\n",poortrace_semaphore);
    return 0;
}
