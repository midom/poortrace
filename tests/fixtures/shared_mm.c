#define _GNU_SOURCE
#include <sched.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
static _Atomic int stopped;
volatile long sink;
__attribute__((noinline)) void shared(int caller) { sink=caller; }
static int child_main(void *arg) {
    (void)arg;prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    while(!atomic_load(&stopped)) {shared(getpid());usleep(1000);}return 0;
}
int main(void) {
    prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    char *stack=mmap(0,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(stack==MAP_FAILED)return 2;
    int child=clone(child_main,stack+65536,CLONE_VM|SIGCHLD,0);if(child<0)return 3;
    printf("%d %lu\n",child,(unsigned long)&shared);fflush(stdout);
    char byte;if(read(0,&byte,1)!=1)return 4;
    for(int i=0;i<10;i++){shared(getpid());usleep(1000);}
    atomic_store(&stopped,1);int status;if(waitpid(child,&status,0)!=child)return 5;return status!=0;
}
