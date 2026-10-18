#define _GNU_SOURCE
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
static ucontext_t scheduler, first, second;
__attribute__((noinline)) int suspended(int id) {
    if (id==1) swapcontext(&first,&scheduler); else swapcontext(&second,&scheduler);
    return id*10;
}
static void run_first(void) { if(suspended(1)!=10)exit(3); }
static void run_second(void) { if(suspended(2)!=20)exit(4); }
int main(void) {
    prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    size_t size=65536;
    char *allocation=mmap(0,size*2+4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(allocation==MAP_FAILED)return 2;
    getcontext(&first);getcontext(&second);
    first.uc_stack.ss_sp=allocation;first.uc_stack.ss_size=size;first.uc_link=&scheduler;
    second.uc_stack.ss_sp=allocation+size;second.uc_stack.ss_size=size;second.uc_link=&scheduler;
    makecontext(&first,run_first,0);makecontext(&second,run_second,0);
    printf("%lu %lu %lu %lu\n",(unsigned long)allocation,(unsigned long)(allocation+size),(unsigned long)(allocation+size),(unsigned long)(allocation+size*2));fflush(stdout);
    char byte;if(read(0,&byte,1)!=1)return 5;
    swapcontext(&scheduler,&first);
    swapcontext(&scheduler,&second);
    swapcontext(&scheduler,&first);
    swapcontext(&scheduler,&second);
    return 0;
}
