#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>
__attribute__((noinline)) long traced_add(long a,long b,long c,long d,long e,long f) {
    __asm__ __volatile__("" ::: "memory");
    return a+b+c+d+e+f;
}
__attribute__((noinline)) long traced_recursive(long n) {
    volatile long value=n;
    if(n<=0) return 1;
    return traced_recursive(n-1)+value;
}
static long run(void) {
    volatile long total=0;
    for(long i=1;i<=3;i++) total+=traced_add(i,2,3,4,5,6);
    return total;
}
static void* worker(void* unused) { (void)unused; return (void*)run(); }
static int shared_worker(void* arg) {(void)arg;run();return 0;}
static void* execute_worker(void* path) {execl((char*)path,(char*)path,(char*)0);_exit(8);}
int main(int argc,char** argv) {
    if(argc>1 && !strcmp(argv[1],"wait")) {
        for(int i=0;i<3;i++){usleep(20000);clock_t start=clock();while(clock()-start<CLOCKS_PER_SEC/40){__asm__ __volatile__("" ::: "memory");}}return 0;
    }
    if(argc>1 && !strcmp(argv[1],"thread-exec")) {pthread_t thread;pthread_create(&thread,0,execute_worker,argv[0]);while(1)pause();}

    if(argc>1 && !strcmp(argv[1],"orphan-sleep")) {
        pid_t child=fork();if(child==0){setsid();close(1);close(2);sleep(30);_exit(0);}
        printf("orphan=%ld\n",(long)child);fflush(stdout);_exit(7);
    }
    if(argc>1 && !strcmp(argv[1],"orphan-exec")) {
        pid_t child=fork(); if(child==0){execl(argv[0],argv[0],(char*)0);_exit(8);} _exit(7);
    }
    if(argc>1 && !strcmp(argv[1],"attach")) {
        prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
        printf("%llx\n",(unsigned long long)(unsigned long)&traced_add);fflush(stdout);
        while(1) {run();usleep(1000);}
    }
    if(argc>1 && !strcmp(argv[1],"shared")) {
        void* stack=malloc(65536);int child=clone(shared_worker,(char*)stack+65536,CLONE_VM|SIGCHLD,0);
        int status=0;waitpid(child,&status,0);free(stack);if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)return 9;
        printf("total=%ld\n",run());
    } else if(argc>1 && !strcmp(argv[1],"threads")) {
        pthread_t threads[2];
        for(int i=0;i<2;i++) pthread_create(&threads[i],0,worker,0);
        long total=run();
        for(int i=0;i<2;i++) {void* value;pthread_join(threads[i],&value);total+=(long)value;}
        printf("total=%ld\n",total);
    } else if(argc>1 && !strcmp(argv[1],"recursive")) {
        printf("total=%ld\n",traced_recursive(3));
    } else if(argc>1 && (!strcmp(argv[1],"fork") || !strcmp(argv[1],"vfork"))) {
        int use_vfork=!strcmp(argv[1],"vfork");
        pid_t child=use_vfork?vfork():fork();
        if(child==0) {if(use_vfork){execl("/bin/true","true",(char*)0);}else{run();} _exit(0);}
        int status=0;waitpid(child,&status,0);if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)return 9;
        printf("total=%ld\n",run());
    } else {printf("total=%ld\n",run());}
    return 0;
}
