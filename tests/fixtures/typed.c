#include <stdio.h>
struct Nested { long value; };
struct Payload { signed char quantity; double ratio; struct Nested nested; };
volatile double sink;
__attribute__((noinline)) void inspect(struct Payload *p) { sink=p->ratio+p->quantity+p->nested.value; }
__attribute__((noinline)) double floating(double x,float y) {sink=x+y;return sink;}
__attribute__((noinline)) long stack_words(long a,long b,long c,long d,long e,long f,long g,long h,long i) {return a+b+c+d+e+f+g+h+i;}
int main(void) {
    struct Payload p={-7,1.25,{42}};inspect(&p);
    printf("float=%.2f stack=%ld\n",floating(1.25,1.5f),stack_words(1,2,3,4,5,6,7,8,9));return 0;
}
