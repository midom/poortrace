#include <cstdio>
namespace ns {
struct Number { long value; };
__attribute__((noinline)) Number operator+(Number a,Number b) {
    __asm__ __volatile__("" ::: "memory");
    return Number{a.value+b.value};
}
}
int main() { ns::Number a{1},b{2};std::printf("total=%ld\n",(a+b).value); }
