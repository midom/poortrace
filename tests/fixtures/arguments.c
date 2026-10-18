#include <stdarg.h>
typedef float Vector __attribute__((vector_size(16)));
struct Pair { long integer; double floating; };
struct Hfa { float first, second, third; };
struct Big { long first, second, third; };
struct VectorHolder { Vector first; };
struct VectorPair { Vector first,second; };
union FloatUnion { float first, second; };
struct __attribute__((aligned(16))) AlignedHfa { float first, second, third; };
volatile double sink;
__attribute__((noinline)) void inspect(signed char small, double ratio,
    struct Pair pair, struct Hfa hfa, Vector vector, struct Big big,
    long a0,long a1,long a2,long a3,long a4,long a5,long a6,long a7,long a8) {
    sink=small+ratio+pair.integer+pair.floating+hfa.first+hfa.second+hfa.third+
        vector[0]+vector[1]+vector[2]+vector[3]+big.first+big.second+big.third+
        a0+a1+a2+a3+a4+a5+a6+a7+a8;
}
__attribute__((noinline)) void spilled(long b0,long b1,long b2,long b3,long b4,long b5,long b6,long b7,long b8,
    double d0,double d1,double d2,double d3,double d4,double d5,double d6,double d7,Vector spillvector) {
    sink=b0+b1+b2+b3+b4+b5+b6+b7+b8+d0+d1+d2+d3+d4+d5+d6+d7+spillvector[0]+spillvector[3];
}
__attribute__((noinline)) void aligned_hfa(struct AlignedHfa padded,int afterpadding) {
    sink=padded.first+padded.second+padded.third+afterpadding;
}
__attribute__((noinline)) void union_hfa(union FloatUnion overlap,int afterunion) {
    sink=overlap.first+afterunion;
}
__attribute__((noinline)) void nested_vector(struct VectorHolder nested,int aftervector) { sink=nested.first[0]+nested.first[3]+aftervector; }
__attribute__((noinline)) void vector_pair(struct VectorPair pair,int afterpair) { sink=pair.first[0]+pair.second[3]+afterpair; }
__attribute__((noinline)) struct Big returns_big(long value,double factor) { return (struct Big){value,(long)factor,33}; }
__attribute__((noinline)) void variadic(int fixed,...) { va_list args;va_start(args,fixed);int small=va_arg(args,int);double ratio=va_arg(args,double);long large=va_arg(args,long);va_end(args);sink=fixed+small+ratio+large; }
int main(void) {
    inspect(-7,1.25,(struct Pair){42,2.5},(struct Hfa){1,2,3},
        (Vector){1.25,2.5,3.75,4},(struct Big){10,20,30},1,2,3,4,5,6,7,8,9);
    spilled(0,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,(Vector){1.25,2.5,3.75,4});
    aligned_hfa((struct AlignedHfa){1.25,2.5,3.75},17);
    union_hfa((union FloatUnion){.first=1.25},17);
    nested_vector((struct VectorHolder){(Vector){1.25,2.5,3.75,4}},17);
    vector_pair((struct VectorPair){(Vector){1,2,3,4},(Vector){5,6,7,8}},19);
    sink+=returns_big(77,2.5).first;
    variadic(7,-3,1.25,99L);
    return sink==0;
}
