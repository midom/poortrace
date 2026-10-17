// A native frame-pointer chain for the opt-in live perf test.
volatile unsigned long stack_running = 1;

__attribute__((noinline)) void stack_leaf(void) {
    volatile unsigned long value = 0;
    while (stack_running) {
        value++;
    }
}

__attribute__((noinline)) void stack_caller(void) {
    stack_leaf();
}

int main(void) {
    stack_caller();
    return 0;
}
