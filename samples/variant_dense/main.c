#include <stdio.h>

__attribute__((noinline, noipa, used)) int variant_dense(int value) {
    long a = value + 1;
    long b = value + 2;
    long c = value + 3;
    long d = value + 4;
    long e = value + 5;
    long f = value + 6;
    __asm__ volatile(
        "add %0, %0, #1\n"
        "add %1, %1, #2\n"
        "add %2, %2, #3\n"
        "add %3, %3, #4\n"
        "add %4, %4, #5\n"
        "add %5, %5, #6\n"
        : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e), "+r"(f));
    return (int)(a + b + c + d + e + f);
}

int main(void) {
    long total = 0;
    for (int i = 0; i < 64; ++i) total += variant_dense(i);
    printf("variant_dense total=%ld status=%s\n", total, total == 14784 ? "OK" : "FAIL");
    return total == 14784 ? 0 : 1;
}
