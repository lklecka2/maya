#include <stdint.h>

__attribute__((noinline, used)) int unsupported_indirect_branch(uintptr_t target) {
    __asm__ volatile("br %0" : : "r"(target));
    return 0;
}

int main(void) { return 0; }
