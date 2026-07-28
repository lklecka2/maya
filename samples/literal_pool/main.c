#include <stdio.h>

extern long literal_pool_add(long value);
__asm__(
    ".text\n.align 2\n.global literal_pool_add\n.type literal_pool_add, %function\n"
    "literal_pool_add:\n"
    "bti c\n"
    "ldr x1, .Lmaya_literal\n"
    "add x0, x0, x1\n"
    "ret\n"
    ".align 3\n"
    ".Lmaya_literal:\n.quad 37\n"
    ".size literal_pool_add, .-literal_pool_add\n");

int main(void) {
    long result = literal_pool_add(5);
    printf("literal_pool=%ld\n", result);
    return result == 42 ? 0 : 1;
}
