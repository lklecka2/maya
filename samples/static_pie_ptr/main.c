#include <stdio.h>

extern int protected_entry(int);
extern int protected_alt(int);

__asm__(
    ".text\n"
    ".align 2\n"
    ".global protected_entry\n"
    ".type protected_entry, %function\n"
    "protected_entry:\n"
    "bti c\n"
    "add w0, w0, #1\n"
    "ret\n"
    ".global protected_alt\n"
    "protected_alt:\n"
    "bti c\n"
    "add w0, w0, #2\n"
    "ret\n"
    ".size protected_entry, .-protected_entry\n");

int (*volatile entry_a)(int) = protected_entry;
int (*volatile entry_b)(int) = protected_entry;
int (*volatile interior_a)(int) = protected_alt;
int (*volatile interior_b)(int) = protected_alt;

int main(void) {
    const int a = entry_a(10);
    const int b = interior_a(10);
    const int stable = entry_a == entry_b && interior_a == interior_b;
    printf("static_pie_ptr entry=%d interior=%d stable=%d\n", a, b, stable);
    return a == 11 && b == 12 && stable ? 0 : 1;
}
