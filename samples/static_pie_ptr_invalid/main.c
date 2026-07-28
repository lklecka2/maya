#include <stdint.h>

extern int protected_entry(int);
__asm__(
    ".text\n.align 2\n.global protected_entry\n.type protected_entry, %function\n"
    "protected_entry:\nbti c\nadd w0, w0, #1\nret\n"
    ".size protected_entry, .-protected_entry\n"
    ".data\n.align 3\n.global invalid_mid_instruction_pointer\n"
    "invalid_mid_instruction_pointer:\n.quad protected_entry + 2\n");

extern uintptr_t invalid_mid_instruction_pointer;
int main(void) { return invalid_mid_instruction_pointer == 0; }
