#include <setjmp.h>
#define MAYA_FIXTURE __attribute__((noinline, noipa, used))

static jmp_buf expired_buffer;

MAYA_FIXTURE static void protected_checkpoint(void) {
    (void)setjmp(expired_buffer);
}

MAYA_FIXTURE static void protected_stale_jump(void) {
    longjmp(expired_buffer, 7);
}

int main(void) {
    protected_checkpoint();
    protected_stale_jump();
    return 1;
}
