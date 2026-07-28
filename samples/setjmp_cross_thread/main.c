#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdatomic.h>
#define MAYA_FIXTURE __attribute__((noinline, noipa, used))

static jmp_buf shared_buffer;
static atomic_int ready;

MAYA_FIXTURE static void protected_owner(void) {
    if (setjmp(shared_buffer) == 0) {
        atomic_store_explicit(&ready, 1, memory_order_release);
        for (;;) sched_yield();
    }
}

MAYA_FIXTURE static void protected_cross_jump(void) {
    longjmp(shared_buffer, 9);
}

static void *owner_thread(void *unused) {
    (void)unused;
    protected_owner();
    return 0;
}

static void *jump_thread(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&ready, memory_order_acquire)) sched_yield();
    protected_cross_jump();
    return 0;
}

int main(void) {
    pthread_t owner, jumper;
    if (pthread_create(&owner, 0, owner_thread, 0) != 0) return 2;
    if (pthread_create(&jumper, 0, jump_thread, 0) != 0) return 3;
    pthread_join(jumper, 0);
    return 4;
}
