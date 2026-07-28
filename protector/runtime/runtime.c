#include "runtime_kdf.h"
#include "xchacha20poly1305.h"
#include <stdint.h>

__attribute__((visibility("default"), section(".text.entry"))) int
maya_fragment_decrypt(uint8_t* plain, const uint8_t* cipher, uint64_t size, const uint8_t* aad,
                      uint64_t aad_size, const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t tag[16]) {
    return maya_xchacha20poly1305_open(plain, cipher, size, aad, aad_size, key, nonce, tag);
}

__attribute__((visibility("default"), section(".text.entry"))) int
maya_fragment_decrypt_root(uint8_t* plain, const uint8_t* cipher, uint64_t size, const uint8_t* aad,
                           uint64_t aad_size, const uint8_t root[32], const uint8_t nonce[24],
                           const uint8_t tag[16]) {
    uint8_t key[32];
    maya_derive_sealed_object_key(key, root, aad, aad_size);
    int result = maya_xchacha20poly1305_open(plain, cipher, size, aad, aad_size, key, nonce, tag);
    maya_secure_wipe(key, sizeof(key));
    return result;
}

static long maya_syscall6(long number, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0, x1 __asm__("x1") = a1, x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3, x4 __asm__("x4") = a4, x5 __asm__("x5") = a5,
                     x8 __asm__("x8") = number;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory");
    return x0;
}
__attribute__((visibility("default"), section(".text.entry"))) void*
maya_nucleus_map(uint64_t size, uint64_t protection) {
    long r = maya_syscall6(222, 0, (long)size, (long)protection, 0x22, -1, 0);
    return r < 0 ? (void*)0 : (void*)r;
}
__attribute__((visibility("default"), section(".text.entry"))) int
maya_nucleus_protect(void* address, uint64_t size, uint64_t protection) {
    return (int)maya_syscall6(226, (long)address, (long)size, (long)protection, 0, 0, 0);
}
__attribute__((visibility("default"), section(".text.entry"))) int
maya_nucleus_unmap(void* address, uint64_t size) {
    return (int)maya_syscall6(215, (long)address, (long)size, 0, 0, 0, 0);
}
__attribute__((visibility("default"), section(".text.entry"))) void
maya_nucleus_cache_sync(void* address, uint64_t size) {
    uintptr_t begin = (uintptr_t)address & ~(uintptr_t)63,
              end = ((uintptr_t)address + size + 63) & ~(uintptr_t)63;
    for (uintptr_t p = begin; p < end; p += 64)
        __asm__ volatile("dc cvau, %0" ::"r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t p = begin; p < end; p += 64)
        __asm__ volatile("ic ivau, %0" ::"r"(p) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
    (void)maya_syscall6(283, 1u << 6, 0, 0, 0, 0, 0);
    (void)maya_syscall6(283, 1u << 5, 0, 0, 0, 0, 0);
}
typedef struct maya_thread_link {
    struct maya_thread_link* next;
    uint64_t tpidr;
} maya_thread_link;
static uint64_t* maya_thread_lock_word(maya_thread_link** head) {
    return (uint64_t*)((uint8_t*)head + 8);
}
static void maya_thread_lock(maya_thread_link** head) {
    uint64_t* lock = maya_thread_lock_word(head);
    while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(lock, __ATOMIC_RELAXED))
            __asm__ volatile("yield" ::: "memory");
    }
}
static void maya_thread_unlock(maya_thread_link** head) {
    __atomic_store_n(maya_thread_lock_word(head), 0, __ATOMIC_RELEASE);
}
__attribute__((visibility("default"), section(".text.entry"))) void*
maya_nucleus_thread_lookup(maya_thread_link** head, uint64_t tpidr, uint64_t size) {
    maya_thread_lock(head);
    maya_thread_link* item = *head;
    while (item) {
        if (item->tpidr == tpidr) {
            maya_thread_unlock(head);
            return item;
        }
        item = item->next;
    }
    item = (maya_thread_link*)maya_nucleus_map(size, 3);
    if (!item) {
        maya_thread_unlock(head);
        return 0;
    }
    item->tpidr = tpidr;
    item->next = *head;
    *head = item;
    maya_thread_unlock(head);
    return item;
}
__attribute__((visibility("default"), section(".text.entry"))) int
maya_nucleus_thread_destroy(maya_thread_link** head, maya_thread_link* item, uint64_t size) {
    if (!item || size < sizeof(*item))
        return -1;
    maya_thread_lock(head);
    maya_thread_link** cursor = head;
    while (*cursor && *cursor != item)
        cursor = &(*cursor)->next;
    if (*cursor != item) {
        maya_thread_unlock(head);
        return -1;
    }
    *cursor = item->next;
    maya_thread_unlock(head);
    maya_secure_wipe(item, size);
    return maya_nucleus_unmap(item, size);
}
