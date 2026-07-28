#include "state_binding.h"
#include "runtime_kdf.h"

static uint64_t load64(const uint8_t* p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static uint64_t rotate_left(uint64_t value, unsigned count) {
    return (value << count) | (value >> (64 - count));
}

static uint64_t avalanche(uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

uint64_t maya_state_mask(const uint8_t root[32], uint64_t binary_cookie, uint64_t thread_cookie,
                         uint64_t epoch, uint64_t path_digest, uint64_t frame_cookie,
                         uint64_t logical_state, uint64_t depth_generation) {
    uint8_t key[32];
    maya_derive_state_binding_key(key, root, binary_cookie);
    uint64_t a = load64(key) ^ binary_cookie ^ UINT64_C(0x6d6179612d76312d);
    uint64_t b = load64(key + 8) ^ thread_cookie;
    uint64_t c = load64(key + 16) ^ epoch ^ rotate_left(path_digest, 17);
    uint64_t d = load64(key + 24) ^ frame_cookie ^ rotate_left(logical_state, 31) ^
                 rotate_left(depth_generation, 47);
    a = avalanche(a + rotate_left(b, 13));
    b = avalanche(b + rotate_left(c, 29));
    c = avalanche(c + rotate_left(d, 41));
    d = avalanche(d + rotate_left(a, 7));
    uint64_t result = avalanche(a ^ b ^ c ^ d);
    maya_secure_wipe(key, sizeof(key));
    return result;
}

uint64_t maya_state_advance(uint64_t path_digest, uint64_t state_mask, uint64_t committed_event) {
    return avalanche(path_digest ^ rotate_left(state_mask, 23) ^ rotate_left(committed_event, 43) ^
                     UINT64_C(0x76312d636f6d6d69));
}
