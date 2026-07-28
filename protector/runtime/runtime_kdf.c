#include "runtime_kdf.h"
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;
} maya_sha256;
static uint32_t load_be32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void store_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
static uint32_t ror32(uint32_t v, unsigned n) { return (v >> n) | (v << (32 - n)); }
static void compress(maya_sha256* c, const uint8_t* b) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = load_be32(b + 4 * i);
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3),
                 s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->state[0], d = c->state[3], e = c->state[4], h = c->state[7], bb = c->state[1],
             cc = c->state[2], f = c->state[5], g = c->state[6];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25), ch = (e & f) ^ ((~e) & g),
                 t1 = h + s1 + ch + k[i] + w[i], s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22),
                 maj = (a & bb) ^ (a & cc) ^ (bb & cc), t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = bb;
        bb = a;
        a = t1 + t2;
    }
    c->state[0] += a;
    c->state[1] += bb;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
    c->state[5] += f;
    c->state[6] += g;
    c->state[7] += h;
}
static void init(maya_sha256* c) {
    static const uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (unsigned i = 0; i < 8; ++i)
        c->state[i] = s[i];
    c->length = 0;
    c->used = 0;
}
static void update(maya_sha256* c, const uint8_t* p, size_t n) {
    c->length += (uint64_t)n * 8;
    while (n) {
        size_t t = 64 - c->used;
        if (t > n)
            t = n;
        for (size_t i = 0; i < t; ++i)
            c->block[c->used + i] = p[i];
        c->used += t;
        p += t;
        n -= t;
        if (c->used == 64) {
            compress(c, c->block);
            c->used = 0;
        }
    }
}
static void finish(maya_sha256* c, uint8_t out[32]) {
    c->block[c->used++] = 0x80;
    if (c->used > 56) {
        while (c->used < 64)
            c->block[c->used++] = 0;
        compress(c, c->block);
        c->used = 0;
    }
    while (c->used < 56)
        c->block[c->used++] = 0;
    for (unsigned i = 0; i < 8; ++i)
        c->block[56 + i] = (uint8_t)(c->length >> (56 - 8 * i));
    compress(c, c->block);
    for (unsigned i = 0; i < 8; ++i)
        store_be32(out + 4 * i, c->state[i]);
}
static void hash(const uint8_t* p, size_t n, uint8_t out[32]) {
    maya_sha256 c;
    init(&c);
    update(&c, p, n);
    finish(&c, out);
}
void maya_sha256_digest(uint8_t out[32], const uint8_t* p, uint64_t n) { hash(p, (size_t)n, out); }
void maya_secure_wipe(void* p, uint64_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--)
        *v++ = 0;
    __asm__ volatile("" ::: "memory");
}
static void hmac(const uint8_t key[32], const uint8_t* p, size_t n, uint8_t out[32]) {
    uint8_t pad[64], inner[32];
    maya_sha256 c;
    for (unsigned i = 0; i < 64; ++i)
        pad[i] = (uint8_t)((i < 32 ? key[i] : 0) ^ 0x36);
    init(&c);
    update(&c, pad, 64);
    update(&c, p, n);
    finish(&c, inner);
    for (unsigned i = 0; i < 64; ++i)
        pad[i] = (uint8_t)((i < 32 ? key[i] : 0) ^ 0x5c);
    init(&c);
    update(&c, pad, 64);
    update(&c, inner, 32);
    finish(&c, out);
    maya_secure_wipe(pad, sizeof(pad));
    maya_secure_wipe(inner, sizeof(inner));
    maya_secure_wipe(&c, sizeof(c));
}
void maya_hmac_sha256(uint8_t out[32], const uint8_t key[32], const uint8_t* p, uint64_t n) {
    hmac(key, p, (size_t)n, out);
}
static void expand_one(uint8_t out[32], const uint8_t root[32], const uint8_t salt[32],
                       const uint8_t* info, size_t n) {
    uint8_t prk[32], buffer[64];
    hmac(salt, root, 32, prk);
    for (size_t i = 0; i < n; ++i)
        buffer[i] = info[i];
    buffer[n] = 1;
    hmac(prk, buffer, n + 1, out);
    maya_secure_wipe(prk, sizeof(prk));
    maya_secure_wipe(buffer, sizeof(buffer));
}
void maya_derive_sealed_object_key(uint8_t out[32], const uint8_t root[32], const uint8_t* aad,
                                   uint64_t aad_size) {
    static const uint8_t prefix[] = {'m', 'a', 'y', 'a', '-', 'd', 'o',
                                     'm', 'a', 'i', 'n', '-', 'v', '1'};
    uint8_t salt[32] = {0}, info[sizeof(prefix) + 4];
    if (aad_size < 4) {
        for (unsigned i = 0; i < 32; ++i)
            out[i] = 0;
        return;
    }
    uint32_t domain =
        (uint32_t)aad[0] | (uint32_t)aad[1] << 8 | (uint32_t)aad[2] << 16 | (uint32_t)aad[3] << 24;
    if (domain != 1 && domain != 8) {
        for (unsigned i = 0; i < 32; ++i)
            out[i] = 0;
        return;
    }
    if (aad_size == 32) {
        for (unsigned i = 0; i < 32; ++i)
            salt[i] = aad[i];
    } else {
        hash(aad, (size_t)aad_size, salt);
    }
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    for (unsigned i = 0; i < 4; ++i)
        info[sizeof(prefix) + i] = (uint8_t)(domain >> (8 * i));
    expand_one(out, root, salt, info, sizeof(info));
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(info, sizeof(info));
}
void maya_derive_legacy_body_key(uint8_t out[32], const uint8_t root[32], uint64_t address,
                                 uint64_t size) {
    static const uint8_t prefix[] = {'m', 'a', 'y', 'a', '-', 'l', 'e', 'g', 'a', 'c',
                                     'y', '-', 'b', 'o', 'd', 'y', '-', 'v', '1'};
    uint8_t salt[32] = {0}, info[sizeof(prefix) + 16];
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    for (unsigned i = 0; i < 8; ++i) {
        info[sizeof(prefix) + i] = (uint8_t)(address >> (8 * i));
        info[sizeof(prefix) + 8 + i] = (uint8_t)(size >> (8 * i));
    }
    expand_one(out, root, salt, info, sizeof(info));
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(info, sizeof(info));
}
void maya_derive_state_binding_key(uint8_t out[32], const uint8_t root[32], uint64_t cookie) {
    static const uint8_t prefix[] = {'m', 'a', 'y', 'a', '-', 'd', 'o',
                                     'm', 'a', 'i', 'n', '-', 'v', '1'};
    uint8_t context[8], salt[32], info[sizeof(prefix) + 4];
    for (unsigned i = 0; i < 8; ++i)
        context[i] = (uint8_t)(cookie >> (8 * i));
    hash(context, sizeof(context), salt);
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    info[sizeof(prefix)] = 13;
    info[sizeof(prefix) + 1] = 0;
    info[sizeof(prefix) + 2] = 0;
    info[sizeof(prefix) + 3] = 0;
    expand_one(out, root, salt, info, sizeof(info));
    maya_secure_wipe(context, sizeof(context));
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(info, sizeof(info));
}
#if MAYA_ENABLE_V3
void maya_v3_derive_vm_key(uint8_t out[32], const uint8_t root[32], const uint8_t owner[16],
                           uint32_t cluster) {
    static const uint8_t prefix[] = {
        14, 0, 0, 0,   'm', 'a', 'y', 'a', '-', 'v', '3', '-', 'd', 'o', 'm', 'a', 'i', 'n', 16,
        0,  0, 0, 'r', 'u', 'n', 't', 'i', 'm', 'e', '-', 'b', 'y', 't', 'e', 'c', 'o', 'd', 'e'};
    uint8_t salt[32], prk[32], info[sizeof(prefix) + 5];
    hash(owner, 16, salt);
    hmac(salt, root, 32, prk);
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    info[sizeof(prefix)] = (uint8_t)cluster;
    info[sizeof(prefix) + 1] = (uint8_t)(cluster >> 8);
    info[sizeof(prefix) + 2] = (uint8_t)(cluster >> 16);
    info[sizeof(prefix) + 3] = (uint8_t)(cluster >> 24);
    info[sizeof(prefix) + 4] = 1;
    hmac(prk, info, sizeof(info), out);
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(prk, sizeof(prk));
    maya_secure_wipe(info, sizeof(info));
}
void maya_v3_derive_capability_key(uint8_t out[32], const uint8_t root[32], const uint8_t owner[16],
                                   uint32_t cluster) {
    static const uint8_t prefix[] = {14,  0,   0,   0,   'm', 'a', 'y', 'a', '-', 'v', '3',
                                     '-', 'd', 'o', 'm', 'a', 'i', 'n', 10,  0,   0,   0,
                                     'c', 'a', 'p', 'a', 'b', 'i', 'l', 'i', 't', 'y'};
    uint8_t salt[32], prk[32], info[sizeof(prefix) + 5];
    hash(owner, 16, salt);
    hmac(salt, root, 32, prk);
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    info[sizeof(prefix)] = (uint8_t)cluster;
    info[sizeof(prefix) + 1] = (uint8_t)(cluster >> 8);
    info[sizeof(prefix) + 2] = (uint8_t)(cluster >> 16);
    info[sizeof(prefix) + 3] = (uint8_t)(cluster >> 24);
    info[sizeof(prefix) + 4] = 1;
    hmac(prk, info, sizeof(info), out);
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(prk, sizeof(prk));
    maya_secure_wipe(info, sizeof(info));
}
void maya_v3_derive_shard_key(uint8_t out[32], const uint8_t root[32], const uint8_t owner[16],
                              uint32_t cluster, uint32_t family) {
    static const uint8_t prefix[] = {14,  0,   0,   0,   'm', 'a', 'y', 'a', '-', 'v', '3', '-',
                                     'd', 'o', 'm', 'a', 'i', 'n', 12,  0,   0,   0,   's', 'h',
                                     'a', 'r', 'd', '-', 'a', 'e', 'a', 'd', '-', 0};
    uint8_t salt[32], prk[32], info[sizeof(prefix) + 5];
    if (family > 2) {
        for (unsigned i = 0; i < 32; ++i)
            out[i] = 0;
        return;
    }
    hash(owner, 16, salt);
    hmac(salt, root, 32, prk);
    for (size_t i = 0; i < sizeof(prefix); ++i)
        info[i] = prefix[i];
    info[sizeof(prefix) - 1] = (uint8_t)('0' + family);
    info[sizeof(prefix)] = (uint8_t)cluster;
    info[sizeof(prefix) + 1] = (uint8_t)(cluster >> 8);
    info[sizeof(prefix) + 2] = (uint8_t)(cluster >> 16);
    info[sizeof(prefix) + 3] = (uint8_t)(cluster >> 24);
    info[sizeof(prefix) + 4] = 1;
    hmac(prk, info, sizeof(info), out);
    maya_secure_wipe(salt, sizeof(salt));
    maya_secure_wipe(prk, sizeof(prk));
    maya_secure_wipe(info, sizeof(info));
}
int maya_v3_validate_capability(const uint8_t token[32], const uint8_t root[32],
                                const uint8_t owner[16], uint32_t cluster, const uint8_t* canonical,
                                uint64_t canonical_size) {
    uint8_t key[32], expected[32];
    uint32_t difference = 0;
    maya_v3_derive_capability_key(key, root, owner, cluster);
    hmac(key, canonical, (size_t)canonical_size, expected);
    for (unsigned i = 0; i < 32; ++i)
        difference |= (uint32_t)(token[i] ^ expected[i]);
    maya_secure_wipe(key, sizeof(key));
    maya_secure_wipe(expected, sizeof(expected));
    return difference == 0;
}
void maya_v3_issue_capability(uint8_t token[32], const uint8_t root[32], const uint8_t owner[16],
                              uint32_t cluster, const uint8_t* canonical, uint64_t canonical_size) {
    uint8_t key[32];
    maya_v3_derive_capability_key(key, root, owner, cluster);
    hmac(key, canonical, (size_t)canonical_size, token);
    maya_secure_wipe(key, sizeof(key));
}
#endif
