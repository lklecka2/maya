#include "xchacha20poly1305.h"

static uint32_t ld32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void st32(uint8_t* p, uint32_t x) {
    for (unsigned i = 0; i < 4; i++)
        p[i] = (uint8_t)(x >> (8 * i));
}
static uint32_t rol(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
#define QR(a, b, c, d)                                                                             \
    a += b;                                                                                        \
    d = rol(d ^ a, 16);                                                                            \
    c += d;                                                                                        \
    b = rol(b ^ c, 12);                                                                            \
    a += b;                                                                                        \
    d = rol(d ^ a, 8);                                                                             \
    c += d;                                                                                        \
    b = rol(b ^ c, 7)
static void hchacha(uint8_t out[32], const uint8_t key[32], const uint8_t n[16]) {
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (unsigned i = 0; i < 8; i++)
        x[4 + i] = ld32(key + 4 * i);
    for (unsigned i = 0; i < 4; i++)
        x[12 + i] = ld32(n + 4 * i);
    for (unsigned i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    unsigned z[8] = {0, 1, 2, 3, 12, 13, 14, 15};
    for (unsigned i = 0; i < 8; i++)
        st32(out + 4 * i, x[z[i]]);
}
static void block(uint8_t out[64], const uint8_t key[32], uint32_t ctr, const uint8_t n[12]) {
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}, w[16];
    for (unsigned i = 0; i < 8; i++)
        x[4 + i] = ld32(key + 4 * i);
    x[12] = ctr;
    for (unsigned i = 0; i < 3; i++)
        x[13 + i] = ld32(n + 4 * i);
    for (unsigned i = 0; i < 16; i++)
        w[i] = x[i];
    for (unsigned i = 0; i < 10; i++) {
        QR(w[0], w[4], w[8], w[12]);
        QR(w[1], w[5], w[9], w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[8], w[13]);
        QR(w[3], w[4], w[9], w[14]);
    }
    for (unsigned i = 0; i < 16; i++)
        st32(out + 4 * i, w[i] + x[i]);
}
typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t buf[16];
    size_t used;
} poly;
static void pblock(poly* p, const uint8_t m[16], uint32_t hibit) {
    uint32_t h0 = p->h[0] + (ld32(m) & 0x3ffffff), h1 = p->h[1] + ((ld32(m + 3) >> 2) & 0x3ffffff),
             h2 = p->h[2] + ((ld32(m + 6) >> 4) & 0x3ffffff),
             h3 = p->h[3] + ((ld32(m + 9) >> 6) & 0x3ffffff),
             h4 = p->h[4] + ((ld32(m + 12) >> 8) | hibit);
    uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4], s1 = r1 * 5,
             s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
                  (uint64_t)h4 * s1,
             d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
                  (uint64_t)h4 * s2,
             d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
                  (uint64_t)h4 * s3,
             d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
                  (uint64_t)h4 * s4,
             d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
                  (uint64_t)h4 * r0;
    uint32_t c = (uint32_t)(d0 >> 26);
    p->h[0] = (uint32_t)d0 & 0x3ffffff;
    d1 += c;
    c = (uint32_t)(d1 >> 26);
    p->h[1] = (uint32_t)d1 & 0x3ffffff;
    d2 += c;
    c = (uint32_t)(d2 >> 26);
    p->h[2] = (uint32_t)d2 & 0x3ffffff;
    d3 += c;
    c = (uint32_t)(d3 >> 26);
    p->h[3] = (uint32_t)d3 & 0x3ffffff;
    d4 += c;
    c = (uint32_t)(d4 >> 26);
    p->h[4] = (uint32_t)d4 & 0x3ffffff;
    p->h[0] += c * 5;
    c = p->h[0] >> 26;
    p->h[0] &= 0x3ffffff;
    p->h[1] += c;
}
static void pinit(poly* p, const uint8_t k[32]) {
    p->r[0] = ld32(k) & 0x3ffffff;
    p->r[1] = (ld32(k + 3) >> 2) & 0x3ffff03;
    p->r[2] = (ld32(k + 6) >> 4) & 0x3ffc0ff;
    p->r[3] = (ld32(k + 9) >> 6) & 0x3f03fff;
    p->r[4] = (ld32(k + 12) >> 8) & 0x00fffff;
    for (unsigned i = 0; i < 5; i++)
        p->h[i] = 0;
    for (unsigned i = 0; i < 4; i++)
        p->pad[i] = ld32(k + 16 + 4 * i);
    p->used = 0;
}
static void pup(poly* p, const uint8_t* m, size_t n) {
    if (p->used) {
        size_t q = 16 - p->used;
        if (q > n)
            q = n;
        for (size_t i = 0; i < q; i++)
            p->buf[p->used + i] = m[i];
        p->used += q;
        m += q;
        n -= q;
        if (p->used == 16) {
            pblock(p, p->buf, 1 << 24);
            p->used = 0;
        }
    }
    while (n >= 16) {
        pblock(p, m, 1 << 24);
        m += 16;
        n -= 16;
    }
    if (n) {
        for (size_t i = 0; i < n; i++)
            p->buf[i] = m[i];
        p->used = n;
    }
}
static void pfinish(poly* p, uint8_t mac[16]) {
    if (p->used) {
        p->buf[p->used] = 1;
        for (size_t i = p->used + 1; i < 16; i++)
            p->buf[i] = 0;
        pblock(p, p->buf, 0);
    }
    uint32_t c = p->h[1] >> 26;
    p->h[1] &= 0x3ffffff;
    p->h[2] += c;
    c = p->h[2] >> 26;
    p->h[2] &= 0x3ffffff;
    p->h[3] += c;
    c = p->h[3] >> 26;
    p->h[3] &= 0x3ffffff;
    p->h[4] += c;
    c = p->h[4] >> 26;
    p->h[4] &= 0x3ffffff;
    p->h[0] += c * 5;
    c = p->h[0] >> 26;
    p->h[0] &= 0x3ffffff;
    p->h[1] += c;
    uint32_t g[5];
    g[0] = p->h[0] + 5;
    c = g[0] >> 26;
    g[0] &= 0x3ffffff;
    for (unsigned i = 1; i < 4; i++) {
        g[i] = p->h[i] + c;
        c = g[i] >> 26;
        g[i] &= 0x3ffffff;
    }
    g[4] = p->h[4] + c - (1 << 26);
    uint32_t mask = (g[4] >> 31) - 1;
    for (unsigned i = 0; i < 5; i++)
        g[i] &= mask;
    mask = ~mask;
    for (unsigned i = 0; i < 5; i++)
        p->h[i] = (p->h[i] & mask) | g[i];
    uint64_t f0 = (uint32_t)(p->h[0] | p->h[1] << 26);
    f0 += p->pad[0];
    uint64_t f1 = (uint32_t)(p->h[1] >> 6 | p->h[2] << 20);
    f1 += p->pad[1] + (f0 >> 32);
    uint64_t f2 = (uint32_t)(p->h[2] >> 12 | p->h[3] << 14);
    f2 += p->pad[2] + (f1 >> 32);
    uint64_t f3 = (uint32_t)(p->h[3] >> 18 | p->h[4] << 8);
    f3 += p->pad[3] + (f2 >> 32);
    st32(mac, (uint32_t)f0);
    st32(mac + 4, (uint32_t)f1);
    st32(mac + 8, (uint32_t)f2);
    st32(mac + 12, (uint32_t)f3);
}
static void pad16(poly* p, size_t n) {
    static const uint8_t z[16] = {0};
    if (n & 15)
        pup(p, z, 16 - (n & 15));
}
static void len64(uint8_t out[8], size_t n) {
    for (unsigned i = 0; i < 8; i++)
        out[i] = (uint8_t)((uint64_t)n >> (8 * i));
}
int maya_xchacha20poly1305_open(uint8_t* plain, const uint8_t* cipher, size_t size,
                                const uint8_t* aad, size_t as, const uint8_t key[32],
                                const uint8_t nonce[24], const uint8_t tag[16]) {
    uint8_t sub[32], n12[12] = {0}, stream[64], calc[16], lens[16];
    hchacha(sub, key, nonce);
    for (unsigned i = 0; i < 8; i++)
        n12[4 + i] = nonce[16 + i];
    block(stream, sub, 0, n12);
    poly p;
    pinit(&p, stream);
    pup(&p, aad, as);
    pad16(&p, as);
    pup(&p, cipher, size);
    pad16(&p, size);
    len64(lens, as);
    len64(lens + 8, size);
    pup(&p, lens, 16);
    pfinish(&p, calc);
    uint32_t diff = 0;
    for (unsigned i = 0; i < 16; i++)
        diff |= calc[i] ^ tag[i];
    if (diff)
        return -1;
    uint32_t ctr = 1;
    for (size_t o = 0; o < size;) {
        block(stream, sub, ctr++, n12);
        size_t n = size - o < 64 ? size - o : 64;
        for (size_t i = 0; i < n; i++)
            plain[o + i] = cipher[o + i] ^ stream[i];
        o += n;
    }
    for (unsigned i = 0; i < 64; i++)
        stream[i] = 0;
    for (unsigned i = 0; i < 32; i++)
        sub[i] = 0;
    return 0;
}
