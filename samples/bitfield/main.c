/* Tests: bitwise operations, bit fields, bit manipulation algorithms,
   byte-level operations (exercises ldrb/strb, shift/mask patterns) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int popcount32(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

static uint32_t reverse_bits(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static int clz32(uint32_t x) {
    if (x == 0) return 32;
    int n = 0;
    if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF000000) == 0) { n += 8;  x <<= 8; }
    if ((x & 0xF0000000) == 0) { n += 4;  x <<= 4; }
    if ((x & 0xC0000000) == 0) { n += 2;  x <<= 2; }
    if ((x & 0x80000000) == 0) { n += 1; }
    return n;
}

static uint32_t next_power_of_2(uint32_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

/* Pack/unpack RGB */
static uint32_t pack_rgb(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
}

static void unpack_rgb(uint32_t color, uint8_t *r, uint8_t *g, uint8_t *b) {
    *r = (color >> 16) & 0xFF;
    *g = (color >> 8) & 0xFF;
    *b = color & 0xFF;
}

/* Simple hash */
static uint32_t fnv1a(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t hash = 0x811c9dc5;
    for (int i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 0x01000193;
    }
    return hash;
}

/* Bit array */
static void bit_set(uint8_t *arr, int bit) {
    arr[bit >> 3] |= (1 << (bit & 7));
}

static int bit_get(const uint8_t *arr, int bit) {
    return (arr[bit >> 3] >> (bit & 7)) & 1;
}

int main(void) {
    printf("popcount(0)=%d\n", popcount32(0));
    printf("popcount(0xFF)=%d\n", popcount32(0xFF));
    printf("popcount(0xAAAAAAAA)=%d\n", popcount32(0xAAAAAAAA));
    printf("popcount(0xFFFFFFFF)=%d\n", popcount32(0xFFFFFFFF));

    printf("reverse(1)=0x%08x\n", reverse_bits(1));
    printf("reverse(0x80000000)=0x%08x\n", reverse_bits(0x80000000));
    printf("reverse(0xF0)=0x%08x\n", reverse_bits(0xF0));

    printf("clz(1)=%d\n", clz32(1));
    printf("clz(0x80000000)=%d\n", clz32(0x80000000));
    printf("clz(0)=%d\n", clz32(0));
    printf("clz(0x100)=%d\n", clz32(0x100));

    printf("npow2(5)=%u\n", next_power_of_2(5));
    printf("npow2(16)=%u\n", next_power_of_2(16));
    printf("npow2(17)=%u\n", next_power_of_2(17));
    printf("npow2(1000)=%u\n", next_power_of_2(1000));

    uint32_t color = pack_rgb(0xAB, 0xCD, 0xEF);
    printf("packed=0x%06x\n", color);
    uint8_t r, g, b;
    unpack_rgb(color, &r, &g, &b);
    printf("unpacked=%02x,%02x,%02x\n", r, g, b);

    printf("fnv1a(hello)=0x%08x\n", fnv1a("hello", 5));
    printf("fnv1a(world)=0x%08x\n", fnv1a("world", 5));
    printf("fnv1a()=0x%08x\n", fnv1a("", 0));

    uint8_t bits[4];
    memset(bits, 0, sizeof(bits));
    bit_set(bits, 0);
    bit_set(bits, 7);
    bit_set(bits, 15);
    bit_set(bits, 31);
    printf("bit0=%d bit1=%d bit7=%d bit15=%d bit31=%d\n",
           bit_get(bits, 0), bit_get(bits, 1), bit_get(bits, 7),
           bit_get(bits, 15), bit_get(bits, 31));

    return 0;
}
