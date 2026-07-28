#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int maya_xchacha20poly1305_open(uint8_t* plain, const uint8_t* cipher, size_t size,
                                const uint8_t* aad, size_t aad_size, const uint8_t key[32],
                                const uint8_t nonce[24], const uint8_t tag[16]);
#ifdef __cplusplus
}
#endif
