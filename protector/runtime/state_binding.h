#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum maya_state_domain {
    MAYA_STATE_CODE = 0x434f4445u,
    MAYA_STATE_EXIT = 0x45584954u,
    MAYA_STATE_CONTINUATION = 0x434f4e54u,
    MAYA_STATE_CONSTANT = 0x434f4e53u,
    MAYA_STATE_CHECKPOINT = 0x43484b50u,
};

uint64_t maya_state_mask(const uint8_t key[32], uint64_t binary_cookie, uint64_t thread_cookie,
                         uint64_t epoch, uint64_t path_digest, uint64_t frame_cookie,
                         uint64_t logical_state, uint64_t depth_generation);
uint64_t maya_state_advance(uint64_t path_digest, uint64_t state_mask, uint64_t committed_event);

#ifdef __cplusplus
}
#endif
