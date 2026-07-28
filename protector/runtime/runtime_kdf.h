#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if MAYA_ENABLE_V3
void maya_v3_derive_vm_key(uint8_t output[32], const uint8_t root[32], const uint8_t owner[16],
                           uint32_t cluster);
void maya_v3_derive_capability_key(uint8_t output[32], const uint8_t root[32],
                                   const uint8_t owner[16], uint32_t cluster);
void maya_v3_derive_shard_key(uint8_t output[32], const uint8_t root[32], const uint8_t owner[16],
                              uint32_t cluster, uint32_t family);
int maya_v3_validate_capability(const uint8_t token[32], const uint8_t root[32],
                                const uint8_t owner[16], uint32_t cluster, const uint8_t* canonical,
                                uint64_t canonical_size);
void maya_v3_issue_capability(uint8_t token[32], const uint8_t root[32], const uint8_t owner[16],
                              uint32_t cluster, const uint8_t* canonical, uint64_t canonical_size);
#endif
void maya_hmac_sha256(uint8_t output[32], const uint8_t key[32], const uint8_t* message,
                      uint64_t message_size);
void maya_sha256_digest(uint8_t output[32], const uint8_t* message, uint64_t message_size);
void maya_derive_sealed_object_key(uint8_t output[32], const uint8_t root[32], const uint8_t* aad,
                                   uint64_t aad_size);
void maya_derive_legacy_body_key(uint8_t output[32], const uint8_t root[32],
                                 uint64_t original_address, uint64_t size);
void maya_derive_state_binding_key(uint8_t output[32], const uint8_t root[32],
                                   uint64_t binary_cookie);
void maya_secure_wipe(void* value, uint64_t size);
#ifdef __cplusplus
}
#endif
