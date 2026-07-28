#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace maya::protection {

inline constexpr uint32_t kControlletContractVersion = 1;
inline constexpr uint32_t kControlletFamilyCount = 3;

struct ClusterAssignment {
    uint32_t cluster_id = 0;
    uint32_t family = 0;
};

struct ShardRecord {
    uint32_t owner_function = 0;
    uint32_t fragment_id = 0;
    uint32_t kind = 0;
    uint64_t value = 0;
};

ClusterAssignment assign_controllet(uint32_t selected_id, uint64_t seed_word,
                                    uint32_t cluster_limit = 7);
uint64_t controllet_cookie(uint64_t binary_cookie, uint32_t family);
uint64_t metadata_shard_mask(uint32_t cluster_id, const std::array<uint8_t, 32>& salt);
size_t metadata_shard_value_offset(uint32_t family, size_t record_index);
uint64_t encode_controllet_token(uint64_t value, uint64_t state_mask, uint32_t family);
uint64_t decode_controllet_token(uint64_t token, uint64_t state_mask, uint32_t family);

std::vector<uint8_t> serialize_metadata_shard(uint32_t family, uint32_t cluster_id,
                                              const std::array<uint8_t, 32>& salt,
                                              const std::vector<ShardRecord>& records);
std::vector<ShardRecord> parse_metadata_shard(uint32_t expected_family, uint32_t expected_cluster,
                                              const std::array<uint8_t, 32>& salt,
                                              const std::vector<uint8_t>& bytes);

} // namespace maya::protection
