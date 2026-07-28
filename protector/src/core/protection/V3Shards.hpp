#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "V3Capabilities.hpp"

namespace maya::protection {

inline constexpr uint32_t kV3ShardContractVersion = 1;
inline constexpr uint32_t kV3ShardFamilyCount = 3;

enum class V3ShardFamily : uint32_t { KeyedHash = 0, AuthenticatedTree = 1, IndirectTable = 2 };

struct V3ShardRecord {
    Opaque128 lookup_label{};
    Opaque128 owner_namespace{};
    EdgeCapability capability{};
    std::vector<uint8_t> resolver_payload;
};

struct SealedV3Shard {
    V3ShardFamily family = V3ShardFamily::KeyedHash;
    uint32_t cluster = 0;
    Opaque128 owner_namespace{};
    uint64_t ciphertext_location = 0;
    uint32_t record_count = 0;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 16> tag{};
    std::vector<uint8_t> ciphertext;
};

SealedV3Shard seal_v3_shard(V3ShardFamily family, uint32_t cluster,
                            const Opaque128& owner_namespace, uint64_t ciphertext_location,
                            const Seed256& build_key, const Seed256& build_seed,
                            const std::vector<V3ShardRecord>& records);
std::vector<V3ShardRecord> open_v3_shard(const SealedV3Shard& shard, const Seed256& build_key);
const V3ShardRecord* find_v3_record(const std::vector<V3ShardRecord>& records,
                                    const Opaque128& lookup_label);

} // namespace maya::protection
