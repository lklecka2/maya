#include "core/protection/V3Shards.hpp"
#include "runtime_kdf.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace maya::protection;

static void must_fail(const std::function<void()>& operation) {
    try {
        operation();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("negative V3 shard test passed");
}

int main() {
    Seed256 seed{};
    for (size_t index = 0; index < seed.size(); ++index)
        seed[index] = static_cast<uint8_t>(index * 13 + 7);
    const auto owner = derive_opaque128(seed, "owner", 1, 4);
    std::vector<V3ShardRecord> records;
    for (uint64_t index = 0; index < 9; ++index) {
        V3ShardRecord record;
        record.lookup_label = derive_opaque128(seed, "lookup", index, 4);
        record.owner_namespace = owner;
        record.capability = {derive_opaque128(seed, "source", index, 4),
                             derive_opaque128(seed, "destination", index, 4), V3EventClass::Next,
                             4};
        record.resolver_payload = {static_cast<uint8_t>(index), static_cast<uint8_t>(index ^ 0xa5)};
        records.push_back(record);
    }
    std::vector<std::vector<uint8_t>> ciphertexts;
    for (uint32_t family = 0; family < kV3ShardFamilyCount; ++family) {
        const auto host_key =
            derive_v3_domain_key(seed, "shard-aead-" + std::to_string(family), owner, 4);
        uint8_t native_key[32]{};
        maya_v3_derive_shard_key(native_key, seed.data(), owner.data(), 4, family);
        if (!std::equal(host_key.begin(), host_key.end(), native_key))
            return 10 + family;
        auto shard = seal_v3_shard(static_cast<V3ShardFamily>(family), 4, owner,
                                   0x9000 + family * 0x1000, seed, seed, records);
        auto decoded = open_v3_shard(shard, seed);
        if (decoded.size() != records.size() ||
            find_v3_record(decoded, records[5].lookup_label) == nullptr)
            return 1;
        ciphertexts.push_back(shard.ciphertext);
        auto corrupt = shard;
        corrupt.ciphertext[corrupt.ciphertext.size() / 2] ^= 1;
        must_fail([&] { open_v3_shard(corrupt, seed); });
        auto relocated = shard;
        relocated.ciphertext_location += 0x1000;
        must_fail([&] { open_v3_shard(relocated, seed); });
        auto wrong_owner = shard;
        wrong_owner.owner_namespace[0] ^= 1;
        must_fail([&] { open_v3_shard(wrong_owner, seed); });
        auto truncated = shard;
        truncated.ciphertext.pop_back();
        must_fail([&] { open_v3_shard(truncated, seed); });
        auto extended = shard;
        extended.ciphertext.push_back(0);
        must_fail([&] { open_v3_shard(extended, seed); });
        auto wrong_family = shard;
        wrong_family.family = static_cast<V3ShardFamily>((family + 1) % kV3ShardFamilyCount);
        must_fail([&] { open_v3_shard(wrong_family, seed); });
    }
    if (ciphertexts[0] == ciphertexts[1] || ciphertexts[1] == ciphertexts[2] ||
        ciphertexts[0] == ciphertexts[2])
        return 2;
    auto duplicate = records;
    duplicate.push_back(records.front());
    must_fail(
        [&] { seal_v3_shard(V3ShardFamily::KeyedHash, 4, owner, 0x9000, seed, seed, duplicate); });
    for (uint32_t family = 0; family < kV3ShardFamilyCount; ++family) {
        for (size_t count : {size_t{0}, size_t{1}, size_t{128}}) {
            std::vector<V3ShardRecord> boundary(records.begin(),
                                                records.begin() + std::min(count, records.size()));
            while (boundary.size() < count) {
                const uint64_t index = boundary.size();
                V3ShardRecord record;
                record.lookup_label = derive_opaque128(seed, "boundary-lookup", index, 4);
                record.owner_namespace = owner;
                record.capability = {derive_opaque128(seed, "boundary-source", index, 4),
                                     derive_opaque128(seed, "boundary-destination", index, 4),
                                     V3EventClass::Next, 4};
                record.resolver_payload.assign((index % 31) + 1, static_cast<uint8_t>(index));
                boundary.push_back(std::move(record));
            }
            auto shard =
                seal_v3_shard(static_cast<V3ShardFamily>(family), 4, owner,
                              0x20000 + family * 0x10000 + count * 0x100, seed, seed, boundary);
            if (open_v3_shard(shard, seed).size() != count)
                return 30 + family;
        }
    }
    std::cout << "V3 shard tests passed\n";
}
