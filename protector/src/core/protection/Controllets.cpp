#include "Controllets.hpp"

#include "FragmentCrypto.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace maya::protection {
namespace {
constexpr uint64_t kFamilyMagic[3] = {
    UINT64_C(0x31414d534159414d), // MAYASMA1
    UINT64_C(0x31424d534159414d),
    UINT64_C(0x31434d534159414d),
};
constexpr uint64_t kCookieDomain[3] = {
    UINT64_C(0x108f7a31d4c25be9),
    UINT64_C(0x692ce804b1573fda),
    UINT64_C(0xd5319b60e82c47af),
};
uint64_t rotl(uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }
void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(uint8_t(v >> (8 * i)));
}
void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(uint8_t(v >> (8 * i)));
}
uint32_t get32(const std::vector<uint8_t>& in, size_t off) {
    if (off > in.size() || in.size() - off < 4)
        throw std::runtime_error("truncated shard u32");
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i)
        v |= uint32_t(in[off + i]) << (8 * i);
    return v;
}
uint64_t get64(const std::vector<uint8_t>& in, size_t off) {
    if (off > in.size() || in.size() - off < 8)
        throw std::runtime_error("truncated shard u64");
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i)
        v |= uint64_t(in[off + i]) << (8 * i);
    return v;
}
uint64_t mask_value(uint64_t value, uint32_t cluster, const std::array<uint8_t, 32>& salt) {
    uint64_t s = 0;
    std::memcpy(&s, salt.data() + (cluster % 4) * 8, 8);
    return value ^ rotl(s ^ cluster, 13);
}
} // namespace

ClusterAssignment assign_controllet(uint32_t selected_id, uint64_t seed_word, uint32_t limit) {
    if (limit < 3)
        throw std::invalid_argument("controllet cluster limit must be at least three");
    // A seeded rotation preserves an even distribution for adjacent function
    // identifiers while remaining identical for deterministic seeded builds.
    const uint32_t cluster = uint32_t((uint64_t(selected_id) + (seed_word % limit)) % limit);
    return {cluster, cluster % kControlletFamilyCount};
}
uint64_t controllet_cookie(uint64_t cookie, uint32_t family) {
    if (family >= 3)
        throw std::invalid_argument("unknown controllet family");
    return cookie ^ kCookieDomain[family];
}
uint64_t metadata_shard_mask(uint32_t cluster, const std::array<uint8_t, 32>& salt) {
    return mask_value(0, cluster, salt);
}
size_t metadata_shard_value_offset(uint32_t family, size_t index) {
    if (family >= 3)
        throw std::invalid_argument("unknown shard family");
    return 24 + index * 24 + (family == 0 ? 16 : family == 1 ? 0 : 8);
}
uint64_t encode_controllet_token(uint64_t value, uint64_t mask, uint32_t family) {
    switch (family) {
    case 0:
        return value ^ mask;
    case 1:
        return rotl(value ^ mask, 47);
    case 2:
        return ~(value ^ mask);
    default:
        throw std::invalid_argument("unknown controllet family");
    }
}
uint64_t decode_controllet_token(uint64_t token, uint64_t mask, uint32_t family) {
    switch (family) {
    case 0:
        return token ^ mask;
    case 1:
        return rotl(token, 17) ^ mask;
    case 2:
        return (~token) ^ mask;
    default:
        throw std::invalid_argument("unknown controllet family");
    }
}

std::vector<uint8_t> serialize_metadata_shard(uint32_t family, uint32_t cluster,
                                              const std::array<uint8_t, 32>& salt,
                                              const std::vector<ShardRecord>& records) {
    if (family >= 3)
        throw std::invalid_argument("unknown shard family");
    std::vector<uint8_t> out;
    put64(out, kFamilyMagic[family]);
    put32(out, kControlletContractVersion);
    if (family == 0) {
        put32(out, cluster);
        put32(out, uint32_t(records.size()));
        put32(out, 24);
    } else if (family == 1) {
        put32(out, uint32_t(records.size()));
        put32(out, 24);
        put32(out, cluster);
    } else {
        put32(out, 24);
        put32(out, cluster);
        put32(out, uint32_t(records.size()));
    }
    for (const auto& r : records) {
        if (family == 0) {
            put32(out, r.owner_function);
            put32(out, r.fragment_id);
            put32(out, r.kind);
            put32(out, 0);
            put64(out, mask_value(r.value, cluster, salt));
        } else if (family == 1) {
            put64(out, mask_value(r.value, cluster, salt));
            put32(out, r.kind);
            put32(out, r.owner_function);
            put32(out, 0);
            put32(out, r.fragment_id);
        } else {
            put32(out, r.fragment_id);
            put32(out, 0);
            put64(out, mask_value(r.value, cluster, salt));
            put32(out, r.owner_function);
            put32(out, r.kind);
        }
    }
    std::vector<uint8_t> authenticated(salt.begin(), salt.end());
    authenticated.insert(authenticated.end(), out.begin(), out.end());
    const auto digest = sha256_bytes(authenticated);
    out.insert(out.end(), digest.begin(), digest.end());
    return out;
}

std::vector<ShardRecord> parse_metadata_shard(uint32_t family, uint32_t cluster,
                                              const std::array<uint8_t, 32>& salt,
                                              const std::vector<uint8_t>& in) {
    if (family >= 3 || in.size() < 56 || get64(in, 0) != kFamilyMagic[family] ||
        get32(in, 8) != kControlletContractVersion)
        throw std::runtime_error("wrong shard family/version");
    uint32_t stored_cluster = 0, count = 0, width = 0;
    if (family == 0) {
        stored_cluster = get32(in, 12);
        count = get32(in, 16);
        width = get32(in, 20);
    } else if (family == 1) {
        count = get32(in, 12);
        width = get32(in, 16);
        stored_cluster = get32(in, 20);
    } else {
        width = get32(in, 12);
        stored_cluster = get32(in, 16);
        count = get32(in, 20);
    }
    if (stored_cluster != cluster || width != 24 || count > (in.size() - 56) / 24 ||
        in.size() != 24 + size_t(count) * 24 + 32)
        throw std::runtime_error("invalid shard bounds/owner");
    std::vector<uint8_t> authenticated(salt.begin(), salt.end());
    authenticated.insert(authenticated.end(), in.begin(), in.end() - 32);
    const auto digest = sha256_bytes(authenticated);
    if (!std::equal(digest.begin(), digest.end(), in.end() - 32))
        throw std::runtime_error("shard authentication failed");
    std::vector<ShardRecord> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const size_t o = 24 + size_t(i) * 24;
        ShardRecord r;
        if (family == 0) {
            r.owner_function = get32(in, o);
            r.fragment_id = get32(in, o + 4);
            r.kind = get32(in, o + 8);
            r.value = mask_value(get64(in, o + 16), cluster, salt);
        } else if (family == 1) {
            r.value = mask_value(get64(in, o), cluster, salt);
            r.kind = get32(in, o + 8);
            r.owner_function = get32(in, o + 12);
            r.fragment_id = get32(in, o + 20);
        } else {
            r.fragment_id = get32(in, o);
            r.value = mask_value(get64(in, o + 8), cluster, salt);
            r.owner_function = get32(in, o + 16);
            r.kind = get32(in, o + 20);
        }
        if (std::any_of(out.begin(), out.end(), [&](const auto& x) {
                return x.owner_function == r.owner_function && x.fragment_id == r.fragment_id &&
                       x.kind == r.kind;
            }))
            throw std::runtime_error("duplicate shard record");
        out.push_back(r);
    }
    return out;
}
} // namespace maya::protection
