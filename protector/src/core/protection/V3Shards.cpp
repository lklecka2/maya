#include "V3Shards.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <set>
#include <stdexcept>

#include "FragmentCrypto.hpp"

namespace maya::protection {
namespace {

void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<uint8_t>(value >> (index * 8)));
}
void put64(std::vector<uint8_t>& out, uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<uint8_t>(value >> (index * 8)));
}
template <size_t N> void put(std::vector<uint8_t>& out, const std::array<uint8_t, N>& value) {
    out.insert(out.end(), value.begin(), value.end());
}

uint32_t get32(const std::vector<uint8_t>& bytes, size_t& offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4)
        throw std::runtime_error("Truncated V3 shard u32");
    uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index)
        value |= uint32_t(bytes[offset + index]) << (index * 8);
    offset += 4;
    return value;
}
uint64_t get64(const std::vector<uint8_t>& bytes, size_t& offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8)
        throw std::runtime_error("Truncated V3 shard u64");
    uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index)
        value |= uint64_t(bytes[offset + index]) << (index * 8);
    offset += 8;
    return value;
}
template <size_t N> std::array<uint8_t, N> get(const std::vector<uint8_t>& bytes, size_t& offset) {
    if (offset > bytes.size() || bytes.size() - offset < N)
        throw std::runtime_error("Truncated V3 shard field");
    std::array<uint8_t, N> value{};
    std::copy_n(bytes.begin() + static_cast<ptrdiff_t>(offset), N, value.begin());
    offset += N;
    return value;
}

bool is_zero(const Opaque128& value) {
    return std::all_of(value.begin(), value.end(), [](uint8_t byte) { return byte == 0; });
}

std::vector<uint8_t> encode_record(const V3ShardRecord& record) {
    if (is_zero(record.lookup_label) || is_zero(record.owner_namespace) ||
        is_zero(record.capability.source) || is_zero(record.capability.destination)) {
        throw std::runtime_error("V3 shard record contains a null authority");
    }
    if (record.resolver_payload.size() > 65536)
        throw std::runtime_error("V3 resolver payload is too large");
    std::vector<uint8_t> out;
    put(out, record.lookup_label);
    put(out, record.owner_namespace);
    put(out, record.capability.source);
    put(out, record.capability.destination);
    put32(out, static_cast<uint32_t>(record.capability.event_class));
    put32(out, record.capability.cluster);
    put32(out, static_cast<uint32_t>(record.resolver_payload.size()));
    out.insert(out.end(), record.resolver_payload.begin(), record.resolver_payload.end());
    return out;
}

V3ShardRecord decode_record(const std::vector<uint8_t>& bytes, size_t offset, size_t size) {
    if (offset > bytes.size() || size > bytes.size() - offset || size < 76) {
        throw std::runtime_error("Invalid V3 shard record range");
    }
    std::vector<uint8_t> record_bytes(bytes.begin() + static_cast<ptrdiff_t>(offset),
                                      bytes.begin() + static_cast<ptrdiff_t>(offset + size));
    size_t cursor = 0;
    V3ShardRecord record;
    record.lookup_label = get<16>(record_bytes, cursor);
    record.owner_namespace = get<16>(record_bytes, cursor);
    record.capability.source = get<16>(record_bytes, cursor);
    record.capability.destination = get<16>(record_bytes, cursor);
    const auto event = get32(record_bytes, cursor);
    if (event < static_cast<uint32_t>(V3EventClass::Next) ||
        event > static_cast<uint32_t>(V3EventClass::NonLocalJump)) {
        throw std::runtime_error("Invalid V3 shard event class");
    }
    record.capability.event_class = static_cast<V3EventClass>(event);
    record.capability.cluster = get32(record_bytes, cursor);
    const uint32_t payload_size = get32(record_bytes, cursor);
    if (payload_size != record_bytes.size() - cursor)
        throw std::runtime_error("Invalid V3 shard payload size");
    record.resolver_payload.assign(record_bytes.begin() + static_cast<ptrdiff_t>(cursor),
                                   record_bytes.end());
    if (is_zero(record.lookup_label) || is_zero(record.owner_namespace) ||
        is_zero(record.capability.source) || is_zero(record.capability.destination)) {
        throw std::runtime_error("Decoded a null V3 authority");
    }
    return record;
}

uint32_t next_power_of_two(uint32_t value) {
    uint32_t result = 1;
    while (result < value) {
        if (result > (1u << 30))
            throw std::runtime_error("V3 shard capacity overflow");
        result <<= 1;
    }
    return result;
}

uint32_t label_hash(const Opaque128& label) {
    uint32_t value = 2166136261u;
    for (uint8_t byte : label)
        value = (value ^ byte) * 16777619u;
    return value;
}

std::vector<uint8_t> encode_hash(const std::vector<V3ShardRecord>& records) {
    const uint32_t capacity =
        next_power_of_two(std::max<uint32_t>(4, static_cast<uint32_t>(records.size() * 2)));
    struct Slot {
        Opaque128 label{};
        uint32_t offset = 0, size = 0;
    };
    std::vector<Slot> slots(capacity);
    std::vector<uint8_t> blob;
    for (const auto& record : records) {
        auto encoded = encode_record(record);
        uint32_t index = label_hash(record.lookup_label) & (capacity - 1);
        while (!is_zero(slots[index].label))
            index = (index + 1) & (capacity - 1);
        slots[index] = {record.lookup_label, static_cast<uint32_t>(blob.size()),
                        static_cast<uint32_t>(encoded.size())};
        blob.insert(blob.end(), encoded.begin(), encoded.end());
    }
    std::vector<uint8_t> out;
    put32(out, static_cast<uint32_t>(records.size()));
    put32(out, capacity);
    put32(out, static_cast<uint32_t>(blob.size()));
    for (const auto& slot : slots) {
        put(out, slot.label);
        put32(out, slot.offset);
        put32(out, slot.size);
    }
    out.insert(out.end(), blob.begin(), blob.end());
    return out;
}

std::vector<V3ShardRecord> decode_hash(const std::vector<uint8_t>& bytes, uint32_t expected_count) {
    size_t cursor = 0;
    const uint32_t count = get32(bytes, cursor), capacity = get32(bytes, cursor),
                   blob_size = get32(bytes, cursor);
    if (count != expected_count || capacity < 4 || (capacity & (capacity - 1)) != 0 ||
        count * 2 > capacity) {
        throw std::runtime_error("Invalid V3 hash shard bounds");
    }
    if (capacity > 1u << 20)
        throw std::runtime_error("Excessive V3 hash shard capacity");
    struct Slot {
        Opaque128 label{};
        uint32_t offset = 0, size = 0;
    };
    std::vector<Slot> slots;
    for (uint32_t index = 0; index < capacity; ++index) {
        slots.push_back({get<16>(bytes, cursor), get32(bytes, cursor), get32(bytes, cursor)});
    }
    if (blob_size != bytes.size() - cursor)
        throw std::runtime_error("Invalid V3 hash shard blob size");
    std::vector<V3ShardRecord> records;
    for (const auto& slot : slots) {
        if (is_zero(slot.label)) {
            if (slot.offset != 0 || slot.size != 0)
                throw std::runtime_error("Ambiguous empty V3 hash slot");
            continue;
        }
        auto record = decode_record(bytes, cursor + slot.offset, slot.size);
        if (record.lookup_label != slot.label)
            throw std::runtime_error("V3 hash label mismatch");
        records.push_back(std::move(record));
    }
    if (records.size() != count)
        throw std::runtime_error("V3 hash shard count mismatch");
    return records;
}

std::vector<uint8_t> encode_tree(const std::vector<V3ShardRecord>& input) {
    std::vector<V3ShardRecord> records = input;
    std::sort(records.begin(), records.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.lookup_label < rhs.lookup_label; });
    struct Node {
        V3ShardRecord record;
        uint32_t left = UINT32_MAX, right = UINT32_MAX;
    };
    std::vector<Node> nodes;
    std::function<uint32_t(size_t, size_t)> build = [&](size_t first, size_t last) -> uint32_t {
        if (first == last)
            return UINT32_MAX;
        const size_t middle = first + (last - first) / 2;
        const uint32_t index = static_cast<uint32_t>(nodes.size());
        nodes.push_back({records[middle]});
        nodes[index].left = build(first, middle);
        nodes[index].right = build(middle + 1, last);
        return index;
    };
    if (!records.empty() && build(0, records.size()) != 0)
        throw std::runtime_error("Invalid V3 tree root");
    std::vector<uint8_t> out;
    put32(out, static_cast<uint32_t>(nodes.size()));
    for (const auto& node : nodes) {
        const auto encoded = encode_record(node.record);
        put32(out, node.left);
        put32(out, node.right);
        put32(out, static_cast<uint32_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
    }
    return out;
}

std::vector<V3ShardRecord> decode_tree(const std::vector<uint8_t>& bytes, uint32_t expected_count) {
    size_t cursor = 0;
    const uint32_t count = get32(bytes, cursor);
    if (count != expected_count || count > 1u << 20)
        throw std::runtime_error("Invalid V3 tree shard count");
    std::vector<V3ShardRecord> records;
    std::vector<std::pair<uint32_t, uint32_t>> children;
    for (uint32_t index = 0; index < count; ++index) {
        const uint32_t left = get32(bytes, cursor), right = get32(bytes, cursor),
                       size = get32(bytes, cursor);
        if ((left != UINT32_MAX && left >= count) || (right != UINT32_MAX && right >= count) ||
            left == index || right == index) {
            throw std::runtime_error("Invalid V3 tree topology");
        }
        children.push_back({left, right});
        records.push_back(decode_record(bytes, cursor, size));
        cursor += size;
    }
    if (cursor != bytes.size())
        throw std::runtime_error("Trailing V3 tree shard data");
    if (count != 0) {
        std::vector<uint8_t> visited(count, 0);
        std::function<void(uint32_t, const Opaque128*, const Opaque128*)> walk =
            [&](uint32_t index, const Opaque128* low, const Opaque128* high) {
                if (index >= count || visited[index])
                    throw std::runtime_error("Invalid V3 tree reachability");
                const auto& label = records[index].lookup_label;
                if ((low && !(label > *low)) || (high && !(label < *high)))
                    throw std::runtime_error("Invalid V3 tree ordering");
                visited[index] = 1;
                if (children[index].first != UINT32_MAX)
                    walk(children[index].first, low, &label);
                if (children[index].second != UINT32_MAX)
                    walk(children[index].second, &label, high);
            };
        walk(0, nullptr, nullptr);
        if (std::find(visited.begin(), visited.end(), 0) != visited.end())
            throw std::runtime_error("Disconnected V3 tree");
    }
    return records;
}

std::vector<uint8_t> encode_indirect(const std::vector<V3ShardRecord>& records) {
    struct Entry {
        uint32_t bucket = 0, offset = 0, size = 0;
    };
    std::vector<Entry> entries;
    std::vector<uint8_t> blob;
    std::vector<size_t> order(records.size());
    for (size_t index = 0; index < order.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t lhs, size_t rhs) {
        return label_hash(records[lhs].lookup_label) > label_hash(records[rhs].lookup_label);
    });
    for (size_t index : order) {
        auto encoded = encode_record(records[index]);
        entries.push_back({label_hash(records[index].lookup_label) & 0xffffu,
                           static_cast<uint32_t>(blob.size()),
                           static_cast<uint32_t>(encoded.size())});
        blob.insert(blob.end(), encoded.rbegin(), encoded.rend());
    }
    std::vector<uint8_t> out;
    put64(out, blob.size());
    put32(out, static_cast<uint32_t>(entries.size()));
    for (const auto& entry : entries) {
        put32(out, entry.bucket);
        put32(out, entry.size);
        put32(out, entry.offset);
    }
    out.insert(out.end(), blob.begin(), blob.end());
    return out;
}

std::vector<V3ShardRecord> decode_indirect(const std::vector<uint8_t>& bytes,
                                           uint32_t expected_count) {
    size_t cursor = 0;
    const uint64_t blob_size = get64(bytes, cursor);
    const uint32_t count = get32(bytes, cursor);
    if (count != expected_count || count > 1u << 20)
        throw std::runtime_error("Invalid V3 indirect shard count");
    struct Entry {
        uint32_t bucket, size, offset;
    };
    std::vector<Entry> entries;
    for (uint32_t index = 0; index < count; ++index)
        entries.push_back({get32(bytes, cursor), get32(bytes, cursor), get32(bytes, cursor)});
    if (blob_size != bytes.size() - cursor)
        throw std::runtime_error("Invalid V3 indirect blob size");
    std::vector<V3ShardRecord> records;
    for (const auto& entry : entries) {
        if (entry.offset > blob_size || entry.size > blob_size - entry.offset)
            throw std::runtime_error("Invalid V3 indirect range");
        std::vector<uint8_t> restored(
            bytes.begin() + static_cast<ptrdiff_t>(cursor + entry.offset),
            bytes.begin() + static_cast<ptrdiff_t>(cursor + entry.offset + entry.size));
        std::reverse(restored.begin(), restored.end());
        auto record = decode_record(restored, 0, restored.size());
        if ((label_hash(record.lookup_label) & 0xffffu) != entry.bucket)
            throw std::runtime_error("V3 indirect bucket mismatch");
        records.push_back(std::move(record));
    }
    return records;
}

void validate_records(const std::vector<V3ShardRecord>& records, const Opaque128& owner,
                      uint32_t cluster) {
    std::set<Opaque128> labels;
    for (const auto& record : records) {
        if (record.owner_namespace != owner || record.capability.cluster != cluster) {
            throw std::runtime_error("V3 shard record owner mismatch");
        }
        if (!labels.insert(record.lookup_label).second)
            throw std::runtime_error("Duplicate V3 shard lookup label");
    }
}

std::vector<uint8_t> shard_aad(const SealedV3Shard& shard) {
    std::vector<uint8_t> aad;
    put32(aad, kV3ShardContractVersion);
    put32(aad, static_cast<uint32_t>(shard.family));
    put32(aad, shard.cluster);
    put32(aad, shard.record_count);
    put(aad, shard.owner_namespace);
    put64(aad, shard.ciphertext_location);
    put64(aad, shard.ciphertext.size());
    return aad;
}

Seed256 shard_key(const Seed256& build_key, const SealedV3Shard& shard) {
    return derive_v3_domain_key(build_key,
                                "shard-aead-" + std::to_string(static_cast<uint32_t>(shard.family)),
                                shard.owner_namespace, shard.cluster);
}

} // namespace

SealedV3Shard seal_v3_shard(V3ShardFamily family, uint32_t cluster,
                            const Opaque128& owner_namespace, uint64_t ciphertext_location,
                            const Seed256& build_key, const Seed256& build_seed,
                            const std::vector<V3ShardRecord>& records) {
    if (static_cast<uint32_t>(family) >= kV3ShardFamilyCount)
        throw std::runtime_error("Unknown V3 shard family");
    validate_records(records, owner_namespace, cluster);
    std::vector<uint8_t> plaintext;
    switch (family) {
    case V3ShardFamily::KeyedHash:
        plaintext = encode_hash(records);
        break;
    case V3ShardFamily::AuthenticatedTree:
        plaintext = encode_tree(records);
        break;
    case V3ShardFamily::IndirectTable:
        plaintext = encode_indirect(records);
        break;
    }
    SealedV3Shard shard;
    shard.family = family;
    shard.cluster = cluster;
    shard.owner_namespace = owner_namespace;
    shard.ciphertext_location = ciphertext_location;
    shard.record_count = static_cast<uint32_t>(records.size());
    std::vector<uint8_t> nonce_info(owner_namespace.begin(), owner_namespace.end());
    put32(nonce_info, cluster);
    put32(nonce_info, static_cast<uint32_t>(family));
    put64(nonce_info, ciphertext_location);
    const auto nonce_material = hkdf_sha256(build_seed, {}, nonce_info);
    std::copy_n(nonce_material.begin(), shard.nonce.size(), shard.nonce.begin());
    shard.ciphertext.resize(plaintext.size());
    auto key = shard_key(build_key, shard);
    const auto sealed = seal_fragment(plaintext, shard_aad(shard), key, shard.nonce);
    secure_zero(key);
    shard.ciphertext = sealed.ciphertext;
    shard.tag = sealed.tag;
    return shard;
}

std::vector<V3ShardRecord> open_v3_shard(const SealedV3Shard& shard, const Seed256& build_key) {
    if (static_cast<uint32_t>(shard.family) >= kV3ShardFamilyCount)
        throw std::runtime_error("Unknown V3 shard family");
    SealedFragment sealed{shard.nonce, shard.tag, shard.ciphertext};
    auto key = shard_key(build_key, shard);
    std::vector<uint8_t> plaintext;
    try {
        plaintext = open_fragment(sealed, shard_aad(shard), key);
    } catch (...) {
        secure_zero(key);
        throw;
    }
    secure_zero(key);
    std::vector<V3ShardRecord> records;
    switch (shard.family) {
    case V3ShardFamily::KeyedHash:
        records = decode_hash(plaintext, shard.record_count);
        break;
    case V3ShardFamily::AuthenticatedTree:
        records = decode_tree(plaintext, shard.record_count);
        break;
    case V3ShardFamily::IndirectTable:
        records = decode_indirect(plaintext, shard.record_count);
        break;
    }
    validate_records(records, shard.owner_namespace, shard.cluster);
    return records;
}

const V3ShardRecord* find_v3_record(const std::vector<V3ShardRecord>& records,
                                    const Opaque128& lookup_label) {
    const auto iterator = std::find_if(records.begin(), records.end(), [&](const auto& record) {
        return record.lookup_label == lookup_label;
    });
    return iterator == records.end() ? nullptr : &*iterator;
}

} // namespace maya::protection
