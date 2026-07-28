#include "core/protection/Controllets.hpp"
#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
using namespace maya::protection;
static void fail(const std::function<void()>& f) {
    try {
        f();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("negative controllet test passed");
}
int main() {
    std::array<uint8_t, 32> salt{};
    for (size_t i = 0; i < salt.size(); ++i)
        salt[i] = uint8_t(i * 11 + 1);
    std::vector<ShardRecord> records = {{3, 4, 5, 0x1122334455667788ULL},
                                        {7, 8, 9, 0x8877665544332211ULL}};
    for (uint32_t family = 0; family < 3; ++family) {
        const uint64_t token =
            encode_controllet_token(records[0].value, 0xa5a5a5a55a5a5a5aULL, family);
        if (decode_controllet_token(token, 0xa5a5a5a55a5a5a5aULL, family) != records[0].value)
            return 1;
        auto bytes = serialize_metadata_shard(family, 6, salt, records);
        auto parsed = parse_metadata_shard(family, 6, salt, bytes);
        if (parsed.size() != 2 || parsed[1].value != records[1].value)
            return 2;
        for (uint32_t wrong = 0; wrong < 3; ++wrong)
            if (wrong != family)
                fail([&] { parse_metadata_shard(wrong, 6, salt, bytes); });
        fail([&] { parse_metadata_shard(family, 5, salt, bytes); });
        auto corrupt = bytes;
        corrupt[25] ^= 1;
        fail([&] { parse_metadata_shard(family, 6, salt, corrupt); });
        auto truncated = bytes;
        truncated.pop_back();
        fail([&] { parse_metadata_shard(family, 6, salt, truncated); });
        auto duplicate = serialize_metadata_shard(family, 6, salt, {records[0], records[0]});
        fail([&] { parse_metadata_shard(family, 6, salt, duplicate); });
        for (size_t cut = 0; cut < bytes.size(); ++cut) {
            auto fuzz = bytes;
            fuzz.resize(cut);
            fail([&] { parse_metadata_shard(family, 6, salt, fuzz); });
        }
        for (size_t i = 0; i < bytes.size(); ++i) {
            auto fuzz = bytes;
            fuzz[i] ^= uint8_t(1u << (i % 8));
            fail([&] { parse_metadata_shard(family, 6, salt, fuzz); });
        }
    }
    const auto a = assign_controllet(42, 99), b = assign_controllet(42, 99);
    if (a.cluster_id != b.cluster_id || a.family != b.family)
        return 3;
    std::cout << "controllet tests passed\n";
}
