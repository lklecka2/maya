#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace maya::protection {
using Seed256 = std::array<uint8_t, 32>;
enum class KeyDomain : uint32_t {
    Fragment = 1,
    Envelope = 2,
    Capability = 3,
    Shard = 4,
    Record = 5,
    VmTemplate = 6,
    InvocationCapsule = 7,
    Variant = 8,
    Continuation = 9,
    Checkpoint = 10,
    ExceptionHandling = 11,
    LegacyBody = 12,
    StateBinding = 13,
};
struct BuildSecrets {
    Seed256 root{};
    Seed256 binary_salt{};
};
struct SealedFragment {
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 16> tag{};
    std::vector<uint8_t> ciphertext;
};

Seed256 parse_seed_hex(const std::string& value);
Seed256 random_seed();
BuildSecrets derive_build_secrets(const Seed256& seed);
Seed256 sha256_bytes(const std::vector<uint8_t>& bytes);
Seed256 hmac_sha256(const Seed256& key, const std::vector<uint8_t>& bytes);
Seed256 hkdf_sha256(const Seed256& input_key, const std::vector<uint8_t>& salt,
                    const std::vector<uint8_t>& info);
Seed256 derive_domain_key(const Seed256& root, KeyDomain domain,
                          const std::vector<uint8_t>& context);
Seed256 derive_sealed_object_key(const Seed256& root, const std::vector<uint8_t>& aad);
Seed256 derive_legacy_body_key(const Seed256& root, uint64_t original_address, uint64_t size);
void secure_zero(Seed256& value);
std::array<uint8_t, 24> derive_fragment_nonce(const Seed256& seed, uint32_t function_id,
                                              uint32_t fragment_id);
SealedFragment seal_fragment(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad,
                             const Seed256& key, const std::array<uint8_t, 24>& nonce);
std::vector<uint8_t> open_fragment(const SealedFragment& sealed, const std::vector<uint8_t>& aad,
                                   const Seed256& key);
} // namespace maya::protection
