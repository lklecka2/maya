#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "FragmentCrypto.hpp"

namespace maya::protection {

inline constexpr uint32_t kV3StateContractVersion = 3;
inline constexpr uint32_t kV3CapabilityContractVersion = 1;

using Opaque128 = std::array<uint8_t, 16>;
using CapabilityToken = std::array<uint8_t, 32>;
enum class V3AuthorityFault : uint32_t { None = 0, Authentication = 1, AlreadyConsumed = 2 };
struct V3AuthorityResult {
    V3AuthorityFault fault = V3AuthorityFault::Authentication;
    CapabilityToken authority{};
    bool consumed = false;
};

enum class V3EventClass : uint32_t {
    Next = 1,
    Call = 2,
    Return = 3,
    TailCall = 4,
    ExternalCall = 5,
    ExternalReturn = 6,
    Callback = 7,
    Checkpoint = 8,
    NonLocalJump = 9,
};

struct V3TransitionState {
    uint32_t profile = 3;
    Opaque128 binary_identity{};
    Opaque128 thread_identity{};
    Opaque128 owner_namespace{};
    Opaque128 fragment_namespace{};
    Opaque128 frame_identity{};
    Opaque128 continuation_identity{};
    uint64_t epoch = 0;
    std::array<uint8_t, 32> path_digest{};
    uint64_t depth = 0;
    uint64_t checkpoint_generation = 0;
};

struct EdgeCapability {
    Opaque128 source{};
    Opaque128 destination{};
    V3EventClass event_class = V3EventClass::Next;
    uint32_t cluster = 0;
};

Opaque128 derive_opaque128(const Seed256& seed, const std::string& domain, uint64_t ordinal,
                           uint32_t cluster = 0);
Seed256 derive_v3_domain_key(const Seed256& root, const std::string& domain, const Opaque128& owner,
                             uint32_t cluster = 0);
std::vector<uint8_t> canonical_capability_bytes(const EdgeCapability& capability,
                                                const V3TransitionState& state, uint32_t purpose);
CapabilityToken issue_capability(const Seed256& capability_key, const EdgeCapability& capability,
                                 const V3TransitionState& state, uint32_t purpose);
bool validate_capability(const CapabilityToken& token, const Seed256& capability_key,
                         const EdgeCapability& capability, const V3TransitionState& state,
                         uint32_t purpose);
V3AuthorityResult validate_authority(const CapabilityToken& token, const Seed256& capability_key,
                                     const EdgeCapability& capability,
                                     const V3TransitionState& state, uint32_t purpose);
bool consume_authority(V3AuthorityResult& result);
void commit_v3_transition(V3TransitionState& state, const CapabilityToken& token,
                          V3EventClass event_class);

} // namespace maya::protection
