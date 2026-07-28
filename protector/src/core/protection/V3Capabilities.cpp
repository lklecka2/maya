#include "V3Capabilities.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace maya::protection {
namespace {

void append32(std::vector<uint8_t>& out, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out.push_back(static_cast<uint8_t>(value >> (index * 8)));
}
void append64(std::vector<uint8_t>& out, uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<uint8_t>(value >> (index * 8)));
}
template <size_t N> void append(std::vector<uint8_t>& out, const std::array<uint8_t, N>& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void append_text(std::vector<uint8_t>& out, const std::string& value) {
    append32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<uint8_t> canonical_state(const EdgeCapability& capability,
                                     const V3TransitionState& state, uint32_t purpose) {
    std::vector<uint8_t> bytes;
    bytes.reserve(224);
    append32(bytes, kV3StateContractVersion);
    append32(bytes, kV3CapabilityContractVersion);
    append32(bytes, state.profile);
    append32(bytes, purpose);
    append32(bytes, static_cast<uint32_t>(capability.event_class));
    append32(bytes, capability.cluster);
    append(bytes, capability.source);
    append(bytes, capability.destination);
    append(bytes, state.binary_identity);
    append(bytes, state.thread_identity);
    append(bytes, state.owner_namespace);
    append(bytes, state.fragment_namespace);
    append(bytes, state.frame_identity);
    append(bytes, state.continuation_identity);
    append64(bytes, state.epoch);
    append(bytes, state.path_digest);
    append64(bytes, state.depth);
    append64(bytes, state.checkpoint_generation);
    return bytes;
}

bool constant_time_equal(const CapabilityToken& lhs, const CapabilityToken& rhs) {
    uint32_t difference = 0;
    for (size_t index = 0; index < lhs.size(); ++index)
        difference |= lhs[index] ^ rhs[index];
    return difference == 0;
}

} // namespace

std::vector<uint8_t> canonical_capability_bytes(const EdgeCapability& capability,
                                                const V3TransitionState& state, uint32_t purpose) {
    return canonical_state(capability, state, purpose);
}

Opaque128 derive_opaque128(const Seed256& seed, const std::string& domain, uint64_t ordinal,
                           uint32_t cluster) {
    std::vector<uint8_t> info;
    append_text(info, "maya-v3-opaque");
    append_text(info, domain);
    append64(info, ordinal);
    append32(info, cluster);
    const auto value = hkdf_sha256(seed, {}, info);
    Opaque128 result{};
    std::copy_n(value.begin(), result.size(), result.begin());
    return result;
}

Seed256 derive_v3_domain_key(const Seed256& root, const std::string& domain, const Opaque128& owner,
                             uint32_t cluster) {
    std::vector<uint8_t> salt(owner.begin(), owner.end());
    std::vector<uint8_t> info;
    append_text(info, "maya-v3-domain");
    append_text(info, domain);
    append32(info, cluster);
    return hkdf_sha256(root, salt, info);
}

CapabilityToken issue_capability(const Seed256& capability_key, const EdgeCapability& capability,
                                 const V3TransitionState& state, uint32_t purpose) {
    return hmac_sha256(capability_key, canonical_state(capability, state, purpose));
}

bool validate_capability(const CapabilityToken& token, const Seed256& capability_key,
                         const EdgeCapability& capability, const V3TransitionState& state,
                         uint32_t purpose) {
    return constant_time_equal(token, issue_capability(capability_key, capability, state, purpose));
}

V3AuthorityResult validate_authority(const CapabilityToken& token, const Seed256& capability_key,
                                     const EdgeCapability& capability,
                                     const V3TransitionState& state, uint32_t purpose) {
    V3AuthorityResult result;
    if (!validate_capability(token, capability_key, capability, state, purpose))
        return result;
    result.fault = V3AuthorityFault::None;
    result.authority = token;
    return result;
}

bool consume_authority(V3AuthorityResult& result) {
    if (result.fault != V3AuthorityFault::None || result.consumed) {
        result.fault = V3AuthorityFault::AlreadyConsumed;
        return false;
    }
    result.consumed = true;
    std::fill(result.authority.begin(), result.authority.end(), 0);
    return true;
}

void commit_v3_transition(V3TransitionState& state, const CapabilityToken& token,
                          V3EventClass event_class) {
    std::vector<uint8_t> input(state.path_digest.begin(), state.path_digest.end());
    input.insert(input.end(), token.begin(), token.end());
    append32(input, static_cast<uint32_t>(event_class));
    append64(input, state.epoch);
    state.path_digest = sha256_bytes(input);
    if (state.epoch == UINT64_MAX)
        throw std::runtime_error("V3 transition epoch exhausted");
    ++state.epoch;
}

} // namespace maya::protection
