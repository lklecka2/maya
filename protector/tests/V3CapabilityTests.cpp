#include "core/protection/V3Capabilities.hpp"
#include "runtime_kdf.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace maya::protection;

int main() {
    Seed256 seed{};
    for (size_t index = 0; index < seed.size(); ++index)
        seed[index] = static_cast<uint8_t>(index * 9 + 1);
    V3TransitionState state;
    state.binary_identity = derive_opaque128(seed, "binary", 0);
    state.thread_identity = derive_opaque128(seed, "thread", 1);
    state.owner_namespace = derive_opaque128(seed, "owner", 2);
    state.fragment_namespace = derive_opaque128(seed, "fragment", 3);
    state.frame_identity = derive_opaque128(seed, "frame", 4);
    state.continuation_identity = derive_opaque128(seed, "continuation", 5);
    state.epoch = 7;
    state.depth = 3;
    state.checkpoint_generation = 11;
    EdgeCapability edge{derive_opaque128(seed, "source", 6),
                        derive_opaque128(seed, "destination", 7), V3EventClass::Call, 2};
    const auto key = derive_v3_domain_key(seed, "capability", state.owner_namespace, edge.cluster);
    const auto token = issue_capability(key, edge, state, 0x45584954u);
    uint8_t native_key[32]{};
    maya_v3_derive_capability_key(native_key, seed.data(), state.owner_namespace.data(),
                                  edge.cluster);
    if (!std::equal(key.begin(), key.end(), native_key))
        return 20;
    const auto canonical = canonical_capability_bytes(edge, state, 0x45584954u);
    uint8_t native_token[32]{};
    maya_v3_issue_capability(native_token, seed.data(), state.owner_namespace.data(), edge.cluster,
                             canonical.data(), canonical.size());
    if (!std::equal(token.begin(), token.end(), native_token))
        return 23;
    if (!maya_v3_validate_capability(token.data(), seed.data(), state.owner_namespace.data(),
                                     edge.cluster, canonical.data(), canonical.size()))
        return 21;
    if (!validate_capability(token, key, edge, state, 0x45584954u))
        return 1;
    auto authority = validate_authority(token, key, edge, state, 0x45584954u);
    if (authority.fault != V3AuthorityFault::None || !consume_authority(authority) ||
        consume_authority(authority) || authority.fault != V3AuthorityFault::AlreadyConsumed)
        return 24;
    auto changed = state;
    changed.epoch ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 2;
    changed = state;
    changed.thread_identity[0] ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 3;
    const auto changed_canonical = canonical_capability_bytes(edge, changed, 0x45584954u);
    if (maya_v3_validate_capability(token.data(), seed.data(), state.owner_namespace.data(),
                                    edge.cluster, changed_canonical.data(),
                                    changed_canonical.size()))
        return 22;
    auto wrong_edge = edge;
    wrong_edge.destination[1] ^= 1;
    if (validate_capability(token, key, wrong_edge, state, 0x45584954u))
        return 4;
    wrong_edge = edge;
    wrong_edge.source[2] ^= 1;
    if (validate_capability(token, key, wrong_edge, state, 0x45584954u))
        return 7;
    wrong_edge = edge;
    wrong_edge.event_class = V3EventClass::Return;
    if (validate_capability(token, key, wrong_edge, state, 0x45584954u))
        return 8;
    changed = state;
    changed.owner_namespace[3] ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 9;
    changed = state;
    changed.profile = 2;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 17;
    changed = state;
    changed.frame_identity[4] ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 10;
    changed = state;
    changed.continuation_identity[5] ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 11;
    changed = state;
    changed.path_digest[6] ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 12;
    changed = state;
    changed.depth ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 13;
    changed = state;
    changed.checkpoint_generation ^= 1;
    if (validate_capability(token, key, edge, changed, 0x45584954u))
        return 14;
    if (validate_capability(token, key, edge, state, 0x45584955u))
        return 15;
    auto wrong_seed = seed;
    wrong_seed[0] ^= 1;
    const auto wrong_key =
        derive_v3_domain_key(wrong_seed, "capability", state.owner_namespace, edge.cluster);
    if (validate_capability(token, wrong_key, edge, state, 0x45584954u))
        return 16;
    const auto old_path = state.path_digest;
    commit_v3_transition(state, token, edge.event_class);
    if (state.epoch != 8 || state.path_digest == old_path)
        return 5;
    if (validate_capability(token, key, edge, state, 0x45584954u))
        return 6;
    std::cout << "V3 capability tests passed\n";
}
