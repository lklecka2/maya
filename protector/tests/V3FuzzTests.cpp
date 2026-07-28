#include "core/protection/Controllets.hpp"
#include "core/protection/FragmentImage.hpp"
#include "core/protection/V3Shards.hpp"
#include "core/protection/V3Vm.hpp"

#include <iostream>

using namespace maya::protection;

static uint64_t next(uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

int main() {
    Seed256 seed{};
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = uint8_t(i * 9 + 1);
    const auto owner = derive_opaque128(seed, "fuzz-owner", 1, 1);
    V3ShardRecord record;
    record.lookup_label = derive_opaque128(seed, "fuzz-label", 1, 1);
    record.owner_namespace = owner;
    record.capability.source = derive_opaque128(seed, "fuzz-src", 1, 1);
    record.capability.destination = derive_opaque128(seed, "fuzz-dst", 1, 1);
    record.capability.event_class = V3EventClass::Next;
    record.capability.cluster = 1;
    record.resolver_payload.assign(24, 0x5a);
    const auto isa = generate_v3_isa(seed, 1);
    const auto semantic = make_v3_transition_program(false, false, 128);
    const auto vm = seal_v3_program(seed, seed, isa, 1, owner, semantic.step_limit,
                                    compile_v3_semantic_program(semantic));
    V3TransitionState state;
    state.owner_namespace = owner;
    state.binary_identity = derive_opaque128(seed, "fuzz-binary", 1);
    state.thread_identity = derive_opaque128(seed, "fuzz-thread", 1);
    state.fragment_namespace = derive_opaque128(seed, "fuzz-fragment", 1);
    state.frame_identity = derive_opaque128(seed, "fuzz-frame", 1);
    state.continuation_identity = derive_opaque128(seed, "fuzz-continuation", 1);
    const auto capability_key =
        derive_v3_domain_key(seed, "capability", owner, record.capability.cluster);
    const auto capability = issue_capability(capability_key, record.capability, state, 0x45584954u);
    uint64_t rng = 0x6d61796166757a7aULL;
    for (auto family : {V3ShardFamily::KeyedHash, V3ShardFamily::AuthenticatedTree,
                        V3ShardFamily::IndirectTable}) {
        const auto shard = seal_v3_shard(family, 1, owner, 0x1000, seed, seed, {record});
        for (unsigned iteration = 0; iteration < 512; ++iteration) {
            auto changed = shard;
            const auto value = next(rng);
            const unsigned field = value % 3;
            if (field == 0)
                changed.tag[value % changed.tag.size()] ^= uint8_t(1u << (value % 8));
            else if (field == 1)
                changed.ciphertext[value % changed.ciphertext.size()] ^= uint8_t(1u << (value % 8));
            else
                changed.nonce[value % changed.nonce.size()] ^= uint8_t(1u << (value % 8));
            try {
                (void)open_v3_shard(changed, seed);
                return 1;
            } catch (const std::exception&) {
            }
        }
    }
    for (unsigned iteration = 0; iteration < 1024; ++iteration) {
        auto changed = vm;
        const auto value = next(rng);
        if (value & 1)
            changed.ciphertext[value % changed.ciphertext.size()] ^= uint8_t(1u << (value % 8));
        else
            changed.tag[value % changed.tag.size()] ^= uint8_t(1u << (value % 8));
        if (execute_v3_program(seed, isa, changed).fault != V3VmFault::Authentication)
            return 2;
    }
    for (unsigned iteration = 0; iteration < 1024; ++iteration) {
        auto changed = capability;
        const auto value = next(rng);
        changed[value % changed.size()] ^= uint8_t(1u << (value % 8));
        if (validate_capability(changed, capability_key, record.capability, state, 0x45584954u))
            return 3;
    }
    std::array<uint8_t, 32> salt{};
    for (size_t i = 0; i < salt.size(); ++i)
        salt[i] = uint8_t(i * 13 + 7);
    for (unsigned iteration = 0; iteration < 2048; ++iteration) {
        std::vector<uint8_t> bytes(next(rng) % 513);
        for (auto& byte : bytes)
            byte = uint8_t(next(rng));
        try {
            (void)parse_fragment_image(bytes);
        } catch (const std::exception&) {
        }
        try {
            (void)parse_metadata_shard(next(rng) % 3, next(rng) % 7, salt, bytes);
        } catch (const std::exception&) {
        }
    }
    std::cout << "V3 deterministic mutation fuzz tests passed\n";
}
