#include "core/protection/StateBinding.hpp"
#include <array>
#include <iostream>
using namespace maya::protection;

int main() {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i * 7 + 3);
    TransitionState base{0x101, 0x202, 3, 0x404, 0x505, 0x606, 7, 8, 9, 10, 11};
    const auto expected = derive_transition_mask(key, base, MAYA_STATE_EXIT);
    if (expected != UINT64_C(0xadaeb97e9b603a5d))
        return 1;
    auto changed = base;
    auto distinct = [&](const TransitionState& s, uint32_t domain = MAYA_STATE_EXIT) {
        return derive_transition_mask(key, s, domain) != expected;
    };
    changed = base;
    changed.binary_cookie ^= 1;
    if (!distinct(changed))
        return 2;
    changed = base;
    changed.thread_cookie ^= 1;
    if (!distinct(changed))
        return 3;
    changed = base;
    changed.epoch ^= 1;
    if (!distinct(changed))
        return 4;
    changed = base;
    changed.path_digest ^= 1;
    if (!distinct(changed))
        return 5;
    changed = base;
    changed.frame_cookie ^= 1;
    if (!distinct(changed))
        return 6;
    changed = base;
    changed.continuation_cookie ^= 1;
    if (!distinct(changed))
        return 7;
    changed = base;
    changed.checkpoint_generation ^= 1;
    if (!distinct(changed))
        return 8;
    changed = base;
    changed.function_id ^= 1;
    if (!distinct(changed))
        return 9;
    changed = base;
    changed.fragment_id ^= 1;
    if (!distinct(changed))
        return 10;
    changed = base;
    changed.site_id ^= 1;
    if (!distinct(changed))
        return 11;
    changed = base;
    changed.depth ^= 1;
    if (!distinct(changed))
        return 12;
    for (uint32_t domain = MAYA_STATE_CODE; domain <= MAYA_STATE_CHECKPOINT; ++domain)
        if (domain != MAYA_STATE_EXIT && !distinct(base, domain))
            return 13;
    commit_transition(changed, expected, 0xabc);
    if (changed.epoch != base.epoch + 1 || changed.path_digest == base.path_digest)
        return 14;
    std::cout << "state binding tests passed\n";
}
