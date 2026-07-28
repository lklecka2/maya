#pragma once
#include "state_binding.h"
#include <array>
#include <cstdint>

namespace maya::protection {

inline constexpr uint32_t kStateContractVersion = 2;
inline constexpr uint32_t kContinuationContractVersion = 2;
inline constexpr uint32_t kFaultContractVersion = 2;

struct TransitionState {
    uint64_t binary_cookie = 0;
    uint64_t thread_cookie = 0;
    uint64_t epoch = 0;
    uint64_t path_digest = 0;
    uint64_t frame_cookie = 0;
    uint64_t continuation_cookie = 0;
    uint64_t checkpoint_generation = 0;
    uint32_t function_id = 0;
    uint32_t fragment_id = 0;
    uint32_t site_id = 0;
    uint32_t depth = 0;
};

uint64_t transition_logical_state(const TransitionState& state, uint32_t successor_class);
uint64_t transition_depth_generation(const TransitionState& state);
uint64_t derive_transition_mask(const std::array<uint8_t, 32>& key, const TransitionState& state,
                                uint32_t successor_class);
void commit_transition(TransitionState& state, uint64_t mask, uint64_t committed_event);

} // namespace maya::protection
