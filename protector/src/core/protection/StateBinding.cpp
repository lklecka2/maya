#include "StateBinding.hpp"

namespace maya::protection {

uint64_t transition_logical_state(const TransitionState& state, uint32_t successor_class) {
    return (uint64_t(state.function_id) << 32) ^ (uint64_t(state.fragment_id) << 16) ^
           (uint64_t(state.site_id) << 4) ^ successor_class ^ state.continuation_cookie;
}

uint64_t transition_depth_generation(const TransitionState& state) {
    return (uint64_t(state.depth) << 32) ^ state.checkpoint_generation;
}

uint64_t derive_transition_mask(const std::array<uint8_t, 32>& key, const TransitionState& state,
                                uint32_t successor_class) {
    return maya_state_mask(key.data(), state.binary_cookie, state.thread_cookie, state.epoch,
                           state.path_digest, state.frame_cookie,
                           transition_logical_state(state, successor_class),
                           transition_depth_generation(state));
}

void commit_transition(TransitionState& state, uint64_t mask, uint64_t committed_event) {
    state.path_digest = maya_state_advance(state.path_digest, mask, committed_event);
    ++state.epoch;
}

} // namespace maya::protection
