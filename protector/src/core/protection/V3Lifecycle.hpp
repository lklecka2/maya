#pragma once

#include <cstdint>
#include <vector>

namespace maya::protection {

enum class V3LifecycleStage : uint8_t {
    PreparePrivate,
    RetirePredecessor,
    MapSuccessorRw,
    AuthenticateSuccessor,
    RelocateSuccessor,
    RegisterEh,
    ProtectSuccessorRx,
    SynchronizeCaches,
    PublishCanonical,
    InstallLaunchHandle,
    Count,
};

enum class V3LifecycleFault : uint8_t { None, Injected, InvalidOrder, RepeatedPublication };

struct V3CanonicalState {
    uint64_t generation = 0;
    uint64_t mapping = 0;
    uint64_t launch_handle = 0;
    uint64_t publication_count = 0;
    bool operator==(const V3CanonicalState& other) const {
        return generation == other.generation && mapping == other.mapping &&
               launch_handle == other.launch_handle && publication_count == other.publication_count;
    }
};

struct V3LifecycleObservation {
    V3LifecycleFault fault = V3LifecycleFault::None;
    V3CanonicalState canonical{};
    bool predecessor_retired = false;
    bool successor_authenticated = false;
    bool successor_rx = false;
    bool cache_synchronized = false;
    bool private_mapping_released = false;
    std::vector<V3LifecycleStage> completed;
};

V3LifecycleObservation execute_v3_lifecycle(const V3CanonicalState& initial,
                                            uint64_t successor_mapping, uint64_t launch_handle,
                                            V3LifecycleStage fail_at = V3LifecycleStage::Count,
                                            bool needs_eh = false);

} // namespace maya::protection
