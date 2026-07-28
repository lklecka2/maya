#include "V3Lifecycle.hpp"

namespace maya::protection {

V3LifecycleObservation execute_v3_lifecycle(const V3CanonicalState& initial,
                                            uint64_t successor_mapping, uint64_t launch_handle,
                                            V3LifecycleStage fail_at, bool needs_eh) {
    V3LifecycleObservation result;
    result.canonical = initial;
    bool mapped_rw = false, relocated = false, eh_registered = !needs_eh, published = false;
    auto stage = [&](V3LifecycleStage value) {
        if (fail_at == value) {
            result.fault = V3LifecycleFault::Injected;
            result.private_mapping_released = mapped_rw;
            result.canonical = initial;
            return false;
        }
        result.completed.push_back(value);
        return true;
    };
    if (!stage(V3LifecycleStage::PreparePrivate))
        return result;
    if (!stage(V3LifecycleStage::RetirePredecessor))
        return result;
    result.predecessor_retired = true;
    if (!stage(V3LifecycleStage::MapSuccessorRw))
        return result;
    mapped_rw = true;
    if (!stage(V3LifecycleStage::AuthenticateSuccessor))
        return result;
    result.successor_authenticated = true;
    if (!stage(V3LifecycleStage::RelocateSuccessor))
        return result;
    relocated = true;
    if (needs_eh) {
        if (!stage(V3LifecycleStage::RegisterEh))
            return result;
        eh_registered = true;
    }
    if (!stage(V3LifecycleStage::ProtectSuccessorRx))
        return result;
    if (!mapped_rw || !result.successor_authenticated || !relocated || !eh_registered) {
        result.fault = V3LifecycleFault::InvalidOrder;
        result.canonical = initial;
        return result;
    }
    result.successor_rx = true;
    if (!stage(V3LifecycleStage::SynchronizeCaches))
        return result;
    result.cache_synchronized = true;
    if (!stage(V3LifecycleStage::PublishCanonical))
        return result;
    if (published || initial.publication_count == UINT64_MAX) {
        result.fault = V3LifecycleFault::RepeatedPublication;
        result.canonical = initial;
        return result;
    }
    published = true;
    result.canonical.generation = initial.generation + 1;
    result.canonical.mapping = successor_mapping;
    result.canonical.publication_count = initial.publication_count + 1;
    if (!stage(V3LifecycleStage::InstallLaunchHandle)) {
        // Publication and launch installation are one release transaction in the
        // canonical model, so an injected launch failure rolls the commit back.
        result.canonical = initial;
        return result;
    }
    result.canonical.launch_handle = launch_handle;
    return result;
}

} // namespace maya::protection
