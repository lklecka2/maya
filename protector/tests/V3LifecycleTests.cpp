#include "core/protection/V3Lifecycle.hpp"

#include <iostream>

using namespace maya::protection;

int main() {
    const V3CanonicalState initial{7, 0x1000, 0x55, 12};
    for (unsigned value = 0; value < static_cast<unsigned>(V3LifecycleStage::Count); ++value) {
        const auto failed =
            execute_v3_lifecycle(initial, 0x9000, 0xa5, static_cast<V3LifecycleStage>(value), true);
        if (failed.fault != V3LifecycleFault::Injected || !(failed.canonical == initial))
            return 1;
        if (failed.canonical.launch_handle != initial.launch_handle)
            return 2;
    }
    const auto success = execute_v3_lifecycle(initial, 0x9000, 0xa5, V3LifecycleStage::Count, true);
    if (success.fault != V3LifecycleFault::None || success.canonical.generation != 8 ||
        success.canonical.mapping != 0x9000 || success.canonical.launch_handle != 0xa5 ||
        success.canonical.publication_count != 13 || !success.predecessor_retired ||
        !success.successor_authenticated || !success.successor_rx || !success.cache_synchronized)
        return 3;
    if (success.completed.back() != V3LifecycleStage::InstallLaunchHandle)
        return 4;
    std::cout << "V3 lifecycle tests passed\n";
}
