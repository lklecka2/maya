#pragma once

#include <string>

#include "Context.hpp"

namespace maya {

inline auto binary_kind_name(BinaryKind kind) -> std::string {
    switch (kind) {
        case BinaryKind::StaticExecutable:
            return "static-executable";
        case BinaryKind::PositionIndependentExecutable:
            return "pie";
    }
    return "unknown";
}

inline auto slot_strategy_name(SlotStrategy strategy) -> std::string {
    switch (strategy) {
        case SlotStrategy::FixedPerFunction:
            return "fixed-per-function";
        case SlotStrategy::RuntimeAllocator:
            return "runtime-allocator";
    }
    return "unknown";
}

} // namespace maya
