#pragma once
#include <cstdint>

namespace Utils {
    inline uint64_t align_to(uint64_t value, uint64_t boundary) {
        if (boundary == 0) return value;
        return (value + boundary - 1) & ~(boundary - 1);
    }
}
