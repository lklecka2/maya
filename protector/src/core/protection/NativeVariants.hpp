#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace maya::protection {

inline constexpr uint32_t kNativeVariantSchemaVersion = 2;
inline constexpr size_t kNativeVariantLimit = 3;

struct NativeVariantCandidate {
    std::vector<uint8_t> bytes;
    std::string transformation;
    std::string proof;
    size_t changed_offset = 0;
};

struct NativeVariantResult {
    std::vector<NativeVariantCandidate> candidates;
    std::string rejection_reason;
};

NativeVariantResult generate_native_variants(const std::vector<uint8_t>& bytes,
                                             size_t application_size,
                                             const std::vector<size_t>& protected_offsets);

} // namespace maya::protection
