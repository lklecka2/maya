#pragma once

#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "StateBinding.hpp"

namespace maya::protection {

inline constexpr uint32_t kFragmentImageVersion = 2;
inline constexpr uint32_t kDescriptorVersion = 2;

enum class FragmentRegionType : uint32_t { RuntimeRx = 1, DescriptorsRo = 2, StateRw = 3 };

struct FragmentRegionDescriptor {
    FragmentRegionType type{};
    uint32_t permissions = 0;
    uint64_t offset = 0;
    uint64_t stored_size = 0;
    uint64_t memory_size = 0;
    uint64_t alignment = 0;
    uint64_t digest_offset = 0;
    uint64_t digest_size = 0;
};

struct FragmentFunctionDescriptor {
    uint32_t version = kDescriptorVersion, function_id = 0, first_fragment = 0, fragment_count = 0;
};
struct FragmentDescriptor {
    uint32_t version = kDescriptorVersion, function_id = 0, fragment_id = 0, flags = 0;
    uint64_t payload_offset = 0, payload_size = 0;
};
struct FragmentImage {
    uint32_t version = kFragmentImageVersion;
    uint32_t state_contract_version = kStateContractVersion;
    uint32_t continuation_contract_version = kContinuationContractVersion;
    uint32_t fault_contract_version = kFaultContractVersion;
    uint32_t feature_flags = 1; // state-bound transitions
    std::vector<FragmentRegionDescriptor> regions;
    std::vector<FragmentFunctionDescriptor> functions;
    std::vector<FragmentDescriptor> fragments;
};

std::vector<uint8_t> serialize_fragment_image(const FragmentImage& image);
FragmentImage parse_fragment_image(const std::vector<uint8_t>& bytes);
FragmentImage make_fragment_image(const std::vector<ProtectedFunction>& funcs,
                                  uint64_t runtime_size);

} // namespace maya::protection
