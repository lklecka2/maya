#pragma once
#include <LIEF/ELF.hpp>
#include <memory>
#include <string>
#include <cstdint>

enum class BinaryKind {
    StaticExecutable,
    PositionIndependentExecutable
};

enum class SlotStrategy {
    FixedPerFunction,
    RuntimeAllocator
};

struct ProtectionOptions {
    std::string output_filename;
    std::string report_filename;
    bool allow_pie = true;
    bool enable_cpp_exceptions = true;
    bool require_upx_compatible_layout = true;
    bool aggressive_symbols = false;
    SlotStrategy slot_strategy = SlotStrategy::RuntimeAllocator;
};

struct RuntimeFeatureSet {
    BinaryKind binary_kind = BinaryKind::StaticExecutable;
    bool has_interpreter = false;
    bool has_eh_frame = false;
    bool has_gcc_except_table = false;
    bool has_cpp_personality = false;
    bool upx_compatible_layout = false;
    SlotStrategy slot_strategy = SlotStrategy::RuntimeAllocator;
};

struct ProtectionContext {
    std::unique_ptr<LIEF::ELF::Binary> binary;
    uint64_t original_entry_point = 0;
    uint64_t segment_request_bias = 0;
    uint64_t final_image_shift = 0;
    bool is_aarch64 = false;
    std::string filename;
    ProtectionOptions options;
    RuntimeFeatureSet runtime_features;
};
