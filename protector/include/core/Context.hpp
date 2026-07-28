#pragma once
#include <LIEF/ELF.hpp>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

enum class BinaryKind {
    StaticExecutable,
    DynamicExecutable,
    DynamicPieExecutable,
    StaticPieExecutable
};

enum class SlotStrategy { FixedPerFunction, RuntimeAllocator };

enum class ExecutionMode { Legacy, FragmentAuto, FragmentRequired };
enum class CliCommand { Protect, Analyze, Help, Version };
enum class ProtectionProfile { Standard, ExperimentalV3 };
enum class BackendPolicy { Auto, FragmentsOnly, Compatibility };

struct ProtectionOptions {
    CliCommand command = CliCommand::Protect;
    ProtectionProfile profile = ProtectionProfile::Standard;
    BackendPolicy backend_policy = BackendPolicy::Auto;
    std::string output_filename;
    std::string report_filename;
    bool require_upx_compatible_layout = false;
    bool native_variants = false;
    bool verbose = false;
    SlotStrategy slot_strategy = SlotStrategy::RuntimeAllocator;
    ExecutionMode execution_mode = ExecutionMode::FragmentAuto;
    std::vector<std::string> include_symbols;
    std::vector<std::string> exclude_symbols;
    std::string seed_hex;
};

struct RuntimeFeatureSet {
    BinaryKind binary_kind = BinaryKind::StaticExecutable;
    bool has_interpreter = false;
    bool has_eh_frame = false;
    bool has_gcc_except_table = false;
    bool has_cpp_personality = false;
    bool has_forced_unwind_or_cancellation = false;
    bool upx_compatible_layout = false;
    SlotStrategy slot_strategy = SlotStrategy::RuntimeAllocator;
};

struct ProtectionStats {
    size_t protected_functions = 0;
    size_t fragments = 0;
    size_t fallbacks = 0;
    size_t rejections = 0;
    size_t native_variants = 0;
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
    std::array<uint8_t, 32> build_seed{};
    std::array<uint8_t, 32> build_root{};
    std::array<uint8_t, 32> fragment_binary_salt{};
    size_t discovered_function_count = 0;
    size_t automatic_root_count = 0;
    ProtectionStats summary;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> deferred_file_writes;
};
