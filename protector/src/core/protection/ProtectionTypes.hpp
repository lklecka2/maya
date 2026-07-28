#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/Context.hpp"

namespace maya::protection {

enum class ProtectionMode { FragmentEligible, LegacyFunctionOnly, Rejected };

enum class SelectedBackend { None, LegacyRuntimeAllocator, LegacyFixedSlot, Fragment };

enum class FinalOutcome { Pending, Protected, Rejected };

enum class ReasonCode {
    None,
    EhCoverage,
    DecodeFailure,
    SimdFpuState,
    SveSmeState,
    IndirectCall,
    IndirectBranch,
    SetjmpLongjmp,
    ProtectedInteriorControl,
    ProtectedInteriorPointer,
    UnmodeledControl
};

enum class ControlEdgeKind {
    IntraFunction,
    ProtectedToProtectedCall,
    ProtectedReturn,
    ProtectedTailCall,
    ExternalCall,
    ExternalTailCall,
    IndirectCall,
    ExceptionEdge,
    UnmodeledEdge
};

enum class ControlTargetDomain { SameFunction, ProtectedFunction, ExternalUnprotected, Unknown };

enum class DataRefKind {
    StringReference,
    ConstantReference,
    LiteralPoolEntry,
    DataPointer,
    VtableTypeinfoReference,
    FunctionPointerReference,
    JumpTableEntry
};

enum class FragmentExitKind : uint32_t {
    NextFragment = 1,
    CallProtected = 2,
    ReturnProtected = 3,
    TailcallProtected = 4,
    ExitFunction = 5,
    CallExternal = 6,
    Fault = 7,
    SetjmpExternal = 8,
    LongjmpExternal = 9
};

struct FragmentExit {
    FragmentExitKind kind = FragmentExitKind::Fault;
    uint32_t site_id = 0;
    uint32_t target_function_id = UINT32_MAX;
    uint32_t target_fragment_id = UINT32_MAX;
    uint32_t continuation_fragment_id = UINT32_MAX;
    uint64_t pc = 0;
    uint64_t compatibility_target = 0;
    std::array<uint8_t, 16> v3_lookup_label{};
    std::array<uint8_t, 16> v3_source_label{};
    std::array<uint8_t, 16> v3_destination_label{};
    uint64_t v3_target_handle = 0;
    uint64_t v3_continuation_handle = 0;
};

struct SealedNativeVariant {
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> aad;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 16> tag{};
    uint64_t ciphertext_vaddr = 0;
    uint64_t nonce_vaddr = 0;
    uint64_t tag_vaddr = 0;
    uint64_t aad_vaddr = 0;
    std::string transformation;
    std::string proof;
    size_t changed_offset = 0;
};

struct ProtectedFragment {
    uint32_t fragment_id = 0;
    uint64_t original_start = 0;
    uint64_t size = 0;
    std::vector<FragmentExit> exits;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> execution_bytes;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> aad;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 16> tag{};
    uint64_t ciphertext_vaddr = 0;
    uint64_t nonce_vaddr = 0;
    uint64_t tag_vaddr = 0;
    uint64_t aad_vaddr = 0;
    uint64_t storage_size = 0;
    std::vector<SealedNativeVariant> variants;
    std::string variant_rejection_reason;
    std::vector<uint8_t> vm_ciphertext;
    std::vector<uint8_t> vm_aad;
    std::array<uint8_t, 24> vm_nonce{};
    std::array<uint8_t, 16> vm_tag{};
    uint64_t vm_ciphertext_vaddr = 0;
    uint64_t vm_aad_vaddr = 0;
    uint64_t vm_nonce_vaddr = 0;
    uint64_t vm_tag_vaddr = 0;
    uint8_t vm_rotate_opcode = 0;
    uint8_t vm_halt_opcode = 0;
    uint8_t vm_register_zero = 0;
    uint8_t vm_operand_mask = 0;
    uint64_t vm_immediate_mask = 0;
    std::array<uint8_t, 18> vm_opcodes{};
    uint64_t vm_step_limit = 0;
    uint64_t vm_required_primitive_trace = 0;
    uint64_t vm_storage_capacity = 0;
    std::vector<size_t> runtime_literal_offsets;
    std::vector<size_t> state_token_offsets;
    std::vector<uint64_t> state_token_values;
    std::vector<uint8_t> state_token_load_bias;
    uint32_t cluster_id = 0;
    uint32_t metadata_family = 0;
    uint64_t v3_handle = 0;
};

struct InstructionFacts {
    size_t direct_branches = 0;
    size_t conditional_branches = 0;
    size_t direct_calls = 0;
    size_t returns = 0;
    size_t adr = 0;
    size_t adrp = 0;
    size_t adrp_pairs = 0;
    size_t literal_pool_refs = 0;
    size_t pc_relative_loads = 0;
    size_t jump_table_candidates = 0;
    size_t indirect_branches = 0;
    size_t indirect_calls = 0;
    size_t function_pointer_materializations = 0;
    size_t got_refs = 0;
    size_t plt_refs = 0;
    size_t tls_refs = 0;
    size_t external_refs = 0;
    size_t stack_frame_setup = 0;
    size_t stack_frame_teardown = 0;
    size_t simd_fpu_use = 0;
    size_t sve_sme_use = 0;
    size_t decode_failures = 0;
};

struct ControlEdge {
    ControlEdgeKind kind = ControlEdgeKind::UnmodeledEdge;
    uint64_t pc = 0;
    uint64_t target = 0;
    uint32_t target_func_id = UINT32_MAX;
    ControlTargetDomain target_domain = ControlTargetDomain::Unknown;
    std::string target_symbol;
    std::string target_section;
};

struct DataReference {
    DataRefKind kind = DataRefKind::ConstantReference;
    uint64_t pc = 0;
    uint64_t target = 0;
};

// Bounds-checked GNU AArch64 exception metadata for one protected function.
// Gateways consume this representation instead of reparsing input bytes.
struct EhCallSite {
    uint64_t start = 0;
    uint64_t length = 0;
    uint64_t landing_pad = 0;
    uint64_t action_offset = 0;
};

struct EhAction {
    size_t table_offset = 0;
    int64_t type_filter = 0;
    int64_t next_offset = 0;
};

struct EhTypeEntry {
    uint64_t index = 0;
    uint64_t address = 0;
};

struct EhMetadata {
    uint32_t schema = 1;
    uint64_t cie_vaddr = 0;
    uint64_t fde_vaddr = 0;
    uint64_t pc_begin = 0;
    uint64_t pc_range = 0;
    uint64_t personality = 0;
    uint64_t personality_pointer = 0;
    size_t personality_field_offset = 0;
    uint8_t personality_encoding = 0xff;
    uint64_t register_frame = 0;
    uint64_t deregister_frame = 0;
    uint64_t unwind_resume = 0;
    uint64_t cxa_throw = 0;
    uint64_t cxa_rethrow = 0;
    uint64_t lsda_vaddr = 0;
    uint64_t lpstart = 0;
    uint64_t type_table_vaddr = 0;
    uint64_t call_site_table_vaddr = 0;
    uint64_t call_site_table_size = 0;
    uint64_t code_alignment = 0;
    int64_t data_alignment = 0;
    uint64_t return_register = 0;
    uint8_t fde_encoding = 0xff;
    uint8_t lsda_encoding = 0xff;
    uint8_t type_encoding = 0xff;
    uint8_t call_site_encoding = 0xff;
    std::string augmentation;
    std::vector<uint8_t> cie_cfi;
    std::vector<uint8_t> fde_cfi;
    std::vector<uint8_t> lsda_bytes;
    std::vector<EhCallSite> call_sites;
    std::vector<EhAction> actions;
    std::vector<EhTypeEntry> types;
};

struct ProtectedFunction {
    uint32_t id = 0;
    uint32_t selected_id = 0;
    std::string name;
    uint64_t original_start = 0;
    uint64_t size = 0;
    uint64_t body_size = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patched_bytes;
    std::vector<uint8_t> fragment_ciphertext;
    std::vector<uint8_t> fragment_aad;
    std::array<uint8_t, 24> fragment_nonce{};
    std::array<uint8_t, 16> fragment_tag{};
    uint64_t stub_vaddr = 0;
    uint64_t slot_vaddr = 0;
    uint64_t slot_size = 0;
    uint64_t enc_vaddr = 0;
    uint64_t active_vaddr = 0;
    uint64_t fragment_nonce_vaddr = 0;
    uint64_t fragment_tag_vaddr = 0;
    uint64_t fragment_aad_vaddr = 0;
    uint64_t fde_vaddr = 0;
    uint64_t eh_registration_vaddr = 0;
    uint64_t eh_normal_cleanup_vaddr = 0;
    uint64_t eh_unwind_cleanup_vaddr = 0;
    uint64_t eh_throw_cleanup_vaddr = 0;
    uint64_t eh_rethrow_cleanup_vaddr = 0;
    std::vector<uint8_t> cie_bytes;
    std::vector<uint8_t> fde_bytes;
    uint64_t fde_pc_begin = 0;
    EhMetadata eh_metadata;
    size_t direct_calls = 0;
    size_t tail_calls = 0;
    size_t indirect_calls = 0;
    size_t entry_pointer_refs = 0;
    size_t runtime_relocations = 0;
    size_t veneer_count = 0;
    size_t literal_pool_bytes = 0;
    std::vector<size_t> runtime_literal_offsets;
    bool plaintext_verified = false;
    bool original_site_patched = false;
    ProtectionMode protection_mode = ProtectionMode::LegacyFunctionOnly;
    SelectedBackend selected_backend = SelectedBackend::None;
    FinalOutcome final_outcome = FinalOutcome::Pending;
    std::vector<ReasonCode> reason_codes;
    std::string protection_reason;
    InstructionFacts instruction_facts;
    std::vector<ControlEdge> control_edges;
    std::vector<DataReference> data_refs;
    std::vector<ProtectedFragment> fragments;
    struct InteriorThunk {
        uint64_t original_target;
        uint64_t thunk_vaddr;
        uint32_t fragment_id;
        std::string source;
    };
    std::vector<InteriorThunk> interior_thunks;
    bool cfg_execution_enabled = false;
    bool native_variants_enabled = false;
    uint64_t event_cookie = 0;
    bool cfg_pie_fixups = false;
    uint32_t cluster_id = 0;
    uint32_t controllet_family = 0;
    uint64_t metadata_shard_vaddr = 0;
    uint64_t metadata_shard_capacity = 0;
    uint64_t metadata_shard_mask = 0;
    std::vector<uint8_t> metadata_shard;
    uint64_t v3_shard_vaddr = 0;
    uint64_t v3_shard_capacity = 0;
    uint32_t v3_shard_family = 0;
    std::array<uint8_t, 16> v3_owner_namespace{};
    std::vector<uint8_t> v3_shard_envelope;
    uint32_t v3_capability_count = 0;
    uint32_t v3_event_gateway_offset = 4;
    uint32_t v3_gateway_abi_family = 0;
    uint64_t entry_stub_capacity = 0;
    uint32_t v3_target_capacity = 0;
    bool v3_control_enabled = false;
    uint64_t v3_function_handle = 0;
    struct V3FunctionTarget {
        uint64_t handle = 0;
        uint64_t entry = 0;
        uint64_t initial_fragment = 0;
    };
    std::vector<V3FunctionTarget> v3_function_targets;
};

struct CallsiteMetadata {
    uint32_t caller_func_id = 0;
    uint32_t callee_func_id = UINT32_MAX;
    uint64_t original_pc = 0;
    uint64_t original_return_pc = 0;
    uint32_t flags = 0;
    uint32_t reserved = 0;
};

struct PayloadLayout {
    uint64_t base_vaddr = 0;
    uint64_t rx_end_vaddr = 0;
    uint64_t ro_start_vaddr = 0;
    uint64_t ro_end_vaddr = 0;
    uint64_t rw_start_vaddr = 0;
    uint64_t return_stub_vaddr = 0;
    uint64_t thread_states_vaddr = 0;
    uint64_t build_root_vaddr = 0;
    uint64_t callsite_meta_vaddr = 0;
    uint64_t callsite_meta_size = 0;
    uint64_t eh_frame_vaddr = 0;
    uint64_t eh_frame_size = 0;
    uint64_t total_size = 0;
    uint64_t fragment_runtime_vaddr = 0;
    uint64_t eh_runtime_arena_vaddr = 0;
    uint64_t eh_runtime_arena_size = 0;
    uint64_t fragment_descriptor_vaddr = 0;
};

struct EhHeaderEntry {
    uint64_t pc = 0;
    uint64_t fde = 0;
};

struct SlotLocalPatch {
    enum Kind { BranchToVeneer, AdrLiteral, AdrpAddLiteral } kind = BranchToVeneer;
    size_t insn_off = 0;
    size_t paired_off = 0;
    uint32_t original_insn = 0;
    uint32_t paired_insn = 0;
    uint64_t target = 0;
};

inline constexpr uint64_t kAlign = 16;
inline constexpr uint64_t kSegmentAlign = 0x10000;
inline constexpr uint64_t kPageSize = 0x1000;
inline constexpr uint64_t kFrameCount = 1024;
inline constexpr uint64_t kLegacyFrameSize = 48;
inline constexpr uint64_t kFrameSize = 128;
inline constexpr uint64_t kThreadSlotCount = 256;
inline constexpr uint64_t kThreadStateSize = 16 + (kFrameCount * kLegacyFrameSize);
inline constexpr uint64_t kDynamicThreadHeaderSize = 64;
inline constexpr uint64_t kCheckpointTablePage = 33;
inline constexpr uint64_t kDynamicThreadStateSize = 34 * kPageSize;
inline constexpr uint64_t kFunctionStateSize = 24;
inline constexpr uint64_t kFragmentAadSize = 128;
// V3 uses the final 128 bytes as a private transaction snapshot of the
// current logical frame.  It is restored on every successor-materialization
// fault before the typed fault is raised.  Bytes 0..383 hold x0-x30 and
// q0-q7, 384..511 hold the V3 transaction snapshot, and 512..535 hold NZCV,
// FPCR and FPSR.  The final eight bytes preserve 16-byte stack alignment.
inline constexpr uint64_t kSaveSize = 544;
// V2 keeps a bounded selector gateway.  Encoded (non-literal) target
// materialization needs more room for large control-flow samples.
inline constexpr uint64_t kEntryStubSize = 96 * 1024;
inline constexpr uint64_t kV3EntryStubSize = 131072;
inline uint64_t semantic_entry_stub_capacity(const ProtectedFunction& func) {
    uint64_t exits = 0;
    for (const auto& fragment : func.fragments)
        exits += fragment.exits.size();
    const uint64_t structural = 12 * 1024 + exits * 2048 + func.fragments.size() * 2048 +
                                uint64_t(func.v3_target_capacity) * 512;
    return (structural + 4095) & ~uint64_t{4095};
}
inline uint64_t entry_stub_size(const ProtectedFunction& func) {
    if (func.entry_stub_capacity != 0)
        return func.entry_stub_capacity;
    // Capacity follows generated semantic objects: the common interpreter,
    // fragment/edge validators, and opaque target adapters.  There is no
    // fixed per-function V3 reservation.
    return semantic_entry_stub_capacity(func);
}
inline constexpr uint64_t kReturnStubSize = 1024;
inline constexpr uint64_t kFragmentRuntimeCapacity = 0x10000;
inline constexpr uint64_t kFragmentDescriptorCapacity = 0x10000;
inline constexpr uint64_t kRuntimeBodyExtraPerInsn = 48;

std::string hex(uint64_t v);
uint64_t encrypted_body_capacity(const ProtectedFunction& func, SlotStrategy strategy);
const char* protection_mode_name(ProtectionMode mode);
const char* selected_backend_name(SelectedBackend backend);
const char* final_outcome_name(FinalOutcome outcome);
const char* reason_code_name(ReasonCode reason);
const char* control_edge_kind_name(ControlEdgeKind kind);
const char* control_target_domain_name(ControlTargetDomain domain);
const char* data_ref_kind_name(DataRefKind kind);
const char* fragment_exit_kind_name(FragmentExitKind kind);

} // namespace maya::protection
