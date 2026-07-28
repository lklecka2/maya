#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "V3Capabilities.hpp"

namespace maya::protection {

inline constexpr uint32_t kV3VmSchemaVersion = 2;
inline constexpr size_t kV3VmRegisterCount = 16;
inline constexpr size_t kV3VmDataStackLimit = 64;
inline constexpr size_t kV3VmCallStackLimit = 32;

enum class V3VmValueType : uint8_t {
    Empty,
    U64,
    Boolean,
    Span,
    Authority,
    ShardRecord,
    TargetHandle,
    Fault,
};

enum class V3VmPrimitive : uint8_t {
    ValidateEnvelope = 1,
    ValidateCapability,
    OpenShard,
    ResolveTarget,
    PrepareSuccessor,
    AuthenticateSuccessor,
    RelocateSuccessor,
    ProtectSuccessor,
    SynchronizeCaches,
    PublishSuccessor,
    RetirePredecessor,
    Cleanup,
    Checkpoint,
    Longjmp,
    RegisterEh,
    ResumeEh,
    SelectVariant,
};

enum class V3VmOp : uint8_t {
    LoadImmediate,
    Move,
    Add,
    Xor,
    RotateRight,
    Equal,
    PushData,
    PopData,
    Call,
    Return,
    MakeSpan,
    CheckSpan,
    Primitive,
    ConsumeAuthority,
    Jump,
    JumpIf,
    Halt,
    Fault,
    Count,
};

struct V3VmInstruction {
    V3VmOp op = V3VmOp::Halt;
    uint8_t destination = 0;
    uint8_t source_a = 0;
    uint8_t source_b = 0;
    uint64_t immediate = 0;
};

// Semantic IR is independent from the seed-shuffled wire ISA.
// Values are checked by the compiler before an authenticated program is emitted.
struct V3VmSemanticInstruction {
    V3VmInstruction instruction{};
    V3VmValueType result_type = V3VmValueType::Empty;
};

struct V3VmSemanticProgram {
    std::vector<V3VmSemanticInstruction> instructions;
    uint64_t step_limit = 0;
};

struct V3VmIsa {
    std::array<uint8_t, static_cast<size_t>(V3VmOp::Count)> opcode{};
    std::array<uint8_t, kV3VmRegisterCount> register_encoding{};
    std::array<uint8_t, kV3VmRegisterCount> register_decoding{};
    uint64_t immediate_mask = 0;
    uint8_t operand_mask = 0;
    uint32_t dispatch_family = 0;
};

struct SealedV3Program {
    uint32_t schema = kV3VmSchemaVersion;
    uint32_t cluster = 0;
    Opaque128 owner_namespace{};
    uint64_t step_limit = 0;
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 16> tag{};
    std::vector<uint8_t> ciphertext;
};

enum class V3VmFault : uint32_t {
    None = 0,
    Authentication = 1,
    InvalidOpcode = 2,
    InvalidOperand = 3,
    InvalidBranch = 4,
    StepLimit = 5,
    ExplicitFault = 6,
    MissingHalt = 7,
    TypeMismatch = 8,
    DataStackOverflow = 9,
    DataStackUnderflow = 10,
    CallStackOverflow = 11,
    CallStackUnderflow = 12,
    InvalidSpan = 13,
    InvalidPrimitive = 14,
    AuthorityConsumed = 15,
};

struct V3VmResult {
    V3VmFault fault = V3VmFault::None;
    std::array<uint64_t, kV3VmRegisterCount> registers{};
    std::array<V3VmValueType, kV3VmRegisterCount> register_types{};
    uint64_t steps = 0;
    uint64_t primitive_trace = 0;
};

V3VmIsa generate_v3_isa(const Seed256& seed, uint32_t cluster);
std::vector<uint8_t> encode_v3_program(const V3VmIsa& isa,
                                       const std::vector<V3VmInstruction>& instructions);
std::vector<V3VmInstruction> compile_v3_semantic_program(const V3VmSemanticProgram& program);
V3VmSemanticProgram make_v3_transition_program(bool include_variant_selection, bool include_eh,
                                               uint64_t step_limit = 128);
SealedV3Program seal_v3_program(const Seed256& build_key, const Seed256& build_seed,
                                const V3VmIsa& isa, uint32_t cluster,
                                const Opaque128& owner_namespace, uint64_t step_limit,
                                const std::vector<V3VmInstruction>& instructions);
V3VmResult execute_v3_program(const Seed256& build_key, const V3VmIsa& isa,
                              const SealedV3Program& program,
                              const std::array<uint64_t, kV3VmRegisterCount>& initial = {});
std::string generate_v3_interpreter_assembly(const V3VmIsa& isa);
std::vector<uint8_t> v3_program_aad(const SealedV3Program& program, const V3VmIsa& isa);
Seed256 derive_v3_program_key(const Seed256& key, const SealedV3Program& program);

} // namespace maya::protection
