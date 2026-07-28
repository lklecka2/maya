#include "V3Vm.hpp"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <sstream>
#include <stdexcept>

#include "FragmentCrypto.hpp"

namespace maya::protection {
namespace {

constexpr size_t kInstructionSize = 12;

void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(uint8_t(value >> (i * 8)));
}
void put64(std::vector<uint8_t>& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(uint8_t(value >> (i * 8)));
}
uint64_t get64(const uint8_t* bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= uint64_t(bytes[i]) << (i * 8);
    return value;
}

std::vector<uint8_t> program_aad(const SealedV3Program& program, const V3VmIsa& isa) {
    std::vector<uint8_t> aad;
    put32(aad, program.schema);
    put32(aad, program.cluster);
    put64(aad, program.step_limit);
    aad.insert(aad.end(), program.owner_namespace.begin(), program.owner_namespace.end());
    aad.insert(aad.end(), isa.opcode.begin(), isa.opcode.end());
    aad.insert(aad.end(), isa.register_encoding.begin(), isa.register_encoding.end());
    put64(aad, isa.immediate_mask);
    aad.push_back(isa.operand_mask);
    put32(aad, isa.dispatch_family);
    put64(aad, program.ciphertext.size());
    return aad;
}

Seed256 program_key(const Seed256& key, const SealedV3Program& program) {
    return derive_v3_domain_key(key, "runtime-bytecode", program.owner_namespace, program.cluster);
}

uint64_t rotate_right(uint64_t value, unsigned count) {
    count &= 63;
    return count == 0 ? value : (value >> count) | (value << (64 - count));
}

V3VmValueType primitive_result(V3VmPrimitive primitive) {
    switch (primitive) {
    case V3VmPrimitive::ValidateCapability:
        return V3VmValueType::Authority;
    case V3VmPrimitive::OpenShard:
        return V3VmValueType::ShardRecord;
    case V3VmPrimitive::ResolveTarget:
        return V3VmValueType::TargetHandle;
    case V3VmPrimitive::ValidateEnvelope:
    case V3VmPrimitive::PrepareSuccessor:
    case V3VmPrimitive::AuthenticateSuccessor:
    case V3VmPrimitive::RelocateSuccessor:
    case V3VmPrimitive::ProtectSuccessor:
    case V3VmPrimitive::SynchronizeCaches:
    case V3VmPrimitive::PublishSuccessor:
    case V3VmPrimitive::RetirePredecessor:
    case V3VmPrimitive::Cleanup:
    case V3VmPrimitive::Checkpoint:
    case V3VmPrimitive::Longjmp:
    case V3VmPrimitive::RegisterEh:
    case V3VmPrimitive::ResumeEh:
    case V3VmPrimitive::SelectVariant:
        return V3VmValueType::Boolean;
    }
    return V3VmValueType::Fault;
}

bool valid_primitive(uint64_t value) {
    return value >= static_cast<uint64_t>(V3VmPrimitive::ValidateEnvelope) &&
           value <= static_cast<uint64_t>(V3VmPrimitive::SelectVariant);
}

} // namespace

V3VmIsa generate_v3_isa(const Seed256& seed, uint32_t cluster) {
    V3VmIsa isa;
    std::vector<uint8_t> info{'m', 'a', 'y', 'a', '-', 'v', '3', '-', 'i', 's', 'a'};
    put32(info, cluster);
    const auto material = hkdf_sha256(seed, {}, info);
    std::array<uint8_t, 256> values{};
    std::iota(values.begin(), values.end(), 0);
    uint64_t state = 0;
    std::memcpy(&state, material.data(), sizeof(state));
    auto next = [&]() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };
    for (size_t index = values.size() - 1; index > 0; --index)
        std::swap(values[index], values[next() % (index + 1)]);
    for (size_t index = 0; index < isa.opcode.size(); ++index)
        isa.opcode[index] = values[index];
    std::array<uint8_t, kV3VmRegisterCount> registers{};
    std::iota(registers.begin(), registers.end(), 0);
    for (size_t index = registers.size() - 1; index > 0; --index)
        std::swap(registers[index], registers[next() % (index + 1)]);
    for (size_t logical = 0; logical < registers.size(); ++logical) {
        isa.register_encoding[logical] = registers[logical];
        isa.register_decoding[registers[logical]] = static_cast<uint8_t>(logical);
    }
    std::memcpy(&isa.immediate_mask, material.data() + 8, sizeof(isa.immediate_mask));
    isa.operand_mask = material[16] & 0xf0u;
    isa.dispatch_family = material[17] % 3;
    return isa;
}

std::vector<uint8_t> encode_v3_program(const V3VmIsa& isa,
                                       const std::vector<V3VmInstruction>& instructions) {
    std::vector<uint8_t> bytes;
    bytes.reserve(instructions.size() * kInstructionSize);
    for (const auto& instruction : instructions) {
        const auto semantic = static_cast<size_t>(instruction.op);
        if (semantic >= isa.opcode.size() || instruction.destination >= kV3VmRegisterCount ||
            instruction.source_a >= kV3VmRegisterCount ||
            instruction.source_b >= kV3VmRegisterCount) {
            throw std::runtime_error("Invalid V3 VM instruction");
        }
        bytes.push_back(isa.opcode[semantic]);
        bytes.push_back(isa.register_encoding[instruction.destination] ^ isa.operand_mask);
        bytes.push_back(isa.register_encoding[instruction.source_a] ^ isa.operand_mask);
        bytes.push_back(isa.register_encoding[instruction.source_b] ^ isa.operand_mask);
        put64(bytes, instruction.immediate ^ isa.immediate_mask);
    }
    return bytes;
}

std::vector<V3VmInstruction> compile_v3_semantic_program(const V3VmSemanticProgram& program) {
    if (program.instructions.empty() || program.step_limit == 0) {
        throw std::runtime_error("V3 semantic program requires instructions and a step limit");
    }
    std::array<V3VmValueType, kV3VmRegisterCount> types{};
    std::vector<V3VmValueType> data_stack;
    size_t call_depth = 0;
    bool has_halt = false;
    std::vector<V3VmInstruction> output;
    output.reserve(program.instructions.size());
    for (size_t pc = 0; pc < program.instructions.size(); ++pc) {
        const auto& semantic = program.instructions[pc];
        const auto& instruction = semantic.instruction;
        if (instruction.destination >= kV3VmRegisterCount ||
            instruction.source_a >= kV3VmRegisterCount ||
            instruction.source_b >= kV3VmRegisterCount || instruction.op >= V3VmOp::Count) {
            throw std::runtime_error("Invalid register or opcode in V3 semantic program");
        }
        V3VmValueType inferred = V3VmValueType::Empty;
        switch (instruction.op) {
        case V3VmOp::LoadImmediate:
            inferred = V3VmValueType::U64;
            break;
        case V3VmOp::Move:
            if (types[instruction.source_a] == V3VmValueType::Empty)
                throw std::runtime_error("V3 VM move reads an untyped value");
            inferred = types[instruction.source_a];
            break;
        case V3VmOp::Add:
        case V3VmOp::Xor:
        case V3VmOp::RotateRight:
            if (types[instruction.source_a] != V3VmValueType::U64 ||
                (instruction.op != V3VmOp::RotateRight &&
                 types[instruction.source_b] != V3VmValueType::U64))
                throw std::runtime_error("V3 VM arithmetic requires u64 operands");
            inferred = V3VmValueType::U64;
            break;
        case V3VmOp::Equal:
            if (types[instruction.source_a] == V3VmValueType::Empty ||
                types[instruction.source_a] != types[instruction.source_b])
                throw std::runtime_error("V3 VM equality requires matching typed operands");
            inferred = V3VmValueType::Boolean;
            break;
        case V3VmOp::PushData:
            if (types[instruction.source_a] == V3VmValueType::Empty ||
                data_stack.size() == kV3VmDataStackLimit)
                throw std::runtime_error("Invalid V3 VM data-stack push");
            data_stack.push_back(types[instruction.source_a]);
            break;
        case V3VmOp::PopData:
            if (data_stack.empty())
                throw std::runtime_error("V3 VM data-stack underflow");
            inferred = data_stack.back();
            data_stack.pop_back();
            break;
        case V3VmOp::Call:
            if (instruction.immediate >= program.instructions.size() ||
                call_depth == kV3VmCallStackLimit)
                throw std::runtime_error("Invalid V3 VM call");
            ++call_depth;
            break;
        case V3VmOp::Return:
            if (call_depth == 0)
                throw std::runtime_error("V3 VM call-stack underflow");
            --call_depth;
            break;
        case V3VmOp::MakeSpan:
            if (types[instruction.source_a] != V3VmValueType::U64 ||
                types[instruction.source_b] != V3VmValueType::U64)
                throw std::runtime_error("V3 VM span requires u64 base and length");
            inferred = V3VmValueType::Span;
            break;
        case V3VmOp::CheckSpan:
            if (types[instruction.source_a] != V3VmValueType::Span)
                throw std::runtime_error("V3 VM span check requires a span");
            inferred = V3VmValueType::Boolean;
            break;
        case V3VmOp::Primitive:
            if (!valid_primitive(instruction.immediate))
                throw std::runtime_error("Invalid V3 VM primitive handle");
            inferred = primitive_result(static_cast<V3VmPrimitive>(instruction.immediate));
            break;
        case V3VmOp::ConsumeAuthority:
            if (types[instruction.source_a] != V3VmValueType::Authority)
                throw std::runtime_error("V3 VM authority operand is not live");
            types[instruction.source_a] = V3VmValueType::Empty;
            inferred = V3VmValueType::Boolean;
            break;
        case V3VmOp::Jump:
            if (instruction.immediate >= program.instructions.size())
                throw std::runtime_error("Invalid V3 VM branch");
            break;
        case V3VmOp::JumpIf:
            if (instruction.immediate >= program.instructions.size() ||
                types[instruction.source_a] != V3VmValueType::Boolean)
                throw std::runtime_error("Invalid typed V3 VM conditional branch");
            break;
        case V3VmOp::Halt:
            has_halt = true;
            break;
        case V3VmOp::Fault:
        case V3VmOp::Count:
            break;
        }
        if (inferred != V3VmValueType::Empty) {
            if (semantic.result_type != inferred)
                throw std::runtime_error("V3 VM semantic result type mismatch");
            types[instruction.destination] = inferred;
        } else if (semantic.result_type != V3VmValueType::Empty) {
            throw std::runtime_error("V3 VM instruction unexpectedly declares a result");
        }
        output.push_back(instruction);
    }
    if (!has_halt)
        throw std::runtime_error("V3 semantic program has no halt");
    return output;
}

V3VmSemanticProgram make_v3_transition_program(bool include_variant_selection, bool include_eh,
                                               uint64_t step_limit) {
    V3VmSemanticProgram program;
    program.step_limit = step_limit;
    auto primitive = [&](V3VmPrimitive value, V3VmValueType type) {
        program.instructions.push_back(
            {{V3VmOp::Primitive, 0, 0, 0, static_cast<uint64_t>(value)}, type});
    };
    primitive(V3VmPrimitive::ValidateEnvelope, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::OpenShard, V3VmValueType::ShardRecord);
    primitive(V3VmPrimitive::ResolveTarget, V3VmValueType::TargetHandle);
    primitive(V3VmPrimitive::ValidateCapability, V3VmValueType::Authority);
    program.instructions.push_back(
        {{V3VmOp::ConsumeAuthority, 1, 0, 0, 0}, V3VmValueType::Boolean});
    primitive(V3VmPrimitive::PrepareSuccessor, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::RetirePredecessor, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::AuthenticateSuccessor, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::RelocateSuccessor, V3VmValueType::Boolean);
    if (include_eh)
        primitive(V3VmPrimitive::RegisterEh, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::ProtectSuccessor, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::SynchronizeCaches, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::PublishSuccessor, V3VmValueType::Boolean);
    if (include_variant_selection)
        primitive(V3VmPrimitive::SelectVariant, V3VmValueType::Boolean);
    primitive(V3VmPrimitive::Cleanup, V3VmValueType::Boolean);
    program.instructions.push_back({{V3VmOp::Halt, 0, 0, 0, 0}, V3VmValueType::Empty});
    return program;
}

SealedV3Program seal_v3_program(const Seed256& build_key, const Seed256& build_seed,
                                const V3VmIsa& isa, uint32_t cluster,
                                const Opaque128& owner_namespace, uint64_t step_limit,
                                const std::vector<V3VmInstruction>& instructions) {
    if (step_limit == 0 || instructions.empty())
        throw std::runtime_error("V3 VM program requires instructions and a step limit");
    SealedV3Program program;
    program.cluster = cluster;
    program.owner_namespace = owner_namespace;
    program.step_limit = step_limit;
    const auto encoded = encode_v3_program(isa, instructions);
    std::vector<uint8_t> nonce_info(owner_namespace.begin(), owner_namespace.end());
    put32(nonce_info, cluster);
    put64(nonce_info, encoded.size());
    nonce_info.insert(nonce_info.end(), isa.opcode.begin(), isa.opcode.end());
    const auto nonce_material = hkdf_sha256(build_seed, {}, nonce_info);
    std::copy_n(nonce_material.begin(), program.nonce.size(), program.nonce.begin());
    program.ciphertext.resize(encoded.size());
    auto key = program_key(build_key, program);
    const auto sealed = seal_fragment(encoded, program_aad(program, isa), key, program.nonce);
    secure_zero(key);
    program.ciphertext = sealed.ciphertext;
    program.tag = sealed.tag;
    return program;
}

V3VmResult execute_v3_program(const Seed256& build_key, const V3VmIsa& isa,
                              const SealedV3Program& program,
                              const std::array<uint64_t, kV3VmRegisterCount>& initial) {
    V3VmResult result;
    result.registers = initial;
    result.register_types.fill(V3VmValueType::U64);
    if (program.schema != kV3VmSchemaVersion || program.ciphertext.empty() ||
        program.ciphertext.size() % kInstructionSize != 0) {
        result.fault = V3VmFault::Authentication;
        return result;
    }
    std::vector<uint8_t> bytes;
    auto key = program_key(build_key, program);
    try {
        bytes = open_fragment({program.nonce, program.tag, program.ciphertext},
                              program_aad(program, isa), key);
    } catch (const std::exception&) {
        secure_zero(key);
        result.fault = V3VmFault::Authentication;
        return result;
    }
    secure_zero(key);
    std::array<int, 256> decode{};
    decode.fill(-1);
    for (size_t index = 0; index < isa.opcode.size(); ++index)
        decode[isa.opcode[index]] = static_cast<int>(index);
    struct StackValue {
        uint64_t value;
        V3VmValueType type;
    };
    std::vector<StackValue> data_stack;
    std::vector<size_t> call_stack;
    std::array<uint8_t, kV3VmRegisterCount> authority_consumed{};
    size_t pc = 0;
    while (pc < bytes.size()) {
        if (result.steps++ >= program.step_limit) {
            result.fault = V3VmFault::StepLimit;
            return result;
        }
        const uint8_t* encoded = bytes.data() + pc;
        const int semantic = decode[encoded[0]];
        if (semantic < 0) {
            result.fault = V3VmFault::InvalidOpcode;
            return result;
        }
        auto reg = [&](uint8_t value) -> uint8_t {
            const uint8_t physical = value ^ isa.operand_mask;
            return physical < kV3VmRegisterCount ? isa.register_decoding[physical] : UINT8_MAX;
        };
        const uint8_t destination = reg(encoded[1]), source_a = reg(encoded[2]),
                      source_b = reg(encoded[3]);
        if (destination >= kV3VmRegisterCount || source_a >= kV3VmRegisterCount ||
            source_b >= kV3VmRegisterCount) {
            result.fault = V3VmFault::InvalidOperand;
            return result;
        }
        const uint64_t immediate = get64(encoded + 4) ^ isa.immediate_mask;
        size_t next_pc = pc + kInstructionSize;
        auto require = [&](uint8_t index, V3VmValueType type) {
            return result.register_types[index] == type;
        };
        switch (static_cast<V3VmOp>(semantic)) {
        case V3VmOp::LoadImmediate:
            result.registers[destination] = immediate;
            result.register_types[destination] = V3VmValueType::U64;
            break;
        case V3VmOp::Move:
            if (result.register_types[source_a] == V3VmValueType::Empty) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] = result.registers[source_a];
            result.register_types[destination] = result.register_types[source_a];
            break;
        case V3VmOp::Add:
            if (!require(source_a, V3VmValueType::U64) || !require(source_b, V3VmValueType::U64)) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] =
                result.registers[source_a] + result.registers[source_b] + immediate;
            result.register_types[destination] = V3VmValueType::U64;
            break;
        case V3VmOp::Xor:
            if (!require(source_a, V3VmValueType::U64) || !require(source_b, V3VmValueType::U64)) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] =
                result.registers[source_a] ^ result.registers[source_b] ^ immediate;
            result.register_types[destination] = V3VmValueType::U64;
            break;
        case V3VmOp::RotateRight:
            if (!require(source_a, V3VmValueType::U64)) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] =
                rotate_right(result.registers[source_a], unsigned(immediate));
            result.register_types[destination] = V3VmValueType::U64;
            break;
        case V3VmOp::Equal:
            if (result.register_types[source_a] == V3VmValueType::Empty ||
                result.register_types[source_a] != result.register_types[source_b]) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] =
                result.registers[source_a] == result.registers[source_b];
            result.register_types[destination] = V3VmValueType::Boolean;
            break;
        case V3VmOp::PushData:
            if (data_stack.size() == kV3VmDataStackLimit) {
                result.fault = V3VmFault::DataStackOverflow;
                return result;
            }
            if (result.register_types[source_a] == V3VmValueType::Empty) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            data_stack.push_back({result.registers[source_a], result.register_types[source_a]});
            break;
        case V3VmOp::PopData:
            if (data_stack.empty()) {
                result.fault = V3VmFault::DataStackUnderflow;
                return result;
            }
            result.registers[destination] = data_stack.back().value;
            result.register_types[destination] = data_stack.back().type;
            data_stack.pop_back();
            break;
        case V3VmOp::Call:
            if (call_stack.size() == kV3VmCallStackLimit) {
                result.fault = V3VmFault::CallStackOverflow;
                return result;
            }
            if (immediate >= bytes.size() / kInstructionSize) {
                result.fault = V3VmFault::InvalidBranch;
                return result;
            }
            call_stack.push_back(next_pc);
            next_pc = immediate * kInstructionSize;
            break;
        case V3VmOp::Return:
            if (call_stack.empty()) {
                result.fault = V3VmFault::CallStackUnderflow;
                return result;
            }
            next_pc = call_stack.back();
            call_stack.pop_back();
            break;
        case V3VmOp::MakeSpan:
            if (!require(source_a, V3VmValueType::U64) || !require(source_b, V3VmValueType::U64) ||
                result.registers[source_b] > UINT32_MAX) {
                result.fault = V3VmFault::InvalidSpan;
                return result;
            }
            result.registers[destination] =
                (result.registers[source_a] & 0xffffffffULL) | (result.registers[source_b] << 32);
            result.register_types[destination] = V3VmValueType::Span;
            break;
        case V3VmOp::CheckSpan:
            if (!require(source_a, V3VmValueType::Span)) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            result.registers[destination] = uint32_t(result.registers[source_a] >> 32) != 0;
            result.register_types[destination] = V3VmValueType::Boolean;
            break;
        case V3VmOp::Primitive:
            if (!valid_primitive(immediate)) {
                result.fault = V3VmFault::InvalidPrimitive;
                return result;
            }
            result.registers[destination] = 1;
            result.register_types[destination] =
                primitive_result(static_cast<V3VmPrimitive>(immediate));
            result.primitive_trace |= uint64_t{1} << (immediate - 1);
            authority_consumed[destination] = 0;
            break;
        case V3VmOp::ConsumeAuthority:
            if (!require(source_a, V3VmValueType::Authority)) {
                result.fault = authority_consumed[source_a] ? V3VmFault::AuthorityConsumed
                                                            : V3VmFault::TypeMismatch;
                return result;
            }
            authority_consumed[source_a] = 1;
            result.registers[source_a] = 0;
            result.register_types[source_a] = V3VmValueType::Empty;
            result.registers[destination] = 1;
            result.register_types[destination] = V3VmValueType::Boolean;
            break;
        case V3VmOp::Jump:
            next_pc = immediate * kInstructionSize;
            break;
        case V3VmOp::JumpIf:
            if (!require(source_a, V3VmValueType::Boolean)) {
                result.fault = V3VmFault::TypeMismatch;
                return result;
            }
            if (result.registers[source_a])
                next_pc = immediate * kInstructionSize;
            break;
        case V3VmOp::Halt:
            return result;
        case V3VmOp::Fault:
            result.fault = V3VmFault::ExplicitFault;
            return result;
        case V3VmOp::Count:
            result.fault = V3VmFault::InvalidOpcode;
            return result;
        }
        if (next_pc > bytes.size() || next_pc % kInstructionSize != 0) {
            result.fault = V3VmFault::InvalidBranch;
            return result;
        }
        pc = next_pc;
    }
    result.fault = V3VmFault::MissingHalt;
    return result;
}

std::string generate_v3_interpreter_assembly(const V3VmIsa& isa) {
    std::ostringstream out;
    out << ".text\n.p2align 4\nmaya_v3_vm_entry:\n";
    out << "mov x9, #0\n";
    const char* dispatch[] = {"cmp-chain", "binary-split", "rotated-chain"};
    out << "// dispatch-family: " << dispatch[isa.dispatch_family] << "\n";
    std::vector<size_t> order(isa.opcode.size());
    std::iota(order.begin(), order.end(), 0);
    if (isa.dispatch_family == 1)
        std::sort(order.begin(), order.end(),
                  [&](size_t a, size_t b) { return isa.opcode[a] < isa.opcode[b]; });
    if (isa.dispatch_family == 2)
        std::rotate(order.begin(), order.begin() + (isa.immediate_mask % order.size()),
                    order.end());
    out << "maya_v3_dispatch:\nldrb w10, [x0], #12\n";
    for (size_t semantic : order)
        out << "cmp w10, #" << unsigned(isa.opcode[semantic]) << "\nb.eq maya_v3_op_" << semantic
            << "\n";
    out << "brk #0x102\n";
    for (size_t semantic : order)
        out << "maya_v3_op_" << semantic << ":\nadd x9, x9, #1\nb maya_v3_dispatch\n";
    return out.str();
}

std::vector<uint8_t> v3_program_aad(const SealedV3Program& program, const V3VmIsa& isa) {
    return program_aad(program, isa);
}

Seed256 derive_v3_program_key(const Seed256& key, const SealedV3Program& program) {
    return program_key(key, program);
}

} // namespace maya::protection
