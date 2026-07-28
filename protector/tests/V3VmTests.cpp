#include "core/protection/FragmentCrypto.hpp"
#include "core/protection/V3Vm.hpp"
#include "runtime_kdf.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace maya::protection;

int main() {
    Seed256 seed{};
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = uint8_t(i * 5 + 3);
    const auto owner = derive_opaque128(seed, "vm-owner", 1, 2);
    const auto isa = generate_v3_isa(seed, 2), same = generate_v3_isa(seed, 2),
               other = generate_v3_isa(seed, 3);
    if (isa.opcode != same.opcode || isa.register_encoding != same.register_encoding ||
        isa.opcode == other.opcode)
        return 1;
    std::vector<V3VmInstruction> instructions = {
        {V3VmOp::LoadImmediate, 0, 0, 0, 19},
        {V3VmOp::LoadImmediate, 1, 0, 0, 23},
        {V3VmOp::Add, 2, 0, 1, 0},
        {V3VmOp::LoadImmediate, 3, 0, 0, 42},
        {V3VmOp::Equal, 4, 2, 3, 0},
        {V3VmOp::JumpIf, 0, 4, 0, 7},
        {V3VmOp::Fault, 0, 0, 0, 0},
        {V3VmOp::Halt, 0, 0, 0, 0},
    };
    auto program = seal_v3_program(seed, seed, isa, 2, owner, 32, instructions);
    Seed256 runtime_key{};
    maya_v3_derive_vm_key(runtime_key.data(), seed.data(), owner.data(), 2);
    if (runtime_key != derive_v3_program_key(seed, program))
        return 8;
    Seed256 wrong_context{};
    maya_v3_derive_vm_key(wrong_context.data(), seed.data(), owner.data(), 3);
    if (wrong_context == runtime_key)
        return 9;
    auto wrong_owner = owner;
    wrong_owner[0] ^= 1;
    maya_v3_derive_vm_key(wrong_context.data(), seed.data(), wrong_owner.data(), 2);
    if (wrong_context == runtime_key)
        return 10;
    const auto result = execute_v3_program(seed, isa, program);
    if (result.fault != V3VmFault::None || result.registers[2] != 42 || result.registers[4] != 1)
        return 2;
    auto corrupt = program;
    corrupt.ciphertext[0] ^= 1;
    if (execute_v3_program(seed, isa, corrupt).fault != V3VmFault::Authentication)
        return 3;
    if (execute_v3_program(seed, other, program).fault != V3VmFault::Authentication)
        return 4;
    auto limited = program;
    limited.step_limit = 1;
    if (execute_v3_program(seed, isa, limited).fault != V3VmFault::Authentication)
        return 5;
    auto short_program = seal_v3_program(seed, seed, isa, 2, owner, 2, instructions);
    if (execute_v3_program(seed, isa, short_program).fault != V3VmFault::StepLimit)
        return 6;
    const auto assembly = generate_v3_interpreter_assembly(isa);
    if (assembly.find("dispatch-family") == std::string::npos ||
        assembly == generate_v3_interpreter_assembly(other))
        return 7;

    const auto semantic = make_v3_transition_program(true, true, 128);
    const auto compiled = compile_v3_semantic_program(semantic);
    auto transition = seal_v3_program(seed, seed, isa, 2, owner, semantic.step_limit, compiled);
    const auto transition_result = execute_v3_program(seed, isa, transition);
    const uint64_t required =
        (uint64_t{1} << (static_cast<unsigned>(V3VmPrimitive::ValidateEnvelope) - 1)) |
        (uint64_t{1} << (static_cast<unsigned>(V3VmPrimitive::ValidateCapability) - 1)) |
        (uint64_t{1} << (static_cast<unsigned>(V3VmPrimitive::OpenShard) - 1)) |
        (uint64_t{1} << (static_cast<unsigned>(V3VmPrimitive::PublishSuccessor) - 1)) |
        (uint64_t{1} << (static_cast<unsigned>(V3VmPrimitive::Cleanup) - 1));
    if (transition_result.fault != V3VmFault::None ||
        (transition_result.primitive_trace & required) != required)
        return 11;

    auto expect_compile_failure = [](V3VmSemanticProgram invalid) {
        try {
            (void)compile_v3_semantic_program(invalid);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    V3VmSemanticProgram bad_type{{{{V3VmOp::Add, 0, 1, 2, 0}, V3VmValueType::U64},
                                  {{V3VmOp::Halt, 0, 0, 0, 0}, V3VmValueType::Empty}},
                                 8};
    if (!expect_compile_failure(bad_type))
        return 12;
    V3VmSemanticProgram bad_branch{{{{V3VmOp::Jump, 0, 0, 0, 99}, V3VmValueType::Empty},
                                    {{V3VmOp::Halt, 0, 0, 0, 0}, V3VmValueType::Empty}},
                                   8};
    if (!expect_compile_failure(bad_branch))
        return 13;
    V3VmSemanticProgram missing_halt{{{{V3VmOp::LoadImmediate, 0, 0, 0, 1}, V3VmValueType::U64}},
                                     8};
    if (!expect_compile_failure(missing_halt))
        return 14;
    V3VmSemanticProgram bad_primitive{{{{V3VmOp::Primitive, 0, 0, 0, 999}, V3VmValueType::Boolean},
                                       {{V3VmOp::Halt, 0, 0, 0, 0}, V3VmValueType::Empty}},
                                      8};
    if (!expect_compile_failure(bad_primitive))
        return 15;
    auto wrong_seed = seed;
    wrong_seed[0] ^= 0x80;
    if (execute_v3_program(wrong_seed, isa, transition).fault != V3VmFault::Authentication)
        return 16;

    auto seal_raw = [&](std::vector<uint8_t> plaintext, SealedV3Program base) {
        base.ciphertext.resize(plaintext.size());
        auto key = derive_v3_program_key(seed, base);
        const auto sealed = seal_fragment(plaintext, v3_program_aad(base, isa), key, base.nonce);
        secure_zero(key);
        base.ciphertext = sealed.ciphertext;
        base.tag = sealed.tag;
        return base;
    };
    auto encoded = encode_v3_program(isa, {{V3VmOp::Halt, 0, 0, 0, 0}});
    uint8_t unknown = 0;
    while (std::find(isa.opcode.begin(), isa.opcode.end(), unknown) != isa.opcode.end())
        ++unknown;
    encoded[0] = unknown;
    if (execute_v3_program(seed, isa,
                           seal_raw(encoded, seal_v3_program(seed, seed, isa, 2, owner, 4,
                                                             {{V3VmOp::Halt, 0, 0, 0, 0}})))
            .fault != V3VmFault::InvalidOpcode)
        return 17;
    encoded = encode_v3_program(isa, {{V3VmOp::Halt, 0, 0, 0, 0}});
    encoded[1] = uint8_t(16 ^ isa.operand_mask);
    if (execute_v3_program(seed, isa,
                           seal_raw(encoded, seal_v3_program(seed, seed, isa, 2, owner, 4,
                                                             {{V3VmOp::Halt, 0, 0, 0, 0}})))
            .fault != V3VmFault::InvalidOperand)
        return 18;
    auto no_halt =
        seal_v3_program(seed, seed, isa, 2, owner, 4, {{V3VmOp::LoadImmediate, 0, 0, 0, 1}});
    if (execute_v3_program(seed, isa, no_halt).fault != V3VmFault::MissingHalt)
        return 19;
    auto invalid_jump = seal_v3_program(seed, seed, isa, 2, owner, 4,
                                        {{V3VmOp::Jump, 0, 0, 0, 99}, {V3VmOp::Halt, 0, 0, 0, 0}});
    if (execute_v3_program(seed, isa, invalid_jump).fault != V3VmFault::InvalidBranch)
        return 20;
    auto invalid_primitive =
        seal_v3_program(seed, seed, isa, 2, owner, 4,
                        {{V3VmOp::Primitive, 0, 0, 0, 999}, {V3VmOp::Halt, 0, 0, 0, 0}});
    if (execute_v3_program(seed, isa, invalid_primitive).fault != V3VmFault::InvalidPrimitive)
        return 21;
    auto bad_return = seal_v3_program(seed, seed, isa, 2, owner, 4,
                                      {{V3VmOp::Return, 0, 0, 0, 0}, {V3VmOp::Halt, 0, 0, 0, 0}});
    if (execute_v3_program(seed, isa, bad_return).fault != V3VmFault::CallStackUnderflow)
        return 22;
    auto bad_condition = seal_v3_program(
        seed, seed, isa, 2, owner, 4, {{V3VmOp::JumpIf, 0, 0, 0, 1}, {V3VmOp::Halt, 0, 0, 0, 0}});
    if (execute_v3_program(seed, isa, bad_condition).fault != V3VmFault::TypeMismatch)
        return 23;
    std::cout << "V3 VM tests passed\n";
}
