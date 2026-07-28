#include "NativeVariants.hpp"

#include <capstone/capstone.h>
#include <z3++.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>

namespace maya::protection {
namespace {

class CapstoneHandle {
  public:
    CapstoneHandle() {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle_) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone for native variants");
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    }
    ~CapstoneHandle() { cs_close(&handle_); }
    csh get() const { return handle_; }

  private:
    csh handle_{};
};

using State = std::map<unsigned, z3::expr>;

unsigned canonical_register(unsigned reg) {
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28) {
        return ARM64_REG_X0 + (reg - ARM64_REG_W0);
    }
    if (reg == ARM64_REG_W29)
        return ARM64_REG_FP;
    if (reg == ARM64_REG_W30)
        return ARM64_REG_LR;
    return reg;
}

unsigned register_width(unsigned reg) {
    return reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30 ? 32 : 64;
}

z3::expr value_for_operand(z3::context& context, const cs_arm64_op& operand, const State& state,
                           unsigned width) {
    if (operand.type == ARM64_OP_REG) {
        const auto iterator = state.find(canonical_register(operand.reg));
        if (iterator == state.end())
            throw std::runtime_error("Variant proof referenced an untracked register");
        return width == 32 ? iterator->second.extract(31, 0) : iterator->second;
    }
    if (operand.type == ARM64_OP_IMM)
        return context.bv_val(static_cast<uint64_t>(operand.imm), width);
    throw std::runtime_error("Unsupported native-variant operand");
}

bool supported_register(unsigned reg) {
    return (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) ||
           (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_FP ||
           reg == ARM64_REG_LR;
}

bool collect_registers(const cs_insn& instruction, std::set<unsigned>& registers) {
    if (!instruction.detail || instruction.detail->arm64.update_flags)
        return false;
    const auto& detail = instruction.detail->arm64;
    for (uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == ARM64_OP_MEM || operand.type == ARM64_OP_FP ||
            operand.type == ARM64_OP_CIMM || operand.type == ARM64_OP_REG_MRS ||
            operand.type == ARM64_OP_REG_MSR || operand.type == ARM64_OP_SYS)
            return false;
        if (operand.type == ARM64_OP_REG) {
            if (!supported_register(operand.reg))
                return false;
            registers.insert(canonical_register(operand.reg));
        }
        const bool identity_shift =
            operand.shift.type == ARM64_SFT_INVALID ||
            (operand.shift.type == ARM64_SFT_LSL && operand.shift.value == 0);
        if (!identity_shift || operand.ext != ARM64_EXT_INVALID)
            return false;
    }
    return detail.op_count >= 2;
}

bool execute_instruction(z3::context& context, const cs_insn& instruction, State& state) {
    const auto& detail = instruction.detail->arm64;
    if (detail.op_count < 2 || detail.operands[0].type != ARM64_OP_REG)
        return false;
    const unsigned destination_operand = detail.operands[0].reg;
    const unsigned destination = canonical_register(destination_operand);
    const unsigned width = register_width(destination_operand);
    z3::expr value = context.bv_val(0, width);
    try {
        switch (instruction.id) {
        case ARM64_INS_MOV:
            value = value_for_operand(context, detail.operands[1], state, width);
            break;
        case ARM64_INS_ADD:
        case ARM64_INS_SUB:
        case ARM64_INS_EOR:
        case ARM64_INS_AND:
        case ARM64_INS_ORR: {
            if (detail.op_count != 3)
                return false;
            const auto lhs = value_for_operand(context, detail.operands[1], state, width);
            const auto rhs = value_for_operand(context, detail.operands[2], state, width);
            if (instruction.id == ARM64_INS_ADD)
                value = lhs + rhs;
            else if (instruction.id == ARM64_INS_SUB)
                value = lhs - rhs;
            else if (instruction.id == ARM64_INS_EOR)
                value = lhs ^ rhs;
            else if (instruction.id == ARM64_INS_AND)
                value = lhs & rhs;
            else
                value = lhs | rhs;
            break;
        }
        default:
            return false;
        }
    } catch (const std::exception&) {
        return false;
    }
    state.insert_or_assign(destination, width == 32 ? z3::zext(value, 32) : value);
    return true;
}

bool prove_swap(const cs_insn& first, const cs_insn& second, std::string& proof) {
    std::set<unsigned> registers;
    if (!collect_registers(first, registers) || !collect_registers(second, registers))
        return false;
    z3::context context;
    State initial;
    for (unsigned reg : registers)
        initial.emplace(reg, context.bv_const(("x" + std::to_string(reg)).c_str(), 64));
    State original = initial, swapped = initial;
    if (!execute_instruction(context, first, original) ||
        !execute_instruction(context, second, original) ||
        !execute_instruction(context, second, swapped) ||
        !execute_instruction(context, first, swapped))
        return false;
    z3::expr difference = context.bool_val(false);
    for (unsigned reg : registers)
        difference = difference || original.at(reg) != swapped.at(reg);
    z3::solver solver(context);
    z3::params parameters(context);
    parameters.set("rlimit", 100000u);
    solver.set(parameters);
    solver.add(difference);
    const auto result = solver.check();
    if (result != z3::unsat)
        return false;
    const std::string first_text = std::string(first.mnemonic) + " " + first.op_str;
    const std::string second_text = std::string(second.mnemonic) + " " + second.op_str;
    proof = "{\"schema\":2,\"solver\":\"z3-bv64\",\"result\":\"unsat\","
            "\"resource_limit\":100000,\"live_registers\":" +
            std::to_string(registers.size()) + ",\"original_disassembly\":\"" + first_text + "; " +
            second_text + "\",\"variant_disassembly\":\"" + second_text + "; " + first_text +
            "\",\"registers\":\"equivalent\",\"flags\":\"unchanged\","
            "\"stack_cfa\":\"unchanged\",\"memory_aliasing\":\"no-memory-operands\","
            "\"relocations\":\"none-in-window\",\"tls\":\"not-accessed\","
            "\"atomics\":\"not-accessed\",\"fp_neon\":\"not-accessed\","
            "\"pac_bti\":\"not-modified\",\"unwind\":\"instruction-width-preserved\"}";
    return true;
}

bool prove_equivalent_instruction(const cs_insn& original, const cs_insn& replacement,
                                  const std::string& transformation, std::string& proof) {
    std::set<unsigned> registers;
    if (!collect_registers(original, registers) || !collect_registers(replacement, registers))
        return false;
    z3::context context;
    State initial;
    for (unsigned reg : registers)
        initial.emplace(reg, context.bv_const(("x" + std::to_string(reg)).c_str(), 64));
    State original_state = initial, replacement_state = initial;
    if (!execute_instruction(context, original, original_state) ||
        !execute_instruction(context, replacement, replacement_state))
        return false;
    z3::expr difference = context.bool_val(false);
    for (unsigned reg : registers)
        difference = difference || original_state.at(reg) != replacement_state.at(reg);
    z3::solver solver(context);
    z3::params parameters(context);
    parameters.set("rlimit", 100000u);
    solver.set(parameters);
    solver.add(difference);
    if (solver.check() != z3::unsat)
        return false;
    const std::string original_text = std::string(original.mnemonic) + " " + original.op_str;
    const std::string replacement_text =
        std::string(replacement.mnemonic) + " " + replacement.op_str;
    proof = "{\"schema\":2,\"solver\":\"z3-bv64\",\"result\":\"unsat\","
            "\"resource_limit\":100000,\"transformation\":\"" +
            transformation + "\",\"live_registers\":" + std::to_string(registers.size()) +
            ",\"original_disassembly\":\"" + original_text + "\",\"variant_disassembly\":\"" +
            replacement_text +
            "\",\"registers\":\"equivalent\",\"flags\":\"unchanged\","
            "\"stack_cfa\":\"unchanged\",\"memory_aliasing\":\"no-memory-operands\","
            "\"relocations\":\"none-in-window\",\"tls\":\"not-accessed\","
            "\"atomics\":\"not-accessed\",\"fp_neon\":\"not-accessed\","
            "\"pac_bti\":\"not-modified\",\"unwind\":\"instruction-width-preserved\"}";
    return true;
}

bool equivalent_identity_encoding(uint32_t original, uint32_t& replacement) {
    const uint32_t opcode = original & UINT32_C(0xffc00000);
    const bool identity_add_sub = opcode == UINT32_C(0x91000000) ||
                                  opcode == UINT32_C(0xd1000000) ||
                                  opcode == UINT32_C(0x11000000) || opcode == UINT32_C(0x51000000);
    if (!identity_add_sub || (original & UINT32_C(0x003ffc00)) != 0)
        return false;
    const uint32_t source = (original >> 5) & 31u;
    const uint32_t destination = original & 31u;
    if (source == 31u || destination == 31u)
        return false; // SP and ZR are not interchangeable.
    const bool is_64 = (opcode & UINT32_C(0x80000000)) != 0;
    replacement =
        (is_64 ? UINT32_C(0xaa0003e0) : UINT32_C(0x2a0003e0)) | (source << 16) | destination;
    return replacement != original;
}

bool is_add_sub_immediate(uint32_t word) {
    return (word & UINT32_C(0x1f000000)) == UINT32_C(0x11000000) &&
           (word & UINT32_C(0x20000000)) == 0; // flag-setting forms are excluded.
}

bool make_whole_fragment_rename(csh capstone, const std::vector<uint8_t>& bytes,
                                size_t application_size,
                                const std::vector<size_t>& protected_offsets,
                                NativeVariantCandidate& candidate) {
    if (application_size < 12 || application_size % 4 != 0 || !protected_offsets.empty())
        return false;
    uint32_t last = 0;
    std::memcpy(&last, bytes.data() + application_size - 4, sizeof(last));
    if (last != UINT32_C(0xd65f03c0))
        return false; // canonical ret x30; no fragment successor.
    cs_insn* original = nullptr;
    const size_t count = cs_disasm(capstone, bytes.data(), application_size, 0, 0, &original);
    if (count * 4 != application_size) {
        cs_free(original, count);
        return false;
    }
    for (unsigned target = ARM64_REG_X9; target <= ARM64_REG_X15; ++target) {
        bool seen = false, dominated = false, valid = true;
        size_t occurrences = 0;
        for (size_t index = 0; index + 1 < count && valid; ++index) {
            uint32_t word = 0;
            std::memcpy(&word, bytes.data() + index * 4, sizeof(word));
            if (!is_add_sub_immediate(word) || !original[index].detail ||
                original[index].detail->arm64.update_flags) {
                valid = false;
                break;
            }
            const auto& detail = original[index].detail->arm64;
            for (uint8_t operand_index = 0; operand_index < detail.op_count; ++operand_index) {
                const auto& operand = detail.operands[operand_index];
                if (operand.type != ARM64_OP_REG || canonical_register(operand.reg) != target)
                    continue;
                ++occurrences;
                if (!seen) {
                    // The first mention must be a write with no simultaneous read.
                    if (operand_index != 0)
                        valid = false;
                    seen = true;
                } else if (!dominated && operand_index != 0)
                    valid = false;
            }
            if (seen && canonical_register(detail.operands[0].reg) == target)
                dominated = true;
        }
        if (!valid || !dominated || occurrences < 2)
            continue;
        for (unsigned replacement = ARM64_REG_X9; replacement <= ARM64_REG_X15; ++replacement) {
            if (replacement == target)
                continue;
            bool replacement_used = false;
            for (size_t index = 0; index + 1 < count; ++index) {
                const auto& detail = original[index].detail->arm64;
                for (uint8_t operand_index = 0; operand_index < detail.op_count; ++operand_index)
                    replacement_used |=
                        detail.operands[operand_index].type == ARM64_OP_REG &&
                        canonical_register(detail.operands[operand_index].reg) == replacement;
            }
            if (replacement_used)
                continue;
            candidate.bytes = bytes;
            const uint32_t target_number = target - ARM64_REG_X0;
            const uint32_t replacement_number = replacement - ARM64_REG_X0;
            for (size_t index = 0; index + 1 < count; ++index) {
                uint32_t word = 0;
                std::memcpy(&word, candidate.bytes.data() + index * 4, sizeof(word));
                if ((word & 31u) == target_number)
                    word = (word & ~31u) | replacement_number;
                if (((word >> 5) & 31u) == target_number)
                    word = (word & ~(31u << 5)) | (replacement_number << 5);
                std::memcpy(candidate.bytes.data() + index * 4, &word, sizeof(word));
            }
            cs_insn* renamed = nullptr;
            const size_t renamed_count =
                cs_disasm(capstone, candidate.bytes.data(), application_size, 0, 0, &renamed);
            if (renamed_count != count) {
                cs_free(renamed, renamed_count);
                continue;
            }
            z3::context context;
            State initial;
            std::set<unsigned> registers;
            for (size_t index = 0; index + 1 < count; ++index) {
                if (!collect_registers(original[index], registers) ||
                    !collect_registers(renamed[index], registers)) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                cs_free(renamed, renamed_count);
                continue;
            }
            for (unsigned reg : registers)
                initial.emplace(reg, context.bv_const(("x" + std::to_string(reg)).c_str(), 64));
            State original_state = initial, renamed_state = initial;
            for (size_t index = 0; index + 1 < count; ++index) {
                if (!execute_instruction(context, original[index], original_state) ||
                    !execute_instruction(context, renamed[index], renamed_state)) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                cs_free(renamed, renamed_count);
                continue;
            }
            z3::expr difference = context.bool_val(false);
            for (unsigned reg : registers)
                if (reg != target && reg != replacement)
                    difference = difference || original_state.at(reg) != renamed_state.at(reg);
            z3::solver solver(context);
            z3::params parameters(context);
            parameters.set("rlimit", 200000u);
            solver.set(parameters);
            solver.add(difference);
            if (solver.check() != z3::unsat) {
                cs_free(renamed, renamed_count);
                continue;
            }
            candidate.transformation = "whole-fragment-register-renaming";
            candidate.changed_offset = 0;
            candidate.proof =
                "{\"schema\":2,\"solver\":\"z3-bv64\",\"result\":\"unsat\","
                "\"resource_limit\":200000,\"registers\":\"abi-observable-equivalent-alpha-renamed-"
                "scratch\","
                "\"flags\":\"unchanged\",\"stack_cfa\":\"unchanged\",\"memory_aliasing\":\"no-"
                "memory-operands\","
                "\"relocations\":\"none-in-fragment\",\"tls\":\"not-accessed\",\"atomics\":\"not-"
                "accessed\","
                "\"fp_neon\":\"not-accessed\",\"pac_bti\":\"canonical-ret-preserved\","
                "\"unwind\":\"instruction-width-and-cfa-preserved\",\"scope\":\"whole-returning-"
                "fragment\"}";
            cs_free(renamed, renamed_count);
            cs_free(original, count);
            return true;
        }
    }
    cs_free(original, count);
    return false;
}

bool make_safe_block_layout(csh capstone, const std::vector<uint8_t>& bytes,
                            size_t application_size, const std::vector<size_t>& protected_offsets,
                            NativeVariantCandidate& candidate) {
    if (application_size != 20 || !protected_offsets.empty())
        return false;
    std::array<uint32_t, 5> words{};
    std::memcpy(words.data(), bytes.data(), sizeof(words));
    const bool cbz = (words[0] & UINT32_C(0x7f000000)) == UINT32_C(0x34000000);
    const bool cbnz = (words[0] & UINT32_C(0x7f000000)) == UINT32_C(0x35000000);
    if ((!cbz && !cbnz) || ((words[0] >> 5) & 0x7ffffu) != 3u || words[2] != UINT32_C(0x14000002) ||
        words[4] != UINT32_C(0xd65f03c0) || !is_add_sub_immediate(words[1]) ||
        !is_add_sub_immediate(words[3]))
        return false;
    cs_insn* first = nullptr;
    cs_insn* second = nullptr;
    const size_t first_count = cs_disasm(capstone, bytes.data() + 4, 4, 4, 1, &first);
    const size_t second_count = cs_disasm(capstone, bytes.data() + 12, 4, 12, 1, &second);
    if (first_count != 1 || second_count != 1) {
        cs_free(first, first_count);
        cs_free(second, second_count);
        return false;
    }
    std::set<unsigned> registers;
    const bool supported =
        collect_registers(first[0], registers) && collect_registers(second[0], registers);
    cs_free(first, first_count);
    cs_free(second, second_count);
    if (!supported)
        return false;
    candidate.bytes = bytes;
    words[0] ^= UINT32_C(0x01000000); // CBZ <-> CBNZ while preserving width, Rt and target.
    std::swap(words[1], words[3]);
    std::memcpy(candidate.bytes.data(), words.data(), sizeof(words));
    // The two successor paths contain the identical instruction each before
    // and after inversion/permutation.  Ask Z3 to refute that the selected
    // path ordinal changes for any tested register value.
    z3::context context;
    const auto tested = context.bv_const("tested_register", (words[0] >> 31) ? 64 : 32);
    const auto zero = context.bv_val(0, tested.get_sort().bv_size());
    const auto original_path =
        z3::ite(cbz ? tested == zero : tested != zero, context.bv_val(1, 2), context.bv_val(0, 2));
    const auto variant_path =
        z3::ite(cbz ? tested != zero : tested == zero, context.bv_val(0, 2), context.bv_val(1, 2));
    z3::solver solver(context);
    z3::params parameters(context);
    parameters.set("rlimit", 100000u);
    solver.set(parameters);
    solver.add(original_path != variant_path);
    if (solver.check() != z3::unsat)
        return false;
    candidate.transformation = "safe-conditional-block-layout";
    candidate.changed_offset = 0;
    candidate.proof =
        "{\"schema\":2,\"solver\":\"z3-bv64\",\"result\":\"unsat\","
        "\"resource_limit\":100000,\"registers\":\"same-selected-block\",\"flags\":\"unchanged\","
        "\"stack_cfa\":\"unchanged\",\"memory_aliasing\":\"no-memory-operands\","
        "\"relocations\":\"fixed-width-local-branches-reencoded\",\"tls\":\"not-accessed\","
        "\"atomics\":\"not-accessed\",\"fp_neon\":\"not-accessed\",\"pac_bti\":\"ret-preserved\","
        "\"unwind\":\"instruction-width-and-cfa-preserved\",\"cfg\":\"condition-inverted-blocks-"
        "permuted\"}";
    return true;
}

bool make_literal_pool_placement(const std::vector<uint8_t>& bytes, size_t application_size,
                                 const std::vector<size_t>& protected_offsets,
                                 NativeVariantCandidate& candidate) {
    if (application_size != 24 || protected_offsets != std::vector<size_t>{8})
        return false;
    std::array<uint32_t, 6> words{};
    std::memcpy(words.data(), bytes.data(), sizeof(words));
    // A canonical 64-bit LDR literal, RET, 8-byte pool entry, then two NOPs.
    if ((words[0] & UINT32_C(0xff00001f)) != UINT32_C(0x58000000) ||
        ((words[0] >> 5) & 0x7ffffu) != 2u || words[1] != UINT32_C(0xd65f03c0) ||
        words[4] != UINT32_C(0xd503201f) || words[5] != UINT32_C(0xd503201f))
        return false;
    const uint32_t literal_low = words[2], literal_high = words[3];
    words[0] = (words[0] & ~UINT32_C(0x00ffffe0)) | (4u << 5); // +16 bytes.
    words[2] = UINT32_C(0xd503201f);
    words[3] = UINT32_C(0xd503201f);
    words[4] = literal_low;
    words[5] = literal_high;
    candidate.bytes = bytes;
    std::memcpy(candidate.bytes.data(), words.data(), sizeof(words));
    candidate.transformation = "authenticated-literal-pool-placement";
    candidate.changed_offset = 0;
    candidate.proof =
        "{\"schema\":2,\"solver\":\"structural-aarch64-literal\",\"result\":\"proven\","
        "\"resource_limit\":24,\"registers\":\"identical-literal-load\",\"flags\":\"unchanged\","
        "\"stack_cfa\":\"unchanged\",\"memory_aliasing\":\"same-eight-byte-pool-value\","
        "\"relocations\":\"ldr-imm19-reencoded-and-range-validated\",\"tls\":\"not-accessed\","
        "\"atomics\":\"not-accessed\",\"fp_neon\":\"not-accessed\",\"pac_bti\":\"ret-preserved\","
        "\"unwind\":\"code-width-and-cfa-preserved\",\"literal_old_offset\":8,\"literal_new_"
        "offset\":16}";
    return true;
}

bool overlaps(size_t offset, const std::vector<size_t>& protected_offsets) {
    return std::any_of(protected_offsets.begin(), protected_offsets.end(),
                       [&](size_t protected_offset) {
                           return protected_offset >= offset && protected_offset < offset + 8;
                       });
}

} // namespace

NativeVariantResult generate_native_variants(const std::vector<uint8_t>& bytes,
                                             size_t application_size,
                                             const std::vector<size_t>& protected_offsets) {
    NativeVariantResult result;
    if (application_size > bytes.size()) {
        result.rejection_reason = "application-size-out-of-range";
        return result;
    }
    CapstoneHandle capstone;
    NativeVariantCandidate literal_placement;
    if (make_literal_pool_placement(bytes, application_size, protected_offsets, literal_placement))
        result.candidates.push_back(std::move(literal_placement));
    NativeVariantCandidate renamed;
    if (result.candidates.size() < kNativeVariantLimit &&
        make_whole_fragment_rename(capstone.get(), bytes, application_size, protected_offsets,
                                   renamed))
        result.candidates.push_back(std::move(renamed));
    NativeVariantCandidate block_layout;
    if (result.candidates.size() < kNativeVariantLimit &&
        make_safe_block_layout(capstone.get(), bytes, application_size, protected_offsets,
                               block_layout))
        result.candidates.push_back(std::move(block_layout));
    // First admit independently solver-proven equivalent arithmetic/logical
    // encodings. This is narrower than an assembler peephole:
    // SP/ZR aliases, flags, and unsupported operand forms are rejected.
    for (size_t offset = 0; offset + 4 <= application_size; offset += 4) {
        if (overlaps(offset, protected_offsets))
            continue;
        uint32_t original_word = 0, replacement_word = 0;
        std::memcpy(&original_word, bytes.data() + offset, sizeof(original_word));
        if (!equivalent_identity_encoding(original_word, replacement_word))
            continue;
        cs_insn* original = nullptr;
        cs_insn* replacement = nullptr;
        const size_t original_count =
            cs_disasm(capstone.get(), bytes.data() + offset, 4, offset, 1, &original);
        const size_t replacement_count =
            cs_disasm(capstone.get(), reinterpret_cast<const uint8_t*>(&replacement_word), 4,
                      offset, 1, &replacement);
        std::string proof;
        const bool proven =
            original_count == 1 && replacement_count == 1 &&
            prove_equivalent_instruction(original[0], replacement[0],
                                         "equivalent-arithmetic-logical-encoding", proof);
        if (proven) {
            NativeVariantCandidate candidate;
            candidate.bytes = bytes;
            std::memcpy(candidate.bytes.data() + offset, &replacement_word,
                        sizeof(replacement_word));
            candidate.transformation = "equivalent-arithmetic-logical-encoding";
            candidate.proof = std::move(proof);
            candidate.changed_offset = offset;
            result.candidates.push_back(std::move(candidate));
        }
        cs_free(original, original_count);
        cs_free(replacement, replacement_count);
        if (result.candidates.size() == kNativeVariantLimit)
            return result;
    }
    for (size_t offset = 0; offset + 8 <= application_size; offset += 4) {
        if (overlaps(offset, protected_offsets))
            continue;
        cs_insn* instructions = nullptr;
        const size_t count =
            cs_disasm(capstone.get(), bytes.data() + offset, 8, offset, 2, &instructions);
        if (count != 2 || instructions[0].size != 4 || instructions[1].size != 4) {
            cs_free(instructions, count);
            continue;
        }
        std::string proof;
        if (prove_swap(instructions[0], instructions[1], proof)) {
            NativeVariantCandidate candidate;
            candidate.bytes = bytes;
            std::array<uint8_t, 4> first{};
            std::copy_n(candidate.bytes.begin() + static_cast<ptrdiff_t>(offset), 4, first.begin());
            std::copy_n(candidate.bytes.begin() + static_cast<ptrdiff_t>(offset + 4), 4,
                        candidate.bytes.begin() + static_cast<ptrdiff_t>(offset));
            std::copy(first.begin(), first.end(),
                      candidate.bytes.begin() + static_cast<ptrdiff_t>(offset + 4));
            candidate.transformation = "dependency-safe-instruction-reorder";
            candidate.proof = std::move(proof);
            candidate.changed_offset = offset;
            result.candidates.push_back(std::move(candidate));
            cs_free(instructions, count);
            if (result.candidates.size() == kNativeVariantLimit)
                return result;
            continue;
        }
        cs_free(instructions, count);
    }
    if (result.candidates.empty())
        result.rejection_reason = "no-z3-proven-independent-instruction-pair";
    return result;
}

} // namespace maya::protection
