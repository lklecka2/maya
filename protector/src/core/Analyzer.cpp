#include "core/Analyzer.hpp"
#include "core/Logger.hpp"
#include <capstone/capstone.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <algorithm>
#include <limits>

static auto to_hex(uint64_t val) -> std::string {
    std::stringstream hex_ss;
    hex_ss << std::hex << val;
    return hex_ss.str();
}

void Analyzer::analyze(ProtectorContext& ctx) {
    uint64_t min_vaddr, max_vaddr, original_min_vaddr;
    find_executable_range(ctx, min_vaddr, max_vaddr, original_min_vaddr);
    mirror_block(ctx, min_vaddr, max_vaddr);
    disassemble_and_scan(ctx, min_vaddr, max_vaddr, original_min_vaddr);
}

void Analyzer::find_executable_range(ProtectorContext& ctx, uint64_t& min_vaddr, uint64_t& max_vaddr, uint64_t& original_min_vaddr) {
    constexpr uint64_t invalid_vaddr = 0xFFFFFFFFFFFFFFFF;
    min_vaddr = invalid_vaddr;
    max_vaddr = 0;

    for (auto& section : ctx.binary->sections()) {
        if (section.has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
            min_vaddr = std::min(min_vaddr, section.virtual_address());
            max_vaddr = std::max(max_vaddr, section.virtual_address() + section.size());
        }
    }

    if (min_vaddr == invalid_vaddr) {
        throw std::runtime_error("No executable sections found.");
    }

    uint64_t total_range_size = max_vaddr - min_vaddr;
    Log::info("Mirroring executable range: 0x" + to_hex(min_vaddr) + " - 0x" + to_hex(max_vaddr) + " (" + std::to_string(total_range_size) + " bytes)");

    original_min_vaddr = min_vaddr;
    constexpr uint64_t page_mask = 0xFFFFULL;
    min_vaddr &= ~page_mask;
    max_vaddr = (max_vaddr + page_mask) & ~page_mask;
}

void Analyzer::mirror_block(ProtectorContext& ctx, uint64_t min_vaddr, uint64_t max_vaddr) {
    uint64_t total_range_size = max_vaddr - min_vaddr;
    FunctionBounds mirrored_block;
    mirrored_block.name = "mirrored_exec_range";
    mirrored_block.start_addr = min_vaddr;
    mirrored_block.size = total_range_size;
    mirrored_block.patched_code.resize(total_range_size, 0x00);

    auto content = ctx.binary->get_content_from_virtual_address(min_vaddr, total_range_size);
    std::copy(content.begin(), content.end(), mirrored_block.patched_code.begin());

    ctx.functions.clear();
    ctx.functions.push_back(std::move(mirrored_block));
}

void Analyzer::disassemble_and_scan(ProtectorContext& ctx, uint64_t min_vaddr, uint64_t max_vaddr, uint64_t original_min_vaddr) {
    csh handle;
    const cs_err cs_err_code = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
    if (cs_err_code != CS_ERR_OK) {
        throw std::runtime_error(
            "Failed to initialize Capstone for InstructionLifter with CS_ARCH_ARM64: " +
            std::string(cs_strerror(cs_err_code))
        );
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    auto& mirrored_block = ctx.functions.front();
    uint64_t total_range_size = max_vaddr - min_vaddr;
    uint64_t binary_min_vaddr = std::numeric_limits<uint64_t>::max();
    uint64_t binary_max_vaddr = 0;

    for (const auto& seg : ctx.binary->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            binary_min_vaddr = std::min(binary_min_vaddr, seg.virtual_address());
            binary_max_vaddr = std::max(binary_max_vaddr, seg.virtual_address() + seg.virtual_size());
        }
    }

    cs_insn* insn = cs_malloc(handle);
    size_t offset = 0;
    const uint8_t* code_ptr = mirrored_block.patched_code.data();

    while (offset + 4 <= total_range_size) {
        uint64_t current_address = min_vaddr + offset;
        const uint8_t* temp_code = code_ptr + offset;
        size_t temp_size = 4;
        uint64_t temp_address = current_address;

        if (current_address >= original_min_vaddr && cs_disasm_iter(handle, &temp_code, &temp_size, &temp_address, insn)) {
            Instruction instr;
            instr.address = insn->address;
            instr.mnemonic = insn->mnemonic;
            instr.op_str = insn->op_str;
            instr.bytes.assign(insn->bytes, insn->bytes + insn->size);
            mirrored_block.instructions.push_back(instr);

            bool is_jump_or_call = false;
            const cs_detail* detail = insn->detail;
            if (detail != nullptr) {
                for (int i = 0; i < detail->groups_count; i++) {
                    if (detail->groups[i] == ARM64_GRP_JUMP || detail->groups[i] == ARM64_GRP_CALL) {
                        is_jump_or_call = true;
                        break;
                    }
                }
            }

            bool is_adrp = (insn->id == ARM64_INS_ADRP);
            bool is_adr = (insn->id == ARM64_INS_ADR);

            if (is_jump_or_call || is_adrp || is_adr) {
                if (detail && detail->arm64.op_count > 0) {
                    for (int i = detail->arm64.op_count - 1; i >= 0; i--) {
                        if (detail->arm64.operands[i].type == ARM64_OP_IMM) {
                            RelocationEntry rel;
                            rel.instruction_addr = insn->address;
                            if (is_adrp) rel.type = RELOC_ADRP;
                            else if (is_adr) rel.type = RELOC_ADR;
                            else rel.type = RELOC_BRANCH;

                            rel.original_target = detail->arm64.operands[i].imm;
                            rel.original_insn_bytes = *reinterpret_cast<const uint32_t*>(insn->bytes);

                            if (is_adrp && offset + 8 <= total_range_size) {
                                cs_insn* next_insn = nullptr;
                                const uint8_t* next_ptr = code_ptr + offset + 4;
                                size_t next_size = 4;
                                uint64_t next_addr = current_address + 4;
                                size_t next_count = cs_disasm(handle, next_ptr, next_size, next_addr, 1, &next_insn);
                                if (next_count > 0 && next_insn->id == ARM64_INS_ADD) {
                                    const cs_detail* nd = next_insn->detail;
                                    if (nd != nullptr && nd->arm64.op_count == 3 &&
                                        nd->arm64.operands[2].type == ARM64_OP_IMM) {
                                        cs_arm64_op adrp_dst = detail->arm64.operands[0];
                                        cs_arm64_op add_src = nd->arm64.operands[1];
                                        if (adrp_dst.type == ARM64_OP_REG && add_src.type == ARM64_OP_REG &&
                                            adrp_dst.reg == add_src.reg) {
                                            uint64_t lo12 = nd->arm64.operands[2].imm;
                                            rel.type = RELOC_ADRP_ADD;
                                            rel.original_target = (rel.original_target & ~0xFFFULL) | (lo12 & 0xFFFULL);
                                            rel.paired_instruction_addr = next_addr;
                                            std::memcpy(&rel.paired_insn_bytes, next_insn->bytes, sizeof(uint32_t));
                                        }
                                    }
                                }
                                if (next_count > 0) {
                                    cs_free(next_insn, next_count);
                                }
                            }

                            if (rel.original_target >= binary_min_vaddr && rel.original_target < binary_max_vaddr) {
                                mirrored_block.relocations.push_back(rel);
                            }
                            break;
                        }
                    }
                }
            }
        } else {
            Instruction data_instr;
            data_instr.address = current_address;
            data_instr.mnemonic = ".word";
            data_instr.bytes.assign(code_ptr + offset, code_ptr + offset + 4);
            mirrored_block.instructions.push_back(data_instr);
        }
        offset += 4;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    Log::info("Full Section Mirroring complete.");
}
