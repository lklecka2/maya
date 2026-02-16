#include "core/Analyzer.hpp"
#include "core/Logger.hpp"
#include <capstone/capstone.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <algorithm>

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
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone engine.");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    auto& mirrored_block = ctx.functions.front();
    uint64_t total_range_size = max_vaddr - min_vaddr;

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
                            mirrored_block.relocations.push_back(rel);
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
