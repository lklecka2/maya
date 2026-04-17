#include "core/Patcher.hpp"
#include "core/Logger.hpp"
#include <iostream>
#include <set>
#include <sstream>

static auto to_hex(uint64_t val) -> std::string {
    std::stringstream hex_ss;
    hex_ss << "0x" << std::hex << val;
    return hex_ss.str();
}

auto Patcher::resolve_target(const ProtectorContext& ctx, uint64_t original_target) -> uint64_t {
    auto* plt_sec = ctx.binary->get_section(".plt");
    if (plt_sec != nullptr) {
        uint64_t plt_start = plt_sec->virtual_address();
        uint64_t plt_end = plt_start + plt_sec->size();

        if (original_target >= plt_start && original_target < plt_end) {
            return original_target;
        }
    }

    for (const auto& func : ctx.functions) {
        constexpr uint64_t page_mask = 0xFFFULL;
        uint64_t func_start_page = func.start_addr & ~page_mask;
        uint64_t func_end_page = (func.start_addr + func.size + page_mask) & ~page_mask;

        if (original_target >= func_start_page && original_target < func_end_page) {
            uint64_t shift = func.new_start_addr - func.start_addr;
            return original_target + shift;
        }
    }
    return original_target;
}

auto Patcher::resolve_target(const ProtectorContext& ctx, const RelocationEntry& reloc) -> uint64_t {
    if (reloc.type == RELOC_ADRP) {
        auto* plt_sec = ctx.binary->get_section(".plt");
        if (plt_sec != nullptr) {
            uint64_t plt_start = plt_sec->virtual_address();
            uint64_t plt_end = plt_start + plt_sec->size();
            if (reloc.original_target >= plt_start && reloc.original_target < plt_end) {
                return reloc.original_target;
            }
        }
        return reloc.original_target;
    }

    return resolve_target(ctx, reloc.original_target);
}

auto Patcher::patch_instruction(const RelocationEntry& reloc, uint64_t new_pc, const ProtectorContext& ctx) -> uint32_t {
    uint32_t insn = reloc.original_insn_bytes;
    uint64_t target = resolve_target(ctx, reloc);

    if (reloc.type == RELOC_BRANCH && target == reloc.original_target) {
        bool in_exec_section = false;
        std::string section_name = "unknown";
        bool is_plt = false;

        for (const auto& sec : ctx.binary->sections()) {
            if (reloc.original_target >= sec.virtual_address() &&
                reloc.original_target < (sec.virtual_address() + sec.size())) {
                section_name = sec.name();
                is_plt = (section_name == ".plt");
                if (sec.has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
                    in_exec_section = true;
                }
                break;
            }
        }

        static std::set<uint64_t> warned_targets;
        if (in_exec_section && !is_plt && warned_targets.find(reloc.original_target) == warned_targets.end()) {
            Log::warn("Target " + to_hex(reloc.original_target) +
                      " is in executable section " + section_name + " but was NOT relocated.");
            warned_targets.insert(reloc.original_target);
        }
    }

    int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(new_pc);

    if (reloc.type == RELOC_BRANCH) {
        constexpr uint32_t branch_mask = 0x7C000000;
        constexpr uint32_t b_opcode = 0x14000000;
        constexpr uint32_t bl_opcode = 0x94000000;

        // Unconditional Branch (B) and Branch with Link (BL)
        if ((insn & branch_mask) == b_opcode || (insn & branch_mask) == bl_opcode) {
            auto imm26 = static_cast<uint32_t>((delta >> 2) & 0x03FFFFFF);
            return (insn & 0xFC000000) | imm26;
        }
        // Conditional Branch (B.cond)
        if ((insn & 0xFF000000) == 0x54000000) {
            auto imm19 = static_cast<uint32_t>((delta >> 2) & 0x7FFFF);
            return (insn & 0xFF00001F) | (imm19 << 5);
        }
        // Compare and Branch (CBZ, CBNZ)
        if ((insn & 0x7F000000) == 0x34000000 || (insn & 0x7F000000) == 0x35000000) {
            auto imm19 = static_cast<uint32_t>((delta >> 2) & 0x7FFFF);
            return (insn & 0xFF00001F) | (imm19 << 5);
        }
        // Test and Branch (TBZ, TBNZ)
        if ((insn & 0x7F000000) == 0x36000000 || (insn & 0x7F000000) == 0x37000000) {
            auto imm14 = static_cast<uint32_t>((delta >> 2) & 0x3FFF);
            return (insn & 0xFFF8001F) | (imm14 << 5);
        }
    }
    else if (reloc.type == RELOC_ADRP_ADD) {
        int64_t page_delta = static_cast<int64_t>(target >> 12) - static_cast<int64_t>(new_pc >> 12);
        auto immlo = static_cast<uint32_t>(page_delta & 3);
        auto immhi = static_cast<uint32_t>((page_delta >> 2) & 0x7FFFF);
        return (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
    }
    else if (reloc.type == RELOC_ADRP) {
        int64_t page_delta = static_cast<int64_t>(target >> 12) - static_cast<int64_t>(new_pc >> 12);
        auto immlo = static_cast<uint32_t>(page_delta & 3);
        auto immhi = static_cast<uint32_t>((page_delta >> 2) & 0x7FFFF);
        return (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
    }
    else if (reloc.type == RELOC_ADR) {
        auto immlo = static_cast<uint32_t>(delta & 3);
        auto immhi = static_cast<uint32_t>((delta >> 2) & 0x7FFFF);
        return (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
    }

    return insn;
}
