#pragma once
#include <LIEF/ELF.hpp>
#include <vector>
#include <map>
#include "Context.hpp"
#include "Patcher.hpp"

class Packager {
public:
    static void build_and_add_section(ProtectorContext& ctx, const std::vector<uint8_t>& final_payload, uint64_t shadow_base, const std::map<uint64_t, uint64_t>& mini_stub_map) {
        constexpr uint64_t invalid_vaddr = 0xFFFFFFFFFFFFFFFF;
        constexpr int64_t max_branch_range = 128LL * 1024 * 1024;
        constexpr uint64_t section_alignment = 0x10000;

        uint64_t min_new_vaddr = invalid_vaddr;
        for (const auto& func_bounds : ctx.functions) {
            min_new_vaddr = std::min(min_new_vaddr, func_bounds.new_start_addr);
        }

        uint64_t total_mirrored_size = shadow_base - min_new_vaddr;
        std::vector<uint8_t> huge_payload(total_mirrored_size, 0);

        // Copy mirrored code
        for (const auto& func_bounds : ctx.functions) {
            std::memcpy(huge_payload.data() + (func_bounds.new_start_addr - min_new_vaddr), func_bounds.patched_code.data(), func_bounds.patched_code.size());
        }

        // Overwrite entries in mirrored code with branches to mini-stubs
        for (const auto& entry : mini_stub_map) {
            uint64_t original_addr = entry.first;
            uint64_t mini_stub_vaddr = entry.second;

            for (const auto& func_bounds : ctx.functions) {
                if (original_addr >= func_bounds.start_addr && original_addr < (func_bounds.start_addr + func_bounds.size)) {
                    uint64_t shadow_entry_addr = func_bounds.new_start_addr + (original_addr - func_bounds.start_addr);
                    int64_t delta = static_cast<int64_t>(mini_stub_vaddr) - static_cast<int64_t>(shadow_entry_addr);
                    if (std::abs(delta) < max_branch_range) {
                        uint32_t branch_insn = 0x14000000 | (static_cast<uint32_t>(delta >> 2) & 0x03FFFFFF);
                        std::memcpy(huge_payload.data() + (shadow_entry_addr - min_new_vaddr), &branch_insn, 4);
                    }
                    break;
                }
            }
        }

        // Append stubs and data
        huge_payload.insert(huge_payload.end(), final_payload.begin(), final_payload.end());

        // Add section to binary
        LIEF::ELF::Section prot_section(".text.prot");
        prot_section.content(huge_payload);
        prot_section.type(LIEF::ELF::Section::TYPE::PROGBITS);
        prot_section.add(LIEF::ELF::Section::FLAGS::ALLOC);
        prot_section.add(LIEF::ELF::Section::FLAGS::EXECINSTR);
        prot_section.virtual_address(min_new_vaddr);
        prot_section.alignment(section_alignment);
        ctx.binary->add(prot_section, true);

        // Fix symbols and entry point
        for (auto& sym : ctx.binary->symbols()) {
            uint64_t val = sym.value();
            if (mini_stub_map.count(val) != 0u) {
                sym.value(mini_stub_map.at(val));
            } else {
                for (const auto& func_bounds : ctx.functions) {
                    if (val >= func_bounds.start_addr && val < (func_bounds.start_addr + func_bounds.size)) {
                        sym.value(func_bounds.new_start_addr + (val - func_bounds.start_addr));
                        break;
                    }
                }
            }
        }

        if (mini_stub_map.count(ctx.original_entry_point) != 0u) {
            ctx.binary->header().entrypoint(mini_stub_map.at(ctx.original_entry_point));
        } else {
            ctx.binary->header().entrypoint(Patcher::resolve_target(ctx, ctx.original_entry_point));
        }
    }
};
