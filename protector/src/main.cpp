#include "core/Context.hpp"
#include "core/Analyzer.hpp"
#include "core/Planner.hpp"
#include "core/Patcher.hpp"
#include "core/PointerFixer.hpp"
#include "core/Instrumenter.hpp"
#include "core/Packager.hpp"
#include "core/Logger.hpp"
#include <LIEF/ELF.hpp>
#include <stdexcept>
#include <cstring>

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        Log::error(std::string("Usage: ") + argv[0] + " <aarch64_elf_binary>");
        return 1;
    }

    ProtectorContext ctx;
    ctx.filename = argv[1];

    try {
        ctx.binary = LIEF::ELF::Parser::parse(ctx.filename);
        if (!ctx.binary) {
            throw std::runtime_error("LIEF failed to parse the binary.");
        }

        ctx.is_aarch64 = (ctx.binary->header().machine_type() == LIEF::ELF::ARCH::AARCH64);
        ctx.original_entry_point = ctx.binary->entrypoint();

        Log::info("Successfully loaded: " + ctx.filename);

        Analyzer::analyze(ctx);
        Planner::plan(ctx);
        PointerFixer::fix(ctx);

        // Apply basic relocations to the mirrored code
        for (auto& func_bounds : ctx.functions) {
            auto content = ctx.binary->get_content_from_virtual_address(func_bounds.start_addr, func_bounds.size);
            func_bounds.patched_code.assign(content.begin(), content.end());
            for (const auto& reloc : func_bounds.relocations) {
                uint64_t new_insn_pc = func_bounds.new_start_addr + (reloc.instruction_addr - func_bounds.start_addr);
                uint32_t patched_insn = Patcher::patch_instruction(reloc, new_insn_pc, ctx);
                uint64_t offset = reloc.instruction_addr - func_bounds.start_addr;
                if (offset + 4 <= func_bounds.patched_code.size()) {
                    std::memcpy(func_bounds.patched_code.data() + offset, &patched_insn, 4);
                }
                if (reloc.type == RELOC_ADRP_ADD && reloc.paired_instruction_addr != 0) {
                    uint64_t target = Patcher::resolve_target(ctx, reloc);
                    uint32_t add_insn = reloc.paired_insn_bytes;
                    uint32_t new_lo12 = static_cast<uint32_t>(target & 0xFFFu);
                    add_insn = (add_insn & 0xFFC003FFu) | (new_lo12 << 10);
                    uint64_t add_offset = reloc.paired_instruction_addr - func_bounds.start_addr;
                    if (add_offset + 4 <= func_bounds.patched_code.size()) {
                        std::memcpy(func_bounds.patched_code.data() + add_offset, &add_insn, 4);
                    }
                }
            }
        }

        auto instrument_res = Instrumenter::instrument(ctx);
        Packager::build_and_add_section(ctx, instrument_res.final_payload, instrument_res.shadow_base, instrument_res.mini_stub_map);

        ctx.binary->write(ctx.filename + ".protected");
        Log::info("Successfully wrote protected binary.");

    } catch (const std::exception& e) {
        Log::error(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}
