#include "core/PointerFixer.hpp"
#include "core/Patcher.hpp"
#include "core/Logger.hpp"
#include <capstone/capstone.h>
#include <vector>
#include <cstring>
#include <set>
#include <stdexcept>

void PointerFixer::fix(ProtectorContext& ctx) {
    if (ctx.functions.empty()) {
        return;
    }

    const auto& mirrored = ctx.functions[0];
    uint64_t old_start = mirrored.start_addr;
    uint64_t old_end = old_start + mirrored.size;
    int64_t shift = static_cast<int64_t>(mirrored.new_start_addr) - static_cast<int64_t>(old_start);

    csh handle;
    const cs_err cs_err_code = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
    if (cs_err_code != CS_ERR_OK) {
        throw std::runtime_error(
            "Failed to initialize Capstone for InstructionLifter with CS_ARCH_ARM64: " +
            std::string(cs_strerror(cs_err_code))
        );
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    std::vector<std::string> safe_sections = {
        ".text", ".init", ".fini", ".plt",
        ".rodata", ".data", ".bss", ".got", ".got.plt",
        ".data.rel.ro", ".init_array", ".fini_array", ".rela.plt"
    };

    // Pre-calculate a set of exact symbol addresses for strict matching
    std::set<uint64_t> symbol_addresses;
    for (const auto& sym : ctx.binary->symtab_symbols()) {
        if (sym.value() >= old_start && sym.value() < old_end) {
            symbol_addresses.insert(sym.value());
        }
    }

    for (const auto& sec_name : safe_sections) {
        auto* sec = ctx.binary->get_section(sec_name);
        if (sec == nullptr) {
            continue;
        }

        auto content = sec->content();
        if (content.size() < 4) {
            continue;
        }

        std::vector<uint8_t> buffer(content.begin(), content.end());
        bool modified = false;
        size_t ptr_fixed = 0;
        size_t insn_patched = 0;

        bool is_code_sec = (sec_name == ".text" || sec_name == ".init" || sec_name == ".fini" || sec_name == ".plt");

        if (!is_code_sec) {
            // Pointer editing in data sections.
            // Only consider naturally aligned 8-byte slots; byte-by-byte
            // scanning corrupts adjacent non-pointer data such as doubles.
            for (size_t i = 0; i + 8 <= buffer.size(); i += 8) {
                uint64_t val;
                std::memcpy(&val, &buffer[i], 8);

                if (val >= old_start && val < old_end) {
                    uint64_t shadow_val = val + shift;
                    std::memcpy(&buffer[i], &shadow_val, 8);
                    modified = true;
                    ptr_fixed++;
                }
            }
        } else {
            // Opcode re-encoding, only for executable sections
            cs_insn* insn = cs_malloc(handle);
            for (size_t i = 0; i + 4 <= buffer.size(); i += 4) {
                uint64_t current_pc = sec->virtual_address() + i;
                const uint8_t* code_ptr = buffer.data() + i;
                size_t code_size = 4;
                uint64_t addr = current_pc;

                if (cs_disasm_iter(handle, &code_ptr, &code_size, &addr, insn)) {
                    // Skip LDR (literal) instructions.
                    if (insn->id == ARM64_INS_LDR || insn->id == ARM64_INS_LDRSW) {
                        continue;
                    }

                    const cs_detail* detail = insn->detail;
                    if (detail != nullptr && detail->arm64.op_count > 0) {
                        for (int j = detail->arm64.op_count - 1; j >= 0; j--) {
                            const auto& op = detail->arm64.operands[j];
                            if (op.type == ARM64_OP_IMM) {
                                uint64_t target = op.imm;

                                // Use page-aware check to match Patcher::resolve_target
                                uint64_t old_start_page = old_start & ~0xFFFULL;
                                uint64_t old_end_page = (old_end + 0xFFFULL) & ~0xFFFULL;

                                if (target >= old_start_page && target < old_end_page) {
                                    RelocationEntry rel;
                                    rel.instruction_addr = current_pc;
                                    rel.original_target = target;
                                    rel.original_insn_bytes = *reinterpret_cast<uint32_t*>(buffer.data() + i);

                                    if (insn->id == ARM64_INS_ADRP) {
                                        rel.type = RELOC_ADRP;
                                    } else if (insn->id == ARM64_INS_ADR) {
                                        rel.type = RELOC_ADR;
                                    } else {
                                        rel.type = RELOC_BRANCH;
                                    }

                                    uint32_t patched = Patcher::patch_instruction(rel, current_pc, ctx);
                                    if (patched != rel.original_insn_bytes) {
                                        std::memcpy(buffer.data() + i, &patched, 4);
                                        modified = true;
                                        insn_patched++;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            cs_free(insn, 1);
        }

        if (modified) {
            sec->content(buffer);
            Log::info("Section " + sec_name + ": Fixed " + std::to_string(ptr_fixed) +
                      " pointers, Re-encoded " + std::to_string(insn_patched) + " instructions.");
        }
    }

    // Relocation editing: Update Addends using LIEF API
    size_t relocs_fixed = 0;
    for (auto& reloc : ctx.binary->relocations()) {
        int64_t addend = reloc.addend();
        if (addend == 0) {
            continue;
        }

        for (const auto& func : ctx.functions) {
            if (static_cast<uint64_t>(addend) >= func.start_addr && static_cast<uint64_t>(addend) < (func.start_addr + func.size)) {
                reloc.addend(addend + static_cast<int64_t>(func.new_start_addr - func.start_addr));
                relocs_fixed++;
                break;
            }
        }
    }
    if (relocs_fixed > 0) {
        Log::info("Relocations: Fixed " + std::to_string(relocs_fixed) + " addends.");
    }

    cs_close(&handle);
}
