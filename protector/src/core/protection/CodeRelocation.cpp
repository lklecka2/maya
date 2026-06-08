#include "CodeRelocation.hpp"

#include <LIEF/ELF.hpp>
#include <capstone/capstone.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

#include "FunctionLayout.hpp"
#include "core/Logger.hpp"

namespace maya::protection {

bool is_bl(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x94000000u;
}

bool is_unconditional_b(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x14000000u;
}

uint64_t map_target_for_body(const ProtectionContext& ctx, const ProtectedFunction& owner, const std::vector<ProtectedFunction>& funcs, uint64_t target) {
    if (target >= owner.original_start && target < owner.original_start + owner.size) {
        return owner.slot_vaddr + (target - owner.original_start);
    }
    if (is_protected_start(funcs, target)) {
        return target + ctx.final_image_shift;
    }
    if (find_func_containing(funcs, target) != nullptr) {
        throw std::runtime_error("Unsupported branch/address target into protected function interior: " + hex(target));
    }
    return target + ctx.final_image_shift;
}

uint32_t patch_branch(uint32_t insn, uint64_t pc, uint64_t target) {
    const int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(pc);
    if ((insn & 0x7C000000u) == 0x14000000u || (insn & 0x7C000000u) == 0x94000000u) {
        if (delta < -(128LL * 1024 * 1024) || delta >= (128LL * 1024 * 1024)) {
            throw std::runtime_error("AArch64 branch target out of range.");
        }
        return (insn & 0xFC000000u) | (static_cast<uint32_t>(delta >> 2) & 0x03FFFFFFu);
    }
    if ((insn & 0xFF000000u) == 0x54000000u) {
        return (insn & 0xFF00001Fu) | ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
    }
    if ((insn & 0x7F000000u) == 0x34000000u || (insn & 0x7F000000u) == 0x35000000u) {
        return (insn & 0xFF00001Fu) | ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
    }
    if ((insn & 0x7F000000u) == 0x36000000u || (insn & 0x7F000000u) == 0x37000000u) {
        return (insn & 0xFFF8001Fu) | ((static_cast<uint32_t>(delta >> 2) & 0x3FFFu) << 5);
    }
    return insn;
}

uint32_t patch_adr(uint32_t insn, uint64_t pc, uint64_t target) {
    const int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(pc);
    return (insn & 0x9F00001Fu) |
           ((static_cast<uint32_t>(delta) & 3u) << 29) |
           ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
}

uint32_t patch_adrp(uint32_t insn, uint64_t pc, uint64_t target) {
    const int64_t page_delta = static_cast<int64_t>(target >> 12) - static_cast<int64_t>(pc >> 12);
    return (insn & 0x9F00001Fu) |
           ((static_cast<uint32_t>(page_delta) & 3u) << 29) |
           ((static_cast<uint32_t>(page_delta >> 2) & 0x7FFFFu) << 5);
}

void append_u32(std::vector<uint8_t>& bytes, uint32_t value) {
    const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
    bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
}

void append_u64(std::vector<uint8_t>& bytes, uint64_t value) {
    const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
    bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
}

size_t append_align(std::vector<uint8_t>& bytes, size_t alignment) {
    while ((bytes.size() % alignment) != 0) {
        append_u32(bytes, 0xD503201Fu);
    }
    return bytes.size();
}

uint32_t encode_ldr_literal_x(uint32_t rt, uint64_t pc, uint64_t literal_addr) {
    const int64_t delta = static_cast<int64_t>(literal_addr) - static_cast<int64_t>(pc);
    if ((delta & 0x3) != 0 || delta < -(1LL << 20) || delta >= (1LL << 20)) {
        throw std::runtime_error("AArch64 LDR literal target out of range.");
    }
    return 0x58000000u | ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5) | (rt & 0x1Fu);
}

size_t append_literal_pool_entry(ProtectedFunction& func, uint64_t target) {
    const size_t literal_off = append_align(func.patched_bytes, 8);
    append_u64(func.patched_bytes, target);
    func.runtime_literal_offsets.push_back(literal_off);
    return literal_off;
}

size_t append_branch_veneer(ProtectedFunction& func, uint64_t target, uint64_t return_off, bool call) {
    const size_t veneer_off = append_align(func.patched_bytes, 8);
    if (call) {
        append_u32(func.patched_bytes, 0xA9BF7BF0u); // stp x16, x30, [sp, #-16]!
        append_u32(func.patched_bytes, encode_ldr_literal_x(16, func.original_start + veneer_off + 4, func.original_start + veneer_off + 24));
        append_u32(func.patched_bytes, 0xD63F0200u); // blr x16
        append_u32(func.patched_bytes, 0xA8C17BF0u); // ldp x16, x30, [sp], #16
        append_u32(func.patched_bytes, make_b(func.original_start + veneer_off + 16, func.original_start + return_off));
        append_u32(func.patched_bytes, 0xD503201Fu);
        func.runtime_literal_offsets.push_back(veneer_off + 24);
        append_u64(func.patched_bytes, target);
    } else {
        append_u32(func.patched_bytes, encode_ldr_literal_x(16, func.original_start + veneer_off, func.original_start + veneer_off + 8));
        append_u32(func.patched_bytes, 0xD61F0200u); // br x16
        func.runtime_literal_offsets.push_back(veneer_off + 8);
        append_u64(func.patched_bytes, target);
    }
    return veneer_off;
}

void apply_slot_local_patches(ProtectedFunction& func, const std::vector<SlotLocalPatch>& patches) {
    for (const auto& patch : patches) {
        if (patch.kind == SlotLocalPatch::BranchToVeneer) {
            const size_t veneer_off = append_branch_veneer(func, patch.target, patch.insn_off + 4, is_bl(patch.original_insn));
            func.veneer_count++;
            const uint32_t patched = patch_branch(
                patch.original_insn,
                func.original_start + patch.insn_off,
                func.original_start + veneer_off
            );
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            continue;
        }
        if (patch.kind == SlotLocalPatch::AdrLiteral) {
            const size_t literal_off = append_literal_pool_entry(func, patch.target);
            func.literal_pool_bytes += 8;
            const uint32_t rt = patch.original_insn & 0x1Fu;
            const uint32_t patched = encode_ldr_literal_x(rt, func.original_start + patch.insn_off, func.original_start + literal_off);
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            continue;
        }
        if (patch.kind == SlotLocalPatch::AdrpAddLiteral) {
            const size_t literal_off = append_literal_pool_entry(func, patch.target);
            func.literal_pool_bytes += 8;
            const uint32_t rt = patch.paired_insn & 0x1Fu;
            const uint32_t patched = encode_ldr_literal_x(rt, func.original_start + patch.insn_off, func.original_start + literal_off);
            const uint32_t nop = 0xD503201Fu;
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            std::memcpy(func.patched_bytes.data() + patch.paired_off, &nop, sizeof(nop));
            continue;
        }
    }
    func.runtime_relocations = patches.size();
    func.body_size = func.patched_bytes.size();
    if (func.body_size > encrypted_body_capacity(func, SlotStrategy::RuntimeAllocator)) {
        throw std::runtime_error("Runtime slot-local metadata exceeded reserved body capacity for " + func.name);
    }
}

void patch_function_bodies(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs, std::vector<CallsiteMeta>& callsites) {
    callsites.clear();
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone.");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    uint64_t binary_min = UINT64_MAX;
    uint64_t binary_max = 0;
    for (const auto& seg : ctx.binary->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            binary_min = std::min(binary_min, seg.virtual_address());
            binary_max = std::max(binary_max, seg.virtual_address() + seg.virtual_size());
        }
    }

    for (auto& func : funcs) {
        std::vector<SlotLocalPatch> slot_local_patches;
        cs_insn* insn = cs_malloc(handle);
        size_t offset = 0;
        while (offset + 4 <= func.size) {
            const uint8_t* ptr = func.patched_bytes.data() + offset;
            size_t size = 4;
            uint64_t addr = func.original_start + offset;
            if (!cs_disasm_iter(handle, &ptr, &size, &addr, insn)) {
                offset += 4;
                continue;
            }
            const cs_detail* detail = insn->detail;
            bool is_branch = false;
            if (detail != nullptr) {
                for (uint8_t i = 0; i < detail->groups_count; ++i) {
                    if (detail->groups[i] == ARM64_GRP_JUMP || detail->groups[i] == ARM64_GRP_CALL) {
                        is_branch = true;
                    }
                }
            }
            const bool is_adr = insn->id == ARM64_INS_ADR;
            const bool is_adrp = insn->id == ARM64_INS_ADRP;
            if ((is_branch || is_adr || is_adrp) && detail != nullptr) {
                if (insn->id == ARM64_INS_BLR || insn->id == ARM64_INS_BR) {
                    func.indirect_calls++;
                }
                for (int i = detail->arm64.op_count - 1; i >= 0; --i) {
                    if (detail->arm64.operands[i].type != ARM64_OP_IMM) {
                        continue;
                    }
                    const uint64_t target = detail->arm64.operands[i].imm;
                    if (target < binary_min || target >= binary_max) {
                        break;
                    }
                    if (is_branch) {
                        const std::string target_name = symbol_name_at(ctx, target);
                        if (target_name.find("setjmp") != std::string::npos ||
                            target_name.find("longjmp") != std::string::npos) {
                            throw std::runtime_error(
                                "Unsupported setjmp/longjmp call in protected function " +
                                func.name + " -> " + target_name
                            );
                        }
                    }
                    const uint64_t new_pc = func.slot_vaddr + offset;
                    uint64_t mapped = target;
                    uint32_t original = 0;
                    std::memcpy(&original, func.patched_bytes.data() + offset, sizeof(original));
                    uint32_t patched = original;
                    if (is_branch) {
                        const auto* callee = find_func_start(funcs, target);
                        if (callee != nullptr) {
                            CallsiteMeta meta;
                            meta.caller_func_id = func.id;
                            meta.callee_func_id = callee->id;
                            meta.original_pc = func.original_start + offset;
                            meta.original_return_pc = meta.original_pc + 4;
                            meta.flags = is_bl(original) ? 1u : (is_unconditional_b(original) ? 2u : 0u);
                            callsites.push_back(meta);
                            if (is_unconditional_b(original)) {
                                func.tail_calls++;
                            } else {
                                func.direct_calls++;
                            }
                        }
                    }
                    const bool runtime_allocator = ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator;
                    const bool owner_internal = target >= func.original_start && target < func.original_start + func.size;
                    if (is_adrp && offset + 8 <= func.patched_bytes.size()) {
                        cs_insn* next = nullptr;
                        const uint8_t* next_ptr = func.patched_bytes.data() + offset + 4;
                        size_t next_size = 4;
                        uint64_t next_addr = func.original_start + offset + 4;
                        size_t count = cs_disasm(handle, next_ptr, next_size, next_addr, 1, &next);
                        if (count > 0 && next->id == ARM64_INS_ADD && next->detail != nullptr &&
                            next->detail->arm64.op_count == 3 &&
                            detail->arm64.operands[0].type == ARM64_OP_REG &&
                            next->detail->arm64.operands[1].type == ARM64_OP_REG &&
                            detail->arm64.operands[0].reg == next->detail->arm64.operands[1].reg &&
                            next->detail->arm64.operands[2].type == ARM64_OP_IMM) {
                            const uint64_t materialized =
                                (target & ~0xFFFULL) | (static_cast<uint64_t>(next->detail->arm64.operands[2].imm) & 0xFFFULL);
                            const bool materialized_owner_internal =
                                materialized >= func.original_start && materialized < func.original_start + func.size;
                            mapped = materialized;
                            mapped = map_target_for_body(ctx, func, funcs, mapped);
                            if (runtime_allocator && materialized_owner_internal) {
                                patched = original;
                            } else if (runtime_allocator && !materialized_owner_internal) {
                                uint32_t add_insn = 0;
                                std::memcpy(&add_insn, func.patched_bytes.data() + offset + 4, sizeof(add_insn));
                                slot_local_patches.push_back({
                                    SlotLocalPatch::AdrpAddLiteral,
                                    offset,
                                    offset + 4,
                                    original,
                                    add_insn,
                                    mapped
                                });
                            } else {
                                patched = patch_adrp(original, new_pc, mapped);
                                uint32_t add_insn = 0;
                                std::memcpy(&add_insn, func.patched_bytes.data() + offset + 4, sizeof(add_insn));
                                add_insn = (add_insn & 0xFFC003FFu) | ((static_cast<uint32_t>(mapped & 0xFFFu)) << 10);
                                std::memcpy(func.patched_bytes.data() + offset + 4, &add_insn, sizeof(add_insn));
                            }
                        } else {
                            mapped = map_target_for_body(ctx, func, funcs, target);
                            if (runtime_allocator && !owner_internal) {
                                slot_local_patches.push_back({
                                    SlotLocalPatch::AdrLiteral,
                                    offset,
                                    0,
                                    original,
                                    0,
                                    mapped
                                });
                            } else {
                                patched = patch_adrp(original, new_pc, mapped);
                            }
                        }
                        if (count > 0) {
                            cs_free(next, count);
                        }
                    } else {
                        mapped = map_target_for_body(ctx, func, funcs, target);
                        if (runtime_allocator && owner_internal) {
                            patched = original;
                        } else if (runtime_allocator && !owner_internal && is_branch) {
                            slot_local_patches.push_back({
                                SlotLocalPatch::BranchToVeneer,
                                offset,
                                0,
                                original,
                                0,
                                mapped
                            });
                        } else if (runtime_allocator && !owner_internal && is_adr) {
                            slot_local_patches.push_back({
                                SlotLocalPatch::AdrLiteral,
                                offset,
                                0,
                                original,
                                0,
                                mapped
                            });
                        } else if (is_branch) {
                            patched = patch_branch(original, new_pc, mapped);
                        } else if (is_adr) {
                            patched = patch_adr(original, new_pc, mapped);
                        }
                    }
                    if (!(runtime_allocator && !owner_internal)) {
                        std::memcpy(func.patched_bytes.data() + offset, &patched, sizeof(patched));
                    }
                    break;
                }
            }
            offset += 4;
        }
        cs_free(insn, 1);
        if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator) {
            apply_slot_local_patches(func, slot_local_patches);
        } else {
            func.body_size = func.patched_bytes.size();
        }
    }
    cs_close(&handle);
}

void validate_function_pointer_refs(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs) {
    const std::vector<std::string> data_sections = {
        ".data", ".data.rel.ro", ".got", ".got.plt", ".init_array", ".fini_array"
    };

    auto mapped_pointer_value = [&](uint64_t value, const std::string& where) -> uint64_t {
        const auto* containing = find_func_containing(funcs, value);
        if (containing == nullptr) {
            return value;
        }
        for (auto& func : funcs) {
            if (func.original_start == containing->original_start) {
                func.entry_pointer_refs++;
                break;
            }
        }
        if (containing->original_start == value) {
            return value;
        }
        if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator) {
            throw std::runtime_error(
                "Protected function interior pointer requires a runtime interior thunk in allocator mode: " +
                hex(value)
            );
        }
        Log::warn(
            "Rewriting pointer to protected function interior in " + where +
            ": " + hex(value) + " -> " + hex(containing->slot_vaddr + (value - containing->original_start))
        );
        return containing->slot_vaddr + (value - containing->original_start);
    };

    auto sync_section_to_segment = [&](const LIEF::ELF::Section& sec, const std::vector<uint8_t>& buffer) {
        const uint64_t sec_start = sec.virtual_address();
        const uint64_t sec_end = sec_start + buffer.size();
        for (auto& segment : ctx.binary->segments()) {
            if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) {
                continue;
            }
            const uint64_t seg_start = segment.virtual_address();
            const uint64_t seg_end = seg_start + segment.virtual_size();
            if (sec_start < seg_start || sec_end > seg_end) {
                continue;
            }
            auto seg_content = segment.content();
            std::vector<uint8_t> seg_buffer(seg_content.begin(), seg_content.end());
            const uint64_t sec_off = sec_start - seg_start;
            if (sec_off + buffer.size() <= seg_buffer.size()) {
                std::copy(buffer.begin(), buffer.end(), seg_buffer.begin() + sec_off);
                segment.content(seg_buffer);
            }
            break;
        }
    };

    for (const auto& name : data_sections) {
        auto* sec = ctx.binary->get_section(name);
        if (sec == nullptr || sec->size() < 8) {
            continue;
        }
        auto content = sec->content();
        std::vector<uint8_t> buffer(content.begin(), content.end());
        bool modified = false;
        for (size_t off = 0; off + 8 <= content.size(); off += 8) {
            uint64_t value = 0;
            std::memcpy(&value, buffer.data() + off, sizeof(value));
            const uint64_t mapped = mapped_pointer_value(value, name + "+" + hex(off));
            if (mapped != value) {
                std::memcpy(buffer.data() + off, &mapped, sizeof(mapped));
                modified = true;
            }
        }
        if (modified) {
            sec->content(buffer);
            sync_section_to_segment(*sec, buffer);
        }
    }

    for (auto& reloc : ctx.binary->relocations()) {
        if (reloc.addend() == 0) {
            continue;
        }
        const uint64_t value = static_cast<uint64_t>(reloc.addend());
        const uint64_t mapped = mapped_pointer_value(value, "relocation addend");
        if (mapped != value) {
            reloc.addend(static_cast<int64_t>(mapped));
        }
    }
}

uint32_t make_b(uint64_t from, uint64_t to) {
    const int64_t delta = static_cast<int64_t>(to) - static_cast<int64_t>(from);
    if (delta < -(128LL * 1024 * 1024) || delta >= (128LL * 1024 * 1024)) {
        throw std::runtime_error("Entry branch out of range from " + hex(from) + " to " + hex(to));
    }
    return 0x14000000u | (static_cast<uint32_t>(delta >> 2) & 0x03FFFFFFu);
}

} // namespace maya::protection
