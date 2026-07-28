#include "CodeRelocation.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <capstone/capstone.h>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>

#include "FunctionLayout.hpp"
#include "core/Logger.hpp"

namespace maya::protection {

bool is_bl(uint32_t insn) { return (insn & 0xFC000000u) == 0x94000000u; }

bool is_unconditional_b(uint32_t insn) { return (insn & 0xFC000000u) == 0x14000000u; }

uint64_t map_target_for_body(const ProtectionContext& ctx, const ProtectedFunction& owner,
                             const std::vector<ProtectedFunction>& funcs, uint64_t target) {
    if (target >= owner.original_start && target < owner.original_start + owner.size) {
        return owner.slot_vaddr + (target - owner.original_start);
    }
    if (is_protected_start(funcs, target)) {
        return target + ctx.final_image_shift;
    }
    if (find_func_containing(funcs, target) != nullptr) {
        throw std::runtime_error(
            "Unsupported branch/address target into protected function interior: " + hex(target));
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
    return (insn & 0x9F00001Fu) | ((static_cast<uint32_t>(delta) & 3u) << 29) |
           ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
}

uint32_t patch_adrp(uint32_t insn, uint64_t pc, uint64_t target) {
    const int64_t page_delta = static_cast<int64_t>(target >> 12) - static_cast<int64_t>(pc >> 12);
    return (insn & 0x9F00001Fu) | ((static_cast<uint32_t>(page_delta) & 3u) << 29) |
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

size_t append_branch_veneer(ProtectedFunction& func, uint64_t target, uint64_t return_off,
                            bool call) {
    const size_t veneer_off = append_align(func.patched_bytes, 8);
    if (call) {
        append_u32(func.patched_bytes, 0xA9BF7BF0u); // stp x16, x30, [sp, #-16]!
        append_u32(func.patched_bytes,
                   encode_ldr_literal_x(16, func.original_start + veneer_off + 4,
                                        func.original_start + veneer_off + 24));
        append_u32(func.patched_bytes, 0xD63F0200u); // blr x16
        append_u32(func.patched_bytes, 0xA8C17BF0u); // ldp x16, x30, [sp], #16
        append_u32(func.patched_bytes,
                   make_b(func.original_start + veneer_off + 16, func.original_start + return_off));
        append_u32(func.patched_bytes, 0xD503201Fu);
        func.runtime_literal_offsets.push_back(veneer_off + 24);
        append_u64(func.patched_bytes, target);
    } else {
        append_u32(func.patched_bytes, encode_ldr_literal_x(16, func.original_start + veneer_off,
                                                            func.original_start + veneer_off + 8));
        append_u32(func.patched_bytes, 0xD61F0200u); // br x16
        func.runtime_literal_offsets.push_back(veneer_off + 8);
        append_u64(func.patched_bytes, target);
    }
    return veneer_off;
}

const ControlEdge* find_control_edge_at(const ProtectedFunction& func, uint64_t pc,
                                        uint64_t target) {
    for (const auto& edge : func.control_edges) {
        if (edge.pc == pc && edge.target == target) {
            return &edge;
        }
    }
    return nullptr;
}

std::string describe_control_edge_expectation(ControlEdgeKind kind, uint64_t pc, uint64_t target) {
    std::ostringstream out;
    out << control_edge_kind_name(kind) << " at " << hex(pc) << " -> " << hex(target);
    return out.str();
}

const ControlEdge* validate_analyzed_direct_edge(const ProtectedFunction& func,
                                                 const std::vector<ProtectedFunction>& funcs,
                                                 uint64_t pc, uint64_t target, uint32_t original) {
    const auto* edge = find_control_edge_at(func, pc, target);
    if (edge == nullptr) {
        throw std::runtime_error("Relocation found a direct branch/call without analysis edge in " +
                                 func.name + " at " + hex(pc) + " -> " + hex(target));
    }

    const auto* callee = find_func_start(funcs, target);
    const auto* containing_target = find_func_containing(funcs, target);
    const bool owner_internal =
        target >= func.original_start && target < func.original_start + func.size;
    ControlEdgeKind expected = ControlEdgeKind::UnmodeledEdge;
    uint32_t expected_target_func_id = UINT32_MAX;
    if (is_bl(original)) {
        if (callee != nullptr) {
            expected = ControlEdgeKind::ProtectedToProtectedCall;
            expected_target_func_id = callee->id;
        } else if (containing_target != nullptr) {
            expected_target_func_id = containing_target->id;
        } else {
            expected = ControlEdgeKind::ExternalCall;
        }
    } else if (owner_internal) {
        expected = ControlEdgeKind::IntraFunction;
        expected_target_func_id = func.id;
    } else if (callee != nullptr && is_unconditional_b(original)) {
        expected = ControlEdgeKind::ProtectedTailCall;
        expected_target_func_id = callee->id;
    } else if (containing_target != nullptr) {
        expected_target_func_id = containing_target->id;
    } else if (is_unconditional_b(original)) {
        expected = ControlEdgeKind::ExternalTailCall;
    }

    if (edge->kind != expected || edge->target_func_id != expected_target_func_id) {
        throw std::runtime_error(
            "Relocation/analysis control-edge mismatch in " + func.name + ": expected " +
            describe_control_edge_expectation(expected, pc, target) + " target_func_id=" +
            (expected_target_func_id == UINT32_MAX ? std::string("-")
                                                   : std::to_string(expected_target_func_id)) +
            ", analyzed " + describe_control_edge_expectation(edge->kind, edge->pc, edge->target) +
            " target_func_id=" +
            (edge->target_func_id == UINT32_MAX ? std::string("-")
                                                : std::to_string(edge->target_func_id)));
    }
    return edge;
}

void build_edge_derived_callsite_meta(std::vector<ProtectedFunction>& funcs,
                                      std::vector<CallsiteMetadata>& callsites) {
    callsites.clear();
    for (auto& func : funcs) {
        func.direct_calls = 0;
        func.tail_calls = 0;
        func.indirect_calls = 0;
        for (const auto& edge : func.control_edges) {
            if (edge.kind == ControlEdgeKind::IndirectCall) {
                func.indirect_calls++;
                continue;
            }
            if (edge.kind != ControlEdgeKind::ProtectedToProtectedCall &&
                edge.kind != ControlEdgeKind::ProtectedTailCall) {
                continue;
            }
            CallsiteMetadata meta;
            meta.caller_func_id = func.id;
            meta.callee_func_id = edge.target_func_id;
            meta.original_pc = edge.pc;
            meta.original_return_pc = edge.pc + 4;
            meta.flags = edge.kind == ControlEdgeKind::ProtectedToProtectedCall ? 1u : 2u;
            callsites.push_back(meta);
            if (edge.kind == ControlEdgeKind::ProtectedToProtectedCall) {
                func.direct_calls++;
            } else {
                func.tail_calls++;
            }
        }
    }
}

void apply_slot_local_patches(ProtectedFunction& func, const std::vector<SlotLocalPatch>& patches) {
    for (const auto& patch : patches) {
        if (patch.kind == SlotLocalPatch::BranchToVeneer) {
            const size_t veneer_off = append_branch_veneer(func, patch.target, patch.insn_off + 4,
                                                           is_bl(patch.original_insn));
            func.veneer_count++;
            const uint32_t patched =
                patch_branch(patch.original_insn, func.original_start + patch.insn_off,
                             func.original_start + veneer_off);
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            continue;
        }
        if (patch.kind == SlotLocalPatch::AdrLiteral) {
            const size_t literal_off = append_literal_pool_entry(func, patch.target);
            func.literal_pool_bytes += 8;
            const uint32_t rt = patch.original_insn & 0x1Fu;
            const uint32_t patched = encode_ldr_literal_x(rt, func.original_start + patch.insn_off,
                                                          func.original_start + literal_off);
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            continue;
        }
        if (patch.kind == SlotLocalPatch::AdrpAddLiteral) {
            const size_t literal_off = append_literal_pool_entry(func, patch.target);
            func.literal_pool_bytes += 8;
            const uint32_t rt = patch.paired_insn & 0x1Fu;
            const uint32_t patched = encode_ldr_literal_x(rt, func.original_start + patch.insn_off,
                                                          func.original_start + literal_off);
            const uint32_t nop = 0xD503201Fu;
            std::memcpy(func.patched_bytes.data() + patch.insn_off, &patched, sizeof(patched));
            std::memcpy(func.patched_bytes.data() + patch.paired_off, &nop, sizeof(nop));
            continue;
        }
    }
    func.runtime_relocations = patches.size();
    func.body_size = func.patched_bytes.size();
    if (func.body_size > encrypted_body_capacity(func, SlotStrategy::RuntimeAllocator)) {
        throw std::runtime_error(
            "Runtime slot-local metadata exceeded reserved body capacity for " + func.name);
    }
}

void patch_function_bodies(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs,
                           std::vector<CallsiteMetadata>& callsites) {
    build_edge_derived_callsite_meta(funcs, callsites);
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
            const bool runtime_eh =
                ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
                func.selected_backend == SelectedBackend::Fragment && !func.fde_bytes.empty();
            if (runtime_eh && insn->id == ARM64_INS_RET) {
                const uint32_t branch =
                    make_b(func.slot_vaddr + offset, func.eh_normal_cleanup_vaddr);
                std::memcpy(func.patched_bytes.data() + offset, &branch, sizeof(branch));
                offset += 4;
                continue;
            }
            const cs_detail* detail = insn->detail;
            bool is_branch = false;
            if (detail != nullptr) {
                for (uint8_t i = 0; i < detail->groups_count; ++i) {
                    if (detail->groups[i] == ARM64_GRP_JUMP ||
                        detail->groups[i] == ARM64_GRP_CALL) {
                        is_branch = true;
                    }
                }
            }
            const bool is_adr = insn->id == ARM64_INS_ADR;
            const bool is_adrp = insn->id == ARM64_INS_ADRP;
            if ((is_branch || is_adr || is_adrp) && detail != nullptr) {
                for (int i = detail->arm64.op_count - 1; i >= 0; --i) {
                    if (detail->arm64.operands[i].type != ARM64_OP_IMM) {
                        continue;
                    }
                    const uint64_t target = detail->arm64.operands[i].imm;
                    if (target < binary_min || target >= binary_max) {
                        break;
                    }
                    uint32_t original = 0;
                    std::memcpy(&original, func.patched_bytes.data() + offset, sizeof(original));
                    const ControlEdge* analyzed_edge = nullptr;
                    if (is_branch) {
                        analyzed_edge = validate_analyzed_direct_edge(
                            func, funcs, func.original_start + offset, target, original);
                    }
                    const uint64_t new_pc = func.slot_vaddr + offset;
                    uint64_t mapped = target;
                    uint32_t patched = original;
                    // Authenticated EH functions are placed in a guaranteed
                    // near-image hole.  Preserve their original call-frame
                    // topology by relocating direct branches/ADRP references
                    // in place; appended veneers would sit outside the FDE's
                    // PC range and make synchronous unwinding unsound.
                    const bool runtime_allocator =
                        ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
                        !(func.selected_backend == SelectedBackend::Fragment &&
                          !func.fde_bytes.empty());
                    const bool owner_internal =
                        target >= func.original_start && target < func.original_start + func.size;
                    if (is_adrp && offset + 8 <= func.patched_bytes.size()) {
                        cs_insn* next = nullptr;
                        const uint8_t* next_ptr = func.patched_bytes.data() + offset + 4;
                        size_t next_size = 4;
                        uint64_t next_addr = func.original_start + offset + 4;
                        size_t count = cs_disasm(handle, next_ptr, next_size, next_addr, 1, &next);
                        if (count > 0 && next->id == ARM64_INS_ADD && next->detail != nullptr &&
                            next->detail->arm64.op_count == 3 &&
                            detail->arm64.operands[0].type == ARM64_OP_REG &&
                            next->detail->arm64.operands[0].type == ARM64_OP_REG &&
                            next->detail->arm64.operands[1].type == ARM64_OP_REG &&
                            detail->arm64.operands[0].reg == next->detail->arm64.operands[1].reg &&
                            detail->arm64.operands[0].reg == next->detail->arm64.operands[0].reg &&
                            next->detail->arm64.operands[2].type == ARM64_OP_IMM) {
                            const uint64_t materialized =
                                (target & ~0xFFFULL) |
                                (static_cast<uint64_t>(next->detail->arm64.operands[2].imm) &
                                 0xFFFULL);
                            const bool materialized_owner_internal =
                                materialized >= func.original_start &&
                                materialized < func.original_start + func.size;
                            mapped = materialized;
                            mapped = map_target_for_body(ctx, func, funcs, mapped);
                            if (runtime_allocator && materialized_owner_internal) {
                                patched = original;
                            } else if (runtime_allocator && !materialized_owner_internal) {
                                uint32_t add_insn = 0;
                                std::memcpy(&add_insn, func.patched_bytes.data() + offset + 4,
                                            sizeof(add_insn));
                                slot_local_patches.push_back({SlotLocalPatch::AdrpAddLiteral,
                                                              offset, offset + 4, original,
                                                              add_insn, mapped});
                            } else {
                                patched = patch_adrp(original, new_pc, mapped);
                                uint32_t add_insn = 0;
                                std::memcpy(&add_insn, func.patched_bytes.data() + offset + 4,
                                            sizeof(add_insn));
                                add_insn = (add_insn & 0xFFC003FFu) |
                                           ((static_cast<uint32_t>(mapped & 0xFFFu)) << 10);
                                std::memcpy(func.patched_bytes.data() + offset + 4, &add_insn,
                                            sizeof(add_insn));
                            }
                        } else {
                            mapped = map_target_for_body(ctx, func, funcs, target);
                            if (runtime_allocator && !owner_internal) {
                                slot_local_patches.push_back(
                                    {SlotLocalPatch::AdrLiteral, offset, 0, original, 0, mapped});
                            } else {
                                patched = patch_adrp(original, new_pc, mapped);
                            }
                        }
                        if (count > 0) {
                            cs_free(next, count);
                        }
                    } else {
                        mapped = map_target_for_body(ctx, func, funcs, target);
                        if (runtime_eh &&
                            ((analyzed_edge != nullptr &&
                              analyzed_edge->target_symbol.find("_Unwind_Resume") !=
                                  std::string::npos) ||
                             target + ctx.final_image_shift == func.eh_metadata.unwind_resume)) {
                            mapped = func.eh_unwind_cleanup_vaddr;
                        }
                        if (runtime_eh &&
                            ((analyzed_edge != nullptr &&
                              analyzed_edge->target_symbol.find("__cxa_throw") !=
                                  std::string::npos) ||
                             target + ctx.final_image_shift == func.eh_metadata.cxa_throw)) {
                            mapped = func.eh_throw_cleanup_vaddr;
                        }
                        if (runtime_eh &&
                            ((analyzed_edge != nullptr &&
                              analyzed_edge->target_symbol.find("__cxa_rethrow") !=
                                  std::string::npos) ||
                             target + ctx.final_image_shift == func.eh_metadata.cxa_rethrow)) {
                            mapped = func.eh_rethrow_cleanup_vaddr;
                        }
                        if (runtime_allocator && owner_internal) {
                            patched = original;
                        } else if (runtime_allocator && !owner_internal && is_branch) {
                            slot_local_patches.push_back(
                                {SlotLocalPatch::BranchToVeneer, offset, 0, original, 0, mapped});
                        } else if (runtime_allocator && !owner_internal && is_adr) {
                            slot_local_patches.push_back(
                                {SlotLocalPatch::AdrLiteral, offset, 0, original, 0, mapped});
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
        if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
            !(func.selected_backend == SelectedBackend::Fragment && !func.fde_bytes.empty())) {
            apply_slot_local_patches(func, slot_local_patches);
        } else {
            func.body_size = func.patched_bytes.size();
        }
    }
    cs_close(&handle);
}

void validate_function_pointer_refs(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs) {
    const std::vector<std::string> data_sections = {".data",    ".data.rel.ro", ".got",
                                                    ".got.plt", ".init_array",  ".fini_array"};

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
            auto& owner = *std::find_if(funcs.begin(), funcs.end(), [&](const auto& func) {
                return func.original_start == containing->original_start;
            });
            const auto fragment =
                std::find_if(owner.fragments.begin(), owner.fragments.end(),
                             [&](const auto& item) { return item.original_start == value; });
            if (!owner.cfg_execution_enabled || fragment == owner.fragments.end()) {
                throw std::runtime_error("Unsafe protected function interior pointer is not a "
                                         "validated fragment entry: " +
                                         hex(value) + " from " + where);
            }
            const auto existing =
                std::find_if(owner.interior_thunks.begin(), owner.interior_thunks.end(),
                             [&](const auto& thunk) { return thunk.original_target == value; });
            if (existing != owner.interior_thunks.end())
                return existing->thunk_vaddr;
            if (owner.interior_thunks.size() >= 16) {
                throw std::runtime_error(
                    "Protected function has too many interior pointer thunks: " + owner.name);
            }
            ProtectedFunction::InteriorThunk thunk{value,
                                                   owner.stub_vaddr + entry_stub_size(owner) -
                                                       0x100 + owner.interior_thunks.size() * 16,
                                                   fragment->fragment_id, where};
            owner.interior_thunks.push_back(thunk);
            Log::info("Rewriting stable interior pointer in " + where + ": " + hex(value) + " -> " +
                      hex(thunk.thunk_vaddr));
            return thunk.thunk_vaddr;
        }
        Log::warn("Rewriting pointer to protected function interior in " + where + ": " +
                  hex(value) + " -> " +
                  hex(containing->slot_vaddr + (value - containing->original_start)));
        return containing->slot_vaddr + (value - containing->original_start);
    };

    auto sync_section_to_segment = [&](const LIEF::ELF::Section& sec,
                                       const std::vector<uint8_t>& buffer) {
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

    std::vector<std::pair<uint64_t, uint64_t>> rewritten_relocation_addends;
    for (auto& reloc : ctx.binary->relocations()) {
        if (reloc.addend() == 0) {
            continue;
        }
        const uint64_t value = static_cast<uint64_t>(reloc.addend());
        const uint64_t mapped = mapped_pointer_value(value, "relocation addend");
        if (mapped != value) {
            reloc.addend(static_cast<int64_t>(mapped));
            rewritten_relocation_addends.emplace_back(reloc.address(), mapped);
        }
    }
    for (const auto& section_name : {".rela.dyn", ".rela.plt"}) {
        auto* sec = ctx.binary->get_section(section_name);
        if (sec == nullptr || rewritten_relocation_addends.empty())
            continue;
        std::vector<uint8_t> buffer(sec->content().begin(), sec->content().end());
        bool modified = false;
        for (size_t off = 0; off + 24 <= buffer.size(); off += 24) {
            uint64_t address = 0;
            std::memcpy(&address, buffer.data() + off, sizeof(address));
            const auto rewrite = std::find_if(
                rewritten_relocation_addends.begin(), rewritten_relocation_addends.end(),
                [&](const auto& item) { return item.first == address; });
            if (rewrite == rewritten_relocation_addends.end())
                continue;
            std::memcpy(buffer.data() + off + 16, &rewrite->second, sizeof(rewrite->second));
            modified = true;
        }
        if (modified) {
            sec->content(buffer);
            sync_section_to_segment(*sec, buffer);
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
