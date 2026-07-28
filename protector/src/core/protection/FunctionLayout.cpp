#include "FunctionLayout.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <fnmatch.h>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>

#include "core/InstrumentationPolicy.hpp"
#include "core/Logger.hpp"
#include "core/Utils.hpp"

namespace maya::protection {

std::string hex(uint64_t v) {
    std::stringstream ss;
    ss << "0x" << std::hex << v;
    return ss.str();
}

std::vector<ProtectedFunction> collect_functions(ProtectionContext& ctx) {
    auto* text = ctx.binary->get_section(".text");
    if (text == nullptr) {
        throw std::runtime_error("Missing .text section.");
    }

    const uint64_t text_start = text->virtual_address();
    const uint64_t text_end = text_start + text->size();
    uint64_t application_code_end = text_end;
    uint64_t application_code_start = text_start;
    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.name() == "frame_dummy" && sym.value() != 0) {
            application_code_start = std::max(application_code_start, sym.value());
        }
        if (sym.name() == "call_fini" && sym.value() != 0) {
            application_code_end = std::min(application_code_end, sym.value());
        }
    }

    std::map<uint64_t, ProtectedFunction> by_addr;
    std::set<std::string> matched_includes;
    std::set<std::string> matched_excludes;
    auto matches_any = [](const std::string& name, const std::vector<std::string>& patterns) {
        return std::any_of(patterns.begin(), patterns.end(), [&](const auto& pattern) {
            return fnmatch(pattern.c_str(), name.c_str(), 0) == 0;
        });
    };
    for (const auto& sym : ctx.binary->symtab_symbols()) {
        if (sym.type() != LIEF::ELF::Symbol::TYPE::FUNC || sym.name().empty() || sym.value() == 0 ||
            sym.size() < 4) {
            continue;
        }
        if (sym.value() < text_start || sym.value() > text_end ||
            sym.size() > text_end - sym.value()) {
            continue;
        }
        const bool explicitly_included = matches_any(sym.name(), ctx.options.include_symbols);
        for (const auto& pattern : ctx.options.include_symbols) {
            if (fnmatch(pattern.c_str(), sym.name().c_str(), 0) == 0)
                matched_includes.insert(pattern);
        }
        const bool safe_candidate =
            maya::should_instrument(sym.name(), sym.value(), text_start, text_end,
                                    application_code_end, explicitly_included);
        if ((!ctx.options.include_symbols.empty() && !explicitly_included) ||
            (ctx.options.include_symbols.empty() && !safe_candidate) ||
            (explicitly_included && !safe_candidate)) {
            continue;
        }
        if (matches_any(sym.name(), ctx.options.exclude_symbols)) {
            for (const auto& pattern : ctx.options.exclude_symbols) {
                if (fnmatch(pattern.c_str(), sym.name().c_str(), 0) == 0) {
                    matched_excludes.insert(pattern);
                }
            }
            continue;
        }
        if ((sym.value() & 0x3ULL) != 0) {
            throw std::runtime_error("Unaligned function candidate: " + sym.name());
        }
        auto [it, inserted] = by_addr.emplace(sym.value(), ProtectedFunction{});
        if (inserted) {
            it->second.name = sym.name();
            it->second.original_start = sym.value();
            it->second.size = sym.size();
        } else {
            it->second.name += "," + sym.name();
            it->second.size = std::max<uint64_t>(it->second.size, sym.size());
        }
    }
    for (const auto& pattern : ctx.options.include_symbols) {
        if (matched_includes.count(pattern) == 0) {
            throw std::runtime_error("--functions pattern matched no candidate symbol: " + pattern);
        }
    }
    for (const auto& pattern : ctx.options.exclude_symbols) {
        if (matched_excludes.count(pattern) == 0) {
            throw std::runtime_error("--exclude pattern matched no candidate symbol: " + pattern);
        }
    }

    std::vector<ProtectedFunction> funcs;
    for (auto& entry : by_addr) {
        funcs.push_back(std::move(entry.second));
    }
    std::sort(funcs.begin(), funcs.end(),
              [](const auto& a, const auto& b) { return a.original_start < b.original_start; });
    for (size_t i = 0; i < funcs.size(); ++i) {
        funcs[i].id = static_cast<uint32_t>(i);
        funcs[i].selected_id = static_cast<uint32_t>(i);
        if (i + 1 < funcs.size() &&
            funcs[i].original_start + funcs[i].size > funcs[i + 1].original_start) {
            throw std::runtime_error("Overlapping protected functions: " + funcs[i].name + " and " +
                                     funcs[i + 1].name);
        }
        auto content =
            ctx.binary->get_content_from_virtual_address(funcs[i].original_start, funcs[i].size);
        funcs[i].original_bytes.assign(content.begin(), content.end());
        funcs[i].patched_bytes = funcs[i].original_bytes;
        funcs[i].body_size = funcs[i].size;
        if (ctx.options.verbose) {
            Log::info("  candidate[" + std::to_string(funcs[i].id) + "] " + funcs[i].name + " @ " +
                      hex(funcs[i].original_start) + " size=" + std::to_string(funcs[i].size));
        }
    }

    Log::info("Discovered " + std::to_string(funcs.size()) + " candidate functions.");
    return funcs;
}

uint64_t encrypted_body_capacity(const ProtectedFunction& func, SlotStrategy strategy) {
    if (strategy == SlotStrategy::FixedPerFunction) {
        return Utils::align_to(func.size, kAlign);
    }
    const uint64_t insns = Utils::align_to(func.size, 4) / 4;
    return Utils::align_to(func.size + insns * kRuntimeBodyExtraPerInsn + 64, kAlign);
}

uint64_t choose_payload_vaddr(const ProtectionContext& ctx) {
    uint64_t max_vaddr = 0;
    for (const auto& seg : ctx.binary->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            max_vaddr = std::max(max_vaddr, seg.virtual_address() + seg.virtual_size());
        }
    }
    return Utils::align_to(max_vaddr + kSegmentAlign, kSegmentAlign);
}

void assign_layout(std::vector<ProtectedFunction>& funcs, PayloadLayout& layout, uint64_t base,
                   SlotStrategy strategy) {
    layout.base_vaddr = base;
    uint64_t cursor = base;
    layout.return_stub_vaddr = cursor;
    cursor += kReturnStubSize;
    cursor = Utils::align_to(cursor, kAlign);

    for (auto& func : funcs) {
        func.stub_vaddr = cursor;
        if (!func.fde_bytes.empty()) {
            func.eh_normal_cleanup_vaddr = cursor + 0x4000;
            func.eh_unwind_cleanup_vaddr = cursor + 0x4400;
            func.eh_throw_cleanup_vaddr = cursor + 0x4800;
            func.eh_rethrow_cleanup_vaddr = cursor + 0x4c00;
        }
        cursor += entry_stub_size(func);
        cursor = Utils::align_to(cursor, kAlign);
    }

    cursor = Utils::align_to(cursor, kPageSize);
    layout.fragment_runtime_vaddr = cursor;
    cursor += kFragmentRuntimeCapacity;

    cursor = Utils::align_to(cursor, kPageSize);
    layout.eh_runtime_arena_vaddr = cursor;
    for (const auto& func : funcs) {
        if (!func.fde_bytes.empty() && func.selected_backend == SelectedBackend::Fragment &&
            strategy == SlotStrategy::RuntimeAllocator) {
            cursor += Utils::align_to(encrypted_body_capacity(func, strategy), kPageSize);
        }
    }
    layout.eh_runtime_arena_size = cursor - layout.eh_runtime_arena_vaddr;

    cursor = Utils::align_to(cursor, kSegmentAlign);
    layout.rx_end_vaddr = cursor;
    cursor += 2 * kSegmentAlign;
    layout.ro_start_vaddr = cursor;

    for (auto& func : funcs) {
        if (!func.cfg_execution_enabled) {
            func.enc_vaddr = cursor;
            cursor += encrypted_body_capacity(func, strategy);
            cursor = Utils::align_to(cursor, kAlign);
        }
        if (func.selected_backend == SelectedBackend::Fragment) {
            for (auto& fragment : func.fragments) {
                fragment.storage_size = Utils::align_to(
                    fragment.size + std::max<size_t>(1, fragment.exits.size()) * 128 +
                        (fragment.size / 4) * 16,
                    kAlign);
                fragment.ciphertext_vaddr = cursor;
                cursor += fragment.storage_size;
                fragment.nonce_vaddr = cursor;
                cursor += fragment.nonce.size();
                fragment.tag_vaddr = cursor;
                cursor += fragment.tag.size();
                fragment.aad_vaddr = cursor;
                cursor += kFragmentAadSize;
                for (auto& variant : fragment.variants) {
                    variant.ciphertext_vaddr = cursor;
                    cursor += fragment.storage_size;
                    variant.nonce_vaddr = cursor;
                    cursor += variant.nonce.size();
                    variant.tag_vaddr = cursor;
                    cursor += variant.tag.size();
                    variant.aad_vaddr = cursor;
                    cursor += kFragmentAadSize;
                }
                if (func.v3_control_enabled || func.native_variants_enabled) {
                    fragment.vm_storage_capacity =
                        func.v3_control_enabled ? (168 + (func.native_variants_enabled ? 12 : 0))
                                                : 24;
                    fragment.vm_ciphertext_vaddr = cursor;
                    cursor += fragment.vm_storage_capacity;
                    fragment.vm_nonce_vaddr = cursor;
                    cursor += fragment.vm_nonce.size();
                    fragment.vm_tag_vaddr = cursor;
                    cursor += fragment.vm_tag.size();
                    fragment.vm_aad_vaddr = cursor;
                    cursor += kFragmentAadSize;
                }
                cursor = Utils::align_to(cursor, kAlign);
            }
        }
        if (func.cfg_execution_enabled) {
            const uint64_t exit_count = std::accumulate(
                func.fragments.begin(), func.fragments.end(), uint64_t{0},
                [](uint64_t total, const auto& fragment) { return total + fragment.exits.size(); });
            if (!func.v3_control_enabled) {
                func.metadata_shard_vaddr = cursor;
                // Each V2 exit stores independently masked target and
                // continuation records (24 bytes each), plus header/digest.
                func.metadata_shard_capacity = Utils::align_to(56 + exit_count * 2 * 24, kAlign);
                cursor += func.metadata_shard_capacity;
            } else {
                func.metadata_shard_vaddr = 0;
                func.metadata_shard_capacity = 0;
            }
            func.v3_shard_vaddr = cursor;
            uint64_t encoded_size = 0;
            if (func.v3_control_enabled) {
                if (func.v3_shard_family == 0) {
                    uint64_t slots = 4;
                    while (slots < exit_count * 2)
                        slots <<= 1;
                    encoded_size = 12 + slots * 24 + exit_count * 100;
                } else if (func.v3_shard_family == 1)
                    encoded_size = 4 + exit_count * 112;
                else
                    encoded_size = 12 + exit_count * 112;
                func.v3_shard_capacity = Utils::align_to(40 + encoded_size, kAlign);
            } else {
                func.v3_shard_capacity = 0;
            }
            cursor += func.v3_shard_capacity;
            cursor = Utils::align_to(cursor, kAlign);
        }
    }

    layout.build_root_vaddr = cursor;
    cursor += 32;
    cursor = Utils::align_to(cursor, kAlign);

    for (auto& func : funcs) {
        if (func.selected_backend != SelectedBackend::Fragment || func.cfg_execution_enabled)
            continue;
        func.fragment_nonce_vaddr = cursor;
        cursor += func.fragment_nonce.size();
        func.fragment_tag_vaddr = cursor;
        cursor += func.fragment_tag.size();
        func.fragment_aad_vaddr = cursor;
        cursor += kFragmentAadSize;
        cursor = Utils::align_to(cursor, kAlign);
    }

    layout.callsite_meta_vaddr = cursor;
    layout.callsite_meta_size = estimate_callsite_meta_capacity(funcs);
    cursor += layout.callsite_meta_size;
    cursor = Utils::align_to(cursor, kAlign);

    layout.eh_frame_vaddr = cursor;
    for (auto& func : funcs) {
        if (!func.fde_bytes.empty()) {
            const bool runtime_registered = strategy == SlotStrategy::RuntimeAllocator &&
                                            func.selected_backend == SelectedBackend::Fragment;
            if (runtime_registered) {
                func.eh_registration_vaddr = cursor;
                cursor += func.cie_bytes.size();
            }
            func.fde_vaddr = cursor;
            cursor += func.fde_bytes.size();
            if (runtime_registered)
                cursor += sizeof(uint32_t); // registration terminator
            cursor = Utils::align_to(cursor, 8);
        }
    }
    layout.eh_frame_size = cursor - layout.eh_frame_vaddr;
    layout.fragment_descriptor_vaddr = cursor;
    cursor += kFragmentDescriptorCapacity;
    cursor = Utils::align_to(cursor, kSegmentAlign);
    layout.ro_end_vaddr = cursor;
    cursor += 2 * kSegmentAlign;
    layout.rw_start_vaddr = cursor;

    layout.thread_states_vaddr = cursor;
    const bool needs_legacy_thread_slots =
        std::any_of(funcs.begin(), funcs.end(), [](const auto& func) {
            return func.selected_backend != SelectedBackend::Fragment ||
                   !func.cfg_execution_enabled;
        });
    cursor += needs_legacy_thread_slots ? kThreadSlotCount * kThreadStateSize : 128;
    cursor = Utils::align_to(cursor, kAlign);

    for (auto& func : funcs) {
        func.active_vaddr = cursor;
        cursor += kFunctionStateSize;
        cursor = Utils::align_to(cursor, kAlign);
    }

    if (strategy == SlotStrategy::FixedPerFunction) {
        for (auto& func : funcs) {
            func.slot_vaddr = cursor;
            func.slot_size = encrypted_body_capacity(func, strategy);
            cursor += func.slot_size;
            cursor = Utils::align_to(cursor, kAlign);
        }
    } else {
        uint64_t eh_slot_cursor = layout.eh_runtime_arena_vaddr;
        const uint64_t eh_slot_limit = layout.eh_runtime_arena_vaddr + layout.eh_runtime_arena_size;
        uint64_t slot_cursor = Utils::align_to(cursor + kSegmentAlign, kPageSize);
        for (auto& func : funcs) {
            func.slot_size = Utils::align_to(encrypted_body_capacity(func, strategy), kPageSize);
            if (!func.fde_bytes.empty() && func.selected_backend == SelectedBackend::Fragment) {
                if (func.slot_size > eh_slot_limit - eh_slot_cursor) {
                    throw std::runtime_error(
                        "Authenticated EH mappings exceed the near-image placement gap.");
                }
                func.slot_vaddr = eh_slot_cursor;
                eh_slot_cursor += func.slot_size;
            } else {
                func.slot_vaddr = slot_cursor;
                slot_cursor += func.slot_size;
            }
        }
    }

    cursor = Utils::align_to(cursor, kSegmentAlign);
    layout.total_size = cursor - base;
}

void shift_layout(std::vector<ProtectedFunction>& funcs, PayloadLayout& layout, int64_t delta) {
    auto shift = [delta](uint64_t v) {
        return static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
    };
    layout.base_vaddr = shift(layout.base_vaddr);
    layout.rx_end_vaddr = shift(layout.rx_end_vaddr);
    layout.ro_start_vaddr = shift(layout.ro_start_vaddr);
    layout.ro_end_vaddr = shift(layout.ro_end_vaddr);
    layout.rw_start_vaddr = shift(layout.rw_start_vaddr);
    layout.return_stub_vaddr = shift(layout.return_stub_vaddr);
    layout.thread_states_vaddr = shift(layout.thread_states_vaddr);
    layout.build_root_vaddr = shift(layout.build_root_vaddr);
    layout.callsite_meta_vaddr = shift(layout.callsite_meta_vaddr);
    layout.eh_frame_vaddr = shift(layout.eh_frame_vaddr);
    layout.fragment_runtime_vaddr = shift(layout.fragment_runtime_vaddr);
    layout.eh_runtime_arena_vaddr = shift(layout.eh_runtime_arena_vaddr);
    layout.fragment_descriptor_vaddr = shift(layout.fragment_descriptor_vaddr);
    for (auto& func : funcs) {
        func.stub_vaddr = shift(func.stub_vaddr);
        if (func.eh_normal_cleanup_vaddr)
            func.eh_normal_cleanup_vaddr = shift(func.eh_normal_cleanup_vaddr);
        if (func.eh_unwind_cleanup_vaddr)
            func.eh_unwind_cleanup_vaddr = shift(func.eh_unwind_cleanup_vaddr);
        if (func.eh_throw_cleanup_vaddr)
            func.eh_throw_cleanup_vaddr = shift(func.eh_throw_cleanup_vaddr);
        if (func.eh_rethrow_cleanup_vaddr)
            func.eh_rethrow_cleanup_vaddr = shift(func.eh_rethrow_cleanup_vaddr);
        func.slot_vaddr = shift(func.slot_vaddr);
        if (func.enc_vaddr)
            func.enc_vaddr = shift(func.enc_vaddr);
        for (auto& fragment : func.fragments) {
            if (fragment.ciphertext_vaddr)
                fragment.ciphertext_vaddr = shift(fragment.ciphertext_vaddr);
            if (fragment.nonce_vaddr)
                fragment.nonce_vaddr = shift(fragment.nonce_vaddr);
            if (fragment.tag_vaddr)
                fragment.tag_vaddr = shift(fragment.tag_vaddr);
            if (fragment.aad_vaddr)
                fragment.aad_vaddr = shift(fragment.aad_vaddr);
            for (auto& variant : fragment.variants) {
                if (variant.ciphertext_vaddr)
                    variant.ciphertext_vaddr = shift(variant.ciphertext_vaddr);
                if (variant.nonce_vaddr)
                    variant.nonce_vaddr = shift(variant.nonce_vaddr);
                if (variant.tag_vaddr)
                    variant.tag_vaddr = shift(variant.tag_vaddr);
                if (variant.aad_vaddr)
                    variant.aad_vaddr = shift(variant.aad_vaddr);
            }
            if (fragment.vm_ciphertext_vaddr)
                fragment.vm_ciphertext_vaddr = shift(fragment.vm_ciphertext_vaddr);
            if (fragment.vm_nonce_vaddr)
                fragment.vm_nonce_vaddr = shift(fragment.vm_nonce_vaddr);
            if (fragment.vm_tag_vaddr)
                fragment.vm_tag_vaddr = shift(fragment.vm_tag_vaddr);
            if (fragment.vm_aad_vaddr)
                fragment.vm_aad_vaddr = shift(fragment.vm_aad_vaddr);
        }
        func.active_vaddr = shift(func.active_vaddr);
        if (func.fragment_nonce_vaddr)
            func.fragment_nonce_vaddr = shift(func.fragment_nonce_vaddr);
        if (func.fragment_tag_vaddr)
            func.fragment_tag_vaddr = shift(func.fragment_tag_vaddr);
        if (func.fragment_aad_vaddr)
            func.fragment_aad_vaddr = shift(func.fragment_aad_vaddr);
        if (func.metadata_shard_vaddr)
            func.metadata_shard_vaddr = shift(func.metadata_shard_vaddr);
        if (func.v3_shard_vaddr)
            func.v3_shard_vaddr = shift(func.v3_shard_vaddr);
        if (func.fde_vaddr != 0) {
            func.fde_vaddr = shift(func.fde_vaddr);
        }
        if (func.eh_registration_vaddr != 0)
            func.eh_registration_vaddr = shift(func.eh_registration_vaddr);
    }
}

uint64_t estimate_callsite_meta_capacity(const std::vector<ProtectedFunction>& funcs) {
    uint64_t instruction_slots = 0;
    for (const auto& func : funcs) {
        instruction_slots += func.size / 4;
    }
    return Utils::align_to(instruction_slots * 32, kAlign);
}

uint64_t reserve_payload_vaddr(ProtectionContext& ctx, uint64_t requested_vaddr,
                               uint64_t total_size) {
    if (ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable) {
        size_t note_slots = 0;
        for (const auto& segment : ctx.binary->segments()) {
            if (segment.type() == LIEF::ELF::Segment::TYPE::NOTE)
                ++note_slots;
        }
        if (note_slots < 3) {
            throw std::runtime_error(
                "Static PIE requires three reusable PT_NOTE slots for W^X payload segments.");
        }
        ctx.final_image_shift = 0;
        ctx.segment_request_bias = 0;
        return requested_vaddr;
    }
    auto probe_binary = LIEF::ELF::Parser::parse(ctx.filename);
    if (!probe_binary) {
        throw std::runtime_error("Failed to reparse binary for payload placement.");
    }
    const auto* original_text = ctx.binary->get_section(".text");
    auto* probe_text_before = probe_binary->get_section(".text");
    const uint64_t original_text_vaddr =
        original_text == nullptr ? 0 : original_text->virtual_address();
    const uint64_t probe_text_vaddr =
        probe_text_before == nullptr ? original_text_vaddr : probe_text_before->virtual_address();

    LIEF::ELF::Segment segment;
    segment.type(LIEF::ELF::Segment::TYPE::LOAD);
    segment.content(std::vector<uint8_t>(total_size, 0));
    segment.add(LIEF::ELF::Segment::FLAGS::R);
    segment.add(LIEF::ELF::Segment::FLAGS::W);
    segment.add(LIEF::ELF::Segment::FLAGS::X);
    segment.virtual_address(requested_vaddr);
    segment.physical_address(requested_vaddr);
    segment.virtual_size(total_size);
    segment.alignment(kSegmentAlign);

    auto* added = probe_binary->add(segment, requested_vaddr);
    if (added == nullptr) {
        throw std::runtime_error("Failed to reserve Maya payload segment.");
    }
    auto* probe_text_after = probe_binary->get_section(".text");
    if (probe_text_after != nullptr) {
        ctx.final_image_shift = probe_text_after->virtual_address() - probe_text_vaddr;
    }
    if (original_text_vaddr != probe_text_vaddr) {
        throw std::runtime_error(
            "Unexpected .text address mismatch while probing payload placement.");
    }
    ctx.segment_request_bias = added->virtual_address() - requested_vaddr;
    return added->virtual_address();
}

const ProtectedFunction* find_func_containing(const std::vector<ProtectedFunction>& funcs,
                                              uint64_t addr) {
    for (auto& func : funcs) {
        if (addr >= func.original_start && addr < func.original_start + func.size) {
            return &func;
        }
    }
    return nullptr;
}

const ProtectedFunction* find_func_start(const std::vector<ProtectedFunction>& funcs,
                                         uint64_t addr) {
    for (auto& func : funcs) {
        if (func.original_start == addr) {
            return &func;
        }
    }
    return nullptr;
}

bool is_protected_start(const std::vector<ProtectedFunction>& funcs, uint64_t addr) {
    return std::any_of(funcs.begin(), funcs.end(),
                       [addr](const auto& func) { return func.original_start == addr; });
}

std::string symbol_name_at(const ProtectionContext& ctx, uint64_t addr) {
    std::string fallback;
    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.value() != addr || sym.name().empty() || sym.name()[0] == '$') {
            continue;
        }
        if (sym.type() == LIEF::ELF::Symbol::TYPE::FUNC) {
            return sym.name();
        }
        if (fallback.empty()) {
            fallback = sym.name();
        }
    }
    return fallback;
}

} // namespace maya::protection
