#include "FunctionLayout.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <map>
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
    uint64_t user_code_cutoff = text_end;
    uint64_t user_code_start = text_start;
    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.name() == "frame_dummy" && sym.value() != 0) {
            user_code_start = std::max(user_code_start, sym.value());
        }
        if (sym.name() == "call_fini" && sym.value() != 0) {
            user_code_cutoff = std::min(user_code_cutoff, sym.value());
        }
    }

    std::map<uint64_t, ProtectedFunction> by_addr;
    for (const auto& sym : ctx.binary->symtab_symbols()) {
        if (sym.type() != LIEF::ELF::Symbol::TYPE::FUNC || sym.value() == 0 || sym.size() < 4) {
            continue;
        }
        if (sym.value() <= user_code_start || sym.value() >= user_code_cutoff) {
            continue;
        }
        if (!InstrumentationPolicy::should_instrument(sym.name(), sym.value(), text_start, text_end, user_code_cutoff, ctx.options.aggressive_symbols)) {
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

    std::vector<ProtectedFunction> funcs;
    for (auto& entry : by_addr) {
        funcs.push_back(std::move(entry.second));
    }
    std::sort(funcs.begin(), funcs.end(), [](const auto& a, const auto& b) {
        return a.original_start < b.original_start;
    });
    for (size_t i = 0; i < funcs.size(); ++i) {
        funcs[i].id = static_cast<uint32_t>(i);
        if (i + 1 < funcs.size() && funcs[i].original_start + funcs[i].size > funcs[i + 1].original_start) {
            throw std::runtime_error("Overlapping protected functions: " + funcs[i].name + " and " + funcs[i + 1].name);
        }
        auto content = ctx.binary->get_content_from_virtual_address(funcs[i].original_start, funcs[i].size);
        funcs[i].original_bytes.assign(content.begin(), content.end());
        funcs[i].patched_bytes = funcs[i].original_bytes;
        funcs[i].body_size = funcs[i].size;
        Log::info("  protect[" + std::to_string(funcs[i].id) + "] " + funcs[i].name +
                  " @ " + hex(funcs[i].original_start) + " size=" + std::to_string(funcs[i].size));
    }

    Log::info("Selected " + std::to_string(funcs.size()) + " functions for encrypted protection.");
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

void assign_layout(std::vector<ProtectedFunction>& funcs, Layout& layout, uint64_t base, SlotStrategy strategy) {
    layout.base_vaddr = base;
    uint64_t cursor = base;
    layout.return_stub_vaddr = cursor;
    cursor += 512;
    cursor = Utils::align_to(cursor, kAlign);

    for (auto& func : funcs) {
        func.stub_vaddr = cursor;
        cursor += kEntryStubSize;
        cursor = Utils::align_to(cursor, kAlign);
    }

    for (auto& func : funcs) {
        func.enc_vaddr = cursor;
        cursor += encrypted_body_capacity(func, strategy);
        cursor = Utils::align_to(cursor, kAlign);
    }

    layout.key_vaddr = cursor;
    cursor += kKey.size();
    cursor = Utils::align_to(cursor, kAlign);

    layout.callsite_meta_vaddr = cursor;
    layout.callsite_meta_size = estimate_callsite_meta_capacity(funcs);
    cursor += layout.callsite_meta_size;
    cursor = Utils::align_to(cursor, kAlign);

    layout.eh_frame_vaddr = cursor;
    for (auto& func : funcs) {
        if (!func.fde_bytes.empty()) {
            func.fde_vaddr = cursor;
            cursor += func.fde_bytes.size();
            cursor = Utils::align_to(cursor, 8);
        }
    }
    layout.eh_frame_size = cursor - layout.eh_frame_vaddr;
    cursor = Utils::align_to(cursor, kAlign);

    layout.thread_states_vaddr = cursor;
    cursor += kThreadSlotCount * kThreadStateSize;
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
        uint64_t slot_cursor = Utils::align_to(cursor + kSegmentAlign, kPageSize);
        for (auto& func : funcs) {
            func.slot_vaddr = slot_cursor;
            func.slot_size = Utils::align_to(encrypted_body_capacity(func, strategy), kPageSize);
            slot_cursor += func.slot_size;
        }
    }

    layout.total_size = cursor - base;
}

void shift_layout(std::vector<ProtectedFunction>& funcs, Layout& layout, int64_t delta) {
    auto shift = [delta](uint64_t v) {
        return static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
    };
    layout.base_vaddr = shift(layout.base_vaddr);
    layout.return_stub_vaddr = shift(layout.return_stub_vaddr);
    layout.thread_states_vaddr = shift(layout.thread_states_vaddr);
    layout.key_vaddr = shift(layout.key_vaddr);
    layout.callsite_meta_vaddr = shift(layout.callsite_meta_vaddr);
    layout.eh_frame_vaddr = shift(layout.eh_frame_vaddr);
    for (auto& func : funcs) {
        func.stub_vaddr = shift(func.stub_vaddr);
        func.slot_vaddr = shift(func.slot_vaddr);
        func.enc_vaddr = shift(func.enc_vaddr);
        func.active_vaddr = shift(func.active_vaddr);
        if (func.fde_vaddr != 0) {
            func.fde_vaddr = shift(func.fde_vaddr);
        }
    }
}

uint64_t estimate_callsite_meta_capacity(const std::vector<ProtectedFunction>& funcs) {
    uint64_t instruction_slots = 0;
    for (const auto& func : funcs) {
        instruction_slots += func.size / 4;
    }
    return Utils::align_to(instruction_slots * 32, kAlign);
}

uint64_t reserve_payload_vaddr(ProtectionContext& ctx, uint64_t requested_vaddr, uint64_t total_size) {
    auto probe_binary = LIEF::ELF::Parser::parse(ctx.filename);
    if (!probe_binary) {
        throw std::runtime_error("Failed to reparse binary for payload placement.");
    }
    const auto* original_text = ctx.binary->get_section(".text");
    auto* probe_text_before = probe_binary->get_section(".text");
    const uint64_t original_text_vaddr = original_text == nullptr ? 0 : original_text->virtual_address();
    const uint64_t probe_text_vaddr = probe_text_before == nullptr ? original_text_vaddr : probe_text_before->virtual_address();

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
        throw std::runtime_error("Unexpected .text address mismatch while probing payload placement.");
    }
    ctx.segment_request_bias = added->virtual_address() - requested_vaddr;
    return added->virtual_address();
}

const ProtectedFunction* find_func_containing(const std::vector<ProtectedFunction>& funcs, uint64_t addr) {
    for (auto& func : funcs) {
        if (addr >= func.original_start && addr < func.original_start + func.size) {
            return &func;
        }
    }
    return nullptr;
}

const ProtectedFunction* find_func_start(const std::vector<ProtectedFunction>& funcs, uint64_t addr) {
    for (auto& func : funcs) {
        if (func.original_start == addr) {
            return &func;
        }
    }
    return nullptr;
}

bool is_protected_start(const std::vector<ProtectedFunction>& funcs, uint64_t addr) {
    return std::any_of(funcs.begin(), funcs.end(), [addr](const auto& func) {
        return func.original_start == addr;
    });
}

std::string symbol_name_at(const ProtectionContext& ctx, uint64_t addr) {
    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.value() == addr && !sym.name().empty()) {
            return sym.name();
        }
    }
    return {};
}

} // namespace maya::protection
