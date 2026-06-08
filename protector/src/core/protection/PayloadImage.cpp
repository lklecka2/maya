#include "PayloadImage.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>

#include "CodeRelocation.hpp"
#include "RuntimeStubs.hpp"
#include "core/Logger.hpp"
#include "core/RuntimeSchema.hpp"
#include "core/Utils.hpp"

namespace maya::protection {

void write_at(std::vector<uint8_t>& payload, const Layout& layout, uint64_t vaddr, const std::vector<uint8_t>& bytes) {
    const uint64_t off = vaddr - layout.base_vaddr;
    if (off + bytes.size() > payload.size()) {
        throw std::runtime_error("Payload write out of bounds.");
    }
    std::copy(bytes.begin(), bytes.end(), payload.begin() + off);
}

void write_u64(std::vector<uint8_t>& payload, const Layout& layout, uint64_t vaddr, uint64_t value) {
    const uint64_t off = vaddr - layout.base_vaddr;
    if (off + sizeof(value) > payload.size()) {
        throw std::runtime_error("Payload write out of bounds.");
    }
    std::memcpy(payload.data() + off, &value, sizeof(value));
}

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> out = bytes;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] ^= kKey[i & 7u];
    }
    return out;
}

std::vector<uint8_t> encode_callsite_meta(const std::vector<CallsiteMeta>& callsites) {
    std::vector<uint8_t> bytes;
    bytes.reserve(callsites.size() * 32);
    auto append32 = [&](uint32_t value) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
        bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
    };
    auto append64 = [&](uint64_t value) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
        bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
    };
    for (const auto& meta : callsites) {
        append32(meta.caller_func_id);
        append32(meta.callee_func_id);
        append64(meta.original_pc);
        append64(meta.original_return_pc);
        append32(meta.flags);
        append32(meta.reserved);
    }
    return bytes;
}

void emit_payload(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs, const Layout& layout, const std::vector<CallsiteMeta>& callsites, std::vector<uint8_t>& payload) {
    (void)ctx;
    write_at(payload, layout, layout.return_stub_vaddr, make_return_stub(layout, ctx.runtime_features.slot_strategy));
    write_at(payload, layout, layout.key_vaddr, std::vector<uint8_t>(kKey.begin(), kKey.end()));

    for (const auto& func : funcs) {
        write_at(payload, layout, func.stub_vaddr,
                 func.fde_bytes.empty() ? make_entry_stub(func, layout, ctx) : make_eh_entry_stub(func, layout));
        write_at(payload, layout, func.enc_vaddr, encrypt(func.patched_bytes));
        if (!func.fde_bytes.empty()) {
            write_at(payload, layout, func.fde_vaddr, func.fde_bytes);
        }
        write_u64(payload, layout, func.active_vaddr, 0);
    }

    auto meta = encode_callsite_meta(callsites);
    if (!meta.empty()) {
        if (layout.callsite_meta_vaddr + meta.size() > layout.thread_states_vaddr) {
            throw std::runtime_error("Callsite metadata exceeded reserved layout space.");
        }
        write_at(payload, layout, layout.callsite_meta_vaddr, meta);
        Log::info("Recorded " + std::to_string(callsites.size()) + " protected direct-call metadata entries.");
    }
}

void add_payload_segment(ProtectionContext& ctx, const Layout& layout, const std::vector<uint8_t>& payload) {
    LIEF::ELF::Segment segment;
    segment.type(LIEF::ELF::Segment::TYPE::LOAD);
    segment.content(payload);
    segment.add(LIEF::ELF::Segment::FLAGS::R);
    segment.add(LIEF::ELF::Segment::FLAGS::W);
    segment.add(LIEF::ELF::Segment::FLAGS::X);
    const uint64_t requested_vaddr = layout.base_vaddr - ctx.segment_request_bias;
    segment.virtual_address(requested_vaddr);
    segment.physical_address(requested_vaddr);
    segment.virtual_size(payload.size());
    segment.alignment(kSegmentAlign);

    auto* added = ctx.binary->add(segment, requested_vaddr);
    if (added == nullptr) {
        throw std::runtime_error("Failed to add Maya payload segment.");
    }
    if (added->virtual_address() != layout.base_vaddr) {
        throw std::runtime_error(
            "Maya payload segment placed at unexpected address. expected=" +
            hex(layout.base_vaddr) + " actual=" + hex(added->virtual_address())
        );
    }
}

void patch_original_entries(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs) {
    auto* text = ctx.binary->get_section(".text");
    if (text == nullptr) {
        throw std::runtime_error("Missing .text section.");
    }
    auto content = text->content();
    std::vector<uint8_t> buffer(content.begin(), content.end());
    const uint64_t text_start = text->virtual_address();
    const uint64_t text_end = text_start + buffer.size();

    for (const auto& func : funcs) {
        if (func.original_start < text_start || func.original_start + func.size > text_end) {
            throw std::runtime_error("Protected function is not fully contained in .text: " + func.name);
        }
        const size_t off = static_cast<size_t>(func.original_start - text_start);
        std::fill(buffer.begin() + off, buffer.begin() + off + func.size, 0x00);
        for (size_t i = 0; i + 4 <= func.size; i += 4) {
            const uint32_t brk = 0xD4200000u;
            std::memcpy(buffer.data() + off + i, &brk, sizeof(brk));
        }
        const uint32_t branch = make_b(func.original_start + ctx.final_image_shift, func.stub_vaddr);
        std::memcpy(buffer.data() + off, &branch, sizeof(branch));
    }

    text->content(buffer);

    for (auto& segment : ctx.binary->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) {
            continue;
        }
        const uint64_t seg_start = segment.virtual_address();
        const uint64_t seg_end = seg_start + segment.virtual_size();
        if (text_start < seg_start || text_end > seg_end) {
            continue;
        }
        auto seg_content = segment.content();
        std::vector<uint8_t> seg_buffer(seg_content.begin(), seg_content.end());
        const uint64_t text_off = text_start - seg_start;
        if (text_off + buffer.size() <= seg_buffer.size()) {
            std::copy(buffer.begin(), buffer.end(), seg_buffer.begin() + text_off);
            segment.content(seg_buffer);
        }
        break;
    }
}

void verify_plaintext_removed(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs, const std::vector<uint8_t>& payload) {
    auto* text = ctx.binary->get_section(".text");
    if (text == nullptr) {
        return;
    }
    auto text_content = text->content();
    std::vector<uint8_t> text_bytes(text_content.begin(), text_content.end());
    const uint64_t text_start = text->virtual_address();
    for (auto& func : funcs) {
        const uint64_t patched_start = func.original_start + ctx.final_image_shift;
        if (patched_start >= text_start &&
            patched_start + std::min<uint64_t>(func.size, 4) <= text_start + text_bytes.size()) {
            const size_t site_off = static_cast<size_t>(patched_start - text_start);
            if (func.original_bytes.size() >= 4 && site_off + 4 <= text_bytes.size() &&
                !std::equal(func.original_bytes.begin(), func.original_bytes.begin() + 4, text_bytes.begin() + site_off)) {
                func.original_site_patched = true;
            }
        }
        if (!func.original_site_patched) {
            throw std::runtime_error("Original function site was not patched for " + func.name);
        }
        if (func.original_bytes.size() < 16) {
            continue;
        }
        const auto needle_begin = func.original_bytes.begin();
        const auto needle_end = func.original_bytes.begin() + std::min<size_t>(func.original_bytes.size(), 32);
        if (!ctx.options.aggressive_symbols &&
            std::search(text_bytes.begin(), text_bytes.end(), needle_begin, needle_end) != text_bytes.end()) {
            throw std::runtime_error("Plaintext body prefix still present in .text for " + func.name);
        }
        if (std::search(payload.begin(), payload.end(), needle_begin, needle_end) != payload.end()) {
            throw std::runtime_error("Plaintext body prefix present in Maya payload for " + func.name);
        }
        func.plaintext_verified = std::search(text_bytes.begin(), text_bytes.end(), needle_begin, needle_end) == text_bytes.end();
    }
}

void write_report(const ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs, const std::vector<CallsiteMeta>& callsites) {
    const std::string path = ctx.options.report_filename.empty()
        ? ctx.filename + ".protection.tsv"
        : ctx.options.report_filename;
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("Failed to write protection report: " + path);
    }
    out << "scope\tstatus\tkey\tvalue\n";
    out << "runtime\tfeature\tbinary_kind\t" << maya::binary_kind_name(ctx.runtime_features.binary_kind) << "\n";
    out << "runtime\tfeature\tslot_strategy\t" << maya::slot_strategy_name(ctx.runtime_features.slot_strategy) << "\n";
    out << "runtime\tfeature\tcpp_eh_frame\t" << (ctx.runtime_features.has_eh_frame ? "yes" : "no") << "\n";
    out << "runtime\tfeature\tcpp_except_table\t" << (ctx.runtime_features.has_gcc_except_table ? "yes" : "no") << "\n";
    out << "runtime\tfeature\tcpp_eh_protected\t"
        << (ctx.runtime_features.has_gcc_except_table && ctx.runtime_features.has_cpp_personality ? "yes" : "no") << "\n";
    out << "runtime\tfeature\tupx_compatible_layout\t" << (ctx.runtime_features.upx_compatible_layout ? "yes" : "no") << "\n";
    out << "runtime\tfeature\tslot_storage\t"
        << (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator ? "runtime-arena" : "payload-fixed-address")
        << "\n";
    out << "scope\tstatus\tid\taddress\tsize\tname\tentry_stub\tslot\tslot_size\tencrypted"
        << "\tbody_size\trelocation_count\tveneer_count\tliteral_pool_bytes\tallocator_size_class"
        << "\tdirect_calls\ttail_calls\tindirect_calls\tentry_pointer_refs\tplaintext_removed\tactive_state\n";
    for (const auto& func : funcs) {
        const uint64_t pages = Utils::align_to(func.slot_size, kPageSize) / kPageSize;
        out << "application\tprotected\t"
            << func.id << "\t"
            << hex(func.original_start) << "\t"
            << func.size << "\t"
            << func.name << "\t"
            << hex(func.stub_vaddr) << "\t"
            << hex(func.slot_vaddr) << "\t"
            << func.slot_size << "\t"
            << hex(func.enc_vaddr) << "\t"
            << func.body_size << "\t"
            << func.runtime_relocations << "\t"
            << func.veneer_count << "\t"
            << func.literal_pool_bytes << "\t"
            << pages << "-page\t"
            << func.direct_calls << "\t"
            << func.tail_calls << "\t"
            << func.indirect_calls << "\t"
            << func.entry_pointer_refs << "\t"
            << (func.plaintext_verified ? "yes" : (func.original_site_patched ? "site-only" : "small-function")) << "\t"
            << hex(func.active_vaddr) << "\n";
    }

    out << "callsite\tmetadata\tcaller_id\tcallee_id\tpc\treturn_pc\tflags\treserved\n";
    for (const auto& meta : callsites) {
        out << "callsite\tmetadata\t"
            << meta.caller_func_id << "\t"
            << meta.callee_func_id << "\t"
            << hex(meta.original_pc) << "\t"
            << hex(meta.original_return_pc) << "\t"
            << meta.flags << "\t"
            << meta.reserved << "\n";
    }
}

} // namespace maya::protection
