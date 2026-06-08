#include "ExceptionFrames.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace maya::protection {

uint32_t read_u32(const std::vector<uint8_t>& bytes, size_t off) {
    if (off + sizeof(uint32_t) > bytes.size()) {
        throw std::runtime_error("Truncated 32-bit read.");
    }
    uint32_t value = 0;
    std::memcpy(&value, bytes.data() + off, sizeof(value));
    return value;
}

int32_t read_s32(const std::vector<uint8_t>& bytes, size_t off) {
    return static_cast<int32_t>(read_u32(bytes, off));
}

void patch_u32(std::vector<uint8_t>& bytes, size_t off, uint32_t value) {
    if (off + sizeof(value) > bytes.size()) {
        throw std::runtime_error("Truncated 32-bit write.");
    }
    std::memcpy(bytes.data() + off, &value, sizeof(value));
}

void patch_s32(std::vector<uint8_t>& bytes, size_t off, int64_t value) {
    if (value < INT32_MIN || value > INT32_MAX) {
        throw std::runtime_error("EH pcrel value is out of sdata4 range.");
    }
    patch_u32(bytes, off, static_cast<uint32_t>(static_cast<int32_t>(value)));
}

std::pair<uint64_t, size_t> read_uleb128(const std::vector<uint8_t>& bytes, size_t off) {
    uint64_t value = 0;
    unsigned shift = 0;
    size_t cursor = off;
    while (cursor < bytes.size()) {
        const uint8_t byte = bytes[cursor++];
        value |= static_cast<uint64_t>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0) {
            return {value, cursor - off};
        }
        shift += 7;
        if (shift >= 64) {
            break;
        }
    }
    throw std::runtime_error("Malformed ULEB128 in EH metadata.");
}

std::vector<EhHdrEntry> read_eh_hdr_entries(const ProtectionContext& ctx) {
    auto* hdr = ctx.binary->get_section(".eh_frame_hdr");
    if (hdr == nullptr) {
        throw std::runtime_error("C++ EH support requires .eh_frame_hdr.");
    }
    auto content = hdr->content();
    std::vector<uint8_t> bytes(content.begin(), content.end());
    if (bytes.size() < 12 || bytes[0] != 1 || bytes[1] != 0x1b || bytes[2] != 0x03 || bytes[3] != 0x3b) {
        throw std::runtime_error("Unsupported .eh_frame_hdr encoding; expected pcrel/datarel sdata4 table.");
    }
    const uint32_t count = read_u32(bytes, 8);
    if (12ull + static_cast<uint64_t>(count) * 8ull > bytes.size()) {
        throw std::runtime_error("Truncated .eh_frame_hdr binary search table.");
    }
    std::vector<EhHdrEntry> entries;
    entries.reserve(count);
    const uint64_t base = hdr->virtual_address();
    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = 12 + static_cast<size_t>(i) * 8;
        entries.push_back({
            static_cast<uint64_t>(static_cast<int64_t>(base) + read_s32(bytes, off)),
            static_cast<uint64_t>(static_cast<int64_t>(base) + read_s32(bytes, off + 4))
        });
    }
    return entries;
}

void prepare_eh_frame_clones(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs) {
    if (!ctx.runtime_features.has_gcc_except_table || !ctx.runtime_features.has_cpp_personality) {
        return;
    }
    auto* eh = ctx.binary->get_section(".eh_frame");
    if (eh == nullptr) {
        throw std::runtime_error("C++ EH binary is missing .eh_frame.");
    }
    auto content = eh->content();
    std::vector<uint8_t> eh_bytes(content.begin(), content.end());
    const uint64_t eh_base = eh->virtual_address();
    const auto entries = read_eh_hdr_entries(ctx);

    for (auto& func : funcs) {
        auto it = std::find_if(entries.begin(), entries.end(), [&](const EhHdrEntry& entry) {
            return entry.pc == func.original_start;
        });
        if (it == entries.end()) {
            throw std::runtime_error("Protected C++ EH function has no .eh_frame_hdr entry: " + func.name);
        }
        if (it->fde < eh_base || it->fde >= eh_base + eh_bytes.size()) {
            throw std::runtime_error("Protected C++ EH function FDE is outside .eh_frame: " + func.name);
        }
        const size_t fde_off = static_cast<size_t>(it->fde - eh_base);
        const uint32_t length = read_u32(eh_bytes, fde_off);
        if (length == 0 || length == 0xffffffffu) {
            throw std::runtime_error("Unsupported FDE length for " + func.name);
        }
        const size_t record_size = static_cast<size_t>(length) + 4;
        if (fde_off + record_size > eh_bytes.size() || record_size < 16) {
            throw std::runtime_error("Truncated FDE for " + func.name);
        }
        func.fde_bytes.assign(eh_bytes.begin() + fde_off, eh_bytes.begin() + fde_off + record_size);
        func.fde_pc_begin = it->pc;
    }
}

void relocate_fde_clone(const ProtectionContext& ctx, ProtectedFunction& func) {
    if (func.fde_bytes.empty()) {
        return;
    }
    const uint64_t old_fde = func.fde_pc_begin == 0 ? 0 : 1;
    (void)old_fde;
    const uint64_t new_fde = func.fde_vaddr;
    const uint64_t cie_field_vaddr = new_fde + 4;
    const uint32_t old_cie_delta = read_u32(func.fde_bytes, 4);
    const uint64_t old_fde_vaddr = static_cast<uint64_t>(
        static_cast<int64_t>(func.fde_pc_begin) -
        read_s32(func.fde_bytes, 8)
    ) - 8;
    const uint64_t old_cie_vaddr = (old_fde_vaddr + 4) - old_cie_delta + ctx.final_image_shift;

    patch_u32(func.fde_bytes, 4, static_cast<uint32_t>(cie_field_vaddr - old_cie_vaddr));
    patch_s32(func.fde_bytes, 8, static_cast<int64_t>(func.slot_vaddr) - static_cast<int64_t>(new_fde + 8));
    patch_u32(func.fde_bytes, 12, static_cast<uint32_t>(func.size));

    if (func.fde_bytes.size() > 17) {
        auto [aug_size, leb_size] = read_uleb128(func.fde_bytes, 16);
        const size_t lsda_off = 16 + leb_size;
        if (aug_size >= 4 && lsda_off + 4 <= func.fde_bytes.size()) {
            const uint64_t old_lsda_field = old_fde_vaddr + lsda_off;
            const uint64_t old_lsda = static_cast<uint64_t>(
                static_cast<int64_t>(old_lsda_field) + read_s32(func.fde_bytes, lsda_off)
            ) + ctx.final_image_shift;
            patch_s32(func.fde_bytes, lsda_off, static_cast<int64_t>(old_lsda) - static_cast<int64_t>(new_fde + lsda_off));
        }
    }
}

void patch_eh_frame_header(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs) {
    bool has_clones = false;
    for (const auto& func : funcs) {
        has_clones = has_clones || !func.fde_bytes.empty();
    }
    if (!has_clones) {
        return;
    }
    auto* hdr = ctx.binary->get_section(".eh_frame_hdr");
    if (hdr == nullptr) {
        throw std::runtime_error("C++ EH support requires .eh_frame_hdr.");
    }
    auto content = hdr->content();
    std::vector<uint8_t> bytes(content.begin(), content.end());
    auto entries = read_eh_hdr_entries(ctx);
    for (auto& entry : entries) {
        entry.pc += ctx.final_image_shift;
        entry.fde += ctx.final_image_shift;
    }
    for (const auto& func : funcs) {
        if (func.fde_bytes.empty()) {
            continue;
        }
        auto it = std::find_if(entries.begin(), entries.end(), [&](const EhHdrEntry& entry) {
            return entry.pc == func.original_start + ctx.final_image_shift;
        });
        if (it == entries.end()) {
            throw std::runtime_error("Failed to replace EH table entry for " + func.name);
        }
        it->pc = func.slot_vaddr;
        it->fde = func.fde_vaddr;
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.pc < b.pc;
    });
    const uint64_t base = hdr->virtual_address() + ctx.final_image_shift;
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t off = 12 + i * 8;
        patch_s32(bytes, off, static_cast<int64_t>(entries[i].pc) - static_cast<int64_t>(base));
        patch_s32(bytes, off + 4, static_cast<int64_t>(entries[i].fde) - static_cast<int64_t>(base));
    }
    hdr->content(bytes);
    for (auto& segment : ctx.binary->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) {
            continue;
        }
        const uint64_t seg_start = segment.virtual_address();
        const uint64_t hdr_start = hdr->virtual_address();
        const uint64_t hdr_end = hdr_start + bytes.size();
        if (hdr_start < seg_start || hdr_end > seg_start + segment.virtual_size()) {
            continue;
        }
        auto seg_content = segment.content();
        std::vector<uint8_t> seg_buffer(seg_content.begin(), seg_content.end());
        const uint64_t hdr_off = hdr_start - seg_start;
        if (hdr_off + bytes.size() <= seg_buffer.size()) {
            std::copy(bytes.begin(), bytes.end(), seg_buffer.begin() + hdr_off);
            segment.content(seg_buffer);
        }
        break;
    }
}

} // namespace maya::protection
