#include "ExceptionFrames.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
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

uint64_t read_u64(const std::vector<uint8_t>& bytes, size_t off) {
    if (off + sizeof(uint64_t) > bytes.size()) {
        throw std::runtime_error("Truncated 64-bit read.");
    }
    uint64_t value = 0;
    std::memcpy(&value, bytes.data() + off, sizeof(value));
    return value;
}

int32_t read_s32(const std::vector<uint8_t>& bytes, size_t off) {
    return static_cast<int32_t>(read_u32(bytes, off));
}

int64_t read_s64(const std::vector<uint8_t>& bytes, size_t off) {
    return static_cast<int64_t>(read_u64(bytes, off));
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

void patch_s64(std::vector<uint8_t>& bytes, size_t off, int64_t value) {
    if (off + sizeof(value) > bytes.size()) {
        throw std::runtime_error("Truncated 64-bit write.");
    }
    std::memcpy(bytes.data() + off, &value, sizeof(value));
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

std::pair<int64_t, size_t> read_sleb128(const std::vector<uint8_t>& bytes, size_t off) {
    uint64_t value = 0;
    unsigned shift = 0;
    size_t cursor = off;
    uint8_t byte = 0;
    while (cursor < bytes.size()) {
        byte = bytes[cursor++];
        value |= static_cast<uint64_t>(byte & 0x7fu) << shift;
        shift += 7;
        if ((byte & 0x80u) == 0) {
            if (shift < 64 && (byte & 0x40u) != 0) {
                value |= (~0ull << shift);
            }
            return {static_cast<int64_t>(value), cursor - off};
        }
        if (shift >= 64) {
            break;
        }
    }
    throw std::runtime_error("Malformed SLEB128 in EH metadata.");
}

size_t eh_encoded_size(uint8_t encoding) {
    switch (encoding & 0x0fu) {
    case 0x00:
        return sizeof(uint64_t); // absptr
    case 0x01:
        return 0; // uleb128, variable
    case 0x02:
        return 2; // udata2
    case 0x03:
        return 4; // udata4
    case 0x04:
        return 8; // udata8
    case 0x09:
        return 0; // sleb128, variable
    case 0x0a:
        return 2; // sdata2
    case 0x0b:
        return 4; // sdata4
    case 0x0c:
        return 8; // sdata8
    default:
        throw std::runtime_error("Unsupported EH pointer encoding.");
    }
}

std::vector<EhHeaderEntry> read_eh_hdr_entries(const ProtectionContext& ctx);

namespace {

struct DecodedEhValue {
    uint64_t value = 0;
    size_t size = 0;
};

DecodedEhValue decode_eh_value(const std::vector<uint8_t>& bytes, size_t off, uint64_t section_base,
                               uint8_t encoding, uint64_t data_base = 0,
                               uint64_t function_base = 0) {
    if (encoding == 0xffu)
        throw std::runtime_error("Attempted to decode an omitted EH pointer.");
    const uint8_t format = encoding & 0x0fu;
    uint64_t raw = 0;
    int64_t signed_raw = 0;
    size_t size = 0;
    switch (format) {
    case 0x00:
        raw = read_u64(bytes, off);
        size = 8;
        break;
    case 0x01: {
        const auto v = read_uleb128(bytes, off);
        raw = v.first;
        size = v.second;
        break;
    }
    case 0x03:
        raw = read_u32(bytes, off);
        size = 4;
        break;
    case 0x04:
        raw = read_u64(bytes, off);
        size = 8;
        break;
    case 0x09: {
        const auto v = read_sleb128(bytes, off);
        signed_raw = v.first;
        raw = static_cast<uint64_t>(signed_raw);
        size = v.second;
        break;
    }
    case 0x0b:
        signed_raw = read_s32(bytes, off);
        raw = static_cast<uint64_t>(signed_raw);
        size = 4;
        break;
    case 0x0c:
        signed_raw = read_s64(bytes, off);
        raw = static_cast<uint64_t>(signed_raw);
        size = 8;
        break;
    default:
        throw std::runtime_error("Unsupported EH pointer encoding format " +
                                 std::to_string(format) + ".");
    }
    const bool signed_format = format == 0x09 || format == 0x0a || format == 0x0b || format == 0x0c;
    const int64_t delta = signed_format ? static_cast<int64_t>(raw) : static_cast<int64_t>(raw);
    uint64_t value = raw;
    switch (encoding & 0x70u) {
    case 0x00:
        break;
    case 0x10:
        value = static_cast<uint64_t>(static_cast<int64_t>(section_base + off) + delta);
        break;
    case 0x30:
        value = static_cast<uint64_t>(static_cast<int64_t>(data_base) + delta);
        break;
    case 0x40:
        value = static_cast<uint64_t>(static_cast<int64_t>(function_base) + delta);
        break;
    default:
        throw std::runtime_error("Unsupported EH relative pointer application " +
                                 std::to_string(encoding & 0x70u) + ".");
    }
    return {value, size};
}

uint64_t read_image_u64(const ProtectionContext& ctx, uint64_t address) {
    const auto bytes = ctx.binary->get_content_from_virtual_address(address, sizeof(uint64_t));
    if (bytes.size() != sizeof(uint64_t)) {
        throw std::runtime_error("EH indirect pointer is outside the load image: " +
                                 std::to_string(address));
    }
    uint64_t value = 0;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

DecodedEhValue decode_image_eh_value(const ProtectionContext& ctx,
                                     const std::vector<uint8_t>& bytes, size_t off,
                                     uint64_t section_base, uint8_t encoding,
                                     uint64_t data_base = 0, uint64_t function_base = 0) {
    auto decoded = decode_eh_value(bytes, off, section_base, encoding, data_base, function_base);
    if ((encoding & 0x80u) != 0)
        decoded.value = read_image_u64(ctx, decoded.value);
    return decoded;
}

void require_record_bounds(size_t cursor, size_t count, size_t end, const char* what) {
    if (cursor > end || count > end - cursor) {
        throw std::runtime_error(std::string("Truncated ") + what + " in EH metadata.");
    }
}

} // namespace

EhMetadata parse_eh_metadata_from_spans(const ProtectionContext& ctx, uint64_t pc_begin,
                                        EhByteSpan eh_frame, uint64_t eh_base,
                                        const std::vector<EhHeaderEntry>& entries, EhByteSpan lsda,
                                        uint64_t lsda_base) {
    if ((eh_frame.size != 0 && eh_frame.data == nullptr) ||
        (lsda.size != 0 && lsda.data == nullptr)) {
        throw std::runtime_error("Null EH byte span.");
    }
    if (eh_frame.size == 0)
        throw std::runtime_error("Empty .eh_frame byte span.");
    const std::vector<uint8_t> bytes(eh_frame.data, eh_frame.data + eh_frame.size);
    const auto entry = std::find_if(entries.begin(), entries.end(),
                                    [&](const auto& item) { return item.pc == pc_begin; });
    if (entry == entries.end())
        throw std::runtime_error("No FDE covers protected EH function " + std::to_string(pc_begin));
    if (entry->fde < eh_base || entry->fde >= eh_base + bytes.size()) {
        throw std::runtime_error("FDE is outside .eh_frame.");
    }

    EhMetadata metadata;
    metadata.fde_vaddr = entry->fde;
    const size_t fde_off = static_cast<size_t>(entry->fde - eh_base);
    const uint32_t fde_length = read_u32(bytes, fde_off);
    if (fde_length == 0 || fde_length == 0xffffffffu)
        throw std::runtime_error("Unsupported FDE length.");
    const size_t fde_end = fde_off + 4 + fde_length;
    require_record_bounds(fde_off, 4 + fde_length, bytes.size(), "FDE");
    const uint32_t cie_delta = read_u32(bytes, fde_off + 4);
    if (cie_delta > fde_off + 4)
        throw std::runtime_error("FDE CIE pointer underflows .eh_frame.");
    const size_t cie_off = fde_off + 4 - cie_delta;
    metadata.cie_vaddr = eh_base + cie_off;
    const uint32_t cie_length = read_u32(bytes, cie_off);
    if (cie_length == 0 || cie_length == 0xffffffffu)
        throw std::runtime_error("Unsupported CIE length.");
    const size_t cie_end = cie_off + 4 + cie_length;
    require_record_bounds(cie_off, 4 + cie_length, bytes.size(), "CIE");
    if (read_u32(bytes, cie_off + 4) != 0)
        throw std::runtime_error("FDE points to a non-CIE record.");

    size_t cursor = cie_off + 8;
    require_record_bounds(cursor, 1, cie_end, "CIE version");
    const uint8_t version = bytes[cursor++];
    if (version != 1 && version != 3 && version != 4)
        throw std::runtime_error("Unsupported CIE version.");
    while (cursor < cie_end && bytes[cursor] != 0)
        metadata.augmentation.push_back(static_cast<char>(bytes[cursor++]));
    require_record_bounds(cursor, 1, cie_end, "CIE augmentation string");
    ++cursor;
    {
        const auto v = read_uleb128(bytes, cursor);
        metadata.code_alignment = v.first;
        cursor += v.second;
    }
    {
        const auto v = read_sleb128(bytes, cursor);
        metadata.data_alignment = v.first;
        cursor += v.second;
    }
    if (version == 1) {
        require_record_bounds(cursor, 1, cie_end, "CIE return register");
        metadata.return_register = bytes[cursor++];
    } else {
        const auto v = read_uleb128(bytes, cursor);
        metadata.return_register = v.first;
        cursor += v.second;
    }
    if (!metadata.augmentation.empty() && metadata.augmentation.front() == 'z') {
        const auto aug = read_uleb128(bytes, cursor);
        cursor += aug.second;
        const size_t aug_end = cursor + static_cast<size_t>(aug.first);
        require_record_bounds(cursor, static_cast<size_t>(aug.first), cie_end,
                              "CIE augmentation data");
        for (size_t i = 1; i < metadata.augmentation.size(); ++i) {
            switch (metadata.augmentation[i]) {
            case 'P': {
                require_record_bounds(cursor, 1, aug_end, "CIE personality encoding");
                const uint8_t encoding = bytes[cursor++];
                const auto raw = decode_eh_value(bytes, cursor, eh_base, encoding);
                metadata.personality_encoding = encoding;
                metadata.personality_field_offset = cursor - cie_off;
                metadata.personality_pointer = raw.value;
                metadata.personality =
                    (encoding & 0x80u) != 0 ? read_image_u64(ctx, raw.value) : raw.value;
                cursor += raw.size;
                break;
            }
            case 'L':
                require_record_bounds(cursor, 1, aug_end, "CIE LSDA encoding");
                metadata.lsda_encoding = bytes[cursor++];
                break;
            case 'R':
                require_record_bounds(cursor, 1, aug_end, "CIE FDE encoding");
                metadata.fde_encoding = bytes[cursor++];
                break;
            case 'S':
                break;
            default:
                throw std::runtime_error("Unsupported CIE augmentation character: " +
                                         std::string(1, metadata.augmentation[i]));
            }
        }
        cursor = aug_end;
    }
    metadata.cie_cfi.assign(bytes.begin() + cursor, bytes.begin() + cie_end);
    if (metadata.fde_encoding == 0xffu)
        metadata.fde_encoding = 0x00u;

    cursor = fde_off + 8;
    auto pc = decode_image_eh_value(ctx, bytes, cursor, eh_base, metadata.fde_encoding);
    metadata.pc_begin = pc.value;
    cursor += pc.size;
    const uint8_t range_encoding = metadata.fde_encoding & 0x0fu;
    auto range = decode_eh_value(bytes, cursor, eh_base, range_encoding);
    metadata.pc_range = range.value;
    cursor += range.size;
    if (metadata.pc_begin != pc_begin)
        throw std::runtime_error("FDE PC does not match requested function.");
    if (!metadata.augmentation.empty() && metadata.augmentation.front() == 'z') {
        const auto aug = read_uleb128(bytes, cursor);
        cursor += aug.second;
        const size_t aug_end = cursor + static_cast<size_t>(aug.first);
        require_record_bounds(cursor, static_cast<size_t>(aug.first), fde_end,
                              "FDE augmentation data");
        if (metadata.lsda_encoding != 0xffu && cursor < aug_end) {
            const auto lsda = decode_image_eh_value(ctx, bytes, cursor, eh_base,
                                                    metadata.lsda_encoding, 0, metadata.pc_begin);
            metadata.lsda_vaddr = lsda.value;
        }
        cursor = aug_end;
    }
    metadata.fde_cfi.assign(bytes.begin() + cursor, bytes.begin() + fde_end);

    if (metadata.lsda_vaddr == 0)
        return metadata;
    if (lsda.size == 0)
        throw std::runtime_error("FDE references missing LSDA bytes.");
    std::vector<uint8_t> all_lsda;
    if (lsda.size != 0)
        all_lsda.assign(lsda.data, lsda.data + lsda.size);
    if (metadata.lsda_vaddr < lsda_base || metadata.lsda_vaddr >= lsda_base + all_lsda.size()) {
        throw std::runtime_error("LSDA pointer is outside .gcc_except_table.");
    }
    const size_t lsda_off = static_cast<size_t>(metadata.lsda_vaddr - lsda_base);
    cursor = lsda_off;
    require_record_bounds(cursor, 1, all_lsda.size(), "LSDA LPStart encoding");
    const uint8_t lp_encoding = all_lsda[cursor++];
    metadata.lpstart = metadata.pc_begin;
    if (lp_encoding != 0xffu) {
        const auto lp = decode_image_eh_value(ctx, all_lsda, cursor, lsda_base, lp_encoding,
                                              lsda_base, metadata.pc_begin);
        metadata.lpstart = lp.value;
        cursor += lp.size;
    }
    require_record_bounds(cursor, 1, all_lsda.size(), "LSDA type-table encoding");
    metadata.type_encoding = all_lsda[cursor++];
    size_t type_table_off = 0;
    if (metadata.type_encoding != 0xffu) {
        const auto type_delta = read_uleb128(all_lsda, cursor);
        cursor += type_delta.second;
        if (type_delta.first > all_lsda.size() - cursor)
            throw std::runtime_error("LSDA type table is out of bounds.");
        type_table_off = cursor + static_cast<size_t>(type_delta.first);
        metadata.type_table_vaddr = lsda_base + type_table_off;
    }
    require_record_bounds(cursor, 1, all_lsda.size(), "LSDA call-site encoding");
    metadata.call_site_encoding = all_lsda[cursor++];
    if ((metadata.call_site_encoding & 0x70u) != 0 || (metadata.call_site_encoding & 0x80u) != 0) {
        throw std::runtime_error("LSDA call-site table uses a relative or indirect encoding.");
    }
    const auto call_size = read_uleb128(all_lsda, cursor);
    cursor += call_size.second;
    const size_t call_begin = cursor;
    const size_t call_end = call_begin + static_cast<size_t>(call_size.first);
    require_record_bounds(call_begin, static_cast<size_t>(call_size.first), all_lsda.size(),
                          "LSDA call-site table");
    metadata.call_site_table_vaddr = lsda_base + call_begin;
    metadata.call_site_table_size = call_size.first;
    while (cursor < call_end) {
        EhCallSite site;
        auto field = decode_eh_value(all_lsda, cursor, lsda_base, metadata.call_site_encoding);
        site.start = metadata.lpstart + field.value;
        cursor += field.size;
        field = decode_eh_value(all_lsda, cursor, lsda_base, metadata.call_site_encoding);
        site.length = field.value;
        cursor += field.size;
        field = decode_eh_value(all_lsda, cursor, lsda_base, metadata.call_site_encoding);
        site.landing_pad = field.value == 0 ? 0 : metadata.lpstart + field.value;
        cursor += field.size;
        const auto action = read_uleb128(all_lsda, cursor);
        site.action_offset = action.first;
        cursor += action.second;
        if (site.start < metadata.lpstart || site.length > metadata.pc_range ||
            site.start - metadata.lpstart > metadata.pc_range - site.length) {
            throw std::runtime_error("LSDA call-site range escapes its FDE.");
        }
        if (site.landing_pad != 0 && (site.landing_pad < metadata.pc_begin ||
                                      site.landing_pad >= metadata.pc_begin + metadata.pc_range)) {
            throw std::runtime_error("LSDA landing pad escapes its FDE.");
        }
        metadata.call_sites.push_back(site);
    }
    if (cursor != call_end)
        throw std::runtime_error("LSDA call-site table is not record aligned.");
    const size_t action_base = call_end;
    std::set<size_t> pending;
    for (const auto& site : metadata.call_sites)
        if (site.action_offset != 0)
            pending.insert(action_base + site.action_offset - 1);
    std::set<size_t> seen;
    while (!pending.empty()) {
        const size_t action_off = *pending.begin();
        pending.erase(pending.begin());
        if (!seen.insert(action_off).second)
            continue;
        if (action_off >= all_lsda.size() || (type_table_off != 0 && action_off >= type_table_off))
            throw std::runtime_error("LSDA action offset is out of bounds.");
        const auto filter = read_sleb128(all_lsda, action_off);
        const auto next = read_sleb128(all_lsda, action_off + filter.second);
        metadata.actions.push_back({action_off - lsda_off, filter.first, next.first});
        if (next.first != 0) {
            const int64_t target = static_cast<int64_t>(action_off) + next.first;
            if (target < 0)
                throw std::runtime_error("LSDA action chain underflows.");
            pending.insert(static_cast<size_t>(target));
        }
    }
    std::sort(metadata.actions.begin(), metadata.actions.end(),
              [](const auto& a, const auto& b) { return a.table_offset < b.table_offset; });
    if (type_table_off != 0) {
        const size_t type_size = eh_encoded_size(metadata.type_encoding);
        if (type_size == 0)
            throw std::runtime_error("Variable-sized LSDA type table encoding is unsupported.");
        std::set<uint64_t> indices;
        for (const auto& action : metadata.actions)
            if (action.type_filter > 0)
                indices.insert(static_cast<uint64_t>(action.type_filter));
        for (const uint64_t index : indices) {
            if (index > type_table_off / type_size)
                throw std::runtime_error("LSDA type index underflows its table.");
            const size_t type_off = type_table_off - static_cast<size_t>(index) * type_size;
            const auto type =
                decode_image_eh_value(ctx, all_lsda, type_off, lsda_base, metadata.type_encoding,
                                      lsda_base, metadata.pc_begin);
            metadata.types.push_back({index, type.value});
        }
    }
    size_t lsda_end = type_table_off != 0 ? type_table_off : call_end;
    for (const auto& action : metadata.actions)
        lsda_end = std::max(lsda_end, lsda_off + action.table_offset + size_t{2});
    lsda_end = std::min(lsda_end, all_lsda.size());
    metadata.lsda_bytes.assign(all_lsda.begin() + lsda_off, all_lsda.begin() + lsda_end);
    return metadata;
}

EhMetadata parse_eh_metadata(const ProtectionContext& ctx, uint64_t pc_begin) {
    auto* eh = ctx.binary->get_section(".eh_frame");
    if (eh == nullptr)
        throw std::runtime_error("C++ EH binary is missing .eh_frame.");
    const auto eh_content = eh->content();
    auto* lsda_section = ctx.binary->get_section(".gcc_except_table");
    std::vector<uint8_t> lsda_content;
    uint64_t lsda_base = 0;
    if (lsda_section != nullptr) {
        const auto content = lsda_section->content();
        lsda_content.assign(content.begin(), content.end());
        lsda_base = lsda_section->virtual_address();
    }
    return parse_eh_metadata_from_spans(ctx, pc_begin, {eh_content.data(), eh_content.size()},
                                        eh->virtual_address(), read_eh_hdr_entries(ctx),
                                        {lsda_content.data(), lsda_content.size()}, lsda_base);
}

uint8_t read_cie_lsda_encoding(const std::vector<uint8_t>& eh_bytes, uint64_t eh_base,
                               uint64_t cie_vaddr) {
    if (cie_vaddr < eh_base || cie_vaddr >= eh_base + eh_bytes.size()) {
        throw std::runtime_error("CIE is outside .eh_frame.");
    }
    const size_t cie_off = static_cast<size_t>(cie_vaddr - eh_base);
    const uint32_t length = read_u32(eh_bytes, cie_off);
    if (length == 0 || length == 0xffffffffu ||
        cie_off + static_cast<size_t>(length) + 4 > eh_bytes.size()) {
        throw std::runtime_error("Unsupported CIE length in EH metadata.");
    }
    size_t cursor = cie_off + 8;
    if (cursor >= eh_bytes.size()) {
        throw std::runtime_error("Truncated CIE in EH metadata.");
    }
    ++cursor; // version
    std::string augmentation;
    while (cursor < eh_bytes.size() && eh_bytes[cursor] != 0) {
        augmentation.push_back(static_cast<char>(eh_bytes[cursor++]));
    }
    if (cursor >= eh_bytes.size()) {
        throw std::runtime_error("Unterminated CIE augmentation string.");
    }
    ++cursor;
    cursor += read_uleb128(eh_bytes, cursor).second;
    cursor += read_sleb128(eh_bytes, cursor).second;
    cursor += read_uleb128(eh_bytes, cursor).second;
    if (augmentation.empty() || augmentation[0] != 'z') {
        return 0xffu;
    }
    cursor += read_uleb128(eh_bytes, cursor).second;
    for (size_t i = 1; i < augmentation.size(); ++i) {
        switch (augmentation[i]) {
        case 'P': {
            if (cursor >= eh_bytes.size()) {
                throw std::runtime_error("Truncated CIE personality encoding.");
            }
            const uint8_t encoding = eh_bytes[cursor++];
            const size_t size = eh_encoded_size(encoding);
            if (size == 0) {
                throw std::runtime_error("Unsupported variable-sized CIE personality encoding.");
            }
            cursor += size;
            break;
        }
        case 'L':
            if (cursor >= eh_bytes.size()) {
                throw std::runtime_error("Truncated CIE LSDA encoding.");
            }
            return eh_bytes[cursor++];
        case 'R':
            if (cursor >= eh_bytes.size()) {
                throw std::runtime_error("Truncated CIE FDE encoding.");
            }
            ++cursor;
            break;
        default:
            break;
        }
    }
    return 0xffu;
}

int64_t read_encoded_signed_value(const std::vector<uint8_t>& bytes, size_t off, uint8_t encoding) {
    switch (encoding & 0x0fu) {
    case 0x0b:
        return read_s32(bytes, off);
    case 0x0c:
        return read_s64(bytes, off);
    default:
        throw std::runtime_error("Unsupported LSDA pointer encoding in FDE clone.");
    }
}

void patch_encoded_signed_value(std::vector<uint8_t>& bytes, size_t off, uint8_t encoding,
                                int64_t value) {
    switch (encoding & 0x0fu) {
    case 0x0b:
        patch_s32(bytes, off, value);
        return;
    case 0x0c:
        patch_s64(bytes, off, value);
        return;
    default:
        throw std::runtime_error("Unsupported LSDA pointer encoding in FDE clone.");
    }
}

std::vector<EhHeaderEntry> read_eh_hdr_entries(const ProtectionContext& ctx) {
    auto* hdr = ctx.binary->get_section(".eh_frame_hdr");
    if (hdr == nullptr) {
        throw std::runtime_error("C++ EH support requires .eh_frame_hdr.");
    }
    auto content = hdr->content();
    std::vector<uint8_t> bytes(content.begin(), content.end());
    if (bytes.size() < 12 || bytes[0] != 1 || bytes[1] != 0x1b || bytes[2] != 0x03 ||
        bytes[3] != 0x3b) {
        throw std::runtime_error(
            "Unsupported .eh_frame_hdr encoding; expected pcrel/datarel sdata4 table.");
    }
    const uint32_t count = read_u32(bytes, 8);
    if (12ull + static_cast<uint64_t>(count) * 8ull > bytes.size()) {
        throw std::runtime_error("Truncated .eh_frame_hdr binary search table.");
    }
    std::vector<EhHeaderEntry> entries;
    entries.reserve(count);
    const uint64_t base = hdr->virtual_address();
    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = 12 + static_cast<size_t>(i) * 8;
        entries.push_back(
            {static_cast<uint64_t>(static_cast<int64_t>(base) + read_s32(bytes, off)),
             static_cast<uint64_t>(static_cast<int64_t>(base) + read_s32(bytes, off + 4))});
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
    uint64_t register_frame = 0;
    uint64_t deregister_frame = 0;
    uint64_t unwind_resume = 0;
    uint64_t cxa_throw = 0;
    uint64_t cxa_rethrow = 0;
    for (const auto& symbol : ctx.binary->symbols()) {
        if (symbol.name() == "__register_frame" && symbol.value() != 0)
            register_frame = symbol.value();
        if (symbol.name() == "__deregister_frame" && symbol.value() != 0)
            deregister_frame = symbol.value();
        if ((symbol.name() == "_Unwind_Resume" || symbol.name() == "_Unwind_Resume_or_Rethrow") &&
            symbol.value() != 0 && unwind_resume == 0)
            unwind_resume = symbol.value();
        if (symbol.name().find("__cxa_throw") != std::string::npos && symbol.value() != 0)
            cxa_throw = symbol.value();
        if (symbol.name().find("__cxa_rethrow") != std::string::npos && symbol.value() != 0)
            cxa_rethrow = symbol.value();
    }

    for (auto& func : funcs) {
        auto it = std::find_if(entries.begin(), entries.end(), [&](const EhHeaderEntry& entry) {
            return entry.pc == func.original_start;
        });
        if (it == entries.end()) {
            throw std::runtime_error("Protected C++ EH function has no .eh_frame_hdr entry: " +
                                     func.name);
        }
        if (it->fde < eh_base || it->fde >= eh_base + eh_bytes.size()) {
            throw std::runtime_error("Protected C++ EH function FDE is outside .eh_frame: " +
                                     func.name);
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
        func.eh_metadata = parse_eh_metadata(ctx, func.original_start);
        const size_t cie_off = static_cast<size_t>(func.eh_metadata.cie_vaddr - eh_base);
        const uint32_t cie_length = read_u32(eh_bytes, cie_off);
        if (cie_length == 0 || cie_length == 0xffffffffu ||
            cie_off + 4ull + cie_length > eh_bytes.size()) {
            throw std::runtime_error("Unsupported CIE record for " + func.name);
        }
        func.cie_bytes.assign(eh_bytes.begin() + cie_off,
                              eh_bytes.begin() + cie_off + 4 + cie_length);
        func.eh_metadata.register_frame = register_frame;
        func.eh_metadata.deregister_frame = deregister_frame;
        func.eh_metadata.unwind_resume = unwind_resume;
        func.eh_metadata.cxa_throw = cxa_throw;
        func.eh_metadata.cxa_rethrow = cxa_rethrow;
        if (func.eh_metadata.pc_range < func.size) {
            throw std::runtime_error("EH FDE does not cover the complete protected function: " +
                                     func.name);
        }
    }
}

void relocate_fde_clone(const ProtectionContext& ctx, ProtectedFunction& func) {
    if (func.fde_bytes.empty()) {
        return;
    }
    if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
        func.selected_backend == SelectedBackend::Fragment &&
        (func.eh_metadata.register_frame == 0 || func.eh_metadata.deregister_frame == 0)) {
        throw std::runtime_error(
            "Fragment-native EH requires __register_frame and __deregister_frame bridges: " +
            func.name);
    }
    func.eh_metadata.register_frame += ctx.final_image_shift;
    func.eh_metadata.deregister_frame += ctx.final_image_shift;
    func.eh_metadata.unwind_resume += ctx.final_image_shift;
    func.eh_metadata.cxa_throw += ctx.final_image_shift;
    func.eh_metadata.cxa_rethrow += ctx.final_image_shift;
    const uint64_t old_fde = func.fde_pc_begin == 0 ? 0 : 1;
    (void)old_fde;
    const bool runtime_registered =
        ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
        func.selected_backend == SelectedBackend::Fragment;
    const uint64_t new_fde =
        runtime_registered ? func.eh_metadata.fde_vaddr + ctx.final_image_shift : func.fde_vaddr;
    const uint64_t cie_field_vaddr = new_fde + 4;
    const uint32_t old_cie_delta = read_u32(func.fde_bytes, 4);
    const uint64_t old_fde_vaddr = static_cast<uint64_t>(static_cast<int64_t>(func.fde_pc_begin) -
                                                         read_s32(func.fde_bytes, 8)) -
                                   8;
    const uint64_t old_cie_vaddr = (old_fde_vaddr + 4) - old_cie_delta;
    const uint64_t final_cie_vaddr = old_cie_vaddr + ctx.final_image_shift;

    (void)runtime_registered;

    patch_u32(func.fde_bytes, 4, static_cast<uint32_t>(cie_field_vaddr - final_cie_vaddr));
    patch_s32(func.fde_bytes, 8,
              static_cast<int64_t>(func.slot_vaddr) - static_cast<int64_t>(new_fde + 8));
    patch_u32(func.fde_bytes, 12, static_cast<uint32_t>(func.size));

    if (func.fde_bytes.size() > 17) {
        auto [aug_size, leb_size] = read_uleb128(func.fde_bytes, 16);
        const size_t lsda_off = 16 + leb_size;
        auto* eh = ctx.binary->get_section(".eh_frame");
        if (eh == nullptr) {
            throw std::runtime_error("C++ EH binary is missing .eh_frame.");
        }
        auto content = eh->content();
        std::vector<uint8_t> eh_bytes(content.begin(), content.end());
        const uint8_t lsda_encoding =
            read_cie_lsda_encoding(eh_bytes, eh->virtual_address(), old_cie_vaddr);
        if (lsda_encoding != 0xffu) {
            const size_t lsda_size = eh_encoded_size(lsda_encoding);
            if ((lsda_encoding & 0x70u) != 0x10u || lsda_size == 0 || aug_size < lsda_size ||
                lsda_off + lsda_size > func.fde_bytes.size()) {
                throw std::runtime_error("Unsupported LSDA pointer encoding in FDE clone.");
            }
            const uint64_t old_lsda_field = old_fde_vaddr + lsda_off;
            const uint64_t old_lsda =
                static_cast<uint64_t>(
                    static_cast<int64_t>(old_lsda_field) +
                    read_encoded_signed_value(func.fde_bytes, lsda_off, lsda_encoding)) +
                ctx.final_image_shift;
            patch_encoded_signed_value(func.fde_bytes, lsda_off, lsda_encoding,
                                       static_cast<int64_t>(old_lsda) -
                                           static_cast<int64_t>(new_fde + lsda_off));
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
    auto* eh = ctx.binary->get_section(".eh_frame");
    if (eh == nullptr)
        throw std::runtime_error("C++ EH binary is missing .eh_frame.");
    auto eh_content = eh->content();
    std::vector<uint8_t> eh_bytes(eh_content.begin(), eh_content.end());
    bool patched_loader_fde = false;
    for (const auto& func : funcs) {
        if (func.eh_registration_vaddr == 0 || func.fde_bytes.empty())
            continue;
        if (func.eh_metadata.fde_vaddr < eh->virtual_address())
            throw std::runtime_error("Runtime FDE precedes .eh_frame.");
        const size_t off = static_cast<size_t>(func.eh_metadata.fde_vaddr - eh->virtual_address());
        if (off + func.fde_bytes.size() > eh_bytes.size())
            throw std::runtime_error("Runtime FDE exceeds .eh_frame.");
        std::copy(func.fde_bytes.begin(), func.fde_bytes.end(), eh_bytes.begin() + off);
        patched_loader_fde = true;
    }
    if (patched_loader_fde)
        eh->content(eh_bytes);
    auto entries = read_eh_hdr_entries(ctx);
    for (auto& entry : entries) {
        entry.pc += ctx.final_image_shift;
        entry.fde += ctx.final_image_shift;
    }
    for (const auto& func : funcs) {
        if (func.fde_bytes.empty()) {
            continue;
        }
        auto it = std::find_if(entries.begin(), entries.end(), [&](const EhHeaderEntry& entry) {
            return entry.pc == func.original_start + ctx.final_image_shift;
        });
        if (it == entries.end()) {
            throw std::runtime_error("Failed to replace EH table entry for " + func.name);
        }
        it->pc = func.slot_vaddr;
        it->fde = func.eh_registration_vaddr != 0
                      ? func.eh_metadata.fde_vaddr + ctx.final_image_shift
                      : func.fde_vaddr;
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.pc < b.pc; });
    const uint64_t base = hdr->virtual_address() + ctx.final_image_shift;
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t off = 12 + i * 8;
        patch_s32(bytes, off, static_cast<int64_t>(entries[i].pc) - static_cast<int64_t>(base));
        patch_s32(bytes, off + 4,
                  static_cast<int64_t>(entries[i].fde) - static_cast<int64_t>(base));
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
    if (patched_loader_fde) {
        for (auto& segment : ctx.binary->segments()) {
            if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD)
                continue;
            const uint64_t seg_start = segment.virtual_address();
            if (eh->virtual_address() < seg_start ||
                eh->virtual_address() + eh_bytes.size() > seg_start + segment.virtual_size())
                continue;
            auto seg_content = segment.content();
            std::vector<uint8_t> seg_buffer(seg_content.begin(), seg_content.end());
            const size_t off = static_cast<size_t>(eh->virtual_address() - seg_start);
            if (off + eh_bytes.size() <= seg_buffer.size()) {
                std::copy(eh_bytes.begin(), eh_bytes.end(), seg_buffer.begin() + off);
                segment.content(seg_buffer);
            }
            break;
        }
    }
}

} // namespace maya::protection
