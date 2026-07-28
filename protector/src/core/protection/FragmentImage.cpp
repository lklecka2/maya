#include "FragmentImage.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace maya::protection {
namespace {
constexpr uint64_t kMagic = 0x32474d494641594dULL; /* MAYAFIMG2 */
constexpr uint64_t kHeaderSize = 72;
constexpr uint64_t kRegionSize = 56;
constexpr uint64_t kFuncSize = 16;
constexpr uint64_t kFragSize = 32;

bool checked_add(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > std::numeric_limits<uint64_t>::max() - a)
        return false;
    out = a + b;
    return true;
}
bool checked_mul(uint64_t a, uint64_t b, uint64_t& out) {
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a)
        return false;
    out = a * b;
    return true;
}
void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (unsigned i = 0; i < 4; i++)
        out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (unsigned i = 0; i < 8; i++)
        out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
uint32_t get32(const std::vector<uint8_t>& b, uint64_t o) {
    if (o > b.size() || b.size() - o < 4)
        throw std::runtime_error("Truncated fragment image u32");
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; i++)
        v |= uint32_t(b[o + i]) << (i * 8);
    return v;
}
uint64_t get64(const std::vector<uint8_t>& b, uint64_t o) {
    if (o > b.size() || b.size() - o < 8)
        throw std::runtime_error("Truncated fragment image u64");
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v |= uint64_t(b[o + i]) << (i * 8);
    return v;
}
void validate_range(uint64_t off, uint64_t count, uint64_t width, uint64_t total) {
    uint64_t size = 0, end = 0;
    if (!checked_mul(count, width, size) || !checked_add(off, size, end) || end > total)
        throw std::runtime_error("Fragment image range overflow/out of bounds");
}
} // namespace

std::vector<uint8_t> serialize_fragment_image(const FragmentImage& image) {
    if (image.version != kFragmentImageVersion)
        throw std::runtime_error("Unsupported fragment image version");
    const uint64_t regions_off = kHeaderSize;
    const uint64_t funcs_off = regions_off + image.regions.size() * kRegionSize;
    const uint64_t frags_off = funcs_off + image.functions.size() * kFuncSize;
    std::vector<uint8_t> out;
    put64(out, kMagic);
    put32(out, image.version);
    put32(out, kDescriptorVersion);
    put32(out, static_cast<uint32_t>(image.regions.size()));
    put32(out, static_cast<uint32_t>(image.functions.size()));
    put32(out, static_cast<uint32_t>(image.fragments.size()));
    put32(out, image.feature_flags);
    put32(out, image.state_contract_version);
    put32(out, image.continuation_contract_version);
    put32(out, image.fault_contract_version);
    put32(out, 0);
    put64(out, regions_off);
    put64(out, funcs_off);
    put64(out, frags_off);
    for (const auto& r : image.regions) {
        put32(out, static_cast<uint32_t>(r.type));
        put32(out, r.permissions);
        put64(out, r.offset);
        put64(out, r.stored_size);
        put64(out, r.memory_size);
        put64(out, r.alignment);
        put64(out, r.digest_offset);
        put64(out, r.digest_size);
    }
    for (const auto& f : image.functions) {
        put32(out, f.version);
        put32(out, f.function_id);
        put32(out, f.first_fragment);
        put32(out, f.fragment_count);
    }
    for (const auto& f : image.fragments) {
        put32(out, f.version);
        put32(out, f.function_id);
        put32(out, f.fragment_id);
        put32(out, f.flags);
        put64(out, f.payload_offset);
        put64(out, f.payload_size);
    }
    return out;
}

FragmentImage parse_fragment_image(const std::vector<uint8_t>& b) {
    if (b.size() < kHeaderSize || get64(b, 0) != kMagic)
        throw std::runtime_error("Invalid fragment image magic/header");
    FragmentImage image;
    image.version = get32(b, 8);
    if (image.version != kFragmentImageVersion || get32(b, 12) != kDescriptorVersion)
        throw std::runtime_error("Unsupported fragment descriptor version");
    image.feature_flags = get32(b, 28);
    image.state_contract_version = get32(b, 32);
    image.continuation_contract_version = get32(b, 36);
    image.fault_contract_version = get32(b, 40);
    if ((image.feature_flags & ~1u) != 0 || get32(b, 44) != 0)
        throw std::runtime_error("Unknown fragment image feature/reserved bits");
    if (image.state_contract_version != kStateContractVersion ||
        image.continuation_contract_version != kContinuationContractVersion ||
        image.fault_contract_version != kFaultContractVersion)
        throw std::runtime_error("Unsupported V1 contract version");
    const uint64_t nr = get32(b, 16), nf = get32(b, 20), ng = get32(b, 24);
    const uint64_t ro = get64(b, 48), fo = get64(b, 56), go = get64(b, 64);
    validate_range(ro, nr, kRegionSize, b.size());
    validate_range(fo, nf, kFuncSize, b.size());
    validate_range(go, ng, kFragSize, b.size());
    struct Span {
        uint64_t begin, end;
    };
    std::vector<Span> tables;
    auto add_span = [&](uint64_t off, uint64_t count, uint64_t width) {
        uint64_t size = 0, end = 0;
        checked_mul(count, width, size);
        checked_add(off, size, end);
        if (size)
            tables.push_back({off, end});
    };
    add_span(ro, nr, kRegionSize);
    add_span(fo, nf, kFuncSize);
    add_span(go, ng, kFragSize);
    std::sort(tables.begin(), tables.end(),
              [](const auto& a, const auto& c) { return a.begin < c.begin; });
    for (size_t i = 1; i < tables.size(); ++i)
        if (tables[i].begin < tables[i - 1].end)
            throw std::runtime_error("Overlapping fragment descriptor tables");
    std::vector<Span> stored_regions;
    std::set<uint32_t> region_types;
    for (uint64_t i = 0; i < nr; i++) {
        uint64_t o = ro + i * kRegionSize;
        FragmentRegionDescriptor r;
        r.type = static_cast<FragmentRegionType>(get32(b, o));
        r.permissions = get32(b, o + 4);
        r.offset = get64(b, o + 8);
        r.stored_size = get64(b, o + 16);
        r.memory_size = get64(b, o + 24);
        r.alignment = get64(b, o + 32);
        r.digest_offset = get64(b, o + 40);
        r.digest_size = get64(b, o + 48);
        const auto type = static_cast<uint32_t>(r.type);
        if (type < 1 || type > 3 || !region_types.insert(type).second)
            throw std::runtime_error("Unknown/duplicate fragment region");
        const uint32_t expected = type == 1 ? 5 : type == 2 ? 1 : 3;
        if (r.permissions != expected || r.stored_size > r.memory_size)
            throw std::runtime_error("Invalid fragment region permissions/size");
        if (r.alignment == 0 || (r.alignment & (r.alignment - 1)) || (r.offset & (r.alignment - 1)))
            throw std::runtime_error("Invalid region alignment");
        validate_range(r.offset, 1, r.stored_size, b.size());
        if (r.digest_size)
            validate_range(r.digest_offset, 1, r.digest_size, b.size());
        image.regions.push_back(r);
    }
    for (const auto& r : image.regions) {
        if (r.stored_size) {
            stored_regions.push_back({r.offset, r.offset + r.stored_size});
        }
    }
    std::sort(stored_regions.begin(), stored_regions.end(),
              [](const auto& a, const auto& c) { return a.begin < c.begin; });
    for (size_t i = 1; i < stored_regions.size(); ++i)
        if (stored_regions[i].begin < stored_regions[i - 1].end)
            throw std::runtime_error("Overlapping fragment regions");
    std::set<uint32_t> function_ids;
    for (uint64_t i = 0; i < nf; i++) {
        uint64_t o = fo + i * kFuncSize;
        FragmentFunctionDescriptor f{get32(b, o), get32(b, o + 4), get32(b, o + 8),
                                     get32(b, o + 12)};
        uint64_t end = 0;
        if (f.version != kDescriptorVersion || !function_ids.insert(f.function_id).second ||
            !checked_add(f.first_fragment, f.fragment_count, end) || end > ng)
            throw std::runtime_error("Invalid/duplicate function descriptor");
        image.functions.push_back(f);
    }
    std::set<std::pair<uint32_t, uint32_t>> fragment_ids;
    for (uint64_t i = 0; i < ng; i++) {
        uint64_t o = go + i * kFragSize;
        FragmentDescriptor f;
        f.version = get32(b, o);
        f.function_id = get32(b, o + 4);
        f.fragment_id = get32(b, o + 8);
        f.flags = get32(b, o + 12);
        f.payload_offset = get64(b, o + 16);
        f.payload_size = get64(b, o + 24);
        uint64_t end = 0;
        if (f.version != kDescriptorVersion || !function_ids.count(f.function_id) ||
            !fragment_ids.emplace(f.function_id, f.fragment_id).second ||
            !checked_add(f.payload_offset, f.payload_size, end))
            throw std::runtime_error("Invalid/duplicate fragment descriptor");
        image.fragments.push_back(f);
    }
    for (const auto& f : image.functions)
        for (uint32_t i = 0; i < f.fragment_count; ++i)
            if (image.fragments[f.first_fragment + i].function_id != f.function_id)
                throw std::runtime_error("Function fragment ownership mismatch");
    return image;
}

FragmentImage make_fragment_image(const std::vector<ProtectedFunction>& funcs,
                                  uint64_t runtime_size) {
    FragmentImage image;
    image.regions.push_back({FragmentRegionType::RuntimeRx, 5, 0, 0, runtime_size, 4096, 0, 0});
    uint32_t fragment_id = 0;
    for (const auto& func : funcs) {
        if (func.final_outcome != FinalOutcome::Protected)
            continue;
        image.functions.push_back({kDescriptorVersion, func.selected_id, fragment_id, 1});
        image.fragments.push_back({kDescriptorVersion, func.selected_id, fragment_id++, 1,
                                   func.enc_vaddr, func.body_size});
    }
    return image;
}
} // namespace maya::protection
