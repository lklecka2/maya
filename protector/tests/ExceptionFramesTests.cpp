#include "core/protection/ExceptionFrames.hpp"

#include <LIEF/ELF.hpp>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace maya::protection;

int main() {
    ProtectionContext ctx;
    ctx.binary = LIEF::ELF::Parser::parse(MAYA_EH_TEST_BINARY);
    if (!ctx.binary)
        throw std::runtime_error("failed to parse EH fixture");
    const auto metadata = parse_eh_metadata(ctx, 0x4015ec);
    if (metadata.schema != 1 || metadata.augmentation != "zPLR")
        return 1;
    if (metadata.pc_begin != 0x4015ec || metadata.pc_range != 136)
        return 2;
    if (metadata.fde_encoding != 0x1b || metadata.lsda_encoding != 0x1b)
        return 3;
    if (metadata.personality != 0x4011b8 || metadata.lsda_vaddr != 0x40a7ec)
        return 4;
    if (metadata.code_alignment != 4 || metadata.data_alignment != -8 ||
        metadata.return_register != 30)
        return 5;
    if (metadata.cie_cfi.empty() || metadata.fde_cfi.empty() || metadata.lsda_bytes.empty())
        return 6;
    if (metadata.call_sites.empty())
        return 7;
    bool has_landing = false;
    for (const auto& site : metadata.call_sites) {
        if (site.start < metadata.pc_begin ||
            site.start + site.length > metadata.pc_begin + metadata.pc_range)
            return 8;
        if (site.landing_pad != 0)
            has_landing = true;
    }
    if (!has_landing)
        return 9;

    auto* eh = ctx.binary->get_section(".eh_frame");
    auto* lsda = ctx.binary->get_section(".gcc_except_table");
    if (eh == nullptr || lsda == nullptr)
        return 11;
    const auto eh_view = eh->content();
    const auto lsda_view = lsda->content();
    const std::vector<uint8_t> eh_bytes(eh_view.begin(), eh_view.end());
    const std::vector<uint8_t> lsda_bytes(lsda_view.begin(), lsda_view.end());
    const std::vector<EhHeaderEntry> entries{{metadata.pc_begin, metadata.fde_vaddr}};
    auto parse_mutation = [&](const std::vector<uint8_t>& changed_eh,
                              const std::vector<uint8_t>& changed_lsda) {
        try {
            (void)parse_eh_metadata_from_spans(
                ctx, metadata.pc_begin, {changed_eh.data(), changed_eh.size()},
                eh->virtual_address(), entries, {changed_lsda.data(), changed_lsda.size()},
                lsda->virtual_address());
        } catch (const std::runtime_error&) {
            // A declared parse rejection is the expected outcome for malformed input.
        }
    };
    for (size_t size = 0; size < eh_bytes.size();
         size += std::max<size_t>(size_t{1}, eh_bytes.size() / 257)) {
        parse_mutation(std::vector<uint8_t>(eh_bytes.begin(), eh_bytes.begin() + size), lsda_bytes);
    }
    for (size_t size = 0; size < lsda_bytes.size();
         size += std::max<size_t>(size_t{1}, lsda_bytes.size() / 257)) {
        parse_mutation(eh_bytes,
                       std::vector<uint8_t>(lsda_bytes.begin(), lsda_bytes.begin() + size));
    }
    for (size_t offset : {size_t{0}, size_t{4}, size_t{8},
                          static_cast<size_t>(metadata.fde_vaddr - eh->virtual_address())}) {
        if (offset + 4 > eh_bytes.size())
            continue;
        auto changed = eh_bytes;
        std::fill(changed.begin() + offset, changed.begin() + offset + 4, 0xff);
        parse_mutation(changed, lsda_bytes);
    }
    auto extended_eh = eh_bytes;
    extended_eh.insert(extended_eh.end(), 4096, 0xff);
    auto extended_lsda = lsda_bytes;
    extended_lsda.insert(extended_lsda.end(), 4096, 0x80);
    parse_mutation(extended_eh, extended_lsda);

    try {
        (void)parse_eh_metadata(ctx, 0x4015ed);
        return 10;
    } catch (const std::runtime_error&) {
    }
    std::cout << "typed EH metadata tests passed\n";
}
