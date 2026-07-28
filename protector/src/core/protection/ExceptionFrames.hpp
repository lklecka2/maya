#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

// Internal parser boundary used by both production ELF extraction and mutation tests.
// The parser owns no input storage and never reads beyond the supplied spans.
struct EhByteSpan {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

EhMetadata parse_eh_metadata(const ProtectionContext& ctx, uint64_t pc_begin);
EhMetadata parse_eh_metadata_from_spans(const ProtectionContext& ctx, uint64_t pc_begin,
                                        EhByteSpan eh_frame, uint64_t eh_base,
                                        const std::vector<EhHeaderEntry>& entries, EhByteSpan lsda,
                                        uint64_t lsda_base);
void prepare_eh_frame_clones(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs);
void relocate_fde_clone(const ProtectionContext& ctx, ProtectedFunction& func);
void patch_eh_frame_header(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs);

} // namespace maya::protection
