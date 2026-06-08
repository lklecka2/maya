#pragma once

#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

void emit_payload(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs, const Layout& layout, const std::vector<CallsiteMeta>& callsites, std::vector<uint8_t>& payload);
void add_payload_segment(ProtectionContext& ctx, const Layout& layout, const std::vector<uint8_t>& payload);
void patch_original_entries(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs);
void verify_plaintext_removed(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs, const std::vector<uint8_t>& payload);
void write_report(const ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs, const std::vector<CallsiteMeta>& callsites);

} // namespace maya::protection
