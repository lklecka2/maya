#pragma once

#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

void prepare_eh_frame_clones(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs);
void relocate_fde_clone(const ProtectionContext& ctx, ProtectedFunction& func);
void patch_eh_frame_header(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs);

} // namespace maya::protection
