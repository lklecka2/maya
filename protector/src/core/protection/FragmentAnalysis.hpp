#pragma once

#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

void analyze_fragment_modes(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs);

} // namespace maya::protection
