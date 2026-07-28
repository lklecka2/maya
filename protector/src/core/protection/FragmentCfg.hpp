#pragma once
#include "ProtectionTypes.hpp"
#include <vector>
namespace maya::protection {
void build_fragment_cfg(std::vector<ProtectedFunction>& funcs);
}
