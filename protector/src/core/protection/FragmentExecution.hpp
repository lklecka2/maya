#pragma once
#include "ProtectionTypes.hpp"
#include <vector>
namespace maya::protection {
void prepare_fragment_execution(std::vector<ProtectedFunction>& funcs);
}
