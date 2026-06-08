#pragma once

#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

std::vector<uint8_t> make_return_stub(const Layout& layout, SlotStrategy strategy);
std::vector<uint8_t> make_entry_stub(const ProtectedFunction& func, const Layout& layout, const ProtectionContext& ctx);
std::vector<uint8_t> make_eh_entry_stub(const ProtectedFunction& func, const Layout& layout);

} // namespace maya::protection
