#pragma once

#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

std::vector<uint8_t> make_return_stub(const PayloadLayout& layout, SlotStrategy strategy);
std::vector<uint8_t> make_entry_stub(const ProtectedFunction& func, const PayloadLayout& layout,
                                     const ProtectionContext& ctx);
std::vector<uint8_t> make_interior_thunk(const ProtectedFunction& func,
                                         const ProtectedFunction::InteriorThunk& thunk);
std::vector<uint8_t> make_eh_entry_stub(const ProtectedFunction& func, const PayloadLayout& layout,
                                        const ProtectionContext& ctx);
std::vector<uint8_t> make_eh_cleanup_stub(const ProtectedFunction& func,
                                          const PayloadLayout& layout);

} // namespace maya::protection
