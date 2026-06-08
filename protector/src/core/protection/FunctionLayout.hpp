#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

std::vector<ProtectedFunction> collect_functions(ProtectionContext& ctx);
uint64_t choose_payload_vaddr(const ProtectionContext& ctx);
void assign_layout(std::vector<ProtectedFunction>& funcs, Layout& layout, uint64_t base, SlotStrategy strategy);
void shift_layout(std::vector<ProtectedFunction>& funcs, Layout& layout, int64_t delta);
uint64_t estimate_callsite_meta_capacity(const std::vector<ProtectedFunction>& funcs);
uint64_t reserve_payload_vaddr(ProtectionContext& ctx, uint64_t requested_vaddr, uint64_t total_size);
const ProtectedFunction* find_func_containing(const std::vector<ProtectedFunction>& funcs, uint64_t addr);
const ProtectedFunction* find_func_start(const std::vector<ProtectedFunction>& funcs, uint64_t addr);
bool is_protected_start(const std::vector<ProtectedFunction>& funcs, uint64_t addr);
std::string symbol_name_at(const ProtectionContext& ctx, uint64_t addr);

} // namespace maya::protection
