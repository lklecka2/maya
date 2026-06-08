#pragma once

#include <cstdint>
#include <vector>

#include "ProtectionTypes.hpp"
#include "core/Context.hpp"

namespace maya::protection {

bool is_bl(uint32_t insn);
bool is_unconditional_b(uint32_t insn);
uint32_t make_b(uint64_t from, uint64_t to);
void patch_function_bodies(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs, std::vector<CallsiteMeta>& callsites);
void validate_function_pointer_refs(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs);

} // namespace maya::protection
