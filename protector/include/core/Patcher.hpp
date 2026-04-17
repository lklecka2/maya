#pragma once
#include "core/Context.hpp"
#include <cstdint>

class Patcher {
public:
    static uint64_t resolve_target(const ProtectorContext& ctx, uint64_t original_target);
    static uint64_t resolve_target(const ProtectorContext& ctx, const RelocationEntry& reloc);
    static uint32_t patch_instruction(const RelocationEntry& reloc, uint64_t new_pc, const ProtectorContext& ctx);
};
