#include "core/Planner.hpp"
#include "core/Logger.hpp"
#include <algorithm>
#include <sstream>

static auto to_hex(uint64_t val) -> std::string {
    std::stringstream hex_ss;
    hex_ss << "0x" << std::hex << val;
    return hex_ss.str();
}

void Planner::plan(ProtectorContext& ctx) {
    if (ctx.functions.empty()) {
        return;
    }

    constexpr uint64_t invalid_vaddr = 0xFFFFFFFFFFFFFFFF;
    uint64_t min_vaddr = invalid_vaddr;
    uint64_t max_binary_vaddr = 0;

    for (const auto& func : ctx.functions) {
        min_vaddr = std::min(min_vaddr, func.start_addr);
    }

    for (const auto& segment : ctx.binary->segments()) {
        max_binary_vaddr = std::max(max_binary_vaddr, segment.virtual_address() + segment.virtual_size());
    }

    // Calculate the required shift to move the code beyond the original binary.
    // The shift must be a multiple of 64KB to preserve page offsets for ADRP/ADD pairs.
    uint64_t raw_shift = max_binary_vaddr - min_vaddr;
    constexpr uint64_t shift_alignment = 0xFFFFULL;
    uint64_t aligned_shift = (raw_shift + shift_alignment) & ~shift_alignment;

    Log::info("Gap-preserving layout planned for " + std::to_string(ctx.functions.size()) +
              " chunks with shift " + to_hex(aligned_shift));

    for (auto& func : ctx.functions) {
        func.new_start_addr = func.start_addr + aligned_shift;
        ctx.addr_map[func.start_addr] = func.new_start_addr;
    }
}
