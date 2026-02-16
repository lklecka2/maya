#pragma once
#include "Context.hpp"

class Analyzer {
public:
    static void analyze(ProtectorContext& ctx);
private:
    static void find_executable_range(ProtectorContext& ctx, uint64_t& min_vaddr, uint64_t& max_vaddr, uint64_t& original_min_vaddr);
    static void mirror_block(ProtectorContext& ctx, uint64_t min_vaddr, uint64_t max_vaddr);
    static void disassemble_and_scan(ProtectorContext& ctx, uint64_t min_vaddr, uint64_t max_vaddr, uint64_t original_min_vaddr);
};
