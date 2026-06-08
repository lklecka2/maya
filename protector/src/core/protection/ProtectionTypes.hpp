#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/Context.hpp"

namespace maya::protection {

struct ProtectedFunction {
    uint32_t id = 0;
    std::string name;
    uint64_t original_start = 0;
    uint64_t size = 0;
    uint64_t body_size = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patched_bytes;
    uint64_t stub_vaddr = 0;
    uint64_t slot_vaddr = 0;
    uint64_t slot_size = 0;
    uint64_t enc_vaddr = 0;
    uint64_t active_vaddr = 0;
    uint64_t fde_vaddr = 0;
    std::vector<uint8_t> fde_bytes;
    uint64_t fde_pc_begin = 0;
    size_t direct_calls = 0;
    size_t tail_calls = 0;
    size_t indirect_calls = 0;
    size_t entry_pointer_refs = 0;
    size_t runtime_relocations = 0;
    size_t veneer_count = 0;
    size_t literal_pool_bytes = 0;
    std::vector<size_t> runtime_literal_offsets;
    bool plaintext_verified = false;
    bool original_site_patched = false;
};

struct CallsiteMeta {
    uint32_t caller_func_id = 0;
    uint32_t callee_func_id = UINT32_MAX;
    uint64_t original_pc = 0;
    uint64_t original_return_pc = 0;
    uint32_t flags = 0;
    uint32_t reserved = 0;
};

struct Layout {
    uint64_t base_vaddr = 0;
    uint64_t return_stub_vaddr = 0;
    uint64_t thread_states_vaddr = 0;
    uint64_t key_vaddr = 0;
    uint64_t callsite_meta_vaddr = 0;
    uint64_t callsite_meta_size = 0;
    uint64_t eh_frame_vaddr = 0;
    uint64_t eh_frame_size = 0;
    uint64_t total_size = 0;
};

struct EhHdrEntry {
    uint64_t pc = 0;
    uint64_t fde = 0;
};

struct SlotLocalPatch {
    enum Kind { BranchToVeneer, AdrLiteral, AdrpAddLiteral } kind = BranchToVeneer;
    size_t insn_off = 0;
    size_t paired_off = 0;
    uint32_t original_insn = 0;
    uint32_t paired_insn = 0;
    uint64_t target = 0;
};

inline constexpr uint64_t kAlign = 16;
inline constexpr uint64_t kSegmentAlign = 0x10000;
inline constexpr uint64_t kPageSize = 0x1000;
inline constexpr uint64_t kFrameCount = 1024;
inline constexpr uint64_t kFrameSize = 32;
inline constexpr uint64_t kThreadSlotCount = 256;
inline constexpr uint64_t kThreadStateSize = 16 + (kFrameCount * kFrameSize);
inline constexpr uint64_t kFunctionStateSize = 24;
inline constexpr uint64_t kSaveSize = 384;
inline constexpr uint64_t kEntryStubSize = 2048;
inline constexpr uint64_t kRuntimeBodyExtraPerInsn = 48;
inline constexpr std::array<uint8_t, 8> kKey = {0x6d, 0x61, 0x79, 0x61, 0x2d, 0x69, 0x70, 0x30};

std::string hex(uint64_t v);
uint64_t encrypted_body_capacity(const ProtectedFunction& func, SlotStrategy strategy);

} // namespace maya::protection
