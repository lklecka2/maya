#include "RuntimeStubs.hpp"
#include "Controllets.hpp"
#include "FragmentCrypto.hpp"
#include "V3Vm.hpp"

#include "maya_runtime_symbols.hpp"
#include <algorithm>
#include <cstring>
#include <keystone/keystone.h>
#include <sstream>
#include <stdexcept>
#include <string>

namespace maya::protection {

class Assembler {
  public:
    Assembler() {
        if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks_) != KS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Keystone.");
        }
    }

    ~Assembler() {
        if (ks_ != nullptr) {
            ks_close(ks_);
        }
    }

    std::vector<uint8_t> assemble(const std::string& asm_text, uint64_t address) {
        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;
        if (ks_asm(ks_, asm_text.c_str(), address, &encode, &size, &count) != KS_ERR_OK) {
            throw std::runtime_error("Keystone failed to assemble runtime stub near statement " +
                                     std::to_string(count) + ": " +
                                     std::string(ks_strerror(ks_errno(ks_))));
        }
        std::vector<uint8_t> out(encode, encode + size);
        ks_free(encode);
        return out;
    }

  private:
    ks_engine* ks_ = nullptr;
};

std::string load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool);
std::string load_raw(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool);
std::string load_encoded_locator(const std::string& reg, uint64_t value,
                                 std::vector<uint64_t>& pool);
void append_pool(std::stringstream& ss, const std::vector<uint64_t>& pool);
void emit_mmap_slot(std::stringstream& ss, const ProtectedFunction& func,
                    const PayloadLayout& layout, std::vector<uint64_t>& pool);
void emit_munmap_slot(std::stringstream& ss, const PayloadLayout& layout,
                      std::vector<uint64_t>& pool);
void emit_mprotect(std::stringstream& ss, const std::string& addr, const std::string& size,
                   uint64_t prot, const std::string& fail, const PayloadLayout& layout,
                   std::vector<uint64_t>& pool);
void emit_save_regs(std::stringstream& ss);
void emit_restore_regs(std::stringstream& ss);
void emit_cache_flush(std::stringstream& ss, const std::string& base_reg,
                      const std::string& size_reg, const PayloadLayout& layout,
                      std::vector<uint64_t>& pool);
void emit_eh_nucleus_cache(std::stringstream& ss, const std::string& base, const std::string& size);
void emit_load_thread_state(std::stringstream& ss, const PayloadLayout& layout,
                            const std::string& dst_reg, std::vector<uint64_t>& pool);
void emit_atomic_active_increment(std::stringstream& ss, const ProtectedFunction& func,
                                  std::vector<uint64_t>& pool);
void emit_publish_active_one(std::stringstream& ss, const ProtectedFunction& func,
                             std::vector<uint64_t>& pool);
void emit_publish_slot_state(std::stringstream& ss, const ProtectedFunction& func,
                             std::vector<uint64_t>& pool);
void emit_load_published_slot(std::stringstream& ss, const ProtectedFunction& func,
                              std::vector<uint64_t>& pool);
void emit_publish_active_zero(std::stringstream& ss);
void emit_atomic_active_decrement(std::stringstream& ss);
void emit_apply_pie_literal_bias(std::stringstream& ss, const ProtectedFunction& func,
                                 std::vector<uint64_t>& pool);
std::vector<uint8_t> make_cfg_entry_stub(const ProtectedFunction& func,
                                         const PayloadLayout& layout);

std::pair<uint64_t, uint64_t> aad_digest_prefix(const std::vector<uint8_t>& aad) {
    const auto digest = sha256_bytes(aad);
    uint64_t low = 0;
    uint64_t high = 0;
    std::memcpy(&low, digest.data(), sizeof(low));
    std::memcpy(&high, digest.data() + sizeof(low), sizeof(high));
    return {low, high};
}

std::string load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool) {
    const size_t idx = pool.size();
    // Never serialize a direct code/data target.  Each use gets an independent
    // deterministic materialization mask; the pool contains only the encoded
    // link-time value and its self-relative PIE anchor.
    uint64_t mask = value ^ (UINT64_C(0x9e3779b97f4a7c15) * (idx + 1));
    mask ^= mask >> 30;
    mask *= UINT64_C(0xbf58476d1ce4e5b9);
    mask ^= mask >> 27;
    mask *= UINT64_C(0x94d049bb133111eb);
    mask ^= mask >> 31;
    if (mask == 0)
        mask = UINT64_C(0xa5f03c96d17e284b);
    pool.push_back(value ^ mask);
    const std::string tmp = (reg == "x17") ? "x16" : "x17";
    const std::string link = (tmp == "x16" || reg == "x16") ? "x15" : "x16";
    std::stringstream ss;
    ss << "adr " << tmp << ", Lpool_" << idx << "\n";
    ss << "ldr " << reg << ", [";
    ss << tmp << "]\n";
    ss << "ldr " << link << ", [" << tmp << ", #8]\n";
    ss << "sub " << tmp << ", " << tmp << ", " << link << "\n";
    ss << "movz " << link << ", #" << (mask & 0xffffu) << "\n";
    ss << "movk " << link << ", #" << ((mask >> 16) & 0xffffu) << ", lsl #16\n";
    ss << "movk " << link << ", #" << ((mask >> 32) & 0xffffu) << ", lsl #32\n";
    ss << "movk " << link << ", #" << ((mask >> 48) & 0xffffu) << ", lsl #48\n";
    ss << "eor " << reg << ", " << reg << ", " << link << "\n";
    ss << "add " << reg << ", " << reg << ", " << tmp << "\n";
    return ss.str();
}

std::string load_raw(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool) {
    const size_t idx = pool.size();
    pool.push_back(value);
    const std::string tmp = reg == "x17" ? "x16" : "x17";
    return "adr " + tmp + ", Lpool_" + std::to_string(idx) + "\nldr " + reg + ", [" + tmp + "]\n";
}

std::string load_encoded_locator(const std::string& reg, uint64_t value,
                                 std::vector<uint64_t>& pool) {
    const size_t idx = pool.size();
    uint64_t mask = value ^ (UINT64_C(0xd6e8feb86659fd93) * (idx + 1));
    mask ^= mask >> 32;
    mask *= UINT64_C(0xd6e8feb86659fd93);
    mask ^= mask >> 32;
    mask *= UINT64_C(0xd6e8feb86659fd93);
    mask ^= mask >> 32;
    if (mask == 0)
        mask = UINT64_C(0x6b8f1d23a974c5e0);
    pool.push_back(value ^ mask);
    const std::string tmp = reg == "x17" ? "x16" : "x17";
    const std::string work = (tmp == "x16" || reg == "x16") ? "x15" : "x16";
    std::stringstream ss;
    ss << "adr " << tmp << ", Lpool_" << idx << "\nldr " << reg << ", [" << tmp << "]\n";
    ss << "movz " << work << ", #" << (mask & 0xffffu) << "\n";
    ss << "movk " << work << ", #" << ((mask >> 16) & 0xffffu) << ", lsl #16\n";
    ss << "movk " << work << ", #" << ((mask >> 32) & 0xffffu) << ", lsl #32\n";
    ss << "movk " << work << ", #" << ((mask >> 48) & 0xffffu) << ", lsl #48\n";
    ss << "eor " << reg << ", " << reg << ", " << work << "\n";
    return ss.str();
}

void append_pool(std::stringstream& ss, const std::vector<uint64_t>& pool) {
    ss << ".align 3\n";
    for (size_t i = 0; i < pool.size(); ++i) {
        ss << "Lpool_" << i << ": .quad " << pool[i] << "\n";
        ss << ".quad Lpool_" << i << "\n";
    }
}

void emit_mmap_slot(std::stringstream& ss, const ProtectedFunction& func,
                    const PayloadLayout& layout, std::vector<uint64_t>& pool) {
    ss << "mov x0, #" << func.slot_size << "\nmov x1, #"
       << (func.selected_backend == SelectedBackend::Fragment ? 3 : 7) << "\n"
       << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_map, pool)
       << "blr x16\ncbz x0, maya_mmap_failed\n";
    ss << "mov x21, x0\n";
}

void emit_munmap_slot(std::stringstream& ss, const PayloadLayout& layout,
                      std::vector<uint64_t>& pool) {
    ss << "mov x0, x13\nmov x1, x15\n"
       << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_unmap,
                   pool)
       << "blr x16\n";
}

void emit_mprotect(std::stringstream& ss, const std::string& addr, const std::string& size,
                   uint64_t prot, const std::string& fail, const PayloadLayout& layout,
                   std::vector<uint64_t>& pool) {
    ss << "sub sp, sp, #64\nstp x9, x10, [sp, #0]\nstp x11, x12, [sp, #16]\nstp x13, x14, [sp, "
          "#32]\nstp x15, x16, [sp, #48]\n";
    ss << "mov x0, " << addr << "\n";
    ss << "mov x1, " << size << "\n";
    ss << "mov x2, #" << prot << "\n";
    ss << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_protect,
                   pool)
       << "blr x16\nmov x8, x0\n"
          "ldp x9, x10, [sp, #0]\nldp x11, x12, [sp, #16]\nldp x13, x14, [sp, #32]\nldp x15, x16, "
          "[sp, #48]\nadd sp, sp, #64\nmov x0, x8\n";
    ss << "cbnz x0, " << fail << "\n";
}

std::vector<uint8_t> make_return_stub(const PayloadLayout& layout, SlotStrategy strategy) {
    std::vector<uint64_t> pool;
    std::stringstream ss;
    ss << "sub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    emit_load_thread_state(ss, layout, "x9", pool);
    ss << "ldr x10, [x9, #8]\n";
    ss << "cbz x10, maya_frame_underflow\n";
    ss << "sub x10, x10, #1\n";
    ss << "str x10, [x9, #8]\n";
    ss << "add x11, x9, #16\n";
    ss << "mov x12, #" << kLegacyFrameSize << "\n";
    ss << "madd x11, x10, x12, x11\n";
    ss << "ldr x17, [x11, #0]\n";
    ss << "mov x27, x17\n";
    ss << "ldr x13, [x11, #8]\n";
    ss << "ldr x14, [x11, #16]\n";
    ss << "ldr x15, [x11, #24]\n";
    emit_atomic_active_decrement(ss);
    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_mprotect(ss, "x13", "x15", 3, "maya_permission_failed", layout, pool);
    }
    ss << "mov x11, #0\n";
    ss << "maya_zero_loop:\n";
    ss << "cmp x11, x15\n";
    ss << "b.hs maya_zero_done\n";
    ss << "strb wzr, [x13, x11]\n";
    ss << "add x11, x11, #1\n";
    ss << "b maya_zero_loop\n";
    ss << "maya_zero_done:\n";
    emit_cache_flush(ss, "x13", "x15", layout, pool);
    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_munmap_slot(ss, layout, pool);
    }
    emit_publish_active_zero(ss);
    ss << "maya_return_restore:\n";
    ss << "str x27, [sp, #240]\n";
    emit_restore_regs(ss);
    ss << "ldr x17, [sp, #240]\n";
    ss << "add sp, sp, #" << kSaveSize << "\n";
    ss << "br x17\n";
    ss << "maya_frame_underflow:\n";
    ss << "brk #0\n";
    ss << "maya_permission_failed:\n";
    ss << "brk #3\n";
    append_pool(ss, pool);
    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), layout.return_stub_vaddr);
    if (bytes.size() > kReturnStubSize) {
        throw std::runtime_error("Return stub exceeded reserved size.");
    }
    return bytes;
}

void emit_save_regs(std::stringstream& ss) {
    ss << "stp x0, x1, [sp, #0]\n";
    ss << "stp x2, x3, [sp, #16]\n";
    ss << "stp x4, x5, [sp, #32]\n";
    ss << "stp x6, x7, [sp, #48]\n";
    ss << "stp x8, x9, [sp, #64]\n";
    ss << "stp x10, x11, [sp, #80]\n";
    ss << "stp x12, x13, [sp, #96]\n";
    ss << "stp x14, x15, [sp, #112]\n";
    ss << "stp x16, x17, [sp, #128]\n";
    ss << "stp x18, x19, [sp, #144]\n";
    ss << "stp x20, x21, [sp, #160]\n";
    ss << "stp x22, x23, [sp, #176]\n";
    ss << "stp x24, x25, [sp, #192]\n";
    ss << "stp x26, x27, [sp, #208]\n";
    ss << "stp x28, x29, [sp, #224]\n";
    ss << "str x30, [sp, #240]\n";
    ss << "stp q0, q1, [sp, #256]\n";
    ss << "stp q2, q3, [sp, #288]\n";
    ss << "stp q4, q5, [sp, #320]\n";
    ss << "stp q6, q7, [sp, #352]\n";
    ss << "mrs x16, nzcv\nstr x16, [sp, #512]\n";
    ss << "mrs x16, fpcr\nstr x16, [sp, #520]\n";
    ss << "mrs x16, fpsr\nstr x16, [sp, #528]\n";
    ss << "ldp x16, x17, [sp, #128]\n";
}

void emit_restore_regs(std::stringstream& ss) {
    ss << "ldr x16, [sp, #512]\nmsr nzcv, x16\n";
    ss << "ldr x16, [sp, #520]\nmsr fpcr, x16\n";
    ss << "ldr x16, [sp, #528]\nmsr fpsr, x16\n";
    ss << "ldp q0, q1, [sp, #256]\n";
    ss << "ldp q2, q3, [sp, #288]\n";
    ss << "ldp q4, q5, [sp, #320]\n";
    ss << "ldp q6, q7, [sp, #352]\n";
    ss << "ldp x0, x1, [sp, #0]\n";
    ss << "ldp x2, x3, [sp, #16]\n";
    ss << "ldp x4, x5, [sp, #32]\n";
    ss << "ldp x6, x7, [sp, #48]\n";
    ss << "ldp x8, x9, [sp, #64]\n";
    ss << "ldp x10, x11, [sp, #80]\n";
    ss << "ldp x12, x13, [sp, #96]\n";
    ss << "ldp x14, x15, [sp, #112]\n";
    ss << "ldp x16, x17, [sp, #128]\n";
    ss << "ldp x18, x19, [sp, #144]\n";
    ss << "ldp x20, x21, [sp, #160]\n";
    ss << "ldp x22, x23, [sp, #176]\n";
    ss << "ldp x24, x25, [sp, #192]\n";
    ss << "ldp x26, x27, [sp, #208]\n";
    ss << "ldp x28, x29, [sp, #224]\n";
}

void emit_cache_flush(std::stringstream& ss, const std::string& base, const std::string& size,
                      const PayloadLayout& layout, std::vector<uint64_t>& pool) {
    ss << "sub sp, sp, #64\nstp x9, x10, [sp, #0]\nstp x11, x12, [sp, #16]\nstp x13, x14, [sp, "
          "#32]\nstp x15, x16, [sp, #48]\n"
       << "mov x0, " << base << "\nmov x1, " << size << "\n"
       << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_cache_sync,
                   pool)
       << "blr x16\n"
       << "ldp x9, x10, [sp, #0]\nldp x11, x12, [sp, #16]\nldp x13, x14, [sp, #32]\nldp x15, x16, "
          "[sp, #48]\nadd sp, sp, #64\n";
}

// EH entry stubs cannot introduce a call frame before transferring to the
// cloned-FDE slot. Keep this low-level nucleus primitive inline and semantic-free.
void emit_eh_nucleus_cache(std::stringstream& ss, const std::string& base,
                           const std::string& size) {
    ss << "add x20, " << base << ", " << size << "\nbic x19, " << base
       << ", #63\n"
          "maya_eh_dc_loop:\ncmp x19, x20\nb.hs maya_eh_dc_done\ndc cvau, x19\nadd x19, x19, "
          "#64\nb maya_eh_dc_loop\n"
          "maya_eh_dc_done:\ndsb ish\nbic x19, "
       << base
       << ", #63\nmaya_eh_ic_loop:\ncmp x19, x20\nb.hs maya_eh_ic_done\nic ivau, x19\nadd x19, "
          "x19, #64\nb maya_eh_ic_loop\n"
          "maya_eh_ic_done:\ndsb ish\nisb\n";
}

void emit_load_thread_state(std::stringstream& ss, const PayloadLayout& layout,
                            const std::string& dst_reg, std::vector<uint64_t>& pool) {
    ss << "mrs x10, tpidr_el0\n";
    ss << "eor x11, x10, x10, lsr #12\n";
    ss << "eor x11, x11, x11, lsr #24\n";
    ss << "and x11, x11, #" << (kThreadSlotCount - 1) << "\n";
    ss << load_abs("x17", layout.thread_states_vaddr, pool);
    ss << "mov x15, #" << kThreadStateSize << "\n";
    ss << "mov x16, #" << kThreadSlotCount << "\n";
    ss << "maya_thread_lookup:\n";
    ss << "madd " << dst_reg << ", x11, x15, x17\n";
    ss << "maya_thread_claim:\n";
    ss << "ldaxr x12, [" << dst_reg << "]\n";
    ss << "cmp x12, x10\n";
    ss << "b.eq maya_thread_found\n";
    ss << "cbnz x12, maya_thread_next\n";
    ss << "stlxr w13, x10, [" << dst_reg << "]\n";
    ss << "cbnz w13, maya_thread_claim\n";
    ss << "b maya_thread_found\n";
    ss << "maya_thread_next:\n";
    ss << "clrex\n";
    ss << "add x11, x11, #1\n";
    ss << "and x11, x11, #" << (kThreadSlotCount - 1) << "\n";
    ss << "subs x16, x16, #1\n";
    ss << "b.ne maya_thread_lookup\n";
    ss << "brk #0\n";
    ss << "maya_thread_found:\n";
}

void emit_atomic_active_increment(std::stringstream& ss, const ProtectedFunction& func,
                                  std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x16, #-1\n";
    ss << "maya_active_inc_loop:\n";
    ss << "ldaxr x10, [x9]\n";
    ss << "cmp x10, x16\n";
    ss << "b.eq maya_active_inc_busy\n";
    ss << "cbz x10, maya_active_inc_claim\n";
    ss << "add x11, x10, #1\n";
    ss << "stlxr w12, x11, [x9]\n";
    ss << "cbnz w12, maya_active_inc_loop\n";
    ss << "b maya_entry_active_ready\n";
    ss << "maya_active_inc_claim:\n";
    ss << "stlxr w12, x16, [x9]\n";
    ss << "cbnz w12, maya_active_inc_loop\n";
    ss << "b maya_active_inc_decrypt\n";
    ss << "maya_active_inc_busy:\n";
    ss << "clrex\n";
    ss << "yield\n";
    ss << "b maya_active_inc_loop\n";
    ss << "maya_active_inc_decrypt:\n";
}

void emit_publish_active_one(std::stringstream& ss, const ProtectedFunction& func,
                             std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x10, #1\n";
    ss << "stlr x10, [x9]\n";
}

void emit_publish_slot_state(std::stringstream& ss, const ProtectedFunction& func,
                             std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "str x21, [x9, #8]\n";
    ss << "mov x10, #" << func.slot_size << "\n";
    ss << "str x10, [x9, #16]\n";
}

void emit_load_published_slot(std::stringstream& ss, const ProtectedFunction& func,
                              std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "add x16, x9, #8\n";
    ss << "ldar x10, [x16]\n";
    ss << "ldr x13, [x9, #16]\n";
    ss << "cbz x10, maya_slot_state_missing\n";
    ss << "cbz x13, maya_slot_state_missing\n";
}

void emit_publish_active_zero(std::stringstream& ss) {
    ss << "str xzr, [x14, #8]\n";
    ss << "str xzr, [x14, #16]\n";
    ss << "mov x10, #0\n";
    ss << "stlr x10, [x14]\n";
}

void emit_atomic_active_decrement(std::stringstream& ss) {
    ss << "mov x16, #-1\n";
    ss << "maya_active_dec_loop:\n";
    ss << "ldaxr x10, [x14]\n";
    ss << "cmp x10, #1\n";
    ss << "b.eq maya_active_dec_last\n";
    ss << "sub x11, x10, #1\n";
    ss << "stlxr w12, x11, [x14]\n";
    ss << "cbnz w12, maya_active_dec_loop\n";
    ss << "b maya_return_restore\n";
    ss << "maya_active_dec_last:\n";
    ss << "stlxr w12, x16, [x14]\n";
    ss << "cbnz w12, maya_active_dec_loop\n";
}

void emit_apply_pie_literal_bias(std::stringstream& ss, const ProtectedFunction& func,
                                 std::vector<uint64_t>& pool) {
    if (func.runtime_literal_offsets.empty()) {
        return;
    }
    ss << load_abs("x17", 0, pool);
    for (size_t off : func.runtime_literal_offsets) {
        ss << "ldr x16, [x10, #" << off << "]\n";
        ss << "add x16, x16, x17\n";
        ss << "str x16, [x10, #" << off << "]\n";
    }
}

std::vector<uint8_t> make_cfg_entry_stub(const ProtectedFunction& func,
                                         const PayloadLayout& layout) {
    std::vector<uint64_t> pool;
    std::stringstream ss;
    ss << "b maya_cfg_normal\n";
    if (func.v3_event_gateway_offset == 4) {
        ss << "b maya_cfg_event\n";
        ss << "b maya_cfg_resume\n";
        ss << "b maya_cfg_external_return\n";
        ss << "b maya_cfg_interior\n";
    } else {
        ss << "b maya_cfg_bad_event\n";
        ss << "b maya_cfg_resume\n";
        ss << "b maya_cfg_external_return\n";
        ss << "b maya_cfg_interior\n";
        if (func.v3_event_gateway_offset < 20 || (func.v3_event_gateway_offset & 3)) {
            throw std::runtime_error("Invalid generated V3 event gateway offset");
        }
        ss << ".space " << (func.v3_event_gateway_offset - 20) << ", 0\n";
    }
    ss << "maya_cfg_event:\n";
    if (func.v3_control_enabled) {
        if (func.v3_gateway_abi_family == 1)
            ss << "ldp x16, x17, [sp], #16\n";
        else if (func.v3_gateway_abi_family == 2)
            ss << "ldr x17, [sp, #8]\nadd sp, sp, #16\n";
        else if (func.v3_gateway_abi_family == 3)
            ss << "mov x16, x12\n";
    }
    ss << "sub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    if (func.v3_control_enabled)
        ss << "mov x29, #0\n";
    if (func.v3_control_enabled) {
        if (func.v3_shard_envelope.size() < 40)
            throw std::runtime_error("V3 shard envelope is truncated at generation time");
        const uint64_t shard_ciphertext_size = func.v3_shard_envelope.size() - 40;
        const uint64_t shard_table_offset = (shard_ciphertext_size + 4095) & ~uint64_t{4095};
        const uint64_t shard_scratch_size = shard_table_offset + 4096;
        uint64_t owner_low = 0, owner_high = 0;
        std::memcpy(&owner_low, func.v3_owner_namespace.data(), 8);
        std::memcpy(&owner_high, func.v3_owner_namespace.data() + 8, 8);
        ss << "mov x21, x16\nmov x22, x17\nsub sp, sp, #96\nstp x21, x22, [sp, #80]\nmov x0, #"
           << shard_scratch_size << "\nmov x1, #3\n"
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_map,
                       pool)
           << "blr x16\ncbz x0, maya_mmap_failed\nmov x20, x0\nadd x14, sp, #32\n"
           << "mov w12, #1\nstur w12, [x14, #0]\nmov w12, #" << func.v3_shard_family
           << "\nstur w12, [x14, #4]\n"
           << "mov w12, #" << func.cluster_id << "\nstur w12, [x14, #8]\nmov w12, #"
           << func.v3_capability_count << "\nstur w12, [x14, #12]\n"
           << load_raw("x12", owner_low, pool) << "stur x12, [x14, #16]\n"
           << load_raw("x12", owner_high, pool) << "stur x12, [x14, #24]\n"
           << load_encoded_locator("x12", func.v3_shard_vaddr, pool) << "stur x12, [x14, #32]\n"
           << "mov x12, #" << shard_ciphertext_size << "\nstur x12, [x14, #40]\n"
           << "mov x0, sp\n"
           << load_abs("x1", layout.build_root_vaddr, pool) << "add x2, sp, #48\nmov w3, #"
           << func.cluster_id << "\nmov w4, #" << func.v3_shard_family << "\n"
           << load_abs("x16",
                       layout.fragment_runtime_vaddr + maya::runtime_offsets::v3_derive_shard_key,
                       pool)
           << "blr x16\n"
           << "mov x0, x20\n"
           << load_abs("x1", func.v3_shard_vaddr + 40, pool) << "mov x2, #" << shard_ciphertext_size
           << "\nadd x3, sp, #32\nmov x4, #48\nmov x5, sp\n"
           << load_abs("x6", func.v3_shard_vaddr, pool)
           << load_abs("x7", func.v3_shard_vaddr + 24, pool)
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::decrypt, pool)
           << "blr x16\nmov x19, x0\nmov x0, sp\nmov x1, #32\n"
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::secure_wipe,
                       pool)
           << "blr x16\ncbnz x19, maya_cfg_bad_shard\n";
        if (func.v3_shard_family == 0) {
            ss << "ldr w12, [x20, #0]\ncmp w12, #" << func.v3_capability_count
               << "\nb.ne maya_cfg_bad_shard\n"
               << "ldr w13, [x20, #4]\ncmp w13, #4\nb.lo maya_cfg_bad_shard\nsub w14, w13, #1\ntst "
                  "w13, w14\nb.ne maya_cfg_bad_shard\n"
               << "lsl w14, w12, #1\ncmp w14, w13\nb.hi maya_cfg_bad_shard\nldr w14, [x20, #8]\n"
               << "mov x15, #24\nmadd x15, x13, x15, x14\nadd x15, x15, #12\n"
               << load_raw("x14", shard_ciphertext_size, pool)
               << "cmp x15, x14\nb.ne maya_cfg_bad_shard\n";
        } else if (func.v3_shard_family == 1) {
            ss << "ldr w12, [x20, #0]\ncmp w12, #" << func.v3_capability_count
               << "\nb.ne maya_cfg_bad_shard\n"
               << "add x13, x20, #4\n"
               << load_raw("x14", shard_ciphertext_size, pool)
               << "add x14, x20, x14\nmov w15, #0\nmaya_v3_tree_structure:\ncmp w15, w12\nb.hs "
                  "maya_v3_tree_structure_done\n"
               << "add x16, x13, #12\ncmp x16, x14\nb.hi maya_cfg_bad_shard\nldr w17, [x13, "
                  "#8]\ncmp w17, #76\nb.lo maya_cfg_bad_shard\nadd x2, x16, x17\n"
               << load_raw("x0", shard_table_offset, pool)
               << "add x0, x20, x0\nstr x16, [x0, x15, lsl #3]\nmov x13, x2\ncmp x13, x14\nb.hi "
                  "maya_cfg_bad_shard\nadd w15, w15, #1\nb maya_v3_tree_structure\n"
               << "maya_v3_tree_structure_done:\ncmp x13, x14\nb.ne maya_cfg_bad_shard\n";
        } else {
            ss << "ldr x12, [x20, #0]\nldr w13, [x20, #8]\ncmp w13, #" << func.v3_capability_count
               << "\nb.ne maya_cfg_bad_shard\n"
               << "mov x14, #12\nmadd x14, x13, x14, x12\nadd x14, x14, #12\n"
               << load_raw("x15", shard_ciphertext_size, pool)
               << "cmp x14, x15\nb.ne maya_cfg_bad_shard\n";
        }
        if (func.v3_shard_family == 0) {
            ss << load_raw("x12", 2166136261u, pool) << "add x13, sp, #80\nmov w14, #16\n"
               << load_raw("x15", 16777619u, pool)
               << "maya_v3_hash_bytes:\nldrb w16, [x13], #1\neor w12, w12, w16\nmul w12, w12, "
                  "w15\nsubs w14, w14, #1\nb.ne maya_v3_hash_bytes\n"
               << "ldr w13, [x20, #4]\nsub w14, w13, #1\nand w12, w12, w14\nmov w15, w13\nadd x16, "
                  "x20, #12\nmov x17, #24\nmadd x18, x12, x17, x16\n"
               << "maya_v3_hash_probe:\nldr x0, [x18, #0]\nldr x1, [x18, #8]\norr x2, x0, x1\ncbz "
                  "x2, maya_cfg_bad_shard\ncmp x0, x21\nb.ne maya_v3_hash_next\ncmp x1, x22\nb.eq "
                  "maya_v3_hash_found\n"
               << "maya_v3_hash_next:\nadd w12, w12, #1\nand w12, w12, w14\nmadd x18, x12, x17, "
                  "x16\nsubs w15, w15, #1\nb.ne maya_v3_hash_probe\nb maya_cfg_bad_shard\n"
               << "maya_v3_hash_found:\nldr w0, [x18, #16]\nldr w1, [x18, #20]\ncmp w1, #100\nb.ne "
                  "maya_cfg_bad_shard\nmov x2, #24\nmadd x2, x13, x2, x16\nadd x18, x2, x0\n"
               << "add x3, x18, x1\n"
               << load_raw("x4", shard_ciphertext_size, pool)
               << "add x4, x20, x4\ncmp x3, x4\nb.hi maya_cfg_bad_shard\n"
               << load_raw("x12", owner_low, pool)
               << "ldr x13, [x18, #16]\ncmp x13, x12\nb.ne maya_cfg_bad_shard\n"
               << load_raw("x12", owner_high, pool)
               << "ldr x13, [x18, #24]\ncmp x13, x12\nb.ne maya_cfg_bad_shard\n"
               << "ldr w12, [x18, #68]\ncmp w12, #" << func.cluster_id
               << "\nb.ne maya_cfg_bad_shard\nldr w12, [x18, #72]\ncmp w12, #24\nb.ne "
                  "maya_cfg_bad_shard\n"
               << "ldr w23, [x18, #76]\nldr x24, [x18, #84]\nldr x26, [x18, #92]\nldr x25, [x18, "
                  "#32]\nb maya_v3_record_selected\n";
        } else if (func.v3_shard_family == 1) {
            ss << "mov w12, #0\n"
               << load_raw("x13", shard_table_offset, pool)
               << "add x13, x20, x13\nadd x14, sp, #80\nmaya_v3_tree_lookup:\ncmp w12, #"
               << func.v3_capability_count << "\nb.hs maya_cfg_bad_shard\n"
               << "ldr x18, [x13, x12, lsl #3]\ncbz x18, maya_cfg_bad_shard\nmov w15, "
                  "#0\nmaya_v3_tree_compare:\ncmp w15, #16\nb.hs maya_v3_tree_found\n"
               << "ldrb w16, [x18, x15]\nldrb w17, [x14, x15]\ncmp w16, w17\nb.lo "
                  "maya_v3_tree_right\nb.hi maya_v3_tree_left\nadd w15, w15, #1\nb "
                  "maya_v3_tree_compare\n"
               << "maya_v3_tree_left:\nldur w12, [x18, #-12]\nmov w15, #-1\ncmp w12, w15\nb.eq "
                  "maya_cfg_bad_shard\nb maya_v3_tree_lookup\n"
               << "maya_v3_tree_right:\nldur w12, [x18, #-8]\nmov w15, #-1\ncmp w12, w15\nb.eq "
                  "maya_cfg_bad_shard\nb maya_v3_tree_lookup\n"
               << "maya_v3_tree_found:\n"
               << load_raw("x12", owner_low, pool)
               << "ldr x13, [x18, #16]\ncmp x13, x12\nb.ne maya_cfg_bad_shard\n"
               << load_raw("x12", owner_high, pool)
               << "ldr x13, [x18, #24]\ncmp x13, x12\nb.ne maya_cfg_bad_shard\n"
               << "ldr w12, [x18, #68]\ncmp w12, #" << func.cluster_id
               << "\nb.ne maya_cfg_bad_shard\nldr w12, [x18, #72]\ncmp w12, #24\nb.ne "
                  "maya_cfg_bad_shard\n"
               << "ldr w23, [x18, #76]\nldr x24, [x18, #84]\nldr x26, [x18, #92]\nldr x25, [x18, "
                  "#32]\nb maya_v3_record_selected\n";
        } else {
            ss << load_raw("x12", 2166136261u, pool) << "add x13, sp, #80\nmov w14, #16\n"
               << load_raw("x15", 16777619u, pool)
               << "maya_v3_indirect_hash_bytes:\nldrb w16, [x13], #1\neor w12, w12, w16\nmul w12, "
                  "w12, w15\nsubs w14, w14, #1\nb.ne maya_v3_indirect_hash_bytes\nand w12, w12, "
                  "#0xffff\n"
               << "ldr w13, [x20, #8]\nadd x14, x20, #12\nmov x15, #12\nmadd x16, x13, x15, "
                  "x14\nmov w15, w13\nrev x0, x22\nrev x1, x21\n"
               << "maya_v3_indirect_entry:\ncbz w15, maya_cfg_bad_shard\nldr w17, [x14, #0]\ncmp "
                  "w17, w12\nb.ne maya_v3_indirect_next\n"
               << "ldr w17, [x14, #4]\ncmp w17, #100\nb.ne maya_cfg_bad_shard\nldr w17, [x14, "
                  "#8]\nadd x2, x17, #100\nldr x3, [x20, #0]\ncmp x2, x3\nb.hi "
                  "maya_cfg_bad_shard\nadd x18, x16, x17\nadd x18, x18, #84\n"
               << "ldr x2, [x18, #0]\ncmp x2, x0\nb.ne maya_v3_indirect_next\nldr x2, [x18, "
                  "#8]\ncmp x2, x1\nb.ne maya_v3_indirect_next\n"
               << "ldur x14, [x18, #-8]\nrev x14, x14\n"
               << load_raw("x15", owner_low, pool) << "cmp x14, x15\nb.ne maya_cfg_bad_shard\n"
               << "ldur x14, [x18, #-16]\nrev x14, x14\n"
               << load_raw("x15", owner_high, pool) << "cmp x14, x15\nb.ne maya_cfg_bad_shard\n"
               << "ldur w14, [x18, #-52]\nrev w14, w14\ncmp w14, #1\nb.lo maya_cfg_bad_shard\ncmp "
                  "w14, #9\nb.hi maya_cfg_bad_shard\n"
               << "ldur w14, [x18, #-56]\nrev w14, w14\ncmp w14, #" << func.cluster_id
               << "\nb.ne maya_cfg_bad_shard\n"
               << "ldur w14, [x18, #-60]\nrev w14, w14\ncmp w14, #24\nb.ne maya_cfg_bad_shard\n"
               << "ldur w23, [x18, #-64]\nrev w23, w23\nldur x24, [x18, #-76]\nrev x24, x24\nldur "
                  "x26, [x18, #-84]\nrev x26, x26\nldur x25, [x18, #-24]\nrev x25, x25\nb "
                  "maya_v3_record_selected\n"
               << "maya_v3_indirect_next:\nadd x14, x14, #12\nsubs w15, w15, #1\nb.ne "
                  "maya_v3_indirect_entry\nb maya_cfg_bad_shard\n";
        }
        ss << "maya_v3_record_selected:\n";
        if (func.cfg_pie_fixups) {
            ss << "cmp w23, #" << static_cast<uint32_t>(FragmentExitKind::CallExternal)
               << "\nb.eq maya_v3_external_bias\n"
               << "cmp w23, #" << static_cast<uint32_t>(FragmentExitKind::SetjmpExternal)
               << "\nb.eq maya_v3_external_bias\n"
               << "cmp w23, #" << static_cast<uint32_t>(FragmentExitKind::LongjmpExternal)
               << "\nb.ne maya_v3_external_bias_done\n"
               << "maya_v3_external_bias:\n"
               << load_abs("x17", 0, pool) << "add x24, x24, x17\n"
               << "maya_v3_external_bias_done:\n";
        }
        ss << "add sp, sp, #96\nmov x13, x20\nmov x15, #" << shard_scratch_size << "\n";
        emit_munmap_slot(ss, layout, pool);
        ss << "maya_v3_edge_decoded:\n";
    } else if (func.controllet_family == 0)
        ss << "mov x23, x16\nmov x24, x17\nmov x25, x13\nmov x26, x12\n";
    else if (func.controllet_family == 1)
        ss << "mov x23, x14\nmov x24, x12\nmov x25, x16\nmov x26, x13\n";
    else
        ss << "mov x23, x13\nmov x24, x14\nmov x25, x12\nmov x26, x17\n";
    ss << "mov x27, #1\n";
    // Unsigned single-register loads support the enlarged V3 save frame;
    // pair-load immediates are limited to 504 bytes on AArch64.
    ss << "ldr x16, [sp, #" << kSaveSize << "]\nldr x17, [sp, #" << (kSaveSize + 8)
       << "]\nstr x16, [sp, #128]\nstr x17, [sp, #136]\n";
    ss << "ldr x14, [sp, #" << (kSaveSize + 16) << "]\nldr x15, [sp, #" << (kSaveSize + 24)
       << "]\nstr x14, [sp, #112]\nstr x15, [sp, #120]\n";
    ss << "ldr x12, [sp, #" << (kSaveSize + 32) << "]\nldr x13, [sp, #" << (kSaveSize + 40)
       << "]\nstr x12, [sp, #96]\nstr x13, [sp, #104]\n";
    ss << "bl maya_cfg_lookup\n";
    ss << "ldr x10, [x9, #16]\ncbz x10, maya_cfg_underflow\nsub x10, x10, #1\n";
    ss << "add x11, x9, #" << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\n";
    ss << "ldr x20, [x11, #24]\n";
    ss << load_abs("x0", layout.build_root_vaddr, pool)
       << load_raw("x1", controllet_cookie(func.event_cookie, func.controllet_family), pool)
       << "ldr x2, [x9, #48]\nldr x3, [x9, #32]\nldr x4, [x9, #40]\nldr x5, [x11, #40]\n"
       << (func.v3_control_enabled
               ? load_raw("x6", func.v3_function_handle, pool) + "eor x6, x6, x20\n"
               : "mov x6, #" + std::to_string(func.id) + "\nlsl x6, x6, #32\norr x6, x6, x20\n")
       << "ldr x12, [x11, #112]\ncmp x6, x12\nb.ne maya_cfg_bad_target\n"
          "ldr x7, [x9, #16]\nlsl x7, x7, #32\nldr x12, [x9, #56]\neor x7, x7, x12\nldr x12, [x11, "
          "#48]\neor x7, x7, x12\nldr x12, [x11, #88]\ncmp x7, x12\nb.ne maya_cfg_bad_depth\n"
       << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::state_mask, pool)
       << "blr x16\nmov x18, x0\nbl maya_cfg_lookup\nldr x10, [x9, #16]\nsub x10, x10, #1\nadd "
          "x11, x9, #"
       << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\n"
          "ldr x12, [x9, #48]\nldr x13, [x11, #80]\ncmp x12, x13\nb.ne maya_cfg_bad_thread\n"
          "ldr x12, [x9, #32]\nldr x13, [x11, #64]\ncmp x12, x13\nb.ne maya_cfg_stale_epoch\n"
          "ldr x12, [x9, #40]\nldr x13, [x11, #72]\ncmp x12, x13\nb.ne maya_cfg_bad_path\n"
          "ldr x12, [x11, #40]\nldr x13, [x11, #96]\ncmp x12, x13\nb.ne maya_cfg_bad_frame\n"
          "ldr x12, [x11, #48]\nldr x13, [x11, #104]\ncmp x12, x13\nb.ne "
          "maya_cfg_bad_continuation\n"
          "ldr x12, [x11, #56]\ncmp x18, x12\nb.ne maya_cfg_stale_epoch\n";
    if (!func.v3_control_enabled) {
        if (func.controllet_family == 1)
            ss << "ror x24, x24, #47\nror x26, x26, #47\n";
        if (func.controllet_family == 2)
            ss << "mvn x24, x24\nmvn x26, x26\n";
        ss << "eor x24, x24, x18\neor x26, x26, x18\n";
    }
    if (func.v3_control_enabled) {
        ss << "mov x21, #0\nb maya_cfg_token_decoded\n";
    } else {
        ss << load_raw("x22", func.event_cookie, pool) << "eor x26, x26, x22\ncmp x23, #"
           << static_cast<uint32_t>(FragmentExitKind::CallExternal)
           << "\nb.eq maya_cfg_external_token\ncmp x23, #"
           << static_cast<uint32_t>(FragmentExitKind::SetjmpExternal)
           << "\nb.eq maya_cfg_external_token\ncmp x23, #"
           << static_cast<uint32_t>(FragmentExitKind::LongjmpExternal)
           << "\nb.eq maya_cfg_external_token\neor x24, x24, x22\nlsr x21, x24, #32\n";
        ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::CallProtected)
           << "\nb.eq maya_cfg_token_function\ncmp x23, #"
           << static_cast<uint32_t>(FragmentExitKind::TailcallProtected)
           << "\nb.eq maya_cfg_token_function\nand x24, x24, #0xffffffff\nb "
              "maya_cfg_token_ready\nmaya_cfg_token_function:\nmov x24, "
              "x21\nmaya_cfg_token_ready:\n";
        ss << "b maya_cfg_token_decoded\nmaya_cfg_external_token:\nmov x21, #0\n";
    }
    ss << "maya_cfg_token_decoded:\n";
    if (!func.v3_control_enabled)
        ss << "and x26, x26, #0xffffffff\n";
    size_t shard_record_base = 0;
    size_t capability_edge_index = 0;
    for (const auto& fragment : func.fragments) {
        if (func.v3_control_enabled)
            ss << load_raw("x22", fragment.v3_handle, pool)
               << "cmp x20, x22\nb.ne maya_validate_fragment_" << fragment.fragment_id << "_next\n";
        else
            ss << "cmp x20, #" << fragment.fragment_id << "\nb.ne maya_validate_fragment_"
               << fragment.fragment_id << "_next\n";
        size_t index = 0;
        for (const auto& exit : fragment.exits) {
            if (func.v3_control_enabled) {
                uint64_t source_low = 0;
                std::memcpy(&source_low, exit.v3_source_label.data(), sizeof(source_low));
                ss << load_raw("x22", source_low, pool) << "cmp x25, x22\nb.ne maya_validate_f"
                   << fragment.fragment_id << "_e" << index << "_next\n";
            } else
                ss << "cmp x25, #" << exit.site_id << "\nb.ne maya_validate_f"
                   << fragment.fragment_id << "_e" << index << "_next\n";
            ss << "cmp x23, #" << static_cast<uint32_t>(exit.kind) << "\nb.ne maya_cfg_bad_event\n";
            if (exit.kind == FragmentExitKind::NextFragment) {
                if (func.v3_control_enabled)
                    ss << load_raw("x22", exit.v3_target_handle, pool)
                       << "cmp x24, x22\nb.ne maya_cfg_bad_event\n";
                else
                    ss << "cmp x24, #" << exit.target_fragment_id << "\nb.ne maya_cfg_bad_event\n";
            }
            if (exit.kind == FragmentExitKind::CallProtected ||
                exit.kind == FragmentExitKind::TailcallProtected) {
                if (func.v3_control_enabled)
                    ss << load_raw("x22", exit.v3_target_handle, pool)
                       << "cmp x24, x22\nb.ne maya_cfg_bad_event\n";
                else
                    ss << "cmp x24, #" << exit.target_function_id << "\nb.ne maya_cfg_bad_event\n";
            }
            if (exit.kind == FragmentExitKind::CallExternal ||
                exit.kind == FragmentExitKind::SetjmpExternal ||
                exit.kind == FragmentExitKind::LongjmpExternal)
                ss << load_abs("x22", exit.compatibility_target, pool)
                   << "cmp x24, x22\nb.ne maya_cfg_bad_event\n";
            if (func.v3_control_enabled)
                ss << "b maya_v3_authorize_" << capability_edge_index << "\n";
            else
                ss << "b maya_cfg_event_valid\n";
            ss << "maya_validate_f" << fragment.fragment_id << "_e" << index << "_next:\n";
            ++index;
            ++capability_edge_index;
        }
        ss << "b maya_cfg_bad_event\nmaya_validate_fragment_" << fragment.fragment_id << "_next:\n";
    }
    ss << "b maya_cfg_bad_event\n";
    if (func.v3_control_enabled) {
        auto event_class = [](FragmentExitKind kind) -> uint32_t {
            switch (kind) {
            case FragmentExitKind::NextFragment:
                return 1;
            case FragmentExitKind::CallProtected:
                return 2;
            case FragmentExitKind::ReturnProtected:
            case FragmentExitKind::ExitFunction:
                return 3;
            case FragmentExitKind::TailcallProtected:
                return 4;
            case FragmentExitKind::CallExternal:
                return 5;
            case FragmentExitKind::SetjmpExternal:
                return 8;
            case FragmentExitKind::LongjmpExternal:
                return 9;
            case FragmentExitKind::Fault:
                return 1;
            }
            return 0;
        };
        size_t authority_index = 0;
        for (const auto& fragment : func.fragments) {
            for (const auto& exit : fragment.exits) {
                uint64_t source_low = 0, source_high = 0, destination_low = 0, destination_high = 0;
                uint64_t owner_low = 0, owner_high = 0;
                std::memcpy(&source_low, exit.v3_source_label.data(), 8);
                std::memcpy(&source_high, exit.v3_source_label.data() + 8, 8);
                std::memcpy(&destination_low, exit.v3_destination_label.data(), 8);
                std::memcpy(&destination_high, exit.v3_destination_label.data() + 8, 8);
                std::memcpy(&owner_low, func.v3_owner_namespace.data(), 8);
                std::memcpy(&owner_high, func.v3_owner_namespace.data() + 8, 8);
                ss << "maya_v3_authorize_" << authority_index
                   << ":\nsub sp, sp, #240\nadd x14, sp, #32\n"
                   << "mov w12, #3\nstur w12, [x14, #0]\nmov w12, #1\nstur w12, [x14, #4]\nmov "
                      "w12, #3\nstur w12, [x14, #8]\n"
                   << load_raw("x12", 0x45584954u, pool) << "stur w12, [x14, #12]\n"
                   << "mov w12, #" << event_class(exit.kind) << "\nstur w12, [x14, #16]\n"
                   << "mov w12, #" << func.cluster_id << "\nstur w12, [x14, #20]\n"
                   << load_raw("x12", source_low, pool) << "stur x12, [x14, #24]\n"
                   << load_raw("x12", source_high, pool) << "stur x12, [x14, #32]\n"
                   << load_raw("x12", destination_low, pool) << "stur x12, [x14, #40]\n"
                   << load_raw("x12", destination_high, pool) << "stur x12, [x14, #48]\n"
                   << load_raw("x12", owner_low ^ 0x6275696c642d7633ULL, pool)
                   << "stur x12, [x14, #56]\n"
                   << load_raw("x12", owner_high ^ 0x6964656e74697479ULL, pool)
                   << "stur x12, [x14, #64]\n"
                   << "ldr x12, [x9, #0]\nstur x12, [x14, #72]\nstur x12, [x14, #80]\n"
                   << load_raw("x12", owner_low, pool) << "stur x12, [x14, #88]\n"
                   << load_raw("x12", owner_high, pool) << "stur x12, [x14, #96]\n"
                   << load_raw("x12", source_low, pool) << "stur x12, [x14, #104]\n"
                   << load_raw("x12", source_high, pool) << "stur x12, [x14, #112]\n"
                   << "ldr x12, [x11, #40]\nstur x12, [x14, #120]\nstur x12, [x14, #128]\n"
                   << "ldr x12, [x11, #48]\nstur x12, [x14, #136]\nstur x12, [x14, #144]\n"
                   << "ldr x12, [x9, #32]\nstur x12, [x14, #152]\nldr x12, [x9, #40]\n"
                   << "stur x12, [x14, #160]\nstur x12, [x14, #168]\nstur x12, [x14, #176]\nstur "
                      "x12, [x14, #184]\n"
                   << "ldr x12, [x9, #16]\nstur x12, [x14, #192]\nldr x12, [x9, #56]\nstur x12, "
                      "[x14, #200]\n"
                   << "mov x0, sp\n"
                   << load_abs("x1", layout.build_root_vaddr, pool) << "add x2, sp, #120\nmov w3, #"
                   << func.cluster_id << "\nadd x4, sp, #32\nmov x5, #208\n"
                   << load_abs("x16",
                               layout.fragment_runtime_vaddr +
                                   maya::runtime_offsets::v3_issue_capability,
                               pool)
                   << "blr x16\n"
                   << "mov x0, sp\n"
                   << load_abs("x1", layout.build_root_vaddr, pool) << "add x2, sp, #120\nmov w3, #"
                   << func.cluster_id << "\nadd x4, sp, #32\nmov x5, #208\n"
                   << load_abs("x16",
                               layout.fragment_runtime_vaddr +
                                   maya::runtime_offsets::v3_validate_capability,
                               pool)
                   << "blr x16\nmov x19, x0\n"
                   << "mov x0, sp\nmov x1, #240\n"
                   << load_abs("x16",
                               layout.fragment_runtime_vaddr + maya::runtime_offsets::secure_wipe,
                               pool)
                   << "blr x16\n"
                   << "add sp, sp, #240\ncbz x19, maya_cfg_capability_failed\nbl maya_cfg_lookup\n"
                   << "ldr x10, [x9, #16]\nsub x10, x10, #1\nadd x11, x9, #"
                   << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
                   << "\nmadd x11, x10, x12, x11\nb maya_cfg_event_valid\n";
                ++authority_index;
            }
        }
    }
    ss << "maya_cfg_event_valid:\n";
    if (func.v3_control_enabled) {
        // Keep an exact private copy until publication.  The V3 abort path
        // restores it after wiping and unmapping an unpublished successor.
        for (uint64_t offset = 0; offset < kFrameSize; offset += 16) {
            ss << "ldp x12, x13, [x11, #" << offset << "]\n"
               << "stp x12, x13, [sp, #" << (384 + offset) << "]\n";
        }
    }
    ss << "ldr x0, [x9, #40]\nmov x1, x18\nlsl x2, x23, #56\nlsl x12, x25, #32\neor x2, x2, "
          "x12\neor x2, x2, x24\n"
       << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::state_advance,
                   pool)
       << "blr x16\nmov x18, x0\nbl maya_cfg_lookup\nldr x10, [x9, #16]\nsub x10, x10, #1\nadd "
          "x11, x9, #"
       << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize << "\nmadd x11, x10, x12, x11\n";
    if (func.v3_control_enabled) {
        // Offset 120 is the private pending-path slot.  Generation remains
        // derivable as canonical_generation + 1 until the release commit.
        ss << "str x18, [x11, #120]\n";
    } else {
        ss << "str x18, [x9, #40]\nldr x12, [x9, #32]\nadd x12, x12, #1\nstr x12, [x9, #32]\n";
    }
    ss << "ldr x13, [x11, #8]\nldr x15, [x11, #32]\n";
    emit_mprotect(ss, "x13", "x15", 3, "maya_cfg_permission_failed", layout, pool);
    ss << "mov x12, #0\nmaya_cfg_zero:\ncmp x12, x15\nb.hs maya_cfg_zero_done\nstrb wzr, [x13, "
          "x12]\nadd x12, x12, #1\nb maya_cfg_zero\nmaya_cfg_zero_done:\n";
    emit_cache_flush(ss, "x13", "x15", layout, pool);
    emit_munmap_slot(ss, layout, pool);
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::ExitFunction)
       << "\nb.eq maya_cfg_exit\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::NextFragment)
       << "\nb.eq maya_cfg_dispatch\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::CallProtected)
       << "\nb.eq maya_cfg_call\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::CallExternal)
       << "\nb.eq maya_cfg_external_call\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::SetjmpExternal)
       << "\nb.eq maya_cfg_setjmp_call\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::LongjmpExternal)
       << "\nb.eq maya_cfg_longjmp_call\n";
    ss << "cmp x23, #" << static_cast<uint32_t>(FragmentExitKind::TailcallProtected)
       << "\nb.eq maya_cfg_tailcall\n";
    ss << "b maya_cfg_unsupported_event\n";

    ss << "maya_cfg_interior:\nsub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    if (func.v3_control_enabled)
        ss << "mov x29, #0\n";
    ss << "mov x24, x16\nmov x27, #0\nb maya_cfg_normal_saved\n";
    ss << "maya_cfg_normal:\nsub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    if (func.v3_control_enabled)
        ss << "mov x29, #0\n";
    ss << "mov x27, #0\n";
    if (func.v3_control_enabled)
        ss << load_raw("x24", func.fragments.front().v3_handle, pool);
    else
        ss << "mov x24, #0\n";
    ss << "maya_cfg_normal_saved:\nbl maya_cfg_lookup\nldr x10, [x9, #16]\ncmp x10, #"
       << kFrameCount << "\nb.hs maya_cfg_overflow\n";
    ss << "add x11, x9, #" << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\n";
    ss << "ldr x12, [sp, #240]\nstr x12, [x11, #0]\n"
       << (func.v3_control_enabled ? load_raw("x12", func.v3_function_handle, pool)
                                   : "mov x12, #" + std::to_string(func.id) + "\n")
       << "str x12, [x11, #16]\n"
       << "ldr x13, [x9, #48]\nldr x14, [x9, #32]\neor x13, x13, x14\neor x13, x13, x10\neor x13, "
          "x13, x12\n"
       << load_raw("x14", func.event_cookie, pool)
       << "eor x13, x13, x14\nror x13, x13, #19\nstr x13, [x11, #40]\nldr x14, [sp, #240]\neor "
          "x14, x14, x13\nstr x14, [x11, #48]\n"
       << "add x10, x10, #1\nstr x10, [x9, #16]\n";
    ss << "b maya_cfg_dispatch\n";
    ss << "maya_cfg_external_return:\nsub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    if (func.v3_control_enabled)
        ss << "mov x29, #0\n";
    ss << "mov x23, #1\nb maya_cfg_resume_saved\n";
    ss << "maya_cfg_resume:\nsub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    if (func.v3_control_enabled)
        ss << "mov x29, #0\n";
    ss << "mov x23, #0\nmaya_cfg_resume_saved:\nmov x27, #0\nbl maya_cfg_lookup\ncbz x23, "
          "maya_cfg_boundary_ready\nldr x12, [x9, #24]\ncbz x12, maya_cfg_boundary_underflow\nsub "
          "x12, x12, #1\nstr x12, [x9, #24]\nmaya_cfg_boundary_ready:\nldr x10, [x9, #16]\ncbz "
          "x10, maya_cfg_underflow\nsub x10, x10, #1\nadd x11, x9, #"
       << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\nldr x22, [x11, #16]\n";
    if (func.v3_control_enabled)
        ss << load_raw("x12", func.v3_function_handle, pool) << "cmp x22, x12\n";
    else
        ss << "cmp x22, #" << func.id << "\n";
    ss << "b.ne maya_cfg_bad_target\nldr x24, [x11, #24]\n";
    if (func.v3_control_enabled) {
        for (const auto& fragment : func.fragments) {
            for (const auto& exit : fragment.exits) {
                if (exit.kind == FragmentExitKind::CallExternal &&
                    exit.continuation_fragment_id == UINT32_MAX) {
                    ss << load_raw("x12", exit.v3_continuation_handle, pool)
                       << "cmp x24, x12\nb.eq maya_cfg_external_tail_exit\n";
                }
            }
        }
    } else {
        ss << "mov w12, #-1\ncmp w24, w12\nb.eq maya_cfg_external_tail_exit\n";
    }
    ss << "maya_cfg_dispatch:\n";
    for (const auto& fragment : func.fragments) {
        if (func.v3_control_enabled)
            ss << load_raw("x12", fragment.v3_handle, pool) << "cmp x24, x12\n";
        else
            ss << "cmp x24, #" << fragment.fragment_id << "\n";
        ss << "b.eq maya_cfg_fragment_" << fragment.fragment_id << "\n";
    }
    ss << "b maya_cfg_bad_target\n";
    for (const auto& fragment : func.fragments) {
        ss << "maya_cfg_fragment_" << fragment.fragment_id << ":\n";
        emit_mmap_slot(ss, func, layout, pool);
        if (func.v3_control_enabled)
            ss << "mov x29, x21\n";
        else
            ss << "str x21, [x11, #8]\n";
        if (func.v3_control_enabled)
            ss << load_raw("x12", fragment.v3_handle, pool);
        else
            ss << "mov x12, #" << fragment.fragment_id << "\n";
        ss << "str x12, [x11, #24]\nmov x12, #" << func.slot_size << "\nstr x12, [x11, #32]\n";
        ss << load_abs("x0", layout.build_root_vaddr, pool)
           << load_raw("x1", controllet_cookie(func.event_cookie, func.controllet_family), pool)
           << "ldr x2, [x9, #48]\n";
        if (func.v3_control_enabled) {
            ss << "cbz x27, maya_v3_binding_current_" << fragment.fragment_id << "\n"
               << "ldr x3, [x9, #32]\nadd x3, x3, #1\nldr x4, [x11, #120]\nb maya_v3_binding_ready_"
               << fragment.fragment_id << "\n"
               << "maya_v3_binding_current_" << fragment.fragment_id
               << ":\nldr x3, [x9, #32]\nldr x4, [x9, #40]\n"
               << "maya_v3_binding_ready_" << fragment.fragment_id << ":\n";
        } else {
            ss << "ldr x3, [x9, #32]\nldr x4, [x9, #40]\n";
        }
        ss << "ldr x5, [x11, #40]\n"
           << (func.v3_control_enabled
                   ? load_raw("x6", func.v3_function_handle ^ fragment.v3_handle, pool)
                   : load_raw("x6", (uint64_t(func.id) << 32) | fragment.fragment_id, pool))
           << "ldr x7, [x9, #16]\nlsl x7, x7, #32\nldr x12, [x9, #56]\neor x7, x7, x12\nldr x12, "
              "[x11, #48]\neor x7, x7, x12\nstr x7, [x11, #88]\n"
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::state_mask,
                       pool)
           << "blr x16\nmov x19, x0\n";
        if (!fragment.vm_ciphertext.empty()) {
            ss << "sub sp, sp, #32\nmov x0, sp\n"
               << load_abs("x1", layout.build_root_vaddr, pool)
               << load_abs("x2", fragment.vm_aad_vaddr + 16, pool)
               << load_abs("x3", fragment.vm_aad_vaddr, pool) << "ldr w3, [x3, #4]\n"
               << load_abs("x16",
                           layout.fragment_runtime_vaddr + maya::runtime_offsets::v3_derive_vm_key,
                           pool)
               << "blr x16\nmov x0, x21\n"
               << load_abs("x1", fragment.vm_ciphertext_vaddr, pool) << "mov x2, #"
               << fragment.vm_ciphertext.size() << "\n"
               << load_abs("x3", fragment.vm_aad_vaddr, pool) << "mov x4, #"
               << fragment.vm_aad.size() << "\n"
               << "mov x5, sp\n"
               << load_abs("x6", fragment.vm_nonce_vaddr, pool)
               << load_abs("x7", fragment.vm_tag_vaddr, pool)
               << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::decrypt,
                           pool)
               << "blr x16\nmov x8, x0\nstp xzr, xzr, [sp, #0]\nstp xzr, xzr, [sp, #16]\nadd sp, "
                  "sp, #32\ncbnz x8, maya_cfg_vm_auth_failed\n";
            if (func.v3_control_enabled) {
                const auto primitive_opcode =
                    fragment.vm_opcodes[static_cast<size_t>(V3VmOp::Primitive)];
                const auto consume_opcode =
                    fragment.vm_opcodes[static_cast<size_t>(V3VmOp::ConsumeAuthority)];
                const auto halt_opcode = fragment.vm_opcodes[static_cast<size_t>(V3VmOp::Halt)];
                ss << "mov x0, x21\nmov x1, #" << fragment.vm_ciphertext.size() << "\nmov x2, #"
                   << fragment.vm_step_limit << "\nmov x3, #" << unsigned(fragment.vm_operand_mask)
                   << "\n"
                   << load_raw("x4", fragment.vm_immediate_mask, pool) << "mov x5, #"
                   << unsigned(primitive_opcode) << "\nmov x6, #" << unsigned(consume_opcode)
                   << "\nmov x7, #" << unsigned(halt_opcode) << "\n"
                   << load_raw("x8", fragment.vm_required_primitive_trace, pool)
                   << "bl maya_cfg_vm_interpret\nmov x18, x19\n";
            } else {
                ss << "ldrb w12, [x21, #0]\ncmp w12, #" << unsigned(fragment.vm_rotate_opcode)
                   << "\nb.ne maya_cfg_vm_invalid\n"
                   << "ldrb w12, [x21, #1]\nmov w13, #"
                   << unsigned(fragment.vm_register_zero ^ fragment.vm_operand_mask)
                   << "\ncmp w12, w13\nb.ne maya_cfg_vm_invalid\n"
                   << "ldrb w12, [x21, #2]\ncmp w12, w13\nb.ne maya_cfg_vm_invalid\n"
                   << "ldr x14, [x21, #4]\n"
                   << load_raw("x15", fragment.vm_immediate_mask, pool)
                   << "eor x14, x14, x15\ncmp x14, #63\nb.hi maya_cfg_vm_invalid\nrorv x18, x19, "
                      "x14\n"
                   << "ldrb w12, [x21, #12]\ncmp w12, #" << unsigned(fragment.vm_halt_opcode)
                   << "\nb.ne maya_cfg_vm_invalid\n";
            }
        } else {
            ss << "mov x18, x19\n";
        }
        ss << "bl maya_cfg_lookup\nldr x10, [x9, #16]\nsub x10, x10, #1\nadd x11, x9, #"
           << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
           << "\nmadd x11, x10, x12, x11\nstr x19, [x11, #56]\n";
        if (func.v3_control_enabled) {
            ss << "cbz x27, maya_v3_snapshot_current_" << fragment.fragment_id << "\n"
               << "ldr x12, [x9, #32]\nadd x12, x12, #1\nstr x12, [x11, #64]\nldr x12, [x11, "
                  "#120]\nstr x12, [x11, #72]\nb maya_v3_snapshot_ready_"
               << fragment.fragment_id << "\n"
               << "maya_v3_snapshot_current_" << fragment.fragment_id
               << ":\nldr x12, [x9, #32]\nstr x12, [x11, #64]\nldr x12, [x9, #40]\nstr x12, [x11, "
                  "#72]\n"
               << "maya_v3_snapshot_ready_" << fragment.fragment_id << ":\n";
        } else {
            ss << "ldr x12, [x9, #32]\nstr x12, [x11, #64]\nldr x12, [x9, #40]\nstr x12, [x11, "
                  "#72]\n";
        }
        ss << "ldr x12, [x9, #48]\nstr x12, [x11, #80]\nldr x12, [x11, #40]\nstr x12, [x11, "
              "#96]\nldr x12, [x11, #48]\nstr x12, [x11, #104]\n"
           << (func.v3_control_enabled
                   ? load_raw("x12", func.v3_function_handle ^ fragment.v3_handle, pool)
                   : load_raw("x12", (uint64_t(func.id) << 32) | fragment.fragment_id, pool))
           << "str x12, [x11, #112]\n";
        ss << "mov x0, x21\n";
        const auto primary_aad_digest = aad_digest_prefix(fragment.aad);
        if (!fragment.variants.empty()) {
            ss << "and x12, x18, #3\n";
            for (size_t index = 0; index < fragment.variants.size(); ++index) {
                ss << "cmp x12, #" << (index + 1) << "\nb.eq maya_cfg_variant_"
                   << fragment.fragment_id << "_" << (index + 1) << "\n";
            }
            ss << "maya_cfg_primary_" << fragment.fragment_id << ":\n"
               << load_abs("x1", fragment.ciphertext_vaddr, pool)
               << load_abs("x3", fragment.aad_vaddr, pool)
               << load_abs("x6", fragment.nonce_vaddr, pool)
               << load_abs("x7", fragment.tag_vaddr, pool)
               << load_raw("x14", primary_aad_digest.first, pool)
               << load_raw("x15", primary_aad_digest.second, pool) << "b maya_cfg_sealed_selected_"
               << fragment.fragment_id << "\n";
            for (size_t index = 0; index < fragment.variants.size(); ++index) {
                const auto& variant = fragment.variants[index];
                const auto variant_aad_digest = aad_digest_prefix(variant.aad);
                ss << "maya_cfg_variant_" << fragment.fragment_id << "_" << (index + 1) << ":\n"
                   << load_abs("x1", variant.ciphertext_vaddr, pool)
                   << load_abs("x3", variant.aad_vaddr, pool)
                   << load_abs("x6", variant.nonce_vaddr, pool)
                   << load_abs("x7", variant.tag_vaddr, pool)
                   << load_raw("x14", variant_aad_digest.first, pool)
                   << load_raw("x15", variant_aad_digest.second, pool)
                   << "b maya_cfg_sealed_selected_" << fragment.fragment_id << "\n";
            }
            ss << "maya_cfg_sealed_selected_" << fragment.fragment_id << ":\n";
        } else {
            ss << load_abs("x1", fragment.ciphertext_vaddr, pool)
               << load_abs("x3", fragment.aad_vaddr, pool)
               << load_abs("x6", fragment.nonce_vaddr, pool)
               << load_abs("x7", fragment.tag_vaddr, pool)
               << load_raw("x14", primary_aad_digest.first, pool)
               << load_raw("x15", primary_aad_digest.second, pool);
        }
        // The sealed object's AAD is attacker-addressable.  Bind it to the
        // statically selected slot before it can influence key derivation.
        // Preserve the selected tuple across the freestanding SHA-256 call.
        ss << "sub sp, sp, #96\n"
           << "stp x1, x3, [sp, #32]\n"
           << "stp x6, x7, [sp, #48]\n"
           << "stp x14, x15, [sp, #64]\n"
           << "mov x0, sp\nmov x1, x3\nmov x2, #" << fragment.aad.size() << "\n"
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::sha256_digest,
                       pool)
           << "blr x16\n"
           << "ldp x12, x13, [sp]\n"
           << "ldp x14, x15, [sp, #64]\n"
           << "eor x12, x12, x14\neor x13, x13, x15\norr x8, x12, x13\n"
           << "ldp x1, x3, [sp, #32]\n"
           << "ldp x6, x7, [sp, #48]\n"
           << "stp xzr, xzr, [sp]\nstp xzr, xzr, [sp, #16]\n"
           << "stp xzr, xzr, [sp, #32]\nstp xzr, xzr, [sp, #48]\n"
           << "stp xzr, xzr, [sp, #64]\nadd sp, sp, #96\n"
           << "cbnz x8, maya_cfg_auth_failed\nmov x0, x21\n";
        ss << "mov x2, #" << fragment.plaintext.size() << "\n";
        ss << "mov x4, #" << fragment.aad.size() << "\n"
           << load_abs("x5", layout.build_root_vaddr, pool)
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::decrypt_root,
                       pool);
        ss << "blr x16\ncbnz x0, maya_cfg_auth_failed\nmov x13, #" << fragment.plaintext.size()
           << "\n";
        if (func.cfg_pie_fixups && !fragment.runtime_literal_offsets.empty()) {
            ss << load_abs("x17", 0, pool);
            for (const auto offset : fragment.runtime_literal_offsets) {
                ss << "ldr x16, [x21, #" << offset << "]\nadd x16, x16, x17\nstr x16, [x21, #"
                   << offset << "]\n";
            }
        }
        for (size_t token_index = 0; token_index < fragment.state_token_offsets.size();
             ++token_index) {
            const auto offset = fragment.state_token_offsets[token_index];
            const auto value_address = func.metadata_shard_vaddr +
                                       metadata_shard_value_offset(func.controllet_family,
                                                                   shard_record_base + token_index);
            ss << load_abs("x15", value_address, pool) << "ldr x16, [x15]\n"
               << load_raw("x15", func.metadata_shard_mask, pool) << "eor x16, x16, x15\n";
            if (fragment.state_token_load_bias[token_index] && func.cfg_pie_fixups)
                ss << load_raw("x14", fragment.state_token_values[token_index], pool)
                   << "cmp x16, x14\nb.ne maya_cfg_bad_shard\n"
                   << load_abs("x16", fragment.state_token_values[token_index], pool);
            ss << "eor x16, x16, x19\n";
            if (func.controllet_family == 1)
                ss << "ror x16, x16, #17\n";
            if (func.controllet_family == 2)
                ss << "mvn x16, x16\n";
            ss << "str x16, [x21, #" << offset << "]\n";
        }
        shard_record_base += fragment.state_token_offsets.size();
        emit_mprotect(ss, "x21", "x13", 5, "maya_cfg_permission_failed", layout, pool);
        ss << "mov x10, x21\n";
        emit_cache_flush(ss, "x10", "x13", layout, pool);
        if (func.v3_control_enabled)
            ss << "bl maya_cfg_lookup\nldr x10, [x9, #16]\nsub x10, x10, #1\nadd x11, x9, #"
               << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
               << "\nmadd x11, x10, x12, x11\n"
                  "cbz x27, maya_v3_publish_mapping_"
               << fragment.fragment_id
               << "\n"
                  "ldr x12, [x11, #120]\nstr x12, [x9, #40]\nldr x12, [x9, #32]\nadd x12, x12, "
                  "#1\nstr x12, [x9, #32]\n"
                  "maya_v3_publish_mapping_"
               << fragment.fragment_id
               << ":\n"
                  "add x12, x11, #8\nstlr x21, [x12]\nmov x29, #0\n";
        ss << "orr x21, x21, x27\nstr x21, [sp, #248]\nb maya_cfg_launch\n";
    }
    auto emit_v3_function_target = [&](const std::string& prefix, const std::string& handle_reg,
                                       uint64_t entry_offset, bool initialize_fragment = false) {
        for (size_t target_index = 0; target_index < func.v3_function_targets.size();
             ++target_index) {
            const auto& target = func.v3_function_targets[target_index];
            ss << load_raw("x12", target.handle, pool) << "cmp " << handle_reg << ", x12\nb.ne "
               << prefix << "_" << target_index << "_next\n"
               << load_abs("x21", target.entry + entry_offset, pool);
            if (initialize_fragment)
                ss << load_raw("x12", target.initial_fragment, pool) << "str x12, [x11, #24]\n";
            ss << "b " << prefix << "_ready\n" << prefix << "_" << target_index << "_next:\n";
        }
        ss << "b maya_cfg_bad_target\n" << prefix << "_ready:\n";
    };
    ss << "maya_cfg_call:\nstr x26, [x11, #24]\n";
    if (func.v3_control_enabled)
        emit_v3_function_target("maya_v3_call_target", "x24", 0);
    else
        ss << load_abs("x21", layout.base_vaddr + kReturnStubSize, pool)
           << load_raw("x12", entry_stub_size(func), pool) << "madd x21, x24, x12, x21\n";
    ss << "orr x21, x21, #1\nstr x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_setjmp_call:\nldr x14, [sp, #0]\nadd x12, x9, #" << kCheckpointTablePage
       << ", lsl #12\nadd x12, x12, #32\nmov x13, #64\n";
    ss << "maya_cfg_setjmp_scan:\nldr x15, [x12, #0]\ncmp x15, x14\nb.eq maya_cfg_setjmp_slot\ncbz "
          "x15, maya_cfg_setjmp_slot\nadd x12, x12, #32\nsubs x13, x13, #1\nb.ne "
          "maya_cfg_setjmp_scan\nb maya_cfg_overflow\n";
    ss << "maya_cfg_setjmp_slot:\nstr x14, [x12, #0]\nldr x15, [x9, #16]\nstr x15, [x12, #8]\nstr "
          "x26, [x12, #16]\n";
    if (func.v3_control_enabled)
        ss << load_raw("x15", func.v3_function_handle, pool);
    else
        ss << "mov x15, #" << func.id << "\n";
    ss << "str x15, [x12, #24]\nb maya_cfg_external_call\n";
    ss << "maya_cfg_longjmp_call:\nldr x14, [sp, #0]\nadd x12, x9, #" << kCheckpointTablePage
       << ", lsl #12\nadd x12, x12, #32\nmov x13, #64\n";
    ss << "maya_cfg_longjmp_scan:\nldr x15, [x12, #0]\ncmp x15, x14\nb.eq "
          "maya_cfg_longjmp_found\nadd x12, x12, #32\nsubs x13, x13, #1\nb.ne "
          "maya_cfg_longjmp_scan\n";
    ss << load_abs("x17", layout.thread_states_vaddr, pool)
       << "ldar x15, [x17]\nmaya_cfg_cross_thread_state:\ncbz x15, maya_cfg_longjmp_unknown\ncmp "
          "x15, x9\nb.eq maya_cfg_cross_thread_next\nadd x12, x15, #"
       << kCheckpointTablePage
       << ", lsl #12\nadd x12, x12, #32\nmov x13, #64\nmaya_cfg_cross_thread_record:\nldr x16, "
          "[x12, #0]\ncmp x16, x14\nb.eq maya_cfg_bad_target\nadd x12, x12, #32\nsubs x13, x13, "
          "#1\nb.ne maya_cfg_cross_thread_record\nmaya_cfg_cross_thread_next:\nldr x15, [x15, "
          "#0]\nb maya_cfg_cross_thread_state\n";
    ss << "maya_cfg_longjmp_unknown:\nmov x10, #0\nstr x10, [x9, #16]\nstr xzr, [x9, #24]\nbl "
          "maya_cfg_invalidate_records\nbl maya_cfg_destroy_thread\nb maya_cfg_longjmp_native\n";
    ss << "maya_cfg_longjmp_found:\nldr x15, [x12, #8]\ncbz x15, maya_cfg_bad_target\ncmp x15, #"
       << kFrameCount
       << "\nb.hi maya_cfg_bad_target\nstr x15, [x9, #16]\nmov x10, x15\nsub x15, x15, #1\nadd "
          "x11, x9, #"
       << kDynamicThreadHeaderSize << "\nmov x13, #" << kFrameSize
       << "\nmadd x11, x15, x13, x11\nldr x13, [x12, #24]\nldr x14, [x11, #16]\ncmp x13, x14\nb.ne "
          "maya_cfg_bad_target\nldr x13, [x12, #16]\nstr x13, [x11, #24]\nmov x13, #1\nstr x13, "
          "[x9, #24]\nbl maya_cfg_invalidate_records\n";
    ss << "maya_cfg_longjmp_native:\nstr x24, [sp, #248]\n";
    emit_restore_regs(ss);
    ss << "ldr x16, [sp, #248]\nadd sp, sp, #" << kSaveSize
       << "\nadd sp, sp, #48\nblr x16\nbrk #11\n";
    ss << "maya_cfg_external_call:\nstr x26, [x11, #24]\nldr x12, [x9, #24]\nadd x12, x12, #1\nstr "
          "x12, [x9, #24]\nstr x24, [sp, #248]\n";
    emit_restore_regs(ss);
    ss << "ldr x16, [sp, #248]\nadd sp, sp, #" << kSaveSize
       << "\nadd sp, sp, #48\nblr x16\nb maya_cfg_external_return\n";
    ss << "maya_cfg_tailcall:\nstr x24, [x11, #16]\nstr xzr, [x11, #24]\n";
    if (func.v3_control_enabled)
        emit_v3_function_target("maya_v3_tail_target", "x24", 8, true);
    else
        ss << load_abs("x21", layout.base_vaddr + kReturnStubSize, pool)
           << load_raw("x12", entry_stub_size(func), pool)
           << "madd x21, x24, x12, x21\nadd x21, x21, #8\n";
    ss << "orr x21, x21, #1\nstr x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_exit:\nstr x10, [x9, #16]\nbl maya_cfg_invalidate_records\ncbnz x10, "
          "maya_cfg_nested_return\nldr x21, [x11, #0]\nbl maya_cfg_destroy_thread\norr x21, x21, "
          "#1\nstr x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_external_tail_exit:\nstr x10, [x9, #16]\nbl maya_cfg_invalidate_records\ncbnz "
          "x10, maya_cfg_external_tail_nested\nldr x21, [x11, #0]\nbl maya_cfg_destroy_thread\nstr "
          "x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_external_tail_nested:\nsub x10, x10, #1\nadd x11, x9, #"
       << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\nldr x24, [x11, #24]\nldr x22, [x11, #16]\n";
    if (func.v3_control_enabled)
        emit_v3_function_target("maya_v3_external_return_target", "x22", 8);
    else
        ss << load_abs("x21", layout.base_vaddr + kReturnStubSize, pool)
           << load_raw("x12", entry_stub_size(func), pool)
           << "madd x21, x22, x12, x21\nadd x21, x21, #8\n";
    ss << "str x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_nested_return:\nsub x10, x10, #1\nadd x11, x9, #" << kDynamicThreadHeaderSize
       << "\nmov x12, #" << kFrameSize
       << "\nmadd x11, x10, x12, x11\nldr x24, [x11, #24]\nldr x22, [x11, #16]\n";
    if (func.v3_control_enabled)
        emit_v3_function_target("maya_v3_nested_return_target", "x22", 8);
    else
        ss << load_abs("x21", layout.base_vaddr + kReturnStubSize, pool)
           << load_raw("x12", entry_stub_size(func), pool)
           << "madd x21, x22, x12, x21\nadd x21, x21, #8\n";
    ss << "orr x21, x21, #1\nstr x21, [sp, #248]\nb maya_cfg_launch\n";
    ss << "maya_cfg_launch:\n";
    emit_restore_regs(ss);
    ss << "ldr x16, [sp, #248]\nadd sp, sp, #" << kSaveSize
       << "\ntbz x16, #0, maya_cfg_branch\nbic x16, x16, #1\nadd sp, sp, #48\nmaya_cfg_branch:\nbr "
          "x16\n";
    ss << "maya_cfg_invalidate_records:\nadd x12, x9, #" << kCheckpointTablePage
       << ", lsl #12\nadd x12, x12, #32\nmov x13, #64\nmaya_cfg_invalidate_loop:\nldr x14, [x12, "
          "#0]\ncbz x14, maya_cfg_invalidate_next\nldr x15, [x12, #8]\ncmp x15, x10\nb.ls "
          "maya_cfg_invalidate_next\nstr xzr, [x12, #8]\nstp xzr, xzr, [x12, "
          "#16]\nmaya_cfg_invalidate_next:\nadd x12, x12, #32\nsubs x13, x13, #1\nb.ne "
          "maya_cfg_invalidate_loop\nret\n";
    ss << "maya_cfg_destroy_thread:\nstr x30, [sp, #-16]!\n"
       << load_abs("x0", layout.thread_states_vaddr, pool) << "mov x1, x9\n"
       << load_raw("x2", kDynamicThreadStateSize, pool)
       << load_abs("x16",
                   layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_thread_destroy,
                   pool)
       << "blr x16\nldr x30, [sp], #16\nret\n";
    ss << "maya_cfg_lookup:\nmrs x28, tpidr_el0\n";
    ss << load_abs("x0", layout.thread_states_vaddr, pool) << "mov x1, x28\nmov x2, #"
       << (kDynamicThreadStateSize / kPageSize) << "\nlsl x2, x2, #12\n"
       << load_abs("x16",
                   layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_thread_lookup,
                   pool)
       << "str x30, [sp, #-16]!\nblr x16\nldr x30, [sp], #16\ncbz x0, maya_cfg_overflow\nmov x9, "
          "x0\nldr x12, [x9, #32]\ncbnz x12, maya_cfg_lookup_found\nmov x12, #1\nstr x12, [x9, "
          "#32]\n"
       << load_raw("x13", func.event_cookie, pool)
       << "str x13, [x9, #40]\neor x12, x28, x13\nror x12, x12, #23\nstr x12, [x9, #48]\nstr xzr, "
          "[x9, #56]\n"
       << "b maya_cfg_lookup_found\n";
    ss << "maya_cfg_lookup_found:\nret\n";
    if (func.v3_control_enabled) {
        ss << "maya_cfg_vm_interpret:\nmov x17, x30\nmov x9, #0\nmov x10, #0\nmov x11, #0\nmov "
              "x14, #0\n"
              "maya_cfg_vm_loop:\ncmp x9, x1\nb.hs maya_cfg_vm_invalid\nadd x12, x0, x9\nldrb w13, "
              "[x12]\n"
              "add x10, x10, #1\ncmp x10, x2\nb.hi maya_cfg_vm_invalid\ncmp w13, w5\nb.eq "
              "maya_cfg_vm_primitive\n"
              "cmp w13, w6\nb.eq maya_cfg_vm_consume\ncmp w13, w7\nb.eq maya_cfg_vm_halt\nb "
              "maya_cfg_vm_invalid\n"
              "maya_cfg_vm_validate_operands:\nldrb w15, [x12, #1]\neor w15, w15, w3\ncmp w15, "
              "#15\nb.hi maya_cfg_vm_invalid\n"
              "ldrb w15, [x12, #2]\neor w15, w15, w3\ncmp w15, #15\nb.hi maya_cfg_vm_invalid\n"
              "ldrb w15, [x12, #3]\neor w15, w15, w3\ncmp w15, #15\nb.hi maya_cfg_vm_invalid\nret\n"
              "maya_cfg_vm_primitive:\nbl maya_cfg_vm_validate_operands\nldr x15, [x12, #4]\neor "
              "x15, x15, x4\n"
              "sub x15, x15, #1\ncmp x15, #16\nb.hi maya_cfg_vm_invalid\nmov x16, #1\nlslv x16, "
              "x16, x15\n"
              "orr x11, x11, x16\ncmp x15, #1\nb.ne maya_cfg_vm_primitive_done\nmov x14, #1\n"
              "maya_cfg_vm_primitive_done:\nadd x9, x9, #12\nb maya_cfg_vm_loop\n"
              "maya_cfg_vm_consume:\nbl maya_cfg_vm_validate_operands\ncbz x14, "
              "maya_cfg_vm_invalid\nmov x14, #0\n"
              "add x9, x9, #12\nb maya_cfg_vm_loop\n"
              "maya_cfg_vm_halt:\nadd x9, x9, #12\ncmp x9, x1\nb.ne maya_cfg_vm_invalid\ncmp x11, "
              "x8\n"
              "b.ne maya_cfg_vm_invalid\ncbnz x14, maya_cfg_vm_invalid\nbr x17\n";
    }
    ss << "maya_cfg_underflow:\nbrk #5\nmaya_cfg_overflow:\nbrk #6\nmaya_cfg_bad_event:\nbrk "
          "#7\nmaya_cfg_bad_target:\nbrk #8\nmaya_cfg_unsupported_event:\nbrk "
          "#9\nmaya_cfg_boundary_underflow:\nbrk #10\nmaya_cfg_stale_epoch:\nbrk "
          "#12\nmaya_cfg_bad_thread:\nbrk #13\nmaya_cfg_bad_path:\nbrk "
          "#14\nmaya_cfg_bad_continuation:\nbrk #15\nmaya_cfg_bad_frame:\nbrk "
          "#16\nmaya_cfg_bad_depth:\nbrk #17\n";
    if (func.v3_control_enabled) {
        ss << "maya_cfg_bad_shard:\nmov x28, #18\nb maya_cfg_transaction_abort\n"
              "maya_cfg_vm_auth_failed:\nmov x28, #19\nb maya_cfg_transaction_abort\n"
              "maya_cfg_vm_invalid:\nmov x28, #20\nb maya_cfg_transaction_abort\n"
              "maya_cfg_capability_failed:\nmov x28, #21\nb maya_cfg_transaction_abort\n"
              "maya_cfg_auth_failed:\nmov x28, #4\nb maya_cfg_transaction_abort\n"
              "maya_cfg_permission_failed:\nmov x28, #3\nb maya_cfg_transaction_abort\n"
              "maya_mmap_failed:\nmov x28, #1\nb maya_cfg_transaction_abort\n"
              "maya_cfg_transaction_abort:\ncbz x29, maya_cfg_transaction_fault\nmov x0, x29\nmov "
              "x1, #"
           << func.slot_size << "\nmov x2, #3\n"
           << load_abs("x16",
                       layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_protect, pool)
           << "blr x16\n"
              "mov x12, #0\nmaya_cfg_transaction_wipe:\ncmp x12, #"
           << func.slot_size
           << "\nb.hs maya_cfg_transaction_unmap\nstrb wzr, [x29, x12]\nadd x12, x12, #1\nb "
              "maya_cfg_transaction_wipe\n"
              "maya_cfg_transaction_unmap:\nmov x0, x29\nmov x1, #"
           << func.slot_size << "\n"
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::nucleus_unmap,
                       pool)
           << "blr x16\nmov x29, #0\n"
              "maya_cfg_transaction_fault:\ncbz x27, maya_cfg_transaction_fault_ready\nbl "
              "maya_cfg_lookup\nldr x10, [x9, #16]\nsub x10, x10, #1\nadd x11, x9, #"
           << kDynamicThreadHeaderSize << "\nmov x12, #" << kFrameSize
           << "\nmadd x11, x10, x12, x11\n";
        for (uint64_t offset = 0; offset < kFrameSize; offset += 16) {
            ss << "ldp x12, x13, [sp, #" << (384 + offset) << "]\n"
               << "stp x12, x13, [x11, #" << offset << "]\n";
        }
        ss << "maya_cfg_transaction_fault_ready:\ncmp x28, #1\nb.eq maya_cfg_fault_1\ncmp x28, "
              "#3\nb.eq maya_cfg_fault_3\ncmp x28, #4\nb.eq maya_cfg_fault_4\ncmp x28, #18\nb.eq "
              "maya_cfg_fault_18\ncmp x28, #19\nb.eq maya_cfg_fault_19\ncmp x28, #20\nb.eq "
              "maya_cfg_fault_20\nbrk #21\n"
              "maya_cfg_fault_1:\nbrk #1\nmaya_cfg_fault_3:\nbrk #3\nmaya_cfg_fault_4:\nbrk "
              "#4\nmaya_cfg_fault_18:\nbrk #18\nmaya_cfg_fault_19:\nbrk "
              "#19\nmaya_cfg_fault_20:\nbrk #20\n";
    } else {
        ss << "maya_cfg_bad_shard:\nbrk #18\nmaya_cfg_vm_auth_failed:\nbrk "
              "#19\nmaya_cfg_vm_invalid:\nbrk #20\nmaya_cfg_capability_failed:\nbrk "
              "#21\nmaya_cfg_auth_failed:\nbrk #4\nmaya_cfg_permission_failed:\nbrk "
              "#3\nmaya_mmap_failed:\nbrk #1\n";
    }
    append_pool(ss, pool);
    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
    if (bytes.size() > entry_stub_size(func))
        throw std::runtime_error("CFG entry stub exceeded reserved size for " + func.name + ": " +
                                 std::to_string(bytes.size()));
    return bytes;
}

std::vector<uint8_t> make_interior_thunk(const ProtectedFunction& func,
                                         const ProtectedFunction::InteriorThunk& thunk) {
    Assembler assembler;
    std::stringstream ss;
    if (func.v3_control_enabled) {
        const auto fragment =
            std::find_if(func.fragments.begin(), func.fragments.end(), [&](const auto& candidate) {
                return candidate.fragment_id == thunk.fragment_id;
            });
        if (fragment == func.fragments.end())
            throw std::runtime_error("V3 interior thunk lacks an opaque fragment handle");
        ss << ".word 0xd503245f\nldr x16, Lhandle\nb " << (func.stub_vaddr + 16)
           << "\n.align 3\nLhandle: .quad " << fragment->v3_handle << "\n";
    } else {
        ss << ".word 0xd503245f\nmov w16, #" << thunk.fragment_id << "\nb "
           << (func.stub_vaddr + 16) << "\n";
    }
    return assembler.assemble(ss.str(), thunk.thunk_vaddr);
}

std::vector<uint8_t> make_entry_stub(const ProtectedFunction& func, const PayloadLayout& layout,
                                     const ProtectionContext& ctx) {
    if (func.cfg_execution_enabled) {
        try {
            return make_cfg_entry_stub(func, layout);
        } catch (const std::exception& error) {
            throw std::runtime_error("Failed to generate CFG runtime for " + func.name + ": " +
                                     error.what());
        }
    }
    const SlotStrategy strategy = ctx.runtime_features.slot_strategy;
    std::vector<uint64_t> pool;
    std::stringstream ss;
    ss << "sub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);

    emit_load_thread_state(ss, layout, "x9", pool);
    ss << "ldr x10, [x9, #8]\n";
    ss << "cmp x10, #" << kFrameCount << "\n";
    ss << "b.hs maya_frame_overflow\n";
    ss << "add x11, x9, #16\n";
    ss << "mov x12, #" << kLegacyFrameSize << "\n";
    ss << "madd x11, x10, x12, x11\n";
    ss << "mov x22, x11\n";
    ss << "ldr x12, [sp, #240]\n";
    ss << "str x12, [x11, #0]\n";
    ss << load_abs("x12", func.slot_vaddr, pool);
    ss << "str x12, [x11, #8]\n";
    ss << load_abs("x12", func.active_vaddr, pool);
    ss << "str x12, [x11, #16]\n";
    ss << "mov x12, #" << func.slot_size << "\n";
    ss << "str x12, [x11, #24]\n";
    ss << "add x10, x10, #1\n";
    ss << "str x10, [x9, #8]\n";

    emit_atomic_active_increment(ss, func, pool);

    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_mmap_slot(ss, func, layout, pool);
        emit_publish_slot_state(ss, func, pool);
        ss << "str x21, [x22, #8]\n";
        ss << "mov x12, #" << func.slot_size << "\n";
        ss << "str x12, [x22, #24]\n";
    }
    ss << load_abs("x9", func.enc_vaddr, pool);
    if (strategy == SlotStrategy::RuntimeAllocator) {
        ss << "mov x10, x21\n";
    } else {
        ss << load_abs("x10", func.slot_vaddr, pool);
    }
    if (func.selected_backend == SelectedBackend::Fragment) {
        ss << "mov x0, x10\n";
        ss << "mov x1, x9\n";
        ss << "mov x2, #" << func.body_size << "\n";
        ss << load_abs("x3", func.fragment_aad_vaddr, pool);
        ss << "mov x4, #" << func.fragment_aad.size() << "\n";
        ss << load_abs("x5", layout.build_root_vaddr, pool);
        ss << load_abs("x6", func.fragment_nonce_vaddr, pool);
        ss << load_abs("x7", func.fragment_tag_vaddr, pool);
        ss << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::decrypt_root,
                       pool);
        ss << "blr x16\n";
        ss << "cbnz x0, maya_authentication_failed\n";
    } else {
        ss << "sub sp, sp, #32\nmov x0, sp\n";
        ss << load_abs("x1", layout.build_root_vaddr, pool);
        ss << load_raw("x2", func.original_start, pool);
        ss << "mov x3, #" << func.body_size << "\n";
        ss << load_abs(
            "x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::derive_legacy_body_key,
            pool);
        ss << "blr x16\n";
        ss << load_abs("x9", func.enc_vaddr, pool);
        if (strategy == SlotStrategy::RuntimeAllocator) {
            ss << "mov x10, x21\n";
        } else {
            ss << load_abs("x10", func.slot_vaddr, pool);
        }
        ss << "mov x11, sp\n";
        ss << "mov x12, #0\n";
        ss << "mov x13, #" << func.body_size << "\n";
        ss << "maya_decrypt_loop:\n";
        ss << "cmp x12, x13\n";
        ss << "b.hs maya_decrypt_done\n";
        ss << "ldrb w14, [x9, x12]\n";
        ss << "and x15, x12, #31\n";
        ss << "ldrb w15, [x11, x15]\n";
        ss << "eor w14, w14, w15\n";
        ss << "strb w14, [x10, x12]\n";
        ss << "add x12, x12, #1\n";
        ss << "b maya_decrypt_loop\n";
        ss << "maya_decrypt_done:\n";
        ss << "stp xzr, xzr, [sp, #0]\nstp xzr, xzr, [sp, #16]\nadd sp, sp, #32\n";
    }
    if (strategy == SlotStrategy::RuntimeAllocator) {
        ss << "mov x10, x21\n";
    } else {
        ss << load_abs("x10", func.slot_vaddr, pool);
    }
    if (strategy == SlotStrategy::RuntimeAllocator &&
        (ctx.runtime_features.binary_kind == BinaryKind::DynamicPieExecutable ||
         ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable)) {
        emit_apply_pie_literal_bias(ss, func, pool);
    }
    ss << "mov x13, #" << func.body_size << "\n";
    if (func.selected_backend == SelectedBackend::Fragment) {
        emit_mprotect(ss, "x10", "x13", 5, "maya_permission_failed", layout, pool);
        if (strategy == SlotStrategy::RuntimeAllocator)
            ss << "mov x10, x21\n";
    }
    emit_cache_flush(ss, "x10", "x13", layout, pool);
    emit_publish_active_one(ss, func, pool);
    ss << "b maya_entry_restore\n";

    ss << "maya_entry_active_ready:\n";
    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_load_published_slot(ss, func, pool);
        ss << "str x10, [x22, #8]\n";
        ss << "str x13, [x22, #24]\n";
    } else {
        ss << load_abs("x10", func.slot_vaddr, pool);
        ss << "mov x13, #" << func.body_size << "\n";
    }
    emit_cache_flush(ss, "x10", "x13", layout, pool);

    ss << "maya_entry_restore:\n";
    emit_restore_regs(ss);
    ss << "add sp, sp, #" << kSaveSize << "\n";
    ss << load_abs("x30", layout.return_stub_vaddr, pool);
    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_load_published_slot(ss, func, pool);
        ss << "br x10\n";
    } else {
        ss << "b " << hex(func.slot_vaddr) << "\n";
    }
    ss << "maya_frame_overflow:\n";
    ss << "brk #0\n";
    ss << "maya_mmap_failed:\n";
    ss << "brk #1\n";
    ss << "maya_slot_state_missing:\n";
    ss << "brk #2\n";
    ss << "maya_authentication_failed:\n";
    ss << "brk #4\n";
    ss << "maya_permission_failed:\n";
    ss << "brk #3\n";
    append_pool(ss, pool);

    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
    if (bytes.size() > kEntryStubSize) {
        throw std::runtime_error("Entry stub exceeded reserved size for " + func.name);
    }
    return bytes;
}

std::vector<uint8_t> make_eh_entry_stub(const ProtectedFunction& func, const PayloadLayout& layout,
                                        const ProtectionContext& ctx) {
    std::vector<uint64_t> pool;
    std::stringstream ss;
    if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
        func.selected_backend == SelectedBackend::Fragment) {
        ss << "sub sp, sp, #" << kSaveSize << "\n";
        emit_save_regs(ss);
        ss << load_abs("x9", func.active_vaddr, pool);
        ss << "mov x16, #-1\n"
              "maya_eh_claim_loop:\nldaxr x10, [x9]\ncbnz x10, maya_eh_claim_busy_or_ready\n"
              "stlxr w11, x16, [x9]\ncbnz w11, maya_eh_claim_loop\nb maya_eh_materialize\n"
              "maya_eh_claim_busy_or_ready:\ncmp x10, x16\nb.eq maya_eh_claim_wait\n"
              "add x11, x10, #1\nstlxr w12, x11, [x9]\ncbnz w12, maya_eh_claim_loop\n"
              "b maya_eh_active_ready\n"
              "maya_eh_claim_wait:\nclrex\nyield\nb maya_eh_claim_loop\n"
              "maya_eh_materialize:\n";
        ss << load_abs("x21", func.slot_vaddr, pool);
        ss << "mov x10, x21\nmov x13, #" << func.slot_size << "\n";
        emit_mprotect(ss, "x10", "x13", 3, "maya_eh_prepare_failed", layout, pool);
        emit_publish_slot_state(ss, func, pool);
        ss << "mov x0, x21\n"
           << load_abs("x1", func.enc_vaddr, pool) << "mov x2, #" << func.body_size << "\n"
           << load_abs("x3", func.fragment_aad_vaddr, pool) << "mov x4, #"
           << func.fragment_aad.size() << "\n"
           << load_abs("x5", layout.build_root_vaddr, pool)
           << load_abs("x6", func.fragment_nonce_vaddr, pool)
           << load_abs("x7", func.fragment_tag_vaddr, pool)
           << load_abs("x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::decrypt_root,
                       pool)
           << "blr x16\ncbnz x0, maya_eh_auth_failed\nmov x10, x21\n";
        if (ctx.runtime_features.binary_kind == BinaryKind::DynamicPieExecutable ||
            ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable) {
            emit_apply_pie_literal_bias(ss, func, pool);
            ss << "mov x10, x21\n";
        }
        ss << "mov x13, #" << func.body_size << "\n";
        emit_mprotect(ss, "x10", "x13", 5, "maya_eh_permission_failed", layout, pool);
        ss << "mov x10, x21\nmov x13, #" << func.body_size << "\n";
        emit_cache_flush(ss, "x10", "x13", layout, pool);
        emit_publish_active_one(ss, func, pool);
        ss << "b maya_eh_launch\n"
              "maya_eh_active_ready:\n";
        emit_load_published_slot(ss, func, pool);
        ss << "mov x21, x10\n"
              "maya_eh_launch:\nstr x21, [sp, #384]\n";
        emit_restore_regs(ss);
        ss << "ldr x16, [sp, #384]\nldr x30, [sp, #240]\nadd sp, sp, #" << kSaveSize
           << "\nbr x16\n"
              "maya_eh_auth_failed:\nmov x28, #4\nb maya_eh_abort\n"
              "maya_eh_permission_failed:\nmov x28, #3\nb maya_eh_abort\n"
              "maya_eh_abort:\nmov x11, #0\n"
              "maya_eh_abort_wipe:\ncmp x11, #"
           << func.slot_size
           << "\nb.hs maya_eh_abort_unmap\n"
              "strb wzr, [x21, x11]\nadd x11, x11, #1\nb maya_eh_abort_wipe\n"
              "maya_eh_abort_unmap:\nmov x0, x21\nmov x1, #"
           << func.slot_size
           << "\nmov x2, #5\nmov x8, #226\nsvc #0\n"
              "maya_eh_abort_clear:\n"
           << load_abs("x9", func.active_vaddr, pool)
           << "str xzr, [x9, #8]\nstr xzr, [x9, #16]\nstlr xzr, [x9]\nbrk #4\n"
              "maya_eh_prepare_failed:\n"
           << load_abs("x9", func.active_vaddr, pool)
           << "stlr xzr, [x9]\nbrk #1\n"
              "maya_slot_state_missing:\nbrk #2\n";
        append_pool(ss, pool);
        Assembler assembler;
        auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
        if (bytes.size() > kEntryStubSize)
            throw std::runtime_error("Runtime EH entry stub exceeded reserved size for " +
                                     func.name);
        return bytes;
    }
    ss << "sub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);

    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x16, #-1\n";
    ss << "maya_eh_claim_loop:\n";
    ss << "ldaxr x10, [x9]\n";
    ss << "cbnz x10, maya_eh_claim_busy_or_ready\n";
    ss << "stlxr w11, x16, [x9]\n";
    ss << "cbnz w11, maya_eh_claim_loop\n";
    ss << "b maya_eh_decrypt\n";
    ss << "maya_eh_claim_busy_or_ready:\n";
    ss << "cmp x10, x16\n";
    ss << "b.ne maya_eh_retain_ready\n";
    ss << "clrex\n";
    ss << "yield\n";
    ss << "b maya_eh_claim_loop\n";
    // A ready slot may be entered concurrently or recursively.  Retain it
    // with the same exclusive monitor used by the cleanup gateway so the
    // final exiting invocation cannot wipe code that another invocation is
    // still executing.  Values with the sign bit set are reserved lifecycle
    // states and fail closed instead of wrapping the reference count.
    ss << "maya_eh_retain_ready:\n";
    ss << "tbnz x10, #63, maya_eh_claim_fault\n";
    ss << "add x11, x10, #1\n";
    ss << "stlxr w12, x11, [x9]\n";
    ss << "cbnz w12, maya_eh_claim_loop\n";
    ss << "b maya_eh_active_ready\n";

    ss << "maya_eh_decrypt:\n";
    ss << load_abs("x9", func.enc_vaddr, pool);
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << "sub sp, sp, #32\nmov x0, sp\n";
    ss << load_abs("x1", layout.build_root_vaddr, pool);
    ss << load_raw("x2", func.original_start, pool);
    ss << "mov x3, #" << func.size << "\n";
    ss << load_abs(
        "x16", layout.fragment_runtime_vaddr + maya::runtime_offsets::derive_legacy_body_key, pool);
    ss << "blr x16\n";
    ss << load_abs("x9", func.enc_vaddr, pool);
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << "mov x11, sp\n";
    ss << "mov x12, #0\n";
    ss << "mov x13, #" << func.size << "\n";
    ss << "maya_eh_decrypt_loop:\n";
    ss << "cmp x12, x13\n";
    ss << "b.hs maya_eh_decrypt_done\n";
    ss << "ldrb w14, [x9, x12]\n";
    ss << "and x15, x12, #31\n";
    ss << "ldrb w15, [x11, x15]\n";
    ss << "eor w14, w14, w15\n";
    ss << "strb w14, [x10, x12]\n";
    ss << "add x12, x12, #1\n";
    ss << "b maya_eh_decrypt_loop\n";
    ss << "maya_eh_decrypt_done:\n";
    ss << "stp xzr, xzr, [sp, #0]\nstp xzr, xzr, [sp, #16]\nadd sp, sp, #32\n";
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << "mov x13, #" << func.size << "\n";
    emit_eh_nucleus_cache(ss, "x10", "x13");
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x10, #1\n";
    ss << "stlr x10, [x9]\n";

    ss << "maya_eh_active_ready:\n";
    emit_restore_regs(ss);
    ss << "ldr x30, [sp, #240]\n";
    ss << "add sp, sp, #" << kSaveSize << "\n";
    ss << "b " << hex(func.slot_vaddr) << "\n";
    ss << "maya_eh_claim_fault:\nbrk #25\n";
    append_pool(ss, pool);

    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
    if (bytes.size() > kEntryStubSize) {
        throw std::runtime_error("EH entry stub exceeded reserved size for " + func.name);
    }
    return bytes;
}

std::vector<uint8_t> make_eh_cleanup_stub(const ProtectedFunction& func,
                                          const PayloadLayout& layout) {
    if (func.eh_metadata.unwind_resume == 0) {
        throw std::runtime_error("Runtime EH cleanup lacks _Unwind_Resume: " + func.name);
    }
    std::vector<uint64_t> pool;
    std::stringstream ss;
    const bool throw_needs_landing_code =
        std::any_of(func.eh_metadata.call_sites.begin(), func.eh_metadata.call_sites.end(),
                    [](const EhCallSite& site) { return site.landing_pad != 0; });
    ss << "mov x28, #0\nb maya_eh_cleanup_save\n.space 1016, 0\n";
    // Keep the typed entry handles independently addressable without
    // embedding a logical selector in either calling convention.
    ss << "maya_eh_cleanup_unwind:\nmov x28, #1\nb maya_eh_cleanup_save\n.space 1016, 0\n"
          "maya_eh_cleanup_throw:\n";
    if (throw_needs_landing_code) {
        // Forced unwinding may transfer control back into this function's cleanup or
        // handler landing pad.  Keep its retain until that path reaches the
        // authenticated unwind gateway or its patched normal return.
        if (func.eh_metadata.cxa_throw != 0) {
            ss << "b maya_eh_throw_passthrough\nnop\n";
        } else {
            // No call in this function can reach the typed throw entry.
            ss << "brk #24\n";
        }
    } else {
        ss << "mov x28, #2\nb maya_eh_cleanup_save\n";
    }
    ss << ".space 1016, 0\nmaya_eh_cleanup_rethrow:\n";
    if (func.eh_metadata.cxa_rethrow != 0) {
        // A rethrow originates in a landing pad.  Its retain is released by
        // the compiler-generated cleanup path that resumes forced unwinding
        // through the authenticated unwind entry.
        ss << "b maya_eh_rethrow_passthrough\nnop\n";
    } else {
        ss << "brk #26\nnop\n";
    }
    ss << ".space 1016, 0\n";
    ss << "maya_eh_cleanup_save:\nsub sp, sp, #" << kSaveSize << "\n";
    emit_save_regs(ss);
    ss << "str x28, [sp, #384]\n"
       << load_abs("x9", func.active_vaddr, pool)
       << "mov x16, #-1\n"
          "maya_eh_cleanup_dec:\nldaxr x10, [x9]\ncmp x10, #1\nb.lo maya_eh_cleanup_fault\n"
          "b.eq maya_eh_cleanup_last\nsub x11, x10, #1\nstlxr w12, x11, [x9]\n"
          "cbnz w12, maya_eh_cleanup_dec\nb maya_eh_cleanup_dispatch\n"
          "maya_eh_cleanup_last:\nstlxr w12, x16, [x9]\ncbnz w12, maya_eh_cleanup_dec\n";
    ss << load_abs("x21", func.slot_vaddr, pool) << "mov x10, x21\nmov x13, #" << func.slot_size
       << "\n";
    emit_mprotect(ss, "x10", "x13", 3, "maya_eh_cleanup_fault", layout, pool);
    ss << "mov x11, #0\nmaya_eh_cleanup_wipe:\ncmp x11, #" << func.slot_size
       << "\nb.hs maya_eh_cleanup_wiped\nstrb wzr, [x21, x11]\nadd x11, x11, #1\n"
          "b maya_eh_cleanup_wipe\nmaya_eh_cleanup_wiped:\n"
          "mov x10, x21\nmov x13, #"
       << func.slot_size << "\n";
    emit_cache_flush(ss, "x10", "x13", layout, pool);
    ss << "mov x10, x21\nmov x13, #" << func.slot_size << "\n";
    emit_mprotect(ss, "x10", "x13", 5, "maya_eh_cleanup_fault", layout, pool);
    ss << load_abs("x9", func.active_vaddr, pool)
       << "str xzr, [x9, #8]\nstr xzr, [x9, #16]\nstlr xzr, [x9]\n"
          "maya_eh_cleanup_dispatch:\nldr x28, [sp, #384]\nldr x30, [sp, #240]\n"
          "str x30, [sp, #392]\n";
    emit_restore_regs(ss);
    ss << "ldr x17, [sp, #392]\nldr x16, [sp, #384]\nadd sp, sp, #" << kSaveSize
       << "\n"
          "cmp x16, #1\nb.eq maya_eh_cleanup_resume\ncmp x16, #2\nb.eq "
          "maya_eh_cleanup_throw_tail\nbr x17\n"
          "maya_eh_cleanup_resume:\n"
       << load_abs("x16", func.eh_metadata.unwind_resume, pool)
       << "br x16\n"
          "maya_eh_cleanup_throw_tail:\n";
    if (func.eh_metadata.cxa_throw != 0)
        ss << load_abs("x16", func.eh_metadata.cxa_throw, pool) << "br x16\n";
    else
        ss << "brk #24\n";
    if (func.eh_metadata.cxa_throw != 0) {
        ss << "maya_eh_throw_passthrough:\n"
           << load_abs("x16", func.eh_metadata.cxa_throw, pool) << "br x16\n";
    }
    if (func.eh_metadata.cxa_rethrow != 0) {
        ss << "maya_eh_rethrow_passthrough:\n"
           << load_abs("x16", func.eh_metadata.cxa_rethrow, pool) << "br x16\n";
    }
    ss << "maya_eh_cleanup_fault:\nbrk #23\n";
    append_pool(ss, pool);
    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.eh_normal_cleanup_vaddr);
    if (bytes.size() > 0x2000)
        throw std::runtime_error("EH cleanup gateway exceeded reserved space: " + func.name);
    return bytes;
}

} // namespace maya::protection
