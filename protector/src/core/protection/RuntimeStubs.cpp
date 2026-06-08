#include "RuntimeStubs.hpp"

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
            throw std::runtime_error("Keystone failed to assemble runtime stub: " + std::string(ks_strerror(ks_errno(ks_))));
        }
        std::vector<uint8_t> out(encode, encode + size);
        ks_free(encode);
        return out;
    }

private:
    ks_engine* ks_ = nullptr;
};

std::string load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool);
void append_pool(std::stringstream& ss, const std::vector<uint64_t>& pool);
void emit_mmap_slot(std::stringstream& ss, const ProtectedFunction& func);
void emit_munmap_slot(std::stringstream& ss);
void emit_save_regs(std::stringstream& ss);
void emit_restore_regs(std::stringstream& ss);
void emit_cache_flush(std::stringstream& ss, const std::string& base_reg, const std::string& size_reg, const std::string& suffix = "");
void emit_sync_core(std::stringstream& ss);
void emit_load_thread_state(std::stringstream& ss, const Layout& layout, const std::string& dst_reg, std::vector<uint64_t>& pool);
void emit_atomic_active_increment(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool);
void emit_publish_active_one(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool);
void emit_publish_slot_state(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool);
void emit_load_published_slot(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool);
void emit_publish_active_zero(std::stringstream& ss);
void emit_atomic_active_decrement(std::stringstream& ss);
void emit_apply_pie_literal_bias(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool);

std::string load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool) {
    const size_t idx = pool.size();
    pool.push_back(value);
    const std::string tmp = (reg == "x17") ? "x16" : "x17";
    const std::string link = (tmp == "x16" || reg == "x16") ? "x15" : "x16";
    std::stringstream ss;
    ss << "adr " << tmp << ", Lpool_" << idx << "\n";
    ss << "ldr " << reg << ", [";
    ss << tmp << "]\n";
    ss << "ldr " << link << ", [" << tmp << ", #8]\n";
    ss << "sub " << tmp << ", " << tmp << ", " << link << "\n";
    ss << "add " << reg << ", " << reg << ", " << tmp << "\n";
    return ss.str();
}

void append_pool(std::stringstream& ss, const std::vector<uint64_t>& pool) {
    ss << ".align 3\n";
    for (size_t i = 0; i < pool.size(); ++i) {
        ss << "Lpool_" << i << ": .quad " << pool[i] << "\n";
        ss << ".quad Lpool_" << i << "\n";
    }
}

void emit_mmap_slot(std::stringstream& ss, const ProtectedFunction& func) {
    constexpr uint64_t kMmapSyscall = 222;
    constexpr uint64_t kProtReadWriteExec = 7;
    constexpr uint64_t kMapPrivateAnonymous = 0x22;
    ss << "mov x0, #0\n";
    ss << "mov x1, #" << func.slot_size << "\n";
    ss << "mov x2, #" << kProtReadWriteExec << "\n";
    ss << "mov x3, #" << kMapPrivateAnonymous << "\n";
    ss << "mov x4, #-1\n";
    ss << "mov x5, #0\n";
    ss << "mov x8, #" << kMmapSyscall << "\n";
    ss << "svc #0\n";
    ss << "tbnz x0, #63, maya_mmap_failed\n";
    ss << "mov x21, x0\n";
}

void emit_munmap_slot(std::stringstream& ss) {
    constexpr uint64_t kMunmapSyscall = 215;
    ss << "mov x0, x13\n";
    ss << "mov x1, x15\n";
    ss << "mov x8, #" << kMunmapSyscall << "\n";
    ss << "svc #0\n";
}

std::vector<uint8_t> make_return_stub(const Layout& layout, SlotStrategy strategy) {
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
    ss << "mov x12, #" << kFrameSize << "\n";
    ss << "madd x11, x10, x12, x11\n";
    ss << "ldr x17, [x11, #0]\n";
    ss << "ldr x13, [x11, #8]\n";
    ss << "ldr x14, [x11, #16]\n";
    ss << "ldr x15, [x11, #24]\n";
    emit_atomic_active_decrement(ss);
    ss << "mov x11, #0\n";
    ss << "maya_zero_loop:\n";
    ss << "cmp x11, x15\n";
    ss << "b.hs maya_zero_done\n";
    ss << "strb wzr, [x13, x11]\n";
    ss << "add x11, x11, #1\n";
    ss << "b maya_zero_loop\n";
    ss << "maya_zero_done:\n";
    emit_cache_flush(ss, "x13", "x15");
    if (strategy == SlotStrategy::RuntimeAllocator) {
        emit_munmap_slot(ss);
    }
    emit_publish_active_zero(ss);
    ss << "maya_return_restore:\n";
    ss << "str x17, [sp, #240]\n";
    emit_restore_regs(ss);
    ss << "ldr x17, [sp, #240]\n";
    ss << "add sp, sp, #" << kSaveSize << "\n";
    ss << "br x17\n";
    ss << "maya_frame_underflow:\n";
    ss << "brk #0\n";
    append_pool(ss, pool);
    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), layout.return_stub_vaddr);
    if (bytes.size() > 512) {
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
}

void emit_restore_regs(std::stringstream& ss) {
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

void emit_cache_flush(std::stringstream& ss, const std::string& base_reg, const std::string& size_reg, const std::string& suffix) {
    ss << "add x20, " << base_reg << ", " << size_reg << "\n";
    ss << "bic x19, " << base_reg << ", #63\n";
    ss << "maya_dc_loop" << suffix << ":\n";
    ss << "cmp x19, x20\n";
    ss << "b.hs maya_dc_done" << suffix << "\n";
    ss << "dc cvau, x19\n";
    ss << "add x19, x19, #64\n";
    ss << "b maya_dc_loop" << suffix << "\n";
    ss << "maya_dc_done" << suffix << ":\n";
    ss << "dsb ish\n";
    ss << "bic x19, " << base_reg << ", #63\n";
    ss << "maya_ic_loop" << suffix << ":\n";
    ss << "cmp x19, x20\n";
    ss << "b.hs maya_ic_done" << suffix << "\n";
    ss << "ic ivau, x19\n";
    ss << "add x19, x19, #64\n";
    ss << "b maya_ic_loop" << suffix << "\n";
    ss << "maya_ic_done" << suffix << ":\n";
    ss << "dsb ish\n";
    ss << "isb\n";
}

void emit_sync_core(std::stringstream& ss) {
    constexpr uint64_t kMembarrierSyscall = 283;
    constexpr uint64_t kPrivateExpeditedSyncCore = 1u << 5;
    constexpr uint64_t kRegisterPrivateExpeditedSyncCore = 1u << 6;
    ss << "mov x8, #" << kMembarrierSyscall << "\n";
    ss << "mov x0, #" << kRegisterPrivateExpeditedSyncCore << "\n";
    ss << "mov x1, #0\n";
    ss << "mov x2, #0\n";
    ss << "svc #0\n";
    ss << "mov x8, #" << kMembarrierSyscall << "\n";
    ss << "mov x0, #" << kPrivateExpeditedSyncCore << "\n";
    ss << "mov x1, #0\n";
    ss << "mov x2, #0\n";
    ss << "svc #0\n";
}

void emit_load_thread_state(std::stringstream& ss, const Layout& layout, const std::string& dst_reg, std::vector<uint64_t>& pool) {
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

void emit_atomic_active_increment(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool) {
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

void emit_publish_active_one(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x10, #1\n";
    ss << "stlr x10, [x9]\n";
}

void emit_publish_slot_state(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool) {
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "str x21, [x9, #8]\n";
    ss << "mov x10, #" << func.slot_size << "\n";
    ss << "str x10, [x9, #16]\n";
}

void emit_load_published_slot(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool) {
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

void emit_apply_pie_literal_bias(std::stringstream& ss, const ProtectedFunction& func, std::vector<uint64_t>& pool) {
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

std::vector<uint8_t> make_entry_stub(const ProtectedFunction& func, const Layout& layout, const ProtectionContext& ctx) {
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
    ss << "mov x12, #" << kFrameSize << "\n";
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
        emit_mmap_slot(ss, func);
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
    ss << load_abs("x11", layout.key_vaddr, pool);
    ss << "mov x12, #0\n";
    ss << "mov x13, #" << func.body_size << "\n";
    ss << "maya_decrypt_loop:\n";
    ss << "cmp x12, x13\n";
    ss << "b.hs maya_decrypt_done\n";
    ss << "ldrb w14, [x9, x12]\n";
    ss << "and x15, x12, #7\n";
    ss << "ldrb w15, [x11, x15]\n";
    ss << "eor w14, w14, w15\n";
    ss << "strb w14, [x10, x12]\n";
    ss << "add x12, x12, #1\n";
    ss << "b maya_decrypt_loop\n";
    ss << "maya_decrypt_done:\n";
    if (strategy == SlotStrategy::RuntimeAllocator) {
        ss << "mov x10, x21\n";
    } else {
        ss << load_abs("x10", func.slot_vaddr, pool);
    }
    if (strategy == SlotStrategy::RuntimeAllocator &&
        ctx.runtime_features.binary_kind == BinaryKind::PositionIndependentExecutable) {
        emit_apply_pie_literal_bias(ss, func, pool);
    }
    ss << "mov x13, #" << func.body_size << "\n";
    emit_cache_flush(ss, "x10", "x13", "_decrypt");
    emit_sync_core(ss);
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
    emit_cache_flush(ss, "x10", "x13", "_ready");

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
    append_pool(ss, pool);

    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
    if (bytes.size() > kEntryStubSize) {
        throw std::runtime_error("Entry stub exceeded reserved size for " + func.name);
    }
    return bytes;
}

std::vector<uint8_t> make_eh_entry_stub(const ProtectedFunction& func, const Layout& layout) {
    std::vector<uint64_t> pool;
    std::stringstream ss;
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
    ss << "clrex\n";
    ss << "cmp x10, x16\n";
    ss << "b.ne maya_eh_active_ready\n";
    ss << "yield\n";
    ss << "b maya_eh_claim_loop\n";

    ss << "maya_eh_decrypt:\n";
    ss << load_abs("x9", func.enc_vaddr, pool);
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << load_abs("x11", layout.key_vaddr, pool);
    ss << "mov x12, #0\n";
    ss << "mov x13, #" << func.size << "\n";
    ss << "maya_eh_decrypt_loop:\n";
    ss << "cmp x12, x13\n";
    ss << "b.hs maya_eh_decrypt_done\n";
    ss << "ldrb w14, [x9, x12]\n";
    ss << "and x15, x12, #7\n";
    ss << "ldrb w15, [x11, x15]\n";
    ss << "eor w14, w14, w15\n";
    ss << "strb w14, [x10, x12]\n";
    ss << "add x12, x12, #1\n";
    ss << "b maya_eh_decrypt_loop\n";
    ss << "maya_eh_decrypt_done:\n";
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << "mov x13, #" << func.size << "\n";
    emit_cache_flush(ss, "x10", "x13", "_eh_decrypt");
    emit_sync_core(ss);
    ss << load_abs("x9", func.active_vaddr, pool);
    ss << "mov x10, #1\n";
    ss << "stlr x10, [x9]\n";

    ss << "maya_eh_active_ready:\n";
    ss << load_abs("x10", func.slot_vaddr, pool);
    ss << "mov x13, #" << func.size << "\n";
    emit_cache_flush(ss, "x10", "x13", "_eh_ready");
    emit_restore_regs(ss);
    ss << "add sp, sp, #" << kSaveSize << "\n";
    ss << "b " << hex(func.slot_vaddr) << "\n";
    append_pool(ss, pool);

    Assembler assembler;
    auto bytes = assembler.assemble(ss.str(), func.stub_vaddr);
    if (bytes.size() > kEntryStubSize) {
        throw std::runtime_error("EH entry stub exceeded reserved size for " + func.name);
    }
    return bytes;
}

} // namespace maya::protection
