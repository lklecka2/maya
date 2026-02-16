#pragma once
#include <keystone/keystone.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include "InstructionLifter.hpp"

class StubGenerator {
public:
    StubGenerator() {
        if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) != KS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Keystone engine");
        }
    }

    ~StubGenerator() {
        if (ks) ks_close(ks);
    }

    std::vector<uint8_t> assemble(const std::string& assembly, uint64_t address = 0) {
        unsigned char* encode;
        size_t size;
        size_t count;

        if (ks_asm(ks, assembly.c_str(), address, &encode, &size, &count) != KS_ERR_OK) {
            std::cerr << "Failed to assemble: " << assembly << "\n";
            std::cerr << "Error: " << ks_strerror(ks_errno(ks)) << "\n";
            throw std::runtime_error("Keystone assembly failed");
        }

        std::vector<uint8_t> result(encode, encode + size);
        ks_free(encode);
        return result;
    }

    std::string load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool) {
        size_t pool_idx = pool.size();
        pool.push_back(value);
        return "ldr " + reg + ", Lpool_" + std::to_string(pool_idx) + "\n";
    }

    std::vector<uint8_t> create_common_bridge() {
        std::stringstream ss;
        ss <<
            "sub sp, sp, #240\n"
            "stp x0, x1, [sp, #0]\n"
            "stp x2, x3, [sp, #16]\n"
            "stp x4, x5, [sp, #32]\n"
            "stp x6, x7, [sp, #48]\n"
            "stp x8, x9, [sp, #64]\n"
            "stp x10, x11, [sp, #80]\n"
            "stp x12, x13, [sp, #96]\n"
            "stp x14, x15, [sp, #112]\n"
            "stp x18, x19, [sp, #128]\n"
            "stp x20, x21, [sp, #144]\n"
            "stp x22, x23, [sp, #160]\n"
            "stp x24, x25, [sp, #176]\n"
            "stp x26, x27, [sp, #192]\n"
            "stp x28, x29, [sp, #208]\n"
            "str x30, [sp, #224]\n"

            "sub sp, sp, #128\n"
            "stp q0, q1, [sp, #0]\n"
            "stp q2, q3, [sp, #32]\n"
            "stp q4, q5, [sp, #64]\n"
            "stp q6, q7, [sp, #96]\n"

            "mov x8, #64\n"
            "mov x0, #2\n"
            "mov x1, x16\n"
            "mov x2, x15\n"
            "svc #0\n"

            "ldp q0, q1, [sp, #0]\n"
            "ldp q2, q3, [sp, #32]\n"
            "ldp q4, q5, [sp, #64]\n"
            "ldp q6, q7, [sp, #96]\n"
            "add sp, sp, #128\n"

            "ldp x0, x1, [sp, #0]\n"
            "ldp x2, x3, [sp, #16]\n"
            "ldp x4, x5, [sp, #32]\n"
            "ldp x6, x7, [sp, #48]\n"
            "ldp x8, x9, [sp, #64]\n"
            "ldp x10, x11, [sp, #80]\n"
            "ldp x12, x13, [sp, #96]\n"
            "ldp x14, x15, [sp, #112]\n"
            "ldp x18, x19, [sp, #128]\n"
            "ldp x20, x21, [sp, #144]\n"
            "ldp x22, x23, [sp, #160]\n"
            "ldp x24, x25, [sp, #176]\n"
            "ldp x26, x27, [sp, #192]\n"
            "ldp x28, x29, [sp, #208]\n"
            "ldr x30, [sp, #224]\n"
            "add sp, sp, #240\n"

            "br x17\n";

        return assemble(ss.str());
    }

    std::vector<uint8_t> create_mini_stub(uint64_t enter_msg_addr, uint64_t enter_msg_len, uint64_t exit_msg_addr, uint64_t exit_msg_len, uint64_t common_bridge_addr, uint64_t original_insn_addr, uint32_t original_insn, uint64_t return_addr, InstructionLifter& lifter) {
        std::vector<uint64_t> pool;
        std::stringstream ss;

        // Save original x30 and x17 on stack.
        // x30 is for intercepting returns, x17 is for bridge calls.
        ss << "stp x29, x30, [sp, #-16]!\n";
        ss << "mov x29, sp\n";

        // Print Enter Message
        ss << "stp x16, x17, [sp, #-16]!\n";
        ss << "stp x14, x15, [sp, #-16]!\n";
        ss << load_abs("x16", enter_msg_addr, pool);
        ss << load_abs("x15", enter_msg_len, pool);
        ss << "adr x17, after_enter_bridge\n";
        ss << load_abs("x14", common_bridge_addr, pool);
        ss << "br x14\n";
        ss << "after_enter_bridge:\n";
        ss << "ldp x14, x15, [sp], #16\n";
        ss << "ldp x16, x17, [sp], #16\n";

        // Call Function Body
        // Set x30 to point to our exit stub.
        ss << "adr x30, return_here\n";

        // Execute First Instruction
        ss << lifter.lift(original_insn, original_insn_addr, pool).assembly;

        ss << load_abs("x15", return_addr, pool);
        ss << "br x15\n";

        ss << "return_here:\n";
        // Print Exit Message
        ss << "stp x16, x17, [sp, #-16]!\n";
        ss << "stp x14, x15, [sp, #-16]!\n";
        ss << load_abs("x16", exit_msg_addr, pool);
        ss << load_abs("x15", exit_msg_len, pool);
        ss << "adr x17, after_exit_bridge\n";
        ss << load_abs("x14", common_bridge_addr, pool);
        ss << "br x14\n";
        ss << "after_exit_bridge:\n";
        ss << "ldp x14, x15, [sp], #16\n";
        ss << "ldp x16, x17, [sp], #16\n";

        // Restore x29, x30 and return
        ss << "ldp x29, x30, [sp], #16\n";
        ss << "ret\n";

        ss << ".align 8\n";
        for (size_t i = 0; i < pool.size(); ++i) {
            ss << "Lpool_" << i << ": .quad " << pool[i] << "\n";
        }

        return assemble(ss.str());
    }

private:
    ks_engine* ks = nullptr;
};
