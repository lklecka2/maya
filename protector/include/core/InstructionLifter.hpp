#pragma once
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>

class InstructionLifter {
public:
    InstructionLifter() {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cs_handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone for InstructionLifter");
        }
        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

        if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks_handle) != KS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Keystone for InstructionLifter");
        }
    }

    ~InstructionLifter() {
        if (cs_handle != 0u) {
            cs_close(&cs_handle);
        }
        if (ks_handle != nullptr) {
            ks_close(ks_handle);
        }
    }

    struct LiftedResult {
        std::string assembly;
        bool was_lifted;
    };

    auto lift(uint32_t insn_bytes, uint64_t insn_addr, std::vector<uint64_t>& pool) -> LiftedResult {
        cs_insn* insn;
        size_t count = cs_disasm(cs_handle, reinterpret_cast<uint8_t*>(&insn_bytes), 4, insn_addr, 1, &insn);
        LiftedResult result = {"", false};

        if (count > 0) {
            const cs_detail* detail = insn->detail;
            if (detail != nullptr && detail->arm64.op_count > 0) {
                if (insn->id == ARM64_INS_ADR || insn->id == ARM64_INS_ADRP) {
                    uint64_t target = detail->arm64.operands[1].imm;
                    std::string reg = cs_reg_name(cs_handle, detail->arm64.operands[0].reg);
                    result.assembly = load_abs(reg, target, pool);
                    result.was_lifted = true;
                }
                else if (insn->id == ARM64_INS_B || insn->id == ARM64_INS_BL) {
                    if (detail->arm64.operands[0].type == ARM64_OP_IMM) {
                        uint64_t target = detail->arm64.operands[0].imm;

                        if (insn->id == ARM64_INS_B && detail->arm64.cc != ARM64_CC_INVALID) {
                            // Conditional branch B.cond
                            std::string cond = insn->mnemonic;
                            if (cond.find('.') != std::string::npos) {
                                cond = cond.substr(cond.find('.') + 1);
                            } else {
                                // Fallback where mnemonic is just 'b' but cc is set
                                static const char* cc_map[] = { "invalid", "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv" };
                                cond = cc_map[detail->arm64.cc];
                            }

                            result.assembly = "b." + cond + " Ltarget_" + std::to_string(pool.size()) + "\n";
                            result.assembly += "b Lskip_abs_branch_" + std::to_string(pool.size()) + "\n";
                            result.assembly += "Ltarget_" + std::to_string(pool.size()) + ":\n";
                            result.assembly += load_abs("x15", target, pool) + "br x15\n";
                            result.assembly += "Lskip_abs_branch_" + std::to_string(pool.size()-1) + ":\n";
                        } else {
                            // Unconditional branch B or BL
                            std::string mnemonic = (insn->id == ARM64_INS_BL) ? "blr" : "br";
                            result.assembly = load_abs("x15", target, pool) + mnemonic + " x15\n";
                        }
                        result.was_lifted = true;
                    }
                }
                else if (insn->id == ARM64_INS_CBZ || insn->id == ARM64_INS_CBNZ) {
                    uint64_t target = detail->arm64.operands[1].imm;
                    std::string reg = cs_reg_name(cs_handle, detail->arm64.operands[0].reg);
                    result.assembly = std::string(insn->mnemonic) + " " + reg + ", Ltarget_" + std::to_string(pool.size()) + "\n";
                    result.assembly += "b Lskip_abs_branch_" + std::to_string(pool.size()) + "\n";
                    result.assembly += "Ltarget_" + std::to_string(pool.size()) + ":\n";
                    result.assembly += load_abs("x15", target, pool) + "br x15\n";
                    result.assembly += "Lskip_abs_branch_" + std::to_string(pool.size()-1) + ":\n";
                    result.was_lifted = true;
                }
                else if (insn->id == ARM64_INS_TBZ || insn->id == ARM64_INS_TBNZ) {
                    uint64_t target = detail->arm64.operands[2].imm;
                    std::string reg = cs_reg_name(cs_handle, detail->arm64.operands[0].reg);
                    std::string bit = std::to_string(detail->arm64.operands[1].imm);
                    result.assembly = std::string(insn->mnemonic) + " " + reg + ", #" + bit + ", Ltarget_" + std::to_string(pool.size()) + "\n";
                    result.assembly += "b Lskip_abs_branch_" + std::to_string(pool.size()) + "\n";
                    result.assembly += "Ltarget_" + std::to_string(pool.size()) + ":\n";
                    result.assembly += load_abs("x15", target, pool) + "br x15\n";
                    result.assembly += "Lskip_abs_branch_" + std::to_string(pool.size()-1) + ":\n";
                    result.was_lifted = true;
                }
            }

            if (!result.was_lifted) {
                // Check if Keystone can assemble this mnemonic
                std::string test_asm = std::string(insn->mnemonic) + " " + std::string(insn->op_str);
                unsigned char* encode;
                size_t size;
                size_t ks_count;
                if (ks_asm(ks_handle, test_asm.c_str(), 0, &encode, &size, &ks_count) == KS_ERR_OK) {
                    ks_free(encode);
                    result.assembly = test_asm + "\n";
                } else {
                    std::stringstream ss_insn;
                    constexpr int insn_hex_width = 8;
                    ss_insn << ".word 0x" << std::hex << std::setw(insn_hex_width) << std::setfill('0') << insn_bytes << "\n";
                    result.assembly = ss_insn.str();
                }
            }
            cs_free(insn, count);
        } else {
            std::stringstream ss_insn;
            constexpr int insn_hex_width = 8;
            ss_insn << ".word 0x" << std::hex << std::setw(insn_hex_width) << std::setfill('0') << insn_bytes << "\n";
            result.assembly = ss_insn.str();
        }

        return result;
    }

private:
    csh cs_handle = 0;
    ks_engine* ks_handle = nullptr;

    static auto load_abs(const std::string& reg, uint64_t value, std::vector<uint64_t>& pool) -> std::string {
        size_t pool_idx = pool.size();
        pool.push_back(value);
        return "ldr " + reg + ", Lpool_" + std::to_string(pool_idx) + "\n";
    }
};
