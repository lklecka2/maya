#pragma once
#include <LIEF/ELF.hpp>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <map>

struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
    std::vector<uint8_t> bytes;
};

enum RelocType : std::uint8_t {
    RELOC_BRANCH,
    RELOC_ADRP,
    RELOC_ADR,
    RELOC_ADRP_ADD,
    RELOC_OTHER
};

struct RelocationEntry {
    uint64_t instruction_addr;
    RelocType type;
    uint64_t original_target;
    uint32_t original_insn_bytes;
    uint64_t paired_instruction_addr = 0;
    uint32_t paired_insn_bytes = 0;
};

struct FunctionBounds {
    std::string name;
    uint64_t start_addr;
    uint64_t size;
    uint64_t new_start_addr = 0;
    std::vector<Instruction> instructions;
    std::vector<RelocationEntry> relocations;
    std::vector<uint8_t> patched_code;
};

struct Function {
    std::string name;
    uint64_t start_addr;
    uint64_t size;
    uint64_t relocated_start_addr;
    uint32_t original_first_insn;
};

struct ProtectorContext {
    std::unique_ptr<LIEF::ELF::Binary> binary;
    uint64_t original_entry_point = 0;
    bool is_aarch64 = false;
    std::string filename;
    std::vector<FunctionBounds> functions;
    std::vector<Function> instrumented_functions;
    std::map<uint64_t, uint64_t> addr_map;
};
