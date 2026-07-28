#include "FragmentExecution.hpp"
#include "CodeRelocation.hpp"
#include "Controllets.hpp"
#include <algorithm>
#include <cstring>
#include <keystone/keystone.h>
#include <sstream>
#include <stdexcept>

namespace maya::protection {
namespace {
std::vector<uint8_t> assemble(const std::string& text, uint64_t pc) {
    ks_engine* engine = nullptr;
    if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &engine) != KS_ERR_OK)
        throw std::runtime_error("Keystone fragment veneer init failed");
    unsigned char* out = nullptr;
    size_t size = 0, count = 0;
    if (ks_asm(engine, text.c_str(), pc, &out, &size, &count) != KS_ERR_OK) {
        std::string error = ks_strerror(ks_errno(engine));
        ks_close(engine);
        throw std::runtime_error("Fragment veneer assembly failed: " + error);
    }
    std::vector<uint8_t> bytes(out, out + size);
    ks_free(out);
    ks_close(engine);
    return bytes;
}
std::vector<uint8_t> veneer(const ProtectedFunction& func, const FragmentExit& exit, uint64_t pc,
                            uint64_t gateway) {
    if (func.v3_control_enabled) {
        uint64_t label_low = 0, label_high = 0;
        std::memcpy(&label_low, exit.v3_lookup_label.data(), sizeof(label_low));
        std::memcpy(&label_high, exit.v3_lookup_label.data() + sizeof(label_low),
                    sizeof(label_high));
        if ((label_low | label_high) == 0)
            throw std::runtime_error("V3 veneer lacks an opaque lookup label");
        std::ostringstream text;
        text << "stp x12, x13, [sp, #-16]!\n"
             << "stp x14, x15, [sp, #-16]!\n"
             << "stp x16, x17, [sp, #-16]!\n"
             << "mov x12, xzr\nmov x13, xzr\nmov x14, xzr\n"
             << (func.v3_gateway_abi_family == 0 ? "ldr x16, Llookup_low\nldr x17, Llookup_high\n"
                 : func.v3_gateway_abi_family == 1
                     ? "ldr x12, Llookup_low\nldr x13, Llookup_high\nstp x12, x13, [sp, #-16]!\n"
                 : func.v3_gateway_abi_family == 2
                     ? "ldr x16, Llookup_low\nldr x13, Llookup_high\nstp xzr, x13, [sp, #-16]!\n"
                     : "ldr x12, Llookup_low\nldr x17, Llookup_high\n")
             << "ldr x15, Lgateway\nbr x15\n.align 3\n"
             << "Llookup_low: .quad " << label_low << "\nLlookup_high: .quad " << label_high
             << "\nLgateway: .quad " << gateway << "\n";
        return assemble(text.str(), pc);
    }
    uint32_t target = exit.target_fragment_id;
    if (exit.kind == FragmentExitKind::CallProtected ||
        exit.kind == FragmentExitKind::TailcallProtected)
        target = exit.target_function_id;
    const uint32_t target_function = (exit.kind == FragmentExitKind::CallProtected ||
                                      exit.kind == FragmentExitKind::TailcallProtected)
                                         ? target
                                         : func.id;
    const bool external = exit.kind == FragmentExitKind::CallExternal ||
                          exit.kind == FragmentExitKind::SetjmpExternal ||
                          exit.kind == FragmentExitKind::LongjmpExternal;
    const uint64_t target_token =
        external ? exit.compatibility_target
                 : (((uint64_t(target_function) << 32) | target) ^ func.event_cookie);
    const uint64_t continuation_token =
        ((uint64_t(func.id) << 32) | exit.continuation_fragment_id) ^ func.event_cookie;
    std::ostringstream text;
    text << "stp x12, x13, [sp, #-16]!\n"
         << "stp x14, x15, [sp, #-16]!\n"
         << "stp x16, x17, [sp, #-16]!\n";
    if (func.controllet_family == 0)
        text << "ldr x12, Lcontinuation\nmov x13, #" << exit.site_id << "\nmov x14, #" << func.id
             << "\nmov x16, #" << static_cast<uint32_t>(exit.kind) << "\nldr x17, Ltarget\n";
    else if (func.controllet_family == 1)
        text << "ldr x12, Ltarget\nldr x13, Lcontinuation\nmov x14, #"
             << static_cast<uint32_t>(exit.kind) << "\nmov x16, #" << exit.site_id << "\nmov x17, #"
             << func.id << "\n";
    else
        text << "mov x12, #" << exit.site_id << "\nmov x13, #" << static_cast<uint32_t>(exit.kind)
             << "\nldr x14, Ltarget\nmov x16, #" << func.id << "\nldr x17, Lcontinuation\n";
    text << "ldr x15, Lgateway\n"
         << "br x15\n.align 3\nLtarget: .quad " << target_token << "\nLcontinuation: .quad "
         << continuation_token << "\nLgateway: .quad " << gateway << "\n";
    return assemble(text.str(), pc);
}
} // namespace
void prepare_fragment_execution(std::vector<ProtectedFunction>& funcs) {
    for (auto& func : funcs) {
        if (!func.cfg_execution_enabled)
            continue;
        // Seed-stable V2 clustering.  The multiplicative permutation prevents
        // adjacent selected functions from sharing one uniform controllet.
        const uint64_t gateway = func.stub_vaddr + func.v3_event_gateway_offset;
        for (auto& fragment : func.fragments) {
            fragment.cluster_id = func.cluster_id;
            fragment.metadata_family = (func.controllet_family + fragment.fragment_id) % 3u;
            fragment.runtime_literal_offsets.clear();
            fragment.state_token_offsets.clear();
            fragment.state_token_values.clear();
            fragment.state_token_load_bias.clear();
            const size_t function_offset = fragment.original_start - func.original_start;
            fragment.execution_bytes.assign(func.patched_bytes.begin() + function_offset,
                                            func.patched_bytes.begin() + function_offset +
                                                fragment.size);
            const uint64_t last = fragment.original_start + fragment.size - 4;
            uint32_t raw = 0;
            std::memcpy(&raw, fragment.execution_bytes.data() + fragment.execution_bytes.size() - 4,
                        4);
            std::vector<FragmentExit> order = fragment.exits;
            if (fragment.exits.size() == 2)
                order = {fragment.exits[1], fragment.exits[0]};
            std::vector<size_t> offsets;
            for (const auto& exit : order) {
                offsets.push_back(fragment.execution_bytes.size());
                const size_t veneer_offset = fragment.execution_bytes.size();
                auto bytes = veneer(
                    func, exit, fragment.original_start + fragment.execution_bytes.size(), gateway);
                if (!func.v3_control_enabled) {
                    fragment.state_token_offsets.push_back(veneer_offset + bytes.size() - 24);
                    fragment.state_token_offsets.push_back(veneer_offset + bytes.size() - 16);
                }
                uint64_t target_value = 0, continuation_value = 0;
                if (!func.v3_control_enabled) {
                    std::memcpy(&target_value, bytes.data() + bytes.size() - 24, 8);
                    std::memcpy(&continuation_value, bytes.data() + bytes.size() - 16, 8);
                }
                uint32_t expected_target = exit.target_fragment_id;
                if (exit.kind == FragmentExitKind::CallProtected ||
                    exit.kind == FragmentExitKind::TailcallProtected)
                    expected_target = exit.target_function_id;
                const uint32_t expected_function =
                    (exit.kind == FragmentExitKind::CallProtected ||
                     exit.kind == FragmentExitKind::TailcallProtected)
                        ? expected_target
                        : func.id;
                const bool expected_external = exit.kind == FragmentExitKind::CallExternal ||
                                               exit.kind == FragmentExitKind::SetjmpExternal ||
                                               exit.kind == FragmentExitKind::LongjmpExternal;
                const uint64_t expected_target_value =
                    expected_external ? exit.compatibility_target
                                      : (((uint64_t(expected_function) << 32) | expected_target) ^
                                         func.event_cookie);
                const uint64_t expected_continuation =
                    ((uint64_t(func.id) << 32) | exit.continuation_fragment_id) ^ func.event_cookie;
                if (!func.v3_control_enabled) {
                    if (target_value != expected_target_value ||
                        continuation_value != expected_continuation)
                        throw std::runtime_error(
                            "Controllet veneer symbolic literal mismatch for " + func.name);
                    fragment.state_token_values.push_back(target_value);
                    fragment.state_token_values.push_back(continuation_value);
                    fragment.state_token_load_bias.push_back(
                        exit.kind == FragmentExitKind::CallExternal ||
                        exit.kind == FragmentExitKind::SetjmpExternal ||
                        exit.kind == FragmentExitKind::LongjmpExternal);
                    fragment.state_token_load_bias.push_back(0);
                    std::memset(bytes.data() + bytes.size() - 24, 0, 16);
                }
                fragment.runtime_literal_offsets.push_back(veneer_offset + bytes.size() - 8);
                fragment.execution_bytes.insert(fragment.execution_bytes.end(), bytes.begin(),
                                                bytes.end());
            }
            const bool terminal = !fragment.exits.empty() && fragment.exits.front().pc == last;
            if (terminal) {
                const size_t chosen = fragment.exits.size() == 2 ? 1 : 0;
                const uint64_t target = fragment.original_start + offsets[chosen];
                const uint32_t branch = fragment.exits.size() == 2 ? patch_branch(raw, last, target)
                                                                   : make_b(last, target);
                std::memcpy(fragment.execution_bytes.data() + fragment.size - 4, &branch, 4);
            }
            for (size_t offset = 0; offset + 4 <= fragment.size; offset += 4) {
                uint32_t insn = 0;
                std::memcpy(&insn, fragment.execution_bytes.data() + offset, 4);
                if ((insn & 0xff000000u) != 0x58000000u)
                    continue;
                int32_t imm19 = static_cast<int32_t>((insn >> 5) & 0x7ffffu);
                if (imm19 & (1 << 18))
                    imm19 |= ~0x7ffff;
                const uint64_t pc = fragment.original_start + offset;
                const uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(pc) +
                                                              (static_cast<int64_t>(imm19) << 2));
                if (target < func.original_start ||
                    target + 8 > func.original_start + func.patched_bytes.size())
                    continue;
                while (fragment.execution_bytes.size() % 8)
                    fragment.execution_bytes.push_back(0);
                const uint64_t local = fragment.original_start + fragment.execution_bytes.size();
                fragment.execution_bytes.insert(
                    fragment.execution_bytes.end(),
                    func.patched_bytes.begin() + (target - func.original_start),
                    func.patched_bytes.begin() + (target - func.original_start) + 8);
                const size_t source_literal_offset =
                    static_cast<size_t>(target - func.original_start);
                const bool relocated_address_literal =
                    std::find(func.runtime_literal_offsets.begin(),
                              func.runtime_literal_offsets.end(),
                              source_literal_offset) != func.runtime_literal_offsets.end();
                const bool analyzed_address_literal =
                    std::any_of(func.data_refs.begin(), func.data_refs.end(), [&](const auto& ref) {
                        return ref.pc == pc && ref.kind != DataRefKind::LiteralPoolEntry &&
                               ref.kind != DataRefKind::ConstantReference;
                    });
                if (relocated_address_literal || analyzed_address_literal) {
                    fragment.runtime_literal_offsets.push_back(
                        static_cast<size_t>(local - fragment.original_start));
                }
                const int64_t delta = static_cast<int64_t>(local) - static_cast<int64_t>(pc);
                const uint32_t patched =
                    (insn & 0xff00001fu) | ((static_cast<uint32_t>(delta >> 2) & 0x7ffffu) << 5);
                std::memcpy(fragment.execution_bytes.data() + offset, &patched, 4);
            }
            if (fragment.execution_bytes.size() > fragment.storage_size)
                throw std::runtime_error(
                    "Fragment execution veneer exceeded reserved storage for " + func.name);
        }
    }
}
} // namespace maya::protection
