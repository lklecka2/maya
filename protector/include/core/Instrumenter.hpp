#pragma once
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <algorithm>
#include "Context.hpp"
#include "InstrumentationPolicy.hpp"
#include "StubGenerator.hpp"
#include "InstructionLifter.hpp"
#include "Utils.hpp"

class Instrumenter {
public:
    struct InstrumentationResult {
        std::vector<uint8_t> final_payload;
        std::map<uint64_t, uint64_t> mini_stub_map;
        uint64_t shadow_base;
    };

    static auto instrument(ProtectorContext& ctx) -> InstrumentationResult {
        InstrumentationResult res;
        StubGenerator stub_gen;
        InstructionLifter lifter;

        constexpr uint64_t section_alignment = 0x10000;
        constexpr size_t stub_alignment = 16;
        constexpr size_t msg_alignment = 8;

        // Calculate shadow base
        res.shadow_base = 0;
        for (const auto& func_bounds : ctx.functions) {
            res.shadow_base = std::max(res.shadow_base, func_bounds.new_start_addr + func_bounds.size);
        }
        res.shadow_base = Utils::align_to(res.shadow_base, section_alignment);

        // Create Common Bridge
        auto common_bridge = stub_gen.create_common_bridge();
        uint64_t common_bridge_vaddr = res.shadow_base;
        res.final_payload.insert(res.final_payload.end(), common_bridge.begin(), common_bridge.end());
        res.final_payload.resize(Utils::align_to(res.final_payload.size(), stub_alignment), 0);

        // Prepare messages
        auto* text_sec = ctx.binary->get_section(".text");
        uint64_t text_start = (text_sec != nullptr) ? text_sec->virtual_address() : 0;
        uint64_t text_end = (text_sec != nullptr) ? text_start + text_sec->size() : 0;
        uint64_t user_code_cutoff = text_end;

        for (const auto& sym : ctx.binary->symbols()) {
            if (sym.name() == "__libc_start_main" && sym.value() != 0) {
                user_code_cutoff = sym.value();
                break;
            }
        }

        struct MsgInfo { uint64_t vaddr; uint64_t len; };
        struct FuncMsgs { MsgInfo enter; MsgInfo exit; };
        std::map<uint64_t, FuncMsgs> function_msgs;
        std::vector<uint8_t> messages_payload;

        for (const auto& sym : ctx.binary->symbols()) {
            if (sym.type() == LIEF::ELF::Symbol::TYPE::FUNC && sym.size() > 0) {
                if (!InstrumentationPolicy::should_instrument(sym.name(), sym.value(), text_start, text_end, user_code_cutoff)) {
                    continue;
                }

                FuncMsgs msgs;

                // Enter message
                std::stringstream enter_ss;
                enter_ss << "[MAYA] Calling: " << sym.name() << " @ 0x" << std::hex << sym.value() << "\n";
                std::string enter_msg = enter_ss.str();
                msgs.enter = { messages_payload.size(), enter_msg.length() };
                messages_payload.insert(messages_payload.end(), enter_msg.begin(), enter_msg.end());
                messages_payload.resize(Utils::align_to(messages_payload.size(), msg_alignment), 0);

                // Exit message
                std::stringstream exit_ss;
                exit_ss << "[MAYA] Returning from: " << sym.name() << " @ 0x" << std::hex << sym.value() << "\n";
                std::string exit_msg = exit_ss.str();
                msgs.exit = { messages_payload.size(), exit_msg.length() };
                messages_payload.insert(messages_payload.end(), exit_msg.begin(), exit_msg.end());
                messages_payload.resize(Utils::align_to(messages_payload.size(), msg_alignment), 0);

                function_msgs[sym.value()] = msgs;
            }
        }

        uint64_t messages_vaddr_start = res.shadow_base + res.final_payload.size();
        for (auto& entry : function_msgs) {
            entry.second.enter.vaddr += messages_vaddr_start;
            entry.second.exit.vaddr += messages_vaddr_start;
        }
        res.final_payload.insert(res.final_payload.end(), messages_payload.begin(), messages_payload.end());
        res.final_payload.resize(Utils::align_to(res.final_payload.size(), stub_alignment), 0);

        // Create Mini-Stubs
        for (const auto& entry : function_msgs) {
            uint64_t original_addr = entry.first;
            FuncMsgs msgs = entry.second;

            uint64_t relocated_addr = 0;
            for (const auto& func_bounds : ctx.functions) {
                if (original_addr >= func_bounds.start_addr && original_addr < (func_bounds.start_addr + func_bounds.size)) {
                    relocated_addr = func_bounds.new_start_addr + (original_addr - func_bounds.start_addr);
                    break;
                }
            }
            if (relocated_addr == 0) {
                continue;
            }

            auto insn_bytes_vec = ctx.binary->get_content_from_virtual_address(original_addr, 4);
            uint32_t original_insn = *reinterpret_cast<const uint32_t*>(insn_bytes_vec.data());

            uint64_t mini_stub_vaddr = res.shadow_base + res.final_payload.size();
            auto mini_stub = stub_gen.create_mini_stub(
                msgs.enter.vaddr, msgs.enter.len,
                msgs.exit.vaddr, msgs.exit.len,
                common_bridge_vaddr,
                original_addr, original_insn, relocated_addr + 4, lifter
            );

            res.final_payload.insert(res.final_payload.end(), mini_stub.begin(), mini_stub.end());
            res.mini_stub_map[original_addr] = mini_stub_vaddr;
            res.final_payload.resize(Utils::align_to(res.final_payload.size(), stub_alignment), 0);
        }

        return res;
    }
};
