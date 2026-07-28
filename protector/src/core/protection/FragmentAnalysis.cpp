#include "FragmentAnalysis.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <capstone/capstone.h>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "CodeRelocation.hpp"
#include "FunctionLayout.hpp"
#include "core/Logger.hpp"

namespace maya::protection {
namespace {

struct AddressRange {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string name;
};

struct NamedAddress {
    uint64_t addr = 0;
    std::string name;
};

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool contains_text(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

std::string join_reasons(const std::vector<std::string>& reasons) {
    if (reasons.empty()) {
        return "ordinary ABI-compatible function";
    }
    std::vector<std::string> unique_reasons;
    for (const auto& reason : reasons) {
        if (std::find(unique_reasons.begin(), unique_reasons.end(), reason) ==
            unique_reasons.end()) {
            unique_reasons.push_back(reason);
        }
    }
    std::ostringstream out;
    for (size_t i = 0; i < unique_reasons.size(); ++i) {
        if (i != 0) {
            out << "; ";
        }
        out << unique_reasons[i];
    }
    return out.str();
}

std::vector<AddressRange> collect_section_ranges(const ProtectionContext& ctx) {
    std::vector<AddressRange> ranges;
    for (const auto& sec : ctx.binary->sections()) {
        if (sec.virtual_address() == 0 || sec.size() == 0) {
            continue;
        }
        ranges.push_back({sec.virtual_address(), sec.virtual_address() + sec.size(), sec.name()});
    }
    return ranges;
}

std::vector<NamedAddress> collect_plt_symbols(const ProtectionContext& ctx) {
    std::vector<NamedAddress> symbols;
    const auto* plt = ctx.binary->get_section(".plt");
    if (plt == nullptr) {
        return symbols;
    }

    const auto& relocations = ctx.binary->pltgot_relocations();
    const uint64_t stride = relocations.empty() ? 0x10 : (plt->size() - 0x20) / relocations.size();
    uint64_t entry = plt->virtual_address() + 0x20;
    for (const auto& reloc : relocations) {
        if (reloc.symbol() == nullptr || reloc.symbol()->name().empty()) {
            entry += stride;
            continue;
        }
        symbols.push_back({entry, reloc.symbol()->name()});
        entry += stride;
    }
    return symbols;
}

std::string section_name_for(const std::vector<AddressRange>& ranges, uint64_t addr) {
    for (const auto& range : ranges) {
        if (addr >= range.start && addr < range.end) {
            return range.name;
        }
    }
    return {};
}

std::string resolved_symbol_name_at(const ProtectionContext& ctx,
                                    const std::vector<NamedAddress>& plt_symbols, uint64_t addr) {
    std::string name = symbol_name_at(ctx, addr);
    if (!name.empty()) {
        return name;
    }
    for (const auto& symbol : plt_symbols) {
        if (symbol.addr == addr) {
            return symbol.name;
        }
    }
    return {};
}

bool address_in_load_image(const ProtectionContext& ctx, uint64_t addr) {
    for (const auto& seg : ctx.binary->segments()) {
        if (seg.type() != LIEF::ELF::Segment::TYPE::LOAD) {
            continue;
        }
        const uint64_t start = seg.virtual_address();
        const uint64_t end = start + seg.virtual_size();
        if (addr >= start && addr < end) {
            return true;
        }
    }
    return false;
}

bool is_probable_string_ref(const ProtectionContext& ctx, uint64_t addr) {
    const std::string sec = section_name_for(collect_section_ranges(ctx), addr);
    if (sec == ".rodata" || contains_text(sec, "str")) {
        return true;
    }
    return false;
}

bool is_simd_or_fpu_reg(csh handle, arm64_reg reg) {
    const char* name = cs_reg_name(handle, reg);
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    if (std::strcmp(name, "sp") == 0 || std::strcmp(name, "wsp") == 0) {
        return false;
    }
    return name[0] == 'b' || name[0] == 'h' || name[0] == 's' || name[0] == 'd' || name[0] == 'q' ||
           name[0] == 'v';
}

bool is_sve_or_sme_reg(csh handle, arm64_reg reg) {
    const char* name = cs_reg_name(handle, reg);
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    return name[0] == 'z' || name[0] == 'p';
}

bool instruction_uses_simd_or_fpu(csh handle, const cs_insn& insn) {
    if (insn.id == ARM64_INS_INVALID || insn.detail == nullptr) {
        return false;
    }
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    if (starts_with(mnemonic, "f") || starts_with(mnemonic, "fc") || starts_with(mnemonic, "scv")) {
        return true;
    }
    const auto& arm = insn.detail->arm64;
    for (uint8_t i = 0; i < arm.op_count; ++i) {
        if (arm.operands[i].type == ARM64_OP_REG &&
            is_simd_or_fpu_reg(handle, arm.operands[i].reg)) {
            return true;
        }
    }
    return false;
}

bool instruction_uses_sve_or_sme(csh handle, const cs_insn& insn) {
    if (insn.id == ARM64_INS_INVALID || insn.detail == nullptr) {
        return false;
    }
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    if (mnemonic == "rdvl" || mnemonic == "rdsvl" || mnemonic == "smstart" ||
        mnemonic == "smstop") {
        return true;
    }
    const auto& arm = insn.detail->arm64;
    for (uint8_t i = 0; i < arm.op_count; ++i) {
        if (arm.operands[i].type == ARM64_OP_REG &&
            is_sve_or_sme_reg(handle, arm.operands[i].reg)) {
            return true;
        }
    }
    return false;
}

bool has_group(const cs_insn& insn, uint8_t group) {
    if (insn.detail == nullptr) {
        return false;
    }
    for (uint8_t i = 0; i < insn.detail->groups_count; ++i) {
        if (insn.detail->groups[i] == group) {
            return true;
        }
    }
    return false;
}

bool has_sp_operand(csh handle, const cs_insn& insn) {
    if (insn.detail == nullptr) {
        return false;
    }
    const auto& arm = insn.detail->arm64;
    for (uint8_t i = 0; i < arm.op_count; ++i) {
        if (arm.operands[i].type != ARM64_OP_REG) {
            continue;
        }
        const char* name = cs_reg_name(handle, arm.operands[i].reg);
        if (name != nullptr && std::string(name) == "sp") {
            return true;
        }
    }
    return false;
}

bool instruction_is_return(const cs_insn& insn) {
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    return insn.id == ARM64_INS_RET || mnemonic == "ret" || mnemonic == "eret";
}

bool instruction_is_indirect_call(const cs_insn& insn) {
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    return insn.id == ARM64_INS_BLR || mnemonic == "blr";
}

bool instruction_is_indirect_branch(const cs_insn& insn) {
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    return insn.id == ARM64_INS_BR || mnemonic == "br";
}

bool instruction_is_direct_control(const cs_insn& insn) {
    switch (insn.id) {
    case ARM64_INS_B:
    case ARM64_INS_BL:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
        return true;
    default:
        break;
    }
    return has_group(insn, ARM64_GRP_JUMP) || has_group(insn, ARM64_GRP_CALL);
}

bool instruction_is_ldr_literal(const cs_insn& insn) {
    if (insn.detail == nullptr) {
        return false;
    }
    const std::string mnemonic = insn.mnemonic == nullptr ? "" : insn.mnemonic;
    if (!starts_with(mnemonic, "ldr") && mnemonic != "prfm") {
        return false;
    }
    for (uint8_t i = 0; i < insn.detail->arm64.op_count; ++i) {
        if (insn.detail->arm64.operands[i].type == ARM64_OP_IMM) {
            return true;
        }
    }
    return false;
}

uint64_t last_immediate_operand(const cs_insn& insn, bool* found) {
    *found = false;
    if (insn.detail == nullptr) {
        return 0;
    }
    uint64_t value = 0;
    for (uint8_t i = 0; i < insn.detail->arm64.op_count; ++i) {
        if (insn.detail->arm64.operands[i].type == ARM64_OP_IMM) {
            value = static_cast<uint64_t>(insn.detail->arm64.operands[i].imm);
            *found = true;
        }
    }
    return value;
}

bool read_u64_at_vaddr(const ProtectionContext& ctx, uint64_t addr, uint64_t* value) {
    if (!address_in_load_image(ctx, addr)) {
        return false;
    }
    auto content = ctx.binary->get_content_from_virtual_address(addr, sizeof(uint64_t));
    if (content.size() != sizeof(uint64_t)) {
        return false;
    }
    std::memcpy(value, content.data(), sizeof(uint64_t));
    return true;
}

bool adrp_materializes_with_next(const cs_insn& adrp, const cs_insn& next, uint64_t page_target,
                                 uint64_t* materialized) {
    if (adrp.detail == nullptr || next.detail == nullptr || adrp.detail->arm64.op_count == 0 ||
        adrp.detail->arm64.operands[0].type != ARM64_OP_REG) {
        return false;
    }
    const auto base_reg = adrp.detail->arm64.operands[0].reg;
    const auto& next_arm = next.detail->arm64;
    if (next.id == ARM64_INS_ADD && next_arm.op_count == 3 &&
        next_arm.operands[1].type == ARM64_OP_REG && next_arm.operands[1].reg == base_reg &&
        next_arm.operands[2].type == ARM64_OP_IMM) {
        *materialized = (page_target & ~0xFFFULL) |
                        (static_cast<uint64_t>(next_arm.operands[2].imm) & 0xFFFULL);
        return true;
    }
    if ((next.id == ARM64_INS_LDR || next.id == ARM64_INS_LDRSW || next.id == ARM64_INS_STR ||
         next.id == ARM64_INS_PRFM) &&
        next_arm.op_count >= 2 && next_arm.operands[1].type == ARM64_OP_MEM &&
        next_arm.operands[1].mem.base == base_reg) {
        *materialized =
            (page_target & ~0xFFFULL) + static_cast<uint64_t>(next_arm.operands[1].mem.disp);
        return true;
    }
    return false;
}

bool symbol_names_setjmp_like(const std::string& name) {
    return contains_text(name, "setjmp") || contains_text(name, "longjmp") ||
           contains_text(name, "sigsetjmp") || contains_text(name, "siglongjmp");
}

DataRefKind classify_data_ref(const ProtectionContext& ctx,
                              const std::vector<ProtectedFunction>& funcs,
                              const std::vector<AddressRange>& sections,
                              const std::vector<NamedAddress>& plt_symbols, uint64_t target) {
    const auto* containing = find_func_containing(funcs, target);
    if (containing != nullptr) {
        return DataRefKind::FunctionPointerReference;
    }
    const std::string sec = section_name_for(sections, target);
    if (contains_text(sec, "got")) {
        return DataRefKind::DataPointer;
    }
    if (contains_text(sec, "rodata") || contains_text(sec, "data.rel.ro")) {
        const std::string symbol = resolved_symbol_name_at(ctx, plt_symbols, target);
        if (contains_text(symbol, "vtable") || contains_text(symbol, "typeinfo") ||
            starts_with(symbol, "_ZTV") || starts_with(symbol, "_ZTI")) {
            return DataRefKind::VtableTypeinfoReference;
        }
        return is_probable_string_ref(ctx, target) ? DataRefKind::StringReference
                                                   : DataRefKind::ConstantReference;
    }
    if (contains_text(sec, "data") || contains_text(sec, "bss")) {
        return DataRefKind::DataPointer;
    }
    return DataRefKind::ConstantReference;
}

void append_data_ref(ProtectedFunction& func, DataRefKind kind, uint64_t pc, uint64_t target) {
    func.data_refs.push_back({kind, pc, target});
}

void append_control_edge(ProtectedFunction& func, const ProtectionContext& ctx,
                         const std::vector<AddressRange>& sections,
                         const std::vector<NamedAddress>& plt_symbols, ControlEdgeKind kind,
                         uint64_t pc, uint64_t target, uint32_t target_func_id,
                         ControlTargetDomain domain) {
    ControlEdge edge;
    edge.kind = kind;
    edge.pc = pc;
    edge.target = target;
    edge.target_func_id = target_func_id;
    edge.target_domain = domain;
    if (target != 0) {
        edge.target_symbol = resolved_symbol_name_at(ctx, plt_symbols, target);
        edge.target_section = section_name_for(sections, target);
    }
    func.control_edges.push_back(std::move(edge));
}

void note_reference_categories(ProtectedFunction& func, const ProtectionContext& ctx,
                               const std::vector<AddressRange>& sections, uint64_t target) {
    const std::string sec = section_name_for(sections, target);
    if (contains_text(sec, "got")) {
        func.instruction_facts.got_refs++;
    }
    if (contains_text(sec, "plt")) {
        func.instruction_facts.plt_refs++;
    }
    if (contains_text(sec, "tls") || sec == ".tdata" || sec == ".tbss") {
        func.instruction_facts.tls_refs++;
    }
    if (!address_in_load_image(ctx, target)) {
        func.instruction_facts.external_refs++;
    }
}

} // namespace

const char* protection_mode_name(ProtectionMode mode) {
    switch (mode) {
    case ProtectionMode::FragmentEligible:
        return "fragment-mode eligible";
    case ProtectionMode::LegacyFunctionOnly:
        return "legacy function-mode only";
    case ProtectionMode::Rejected:
        return "rejected";
    }
    return "unknown";
}

const char* selected_backend_name(SelectedBackend backend) {
    switch (backend) {
    case SelectedBackend::None:
        return "none";
    case SelectedBackend::LegacyRuntimeAllocator:
        return "legacy-runtime-allocator";
    case SelectedBackend::LegacyFixedSlot:
        return "legacy-fixed-slot";
    case SelectedBackend::Fragment:
        return "fragment";
    }
    return "unknown";
}

const char* final_outcome_name(FinalOutcome outcome) {
    switch (outcome) {
    case FinalOutcome::Pending:
        return "pending";
    case FinalOutcome::Protected:
        return "protected";
    case FinalOutcome::Rejected:
        return "rejected";
    }
    return "unknown";
}

const char* reason_code_name(ReasonCode reason) {
    switch (reason) {
    case ReasonCode::None:
        return "none";
    case ReasonCode::EhCoverage:
        return "eh_coverage";
    case ReasonCode::DecodeFailure:
        return "decode_failure";
    case ReasonCode::SimdFpuState:
        return "simd_fpu_state";
    case ReasonCode::SveSmeState:
        return "sve_sme_state";
    case ReasonCode::IndirectCall:
        return "indirect_call";
    case ReasonCode::IndirectBranch:
        return "indirect_branch";
    case ReasonCode::SetjmpLongjmp:
        return "setjmp_longjmp";
    case ReasonCode::ProtectedInteriorControl:
        return "protected_interior_control";
    case ReasonCode::ProtectedInteriorPointer:
        return "protected_interior_pointer";
    case ReasonCode::UnmodeledControl:
        return "unmodeled_control";
    }
    return "unknown";
}

const char* control_edge_kind_name(ControlEdgeKind kind) {
    switch (kind) {
    case ControlEdgeKind::IntraFunction:
        return "intra-function edge";
    case ControlEdgeKind::ProtectedToProtectedCall:
        return "protected-to-protected call";
    case ControlEdgeKind::ProtectedReturn:
        return "protected return";
    case ControlEdgeKind::ProtectedTailCall:
        return "protected tail call";
    case ControlEdgeKind::ExternalCall:
        return "external call";
    case ControlEdgeKind::ExternalTailCall:
        return "external tail call";
    case ControlEdgeKind::IndirectCall:
        return "indirect call";
    case ControlEdgeKind::ExceptionEdge:
        return "exception edge";
    case ControlEdgeKind::UnmodeledEdge:
        return "unmodeled edge";
    }
    return "unknown";
}

const char* control_target_domain_name(ControlTargetDomain domain) {
    switch (domain) {
    case ControlTargetDomain::SameFunction:
        return "same-function";
    case ControlTargetDomain::ProtectedFunction:
        return "protected-function";
    case ControlTargetDomain::ExternalUnprotected:
        return "external/unprotected";
    case ControlTargetDomain::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* data_ref_kind_name(DataRefKind kind) {
    switch (kind) {
    case DataRefKind::StringReference:
        return "string reference";
    case DataRefKind::ConstantReference:
        return "constant reference";
    case DataRefKind::LiteralPoolEntry:
        return "literal-pool entry";
    case DataRefKind::DataPointer:
        return "data pointer";
    case DataRefKind::VtableTypeinfoReference:
        return "vtable/typeinfo reference";
    case DataRefKind::FunctionPointerReference:
        return "function-pointer reference";
    case DataRefKind::JumpTableEntry:
        return "jump-table entry";
    }
    return "unknown";
}

void analyze_fragment_modes(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs) {
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone for fragment analysis.");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const auto sections = collect_section_ranges(ctx);
    const auto plt_symbols = collect_plt_symbols(ctx);

    for (auto& func : funcs) {
        func.protection_mode = ProtectionMode::FragmentEligible;
        func.protection_reason.clear();
        func.instruction_facts = {};
        func.control_edges.clear();
        func.data_refs.clear();
        func.reason_codes.clear();

        std::vector<std::string> reasons;
        bool reject_function = false;
        if (!func.fde_bytes.empty()) {
            if (ctx.runtime_features.slot_strategy != SlotStrategy::RuntimeAllocator) {
                reasons.push_back(
                    "EH-bearing function uses fixed-slot native unwind compatibility");
            } else if (func.eh_metadata.pc_begin != func.original_start ||
                       func.eh_metadata.pc_range < func.size ||
                       (func.eh_metadata.personality == 0 &&
                        func.eh_metadata.personality_pointer == 0) ||
                       func.eh_metadata.lsda_vaddr == 0) {
                reasons.push_back(
                    "EH metadata is outside the supported synchronous native unwind subset");
            }
            ControlEdge edge;
            edge.kind = ControlEdgeKind::ExceptionEdge;
            edge.pc = func.original_start;
            edge.target_domain = ControlTargetDomain::Unknown;
            edge.target_section = ".eh_frame";
            edge.target_symbol = "fde_pc_begin=" + hex(func.fde_pc_begin) +
                                 ", fde_size=" + std::to_string(func.fde_bytes.size()) +
                                 ", lsda=decoded-if-present";
            func.control_edges.push_back(std::move(edge));
        }

        cs_insn* insn = cs_malloc(handle);
        size_t offset = 0;
        std::vector<std::pair<uint64_t, uint64_t>> discovered_literal_data;
        while (offset + 4 <= func.original_bytes.size()) {
            const uint64_t current_pc = func.original_start + offset;
            const bool is_literal_data =
                std::any_of(discovered_literal_data.begin(), discovered_literal_data.end(),
                            [&](const auto& range) {
                                return current_pc >= range.first && current_pc < range.second;
                            });
            if (is_literal_data) {
                offset += 4;
                continue;
            }
            const uint8_t* ptr = func.original_bytes.data() + offset;
            size_t size = 4;
            uint64_t addr = func.original_start + offset;
            if (!cs_disasm_iter(handle, &ptr, &size, &addr, insn)) {
                func.instruction_facts.decode_failures++;
                reasons.push_back("undecodable instruction at " +
                                  hex(func.original_start + offset));
                offset += 4;
                continue;
            }

            const std::string mnemonic = insn->mnemonic == nullptr ? "" : insn->mnemonic;
            if (instruction_uses_simd_or_fpu(handle, *insn)) {
                func.instruction_facts.simd_fpu_use++;
            }
            if (instruction_uses_sve_or_sme(handle, *insn)) {
                func.instruction_facts.sve_sme_use++;
                reasons.push_back("SVE/SME state is not fragment-mode eligible");
            }
            if ((mnemonic == "stp" || mnemonic == "str" || mnemonic == "sub") &&
                has_sp_operand(handle, *insn)) {
                func.instruction_facts.stack_frame_setup++;
            }
            if ((mnemonic == "ldp" || mnemonic == "ldr" || mnemonic == "add") &&
                has_sp_operand(handle, *insn)) {
                func.instruction_facts.stack_frame_teardown++;
            }

            if (instruction_is_return(*insn)) {
                func.instruction_facts.returns++;
                append_control_edge(func, ctx, sections, plt_symbols,
                                    ControlEdgeKind::ProtectedReturn, insn->address, 0, UINT32_MAX,
                                    ControlTargetDomain::SameFunction);
            }

            if (instruction_is_indirect_call(*insn)) {
                func.instruction_facts.indirect_calls++;
                append_control_edge(func, ctx, sections, plt_symbols, ControlEdgeKind::IndirectCall,
                                    insn->address, 0, UINT32_MAX, ControlTargetDomain::Unknown);
                reasons.push_back("indirect call site requires legacy dispatch model");
            } else if (instruction_is_indirect_branch(*insn)) {
                if (mnemonic == "br" && offset + 4 == func.original_bytes.size()) {
                    func.instruction_facts.indirect_calls++;
                    append_control_edge(func, ctx, sections, plt_symbols,
                                        ControlEdgeKind::IndirectCall, insn->address, 0, UINT32_MAX,
                                        ControlTargetDomain::Unknown);
                    reasons.push_back("indirect tail call site requires legacy dispatch model");
                } else {
                    func.instruction_facts.indirect_branches++;
                    func.instruction_facts.jump_table_candidates++;
                    append_control_edge(func, ctx, sections, plt_symbols,
                                        ControlEdgeKind::UnmodeledEdge, insn->address, 0,
                                        UINT32_MAX, ControlTargetDomain::Unknown);
                    append_data_ref(func, DataRefKind::JumpTableEntry, insn->address, 0);
                    reasons.push_back(
                        "indirect branch or jump-table candidate is not safely relocatable");
                    reject_function = true;
                }
            }

            const bool is_branch = instruction_is_direct_control(*insn);
            const bool is_call = has_group(*insn, ARM64_GRP_CALL) || insn->id == ARM64_INS_BL;
            const bool is_adr = insn->id == ARM64_INS_ADR;
            const bool is_adrp = insn->id == ARM64_INS_ADRP;
            if (is_adr) {
                func.instruction_facts.adr++;
            }
            if (is_adrp) {
                func.instruction_facts.adrp++;
            }
            if (instruction_is_ldr_literal(*insn)) {
                func.instruction_facts.pc_relative_loads++;
                func.instruction_facts.literal_pool_refs++;
            }

            bool found_imm = false;
            const uint64_t target = last_immediate_operand(*insn, &found_imm);
            if (found_imm) {
                note_reference_categories(func, ctx, sections, target);
            }

            if (is_branch && found_imm) {
                const auto* callee = find_func_start(funcs, target);
                const auto* containing_target = find_func_containing(funcs, target);
                const bool owner_internal =
                    target >= func.original_start && target < func.original_start + func.size;
                if (is_call) {
                    func.instruction_facts.direct_calls++;
                    const std::string target_name =
                        resolved_symbol_name_at(ctx, plt_symbols, target);
                    if (callee != nullptr) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::ProtectedToProtectedCall,
                                            insn->address, target, callee->id,
                                            ControlTargetDomain::ProtectedFunction);
                    } else if (containing_target != nullptr) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::UnmodeledEdge, insn->address, target,
                                            containing_target->id,
                                            ControlTargetDomain::ProtectedFunction);
                        reasons.push_back("direct call to protected function interior is not "
                                          "fragment-mode eligible");
                    } else {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::ExternalCall, insn->address, target,
                                            UINT32_MAX, ControlTargetDomain::ExternalUnprotected);
                    }
                } else {
                    func.instruction_facts.direct_branches++;
                    uint32_t raw = 0;
                    std::memcpy(&raw, func.original_bytes.data() + offset, sizeof(raw));
                    if (!is_unconditional_b(raw)) {
                        func.instruction_facts.conditional_branches++;
                    }
                    if (owner_internal) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::IntraFunction, insn->address, target,
                                            func.id, ControlTargetDomain::SameFunction);
                    } else if (callee != nullptr && is_unconditional_b(raw)) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::ProtectedTailCall, insn->address,
                                            target, callee->id,
                                            ControlTargetDomain::ProtectedFunction);
                    } else if (containing_target != nullptr) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::UnmodeledEdge, insn->address, target,
                                            containing_target->id,
                                            ControlTargetDomain::ProtectedFunction);
                        if (containing_target->id != func.id) {
                            reasons.push_back("conditional or interior branch to protected "
                                              "function is not fragment-mode eligible");
                        }
                    } else if (!address_in_load_image(ctx, target)) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::UnmodeledEdge, insn->address, target,
                                            UINT32_MAX, ControlTargetDomain::Unknown);
                        reasons.push_back(
                            "direct branch outside loaded image is not fragment-mode eligible");
                    } else if (is_unconditional_b(raw)) {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::ExternalTailCall, insn->address,
                                            target, UINT32_MAX,
                                            ControlTargetDomain::ExternalUnprotected);
                    } else {
                        append_control_edge(func, ctx, sections, plt_symbols,
                                            ControlEdgeKind::UnmodeledEdge, insn->address, target,
                                            UINT32_MAX, ControlTargetDomain::ExternalUnprotected);
                        reasons.push_back("direct branch outside modeled function graph requires "
                                          "legacy function mode");
                    }
                }
            }

            if ((is_adr || instruction_is_ldr_literal(*insn)) && found_imm &&
                address_in_load_image(ctx, target)) {
                const auto kind =
                    instruction_is_ldr_literal(*insn)
                        ? DataRefKind::LiteralPoolEntry
                        : classify_data_ref(ctx, funcs, sections, plt_symbols, target);
                append_data_ref(func, kind, insn->address, target);
                if (instruction_is_ldr_literal(*insn)) {
                    discovered_literal_data.emplace_back(target, target + 8);
                    uint64_t literal_value = 0;
                    if (read_u64_at_vaddr(ctx, target, &literal_value) &&
                        address_in_load_image(ctx, literal_value)) {
                        note_reference_categories(func, ctx, sections, literal_value);
                        append_data_ref(
                            func,
                            classify_data_ref(ctx, funcs, sections, plt_symbols, literal_value),
                            insn->address, literal_value);
                    }
                }
                if (kind == DataRefKind::FunctionPointerReference) {
                    func.instruction_facts.function_pointer_materializations++;
                    const auto* containing = find_func_containing(funcs, target);
                    if (containing != nullptr && containing->original_start != target) {
                        reasons.push_back("protected-interior function pointer materialization");
                        if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator) {
                            reject_function = true;
                        }
                    }
                }
            }

            if (is_adrp && found_imm && offset + 8 <= func.original_bytes.size()) {
                cs_insn* next = nullptr;
                const uint8_t* next_ptr = func.original_bytes.data() + offset + 4;
                size_t next_size = 4;
                uint64_t next_addr = func.original_start + offset + 4;
                const size_t count = cs_disasm(handle, next_ptr, next_size, next_addr, 1, &next);
                uint64_t materialized = 0;
                if (count > 0 && adrp_materializes_with_next(*insn, *next, target, &materialized)) {
                    func.instruction_facts.adrp_pairs++;
                    note_reference_categories(func, ctx, sections, materialized);
                    const auto kind =
                        classify_data_ref(ctx, funcs, sections, plt_symbols, materialized);
                    append_data_ref(func, kind, insn->address, materialized);
                    if (kind == DataRefKind::FunctionPointerReference) {
                        func.instruction_facts.function_pointer_materializations++;
                        const auto* containing = find_func_containing(funcs, materialized);
                        if (containing != nullptr && containing->original_start != materialized) {
                            reasons.push_back(
                                "protected-interior function pointer materialization");
                            if (ctx.runtime_features.slot_strategy ==
                                SlotStrategy::RuntimeAllocator) {
                                reject_function = true;
                            }
                        }
                    }
                }
                if (count > 0) {
                    cs_free(next, count);
                }
            }

            offset += 4;
        }
        cs_free(insn, 1);

        if (!func.fde_bytes.empty() && func.eh_metadata.cxa_throw == 0) {
            for (const auto& edge : func.control_edges) {
                if (edge.target_symbol.find("__cxa_throw") != std::string::npos) {
                    func.eh_metadata.cxa_throw = edge.target;
                    break;
                }
            }
        }
        if (!func.fde_bytes.empty() && func.eh_metadata.cxa_rethrow == 0) {
            for (const auto& edge : func.control_edges) {
                if (edge.target_symbol.find("__cxa_rethrow") != std::string::npos) {
                    func.eh_metadata.cxa_rethrow = edge.target;
                    break;
                }
            }
        }

        if (func.instruction_facts.decode_failures != 0 || reject_function) {
            func.protection_mode = ProtectionMode::Rejected;
        } else if (!reasons.empty()) {
            func.protection_mode = ProtectionMode::LegacyFunctionOnly;
        } else {
            func.protection_mode = ProtectionMode::FragmentEligible;
        }
        func.protection_reason = join_reasons(reasons);
        auto add_reason = [&](ReasonCode code) {
            if (std::find(func.reason_codes.begin(), func.reason_codes.end(), code) ==
                func.reason_codes.end()) {
                func.reason_codes.push_back(code);
            }
        };
        if (!func.fde_bytes.empty())
            add_reason(ReasonCode::EhCoverage);
        if (func.instruction_facts.decode_failures)
            add_reason(ReasonCode::DecodeFailure);
        if (func.instruction_facts.simd_fpu_use)
            add_reason(ReasonCode::SimdFpuState);
        if (func.instruction_facts.sve_sme_use)
            add_reason(ReasonCode::SveSmeState);
        if (func.instruction_facts.indirect_calls)
            add_reason(ReasonCode::IndirectCall);
        if (func.instruction_facts.indirect_branches)
            add_reason(ReasonCode::IndirectBranch);
        for (const auto& edge : func.control_edges) {
            if (edge.kind == ControlEdgeKind::UnmodeledEdge)
                add_reason(ReasonCode::UnmodeledControl);
        }
        if (func.instruction_facts.function_pointer_materializations && reject_function) {
            add_reason(ReasonCode::ProtectedInteriorPointer);
        }
        if (func.protection_reason.find("setjmp/longjmp") != std::string::npos)
            add_reason(ReasonCode::SetjmpLongjmp);
        if (func.protection_reason.find("protected function interior") != std::string::npos) {
            add_reason(ReasonCode::ProtectedInteriorControl);
        }
        if (func.reason_codes.empty())
            add_reason(ReasonCode::None);
        if (ctx.options.verbose) {
            Log::info("  fragment-analysis[" + std::to_string(func.id) + "] " +
                      protection_mode_name(func.protection_mode) + " " + func.name + " (" +
                      func.protection_reason + ")");
        }
    }

    cs_close(&handle);
}

} // namespace maya::protection
