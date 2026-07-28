#include "core/ProtectionPipeline.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/Logger.hpp"
#include "core/RuntimeSchema.hpp"
#include "protection/CodeRelocation.hpp"
#include "protection/Controllets.hpp"
#include "protection/ExceptionFrames.hpp"
#include "protection/FragmentAnalysis.hpp"
#include "protection/FragmentCfg.hpp"
#include "protection/FragmentCrypto.hpp"
#include "protection/FragmentExecution.hpp"
#include "protection/FragmentImage.hpp"
#include "protection/FunctionLayout.hpp"
#include "protection/PayloadImage.hpp"
#include "protection/StateBinding.hpp"
#if MAYA_ENABLE_V3
#include "protection/NativeVariants.hpp"
#include "protection/V3Capabilities.hpp"
#include "protection/V3Shards.hpp"
#include "protection/V3Vm.hpp"
#endif

namespace {

void initialize_options(ProtectionContext& ctx) {
    if (ctx.options.output_filename.empty()) {
        ctx.options.output_filename = ctx.filename + ".protected";
    }
    if (ctx.options.report_filename.empty()) {
        ctx.options.report_filename = ctx.filename + ".protection.tsv";
    }
}

void initialize_fragment_secrets(ProtectionContext& ctx) {
    ctx.build_seed = ctx.options.seed_hex.empty()
                         ? maya::protection::random_seed()
                         : maya::protection::parse_seed_hex(ctx.options.seed_hex);
    const auto derived = maya::protection::derive_build_secrets(ctx.build_seed);
    ctx.build_root = derived.root;
    ctx.fragment_binary_salt = derived.binary_salt;
}

void detect_runtime_features(ProtectionContext& ctx) {
    ctx.runtime_features.has_interpreter = ctx.binary->has_interpreter();
    const auto file_type = ctx.binary->header().file_type();
    if (file_type == LIEF::ELF::Header::FILE_TYPE::DYN) {
        ctx.runtime_features.binary_kind = ctx.runtime_features.has_interpreter
                                               ? BinaryKind::DynamicPieExecutable
                                               : BinaryKind::StaticPieExecutable;
    } else if (ctx.runtime_features.has_interpreter) {
        ctx.runtime_features.binary_kind = BinaryKind::DynamicExecutable;
    } else {
        ctx.runtime_features.binary_kind = BinaryKind::StaticExecutable;
    }
    ctx.runtime_features.has_eh_frame = ctx.binary->get_section(".eh_frame") != nullptr;
    ctx.runtime_features.has_gcc_except_table =
        ctx.binary->get_section(".gcc_except_table") != nullptr;
    ctx.runtime_features.upx_compatible_layout = ctx.options.require_upx_compatible_layout;
    ctx.runtime_features.slot_strategy = ctx.options.slot_strategy;

    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.name().find("__gxx_personality_v0") != std::string::npos) {
            ctx.runtime_features.has_cpp_personality = true;
        }
        // libgcc_eh itself defines _Unwind_ForcedUnwind even when the input
        // never requests it, so the symbol alone does not mark an active
        // forced-unwind path.  pthread_cancel is the externally reachable
        // Linux cancellation trigger and is retained only when referenced.
        if (sym.name() == "pthread_cancel" && sym.value() == 0) {
            ctx.runtime_features.has_forced_unwind_or_cancellation = true;
        }
    }
    if (ctx.runtime_features.has_forced_unwind_or_cancellation &&
        ctx.options.execution_mode == ExecutionMode::FragmentAuto) {
        // Forced unwinding can bypass the synchronous cleanup gateways.  Auto
        // mode therefore selects the protected loader-owned fixed-slot path
        // for the complete image; required mode receives a precise rejection
        // after the selected EH functions have been identified.
        ctx.options.execution_mode = ExecutionMode::Legacy;
        ctx.options.slot_strategy = SlotStrategy::FixedPerFunction;
        ctx.runtime_features.slot_strategy = SlotStrategy::FixedPerFunction;
    }
}

bool has_cpp_eh(const ProtectionContext& ctx) {
    return ctx.runtime_features.has_gcc_except_table && ctx.runtime_features.has_cpp_personality;
}

void validate_input(const ProtectionContext& ctx) {
    if (!ctx.is_aarch64) {
        throw std::runtime_error("Input is not an AArch64 ELF.");
    }
    if (ctx.options.execution_mode != ExecutionMode::Legacy &&
        ctx.runtime_features.slot_strategy != SlotStrategy::RuntimeAllocator) {
        throw std::runtime_error(
            "The selected backend is incompatible with runtime fragment allocation.");
    }
}

void log_pipeline_features(const ProtectionContext& ctx) {
#if MAYA_ENABLE_V3
    const std::string profile =
        ctx.options.profile == ProtectionProfile::ExperimentalV3 ? "experimental-v3" : "standard";
#else
    const std::string profile = "standard";
#endif
    Log::info("Profile " + profile + ": " +
              maya::binary_kind_name(ctx.runtime_features.binary_kind) + ", " +
              maya::slot_strategy_name(ctx.runtime_features.slot_strategy) +
              (has_cpp_eh(ctx) ? ", C++ EH detected" : ""));
    if (ctx.options.verbose) {
        Log::info(std::string("  operation=") +
                  (ctx.options.command == CliCommand::Analyze ? "analyze" : "protect"));
        Log::info(std::string("  upx-compatible-layout=") +
                  (ctx.runtime_features.upx_compatible_layout ? "requested" : "disabled"));
        Log::info(std::string("  native-variants=") +
                  (ctx.options.native_variants ? "enabled" : "disabled"));
    }
}

bool has_symbol_name(const maya::protection::ProtectedFunction& func, const std::string& expected) {
    size_t begin = 0;
    while (begin <= func.name.size()) {
        const size_t end = func.name.find(',', begin);
        const std::string alias =
            func.name.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        if (alias == expected)
            return true;
        if (end == std::string::npos)
            break;
        begin = end + 1;
    }
    return false;
}

std::vector<maya::protection::ProtectedFunction>
select_application_graph(ProtectionContext& ctx,
                         std::vector<maya::protection::ProtectedFunction> candidates) {
    std::set<uint32_t> selected;
    for (const auto& func : candidates) {
        if (has_symbol_name(func, "main"))
            selected.insert(func.id);
    }
    if (selected.empty()) {
        for (const auto& func : candidates) {
            if (ctx.original_entry_point >= func.original_start &&
                ctx.original_entry_point < func.original_start + func.size) {
                selected.insert(func.id);
                break;
            }
        }
    }
    if (selected.empty()) {
        throw std::runtime_error(
            "Unable to identify an application root. Provide an unstripped executable "
            "with a main symbol or select functions explicitly with --functions.");
    }
    ctx.automatic_root_count = selected.size();

    auto function_at = [&](uint64_t address) -> uint32_t {
        for (const auto& candidate : candidates) {
            if (candidate.original_start == address)
                return candidate.id;
        }
        return UINT32_MAX;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& func : candidates) {
            if (selected.count(func.id) == 0)
                continue;
            for (const auto& edge : func.control_edges) {
                if (edge.target_func_id != UINT32_MAX &&
                    selected.insert(edge.target_func_id).second) {
                    changed = true;
                }
            }
            for (const auto& ref : func.data_refs) {
                if (ref.kind != maya::protection::DataRefKind::FunctionPointerReference)
                    continue;
                const uint32_t target = function_at(ref.target);
                if (target != UINT32_MAX && selected.insert(target).second)
                    changed = true;
            }
        }
    }

    std::vector<maya::protection::ProtectedFunction> result;
    for (auto& candidate : candidates) {
        if (selected.count(candidate.id) != 0)
            result.push_back(std::move(candidate));
    }
    for (size_t index = 0; index < result.size(); ++index) {
        result[index].id = static_cast<uint32_t>(index);
        result[index].selected_id = static_cast<uint32_t>(index);
    }
    Log::info("Selected " + std::to_string(result.size()) + " application functions from " +
              std::to_string(ctx.discovered_function_count) + " candidates.");
    return result;
}

std::vector<maya::protection::ProtectedFunction>
build_protected_worklist(std::vector<maya::protection::ProtectedFunction>& selected_funcs,
                         const ProtectionContext& ctx) {
    auto is_leaf = [](const auto& func) {
        if (func.protection_mode != maya::protection::ProtectionMode::FragmentEligible ||
            !func.fde_bytes.empty())
            return false;
        return std::none_of(
            func.control_edges.begin(), func.control_edges.end(), [](const auto& edge) {
                return edge.kind != maya::protection::ControlEdgeKind::IntraFunction &&
                       edge.kind != maya::protection::ControlEdgeKind::ProtectedReturn;
            });
    };
    auto supports_cfg_control = [&ctx](const auto& func) {
        if (func.protection_mode != maya::protection::ProtectionMode::FragmentEligible ||
            !func.fde_bytes.empty())
            return false;
        if (std::any_of(func.data_refs.begin(), func.data_refs.end(), [](const auto& ref) {
                return ref.kind == maya::protection::DataRefKind::FunctionPointerReference ||
                       ref.kind == maya::protection::DataRefKind::JumpTableEntry;
            }))
            return false;
        return std::all_of(
            func.control_edges.begin(), func.control_edges.end(), [](const auto& edge) {
                return edge.kind == maya::protection::ControlEdgeKind::IntraFunction ||
                       edge.kind == maya::protection::ControlEdgeKind::ProtectedReturn ||
                       edge.kind == maya::protection::ControlEdgeKind::ProtectedToProtectedCall ||
                       edge.kind == maya::protection::ControlEdgeKind::ProtectedTailCall ||
                       edge.kind == maya::protection::ControlEdgeKind::ExternalCall ||
                       edge.kind == maya::protection::ControlEdgeKind::ExternalTailCall;
            });
    };
    auto supports_fragment_eh = [&ctx](const auto& func) {
        return ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator &&
               func.protection_mode == maya::protection::ProtectionMode::FragmentEligible &&
               !func.fde_bytes.empty() && func.eh_metadata.pc_begin == func.original_start &&
               func.eh_metadata.pc_range >= func.size &&
               (func.eh_metadata.personality != 0 || func.eh_metadata.personality_pointer != 0) &&
               func.eh_metadata.lsda_vaddr != 0;
    };
    std::vector<maya::protection::ProtectedFunction> protected_funcs;
    for (auto& func : selected_funcs) {
        if (ctx.options.execution_mode == ExecutionMode::FragmentRequired &&
            ctx.runtime_features.has_forced_unwind_or_cancellation && !func.fde_bytes.empty()) {
            func.final_outcome = maya::protection::FinalOutcome::Rejected;
            func.protection_reason =
                "forced unwinding or pthread cancellation is unsupported by fragment-native EH";
            if (ctx.options.command == CliCommand::Analyze)
                continue;
            throw std::runtime_error(
                "Fragment-native C++ EH rejects forced unwinding or pthread cancellation: " +
                func.name);
        }
        if (func.protection_mode == maya::protection::ProtectionMode::Rejected) {
            func.final_outcome = maya::protection::FinalOutcome::Rejected;
            if (ctx.options.command == CliCommand::Analyze)
                continue;
            throw std::runtime_error("Selected function rejected: " + func.name + " (" +
                                     func.protection_reason + ")");
        }
        if (ctx.options.execution_mode == ExecutionMode::FragmentRequired && !is_leaf(func) &&
            !supports_cfg_control(func) && !supports_fragment_eh(func)) {
            func.final_outcome = maya::protection::FinalOutcome::Rejected;
            if (ctx.options.command == CliCommand::Analyze) {
                func.protection_reason =
                    "selected function is outside the authenticated fragment subset";
                continue;
            }
            throw std::runtime_error(
                "Selected function is outside the authenticated leaf subset: " + func.name);
        }
        protected_funcs.push_back(func);
    }
    for (size_t i = 0; i < protected_funcs.size(); ++i) {
        protected_funcs[i].id = static_cast<uint32_t>(i);
        const bool fragment =
            ctx.options.execution_mode != ExecutionMode::Legacy &&
            (is_leaf(protected_funcs[i]) || supports_cfg_control(protected_funcs[i]) ||
             supports_fragment_eh(protected_funcs[i]));
        protected_funcs[i].selected_backend =
            fragment ? maya::protection::SelectedBackend::Fragment
                     : (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator
                            ? maya::protection::SelectedBackend::LegacyRuntimeAllocator
                            : maya::protection::SelectedBackend::LegacyFixedSlot);
        protected_funcs[i].final_outcome = maya::protection::FinalOutcome::Protected;
    }
    for (auto& func : selected_funcs) {
        if (func.protection_mode == maya::protection::ProtectionMode::Rejected) {
            func.final_outcome = maya::protection::FinalOutcome::Rejected;
        }
        const auto candidate = std::find_if(
            protected_funcs.begin(), protected_funcs.end(), [&](const auto& protected_func) {
                return protected_func.selected_id == func.selected_id;
            });
        if (candidate != protected_funcs.end()) {
            func.selected_backend = candidate->selected_backend;
            func.final_outcome = ctx.options.command == CliCommand::Analyze
                                     ? maya::protection::FinalOutcome::Pending
                                     : maya::protection::FinalOutcome::Protected;
        }
    }
    // Translate frozen selected IDs into backend-local IDs without re-running analysis.
    for (auto& func : protected_funcs) {
        for (auto& edge : func.control_edges) {
            if (edge.target_func_id == UINT32_MAX)
                continue;
            const uint32_t selected_target = edge.target_func_id;
            const auto it = std::find_if(
                protected_funcs.begin(), protected_funcs.end(),
                [&](const auto& candidate) { return candidate.selected_id == selected_target; });
            edge.target_func_id = it == protected_funcs.end() ? UINT32_MAX : it->id;
        }
    }
    return protected_funcs;
}

void seal_authenticated_leaves(ProtectionContext& ctx,
                               std::vector<maya::protection::ProtectedFunction>& funcs) {
    auto append32 = [](std::vector<uint8_t>& v, uint32_t x) {
        for (unsigned i = 0; i < 4; i++)
            v.push_back(static_cast<uint8_t>(x >> (8 * i)));
    };
    auto append64 = [](std::vector<uint8_t>& v, uint64_t x) {
        for (unsigned i = 0; i < 8; i++)
            v.push_back(static_cast<uint8_t>(x >> (8 * i)));
    };
    for (auto& func : funcs) {
#if MAYA_ENABLE_V3
        const bool v3 = ctx.options.profile == ProtectionProfile::ExperimentalV3;
#else
        constexpr bool v3 = false;
#endif
        if (func.selected_backend != maya::protection::SelectedBackend::Fragment)
            continue;
        if (!func.cfg_execution_enabled) {
            func.fragment_aad.clear();
            append32(func.fragment_aad,
                     static_cast<uint32_t>(maya::protection::KeyDomain::Fragment));
            append32(func.fragment_aad, maya::protection::kFragmentImageVersion);
            append32(func.fragment_aad, maya::protection::kDescriptorVersion);
            append32(func.fragment_aad, maya::protection::kStateContractVersion);
            append32(func.fragment_aad, maya::protection::kContinuationContractVersion);
            append32(func.fragment_aad, maya::protection::kFaultContractVersion);
            func.fragment_aad.insert(func.fragment_aad.end(), ctx.fragment_binary_salt.begin(),
                                     ctx.fragment_binary_salt.end());
            if (v3)
                append64(func.fragment_aad, func.v3_function_handle);
            else {
                append32(func.fragment_aad, func.selected_id);
                append32(func.fragment_aad, 0);
            }
            append64(func.fragment_aad, func.patched_bytes.size());
            append32(func.fragment_aad, func.runtime_relocations);
            std::vector<uint8_t> descriptor_fields;
            if (v3)
                append64(descriptor_fields, func.v3_function_handle);
            else {
                append32(descriptor_fields, func.selected_id);
                append32(descriptor_fields, 0);
            }
            append64(descriptor_fields, func.patched_bytes.size());
            append32(descriptor_fields, func.runtime_relocations);
            for (const auto offset : func.runtime_literal_offsets)
                append64(descriptor_fields, offset);
            const auto descriptor_digest = maya::protection::sha256_bytes(descriptor_fields);
            func.fragment_aad.insert(func.fragment_aad.end(), descriptor_digest.begin(),
                                     descriptor_digest.end());
            while (func.fragment_aad.size() < maya::protection::kFragmentAadSize)
                func.fragment_aad.push_back(0);
            func.fragment_nonce = maya::protection::derive_fragment_nonce(
                ctx.build_seed, func.selected_id, UINT32_MAX);
            auto object_key =
                maya::protection::derive_sealed_object_key(ctx.build_root, func.fragment_aad);
            const auto sealed = maya::protection::seal_fragment(
                func.patched_bytes, func.fragment_aad, object_key, func.fragment_nonce);
            maya::protection::secure_zero(object_key);
            func.fragment_ciphertext = sealed.ciphertext;
            func.fragment_tag = sealed.tag;
        }
        for (auto& fragment : func.fragments) {
            const size_t offset = fragment.original_start - func.original_start;
            if (fragment.execution_bytes.empty()) {
                fragment.plaintext.assign(func.patched_bytes.begin() + offset,
                                          func.patched_bytes.begin() + offset + fragment.size);
            } else {
                fragment.plaintext = fragment.execution_bytes;
            }
            fragment.aad.clear();
            append32(fragment.aad, static_cast<uint32_t>(maya::protection::KeyDomain::Fragment));
            append32(fragment.aad, maya::protection::kFragmentImageVersion);
            append32(fragment.aad, maya::protection::kDescriptorVersion);
            append32(fragment.aad, maya::protection::kStateContractVersion);
            append32(fragment.aad, maya::protection::kContinuationContractVersion);
            append32(fragment.aad, maya::protection::kFaultContractVersion);
            fragment.aad.insert(fragment.aad.end(), ctx.fragment_binary_salt.begin(),
                                ctx.fragment_binary_salt.end());
            if (v3) {
                append64(fragment.aad, func.v3_function_handle);
                append64(fragment.aad, fragment.v3_handle);
            } else {
                append32(fragment.aad, func.selected_id);
                append32(fragment.aad, fragment.fragment_id);
            }
            append32(fragment.aad, fragment.cluster_id);
            append32(fragment.aad, fragment.metadata_family);
            append64(fragment.aad, fragment.plaintext.size());
            append32(fragment.aad, fragment.exits.size());
            std::vector<uint8_t> exit_fields;
            append32(exit_fields, fragment.metadata_family);
            for (const auto& exit : fragment.exits) {
                append32(exit_fields, static_cast<uint32_t>(exit.kind));
                if (v3) {
                    exit_fields.insert(exit_fields.end(), exit.v3_source_label.begin(),
                                       exit.v3_source_label.end());
                    exit_fields.insert(exit_fields.end(), exit.v3_destination_label.begin(),
                                       exit.v3_destination_label.end());
                    append64(exit_fields, exit.v3_target_handle);
                    append64(exit_fields, exit.v3_continuation_handle);
                } else {
                    append32(exit_fields, exit.site_id);
                    append32(exit_fields, exit.target_function_id);
                    append32(exit_fields, exit.target_fragment_id);
                    append32(exit_fields, exit.continuation_fragment_id);
                    append64(exit_fields, exit.compatibility_target);
                }
            }
            for (size_t i = 0; i < fragment.state_token_offsets.size(); ++i) {
                append64(exit_fields, fragment.state_token_offsets[i]);
                append64(exit_fields, fragment.state_token_values[i]);
                append32(exit_fields, fragment.state_token_load_bias[i]);
            }
            const auto digest = maya::protection::sha256_bytes(exit_fields);
            fragment.aad.insert(fragment.aad.end(), digest.begin(), digest.end());
            while (fragment.aad.size() < maya::protection::kFragmentAadSize)
                fragment.aad.push_back(0);
            fragment.nonce = maya::protection::derive_fragment_nonce(
                ctx.build_seed, func.selected_id, fragment.fragment_id);
            auto fragment_key =
                maya::protection::derive_sealed_object_key(ctx.build_root, fragment.aad);
            const auto fragment_sealed = maya::protection::seal_fragment(
                fragment.plaintext, fragment.aad, fragment_key, fragment.nonce);
            maya::protection::secure_zero(fragment_key);
            fragment.ciphertext = fragment_sealed.ciphertext;
            fragment.tag = fragment_sealed.tag;
#if MAYA_ENABLE_V3
            if (func.native_variants_enabled) {
                const auto allocated_variant_slots = fragment.variants;
                fragment.variants.clear();
                const auto variants = maya::protection::generate_native_variants(
                    fragment.plaintext, fragment.size, fragment.state_token_offsets);
                fragment.variant_rejection_reason = variants.rejection_reason;
                for (size_t variant_index = 0; variant_index < variants.candidates.size();
                     ++variant_index) {
                    const auto& candidate = variants.candidates[variant_index];
                    maya::protection::SealedNativeVariant variant;
                    variant.plaintext = candidate.bytes;
                    variant.transformation = candidate.transformation;
                    variant.proof = candidate.proof;
                    variant.changed_offset = candidate.changed_offset;
                    if (variant_index >= allocated_variant_slots.size()) {
                        throw std::runtime_error(
                            "Native variant count exceeded deterministic layout capacity");
                    }
                    variant.ciphertext_vaddr =
                        allocated_variant_slots[variant_index].ciphertext_vaddr;
                    variant.nonce_vaddr = allocated_variant_slots[variant_index].nonce_vaddr;
                    variant.tag_vaddr = allocated_variant_slots[variant_index].tag_vaddr;
                    variant.aad_vaddr = allocated_variant_slots[variant_index].aad_vaddr;
                    variant.aad = fragment.aad;
                    if (variant.aad.empty()) {
                        throw std::runtime_error("V3 variant has empty authenticated context");
                    }
                    const uint32_t variant_domain =
                        static_cast<uint32_t>(maya::protection::KeyDomain::Variant);
                    for (unsigned byte = 0; byte < 4; ++byte) {
                        variant.aad[byte] = static_cast<uint8_t>(variant_domain >> (byte * 8));
                    }
                    variant.aad.back() ^= static_cast<uint8_t>(0x80u | (variant_index + 1));
                    variant.nonce = maya::protection::derive_fragment_nonce(
                        ctx.build_seed, func.selected_id,
                        fragment.fragment_id ^
                            (0x80000000u + static_cast<uint32_t>(variant_index)));
                    auto variant_key =
                        maya::protection::derive_sealed_object_key(ctx.build_root, variant.aad);
                    const auto variant_sealed = maya::protection::seal_fragment(
                        variant.plaintext, variant.aad, variant_key, variant.nonce);
                    maya::protection::secure_zero(variant_key);
                    variant.ciphertext = variant_sealed.ciphertext;
                    variant.tag = variant_sealed.tag;
                    fragment.variants.push_back(std::move(variant));
                }
            }
            if (v3 || (!fragment.variants.empty() && func.native_variants_enabled)) {
                const auto isa = maya::protection::generate_v3_isa(ctx.build_seed, func.cluster_id);
                std::vector<maya::protection::V3VmInstruction> program_instructions;
                uint64_t step_limit = 0;
                if (v3) {
                    const auto semantic = maya::protection::make_v3_transition_program(
                        !fragment.variants.empty(), false, 128);
                    program_instructions = maya::protection::compile_v3_semantic_program(semantic);
                    step_limit = semantic.step_limit;
                } else {
                    const uint64_t changed_offset =
                        fragment.variants.empty() ? 0 : fragment.variants.front().changed_offset;
                    const uint64_t rotate = 1 + ((fragment.fragment_id + changed_offset) % 63);
                    program_instructions = {
                        {maya::protection::V3VmOp::RotateRight, 0, 0, 0, rotate},
                        {maya::protection::V3VmOp::Halt, 0, 0, 0, 0},
                    };
                    step_limit = 2;
                }
                const auto program = maya::protection::seal_v3_program(
                    ctx.build_root, ctx.build_seed, isa, func.cluster_id, func.v3_owner_namespace,
                    step_limit, program_instructions);
                fragment.vm_ciphertext = program.ciphertext;
                fragment.vm_nonce = program.nonce;
                fragment.vm_tag = program.tag;
                fragment.vm_aad = maya::protection::v3_program_aad(program, isa);
                fragment.vm_rotate_opcode =
                    isa.opcode[static_cast<size_t>(maya::protection::V3VmOp::RotateRight)];
                fragment.vm_halt_opcode =
                    isa.opcode[static_cast<size_t>(maya::protection::V3VmOp::Halt)];
                fragment.vm_register_zero = isa.register_encoding[0];
                fragment.vm_operand_mask = isa.operand_mask;
                fragment.vm_immediate_mask = isa.immediate_mask;
                fragment.vm_opcodes = isa.opcode;
                fragment.vm_step_limit = step_limit;
                if (v3) {
                    for (const auto& instruction : program_instructions) {
                        if (instruction.op == maya::protection::V3VmOp::Primitive)
                            fragment.vm_required_primitive_trace |= uint64_t{1}
                                                                    << (instruction.immediate - 1);
                    }
                }
                std::array<uint64_t, maya::protection::kV3VmRegisterCount> initial{};
                initial[0] = 0x0123456789abcdefULL;
                const auto vm_result =
                    maya::protection::execute_v3_program(ctx.build_root, isa, program, initial);
                if (vm_result.fault != maya::protection::V3VmFault::None ||
                    (v3 && (vm_result.primitive_trace & fragment.vm_required_primitive_trace) !=
                               fragment.vm_required_primitive_trace))
                    throw std::runtime_error(
                        "Generated V3 control VM failed reference verification");
            }
#endif
        }
    }
}

#if MAYA_ENABLE_V3
maya::protection::V3EventClass v3_event_class(maya::protection::FragmentExitKind kind) {
    using maya::protection::FragmentExitKind;
    using maya::protection::V3EventClass;
    switch (kind) {
    case FragmentExitKind::NextFragment:
        return V3EventClass::Next;
    case FragmentExitKind::CallProtected:
        return V3EventClass::Call;
    case FragmentExitKind::ReturnProtected:
    case FragmentExitKind::ExitFunction:
        return V3EventClass::Return;
    case FragmentExitKind::TailcallProtected:
        return V3EventClass::TailCall;
    case FragmentExitKind::CallExternal:
        return V3EventClass::ExternalCall;
    case FragmentExitKind::SetjmpExternal:
        return V3EventClass::Checkpoint;
    case FragmentExitKind::LongjmpExternal:
        return V3EventClass::NonLocalJump;
    case FragmentExitKind::Fault:
        return V3EventClass::Next;
    }
    throw std::runtime_error("Unknown fragment exit kind for V3 capability");
}
void build_v3_shards(ProtectionContext& ctx,
                     std::vector<maya::protection::ProtectedFunction>& funcs) {
    using namespace maya::protection;
    auto append32 = [](std::vector<uint8_t>& bytes, uint32_t value) {
        for (unsigned index = 0; index < 4; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    };
    auto append64 = [](std::vector<uint8_t>& bytes, uint64_t value) {
        for (unsigned index = 0; index < 8; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    };
    auto handle64 = [&](const std::string& domain, uint64_t ordinal, uint32_t cluster) {
        const auto opaque = derive_opaque128(ctx.build_seed, domain, ordinal, cluster);
        uint64_t value = 0;
        std::memcpy(&value, opaque.data(), sizeof(value));
        return value == 0 ? uint64_t{1} : value;
    };
    for (auto& func : funcs) {
        func.v3_function_handle = handle64("function-handle", func.selected_id, func.cluster_id);
        for (auto& fragment : func.fragments) {
            fragment.v3_handle = handle64("fragment-handle",
                                          (uint64_t(func.selected_id) << 32) | fragment.fragment_id,
                                          func.cluster_id);
        }
    }
    for (auto& func : funcs) {
        if (!func.cfg_execution_enabled)
            continue;
        func.v3_function_targets.clear();
        for (const auto& target : funcs) {
            if (target.cfg_execution_enabled)
                func.v3_function_targets.push_back({target.v3_function_handle, target.stub_vaddr,
                                                    target.fragments.front().v3_handle});
        }
    }
    for (auto& func : funcs) {
        if (!func.cfg_execution_enabled)
            continue;
        func.v3_shard_family = func.controllet_family % kV3ShardFamilyCount;
        func.v3_owner_namespace =
            derive_opaque128(ctx.build_seed, "owner", func.selected_id, func.cluster_id);
        std::vector<V3ShardRecord> records;
        uint64_t ordinal = 0;
        for (auto& fragment : func.fragments) {
            for (auto& exit : fragment.exits) {
                V3ShardRecord record;
                const uint64_t edge_ordinal = (uint64_t(func.selected_id) << 32) | ordinal;
                record.lookup_label =
                    derive_opaque128(ctx.build_seed, "lookup", edge_ordinal, func.cluster_id);
                record.owner_namespace = func.v3_owner_namespace;
                record.capability.source =
                    derive_opaque128(ctx.build_seed, "edge-source", edge_ordinal, func.cluster_id);
                record.capability.destination = derive_opaque128(ctx.build_seed, "edge-destination",
                                                                 edge_ordinal, func.cluster_id);
                record.capability.event_class = v3_event_class(exit.kind);
                record.capability.cluster = func.cluster_id;
                exit.v3_lookup_label = record.lookup_label;
                exit.v3_source_label = record.capability.source;
                exit.v3_destination_label = record.capability.destination;
                if (exit.kind == FragmentExitKind::CallProtected ||
                    exit.kind == FragmentExitKind::TailcallProtected) {
                    const auto target =
                        std::find_if(funcs.begin(), funcs.end(), [&](const auto& candidate) {
                            return candidate.id == exit.target_function_id;
                        });
                    if (target == funcs.end() || !target->cfg_execution_enabled)
                        throw std::runtime_error("V3 edge has no opaque function handle");
                    exit.v3_target_handle = target->v3_function_handle;
                } else if (exit.kind == FragmentExitKind::NextFragment) {
                    const auto target = std::find_if(
                        func.fragments.begin(), func.fragments.end(), [&](const auto& candidate) {
                            return candidate.fragment_id == exit.target_fragment_id;
                        });
                    if (target == func.fragments.end())
                        throw std::runtime_error("V3 edge has no opaque fragment handle");
                    exit.v3_target_handle = target->v3_handle;
                } else if (exit.kind == FragmentExitKind::CallExternal ||
                           exit.kind == FragmentExitKind::SetjmpExternal ||
                           exit.kind == FragmentExitKind::LongjmpExternal) {
                    exit.v3_target_handle = exit.compatibility_target;
                }
                if (exit.continuation_fragment_id != UINT32_MAX) {
                    const auto continuation = std::find_if(
                        func.fragments.begin(), func.fragments.end(), [&](const auto& candidate) {
                            return candidate.fragment_id == exit.continuation_fragment_id;
                        });
                    if (continuation == func.fragments.end())
                        throw std::runtime_error("V3 edge has no opaque continuation handle");
                    exit.v3_continuation_handle = continuation->v3_handle;
                } else if (exit.kind == FragmentExitKind::CallExternal) {
                    // External tail calls have no in-function continuation.
                    // Give each edge an opaque sentinel instead of exposing the
                    // retired UINT32_MAX logical continuation convention.
                    exit.v3_continuation_handle =
                        handle64("external-tail-continuation", edge_ordinal, func.cluster_id);
                }
                append32(record.resolver_payload, static_cast<uint32_t>(exit.kind));
                append32(record.resolver_payload,
                         exit.v3_target_handle == exit.compatibility_target &&
                                 exit.compatibility_target != 0
                             ? 2u
                             : 1u);
                append64(record.resolver_payload, exit.v3_target_handle);
                append64(record.resolver_payload, exit.v3_continuation_handle);
                records.push_back(std::move(record));
                ++ordinal;
            }
        }
        func.v3_capability_count = static_cast<uint32_t>(records.size());
        const auto sealed = seal_v3_shard(
            static_cast<V3ShardFamily>(func.v3_shard_family), func.cluster_id,
            func.v3_owner_namespace, func.v3_shard_vaddr, ctx.build_root, ctx.build_seed, records);
        func.v3_shard_envelope.clear();
        func.v3_shard_envelope.insert(func.v3_shard_envelope.end(), sealed.nonce.begin(),
                                      sealed.nonce.end());
        func.v3_shard_envelope.insert(func.v3_shard_envelope.end(), sealed.tag.begin(),
                                      sealed.tag.end());
        func.v3_shard_envelope.insert(func.v3_shard_envelope.end(), sealed.ciphertext.begin(),
                                      sealed.ciphertext.end());
        if (func.v3_shard_envelope.size() > func.v3_shard_capacity) {
            throw std::runtime_error("V3 capability shard exceeds reserved page for " + func.name);
        }
        if (open_v3_shard(sealed, ctx.build_root).size() != records.size()) {
            throw std::runtime_error("V3 shard verification count mismatch");
        }
    }
}
#endif

void merge_protected_results(
    std::vector<maya::protection::ProtectedFunction>& selected_funcs,
    const std::vector<maya::protection::ProtectedFunction>& protected_funcs) {
    for (auto& selected : selected_funcs) {
        const auto it = std::find_if(protected_funcs.begin(), protected_funcs.end(),
                                     [&](const auto& protected_func) {
                                         return protected_func.selected_id == selected.selected_id;
                                     });
        if (it != protected_funcs.end()) {
            selected = *it;
        }
    }
}

} // namespace

void maya::protect_binary(ProtectionContext& ctx) {
    initialize_options(ctx);
    initialize_fragment_secrets(ctx);
    detect_runtime_features(ctx);
    validate_input(ctx);
    log_pipeline_features(ctx);

    auto selected_funcs = maya::protection::collect_functions(ctx);
    if (selected_funcs.empty()) {
        throw std::runtime_error("No eligible protected functions found.");
    }
    ctx.discovered_function_count = selected_funcs.size();

    maya::protection::PayloadLayout layout;
    std::vector<maya::protection::CallsiteMetadata> callsites;
    maya::protection::prepare_eh_frame_clones(ctx, selected_funcs);
    maya::protection::analyze_fragment_modes(ctx, selected_funcs);
    if (ctx.options.include_symbols.empty()) {
        selected_funcs = select_application_graph(ctx, std::move(selected_funcs));
        maya::protection::analyze_fragment_modes(ctx, selected_funcs);
    } else {
        ctx.automatic_root_count = selected_funcs.size();
        Log::info("Selected " + std::to_string(selected_funcs.size()) +
                  " explicitly matched functions.");
    }
    std::vector<maya::protection::ProtectedFunction> protected_funcs;
    try {
        protected_funcs = build_protected_worklist(selected_funcs, ctx);
    } catch (...) {
        maya::protection::write_report(ctx, selected_funcs, callsites);
        throw;
    }
    if (ctx.options.command == CliCommand::Analyze) {
        maya::protection::write_report(ctx, selected_funcs, callsites);
        return;
    }
    if (protected_funcs.empty()) {
        maya::protection::write_report(ctx, selected_funcs, callsites);
        throw std::runtime_error("All selected functions were rejected by control-edge analysis.");
    }
    maya::protection::build_fragment_cfg(protected_funcs);
#if MAYA_ENABLE_V3
    uint32_t v3_family_rotation = 0;
    if (ctx.options.profile == ProtectionProfile::ExperimentalV3) {
        const auto rotation =
            maya::protection::derive_opaque128(ctx.build_seed, "shard-family-rotation", 0, 0);
        std::memcpy(&v3_family_rotation, rotation.data(), sizeof(v3_family_rotation));
        v3_family_rotation %= maya::protection::kV3ShardFamilyCount;
    }
#endif
    for (auto& func : protected_funcs) {
        const bool supported_data =
            std::none_of(func.data_refs.begin(), func.data_refs.end(), [](const auto& ref) {
                return ref.kind == maya::protection::DataRefKind::FunctionPointerReference ||
                       ref.kind == maya::protection::DataRefKind::JumpTableEntry;
            });
        func.cfg_execution_enabled =
            func.selected_backend == maya::protection::SelectedBackend::Fragment &&
            !func.fragments.empty() && supported_data;
        func.cfg_pie_fixups =
            func.cfg_execution_enabled &&
            (ctx.runtime_features.binary_kind == BinaryKind::DynamicPieExecutable ||
             ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable);
        std::memcpy(&func.event_cookie, ctx.fragment_binary_salt.data(), sizeof(func.event_cookie));
        if (func.event_cookie == 0)
            func.event_cookie = 0x6d6179612d657674ULL;
        if (func.cfg_execution_enabled) {
            func.native_variants_enabled = ctx.options.native_variants;
            const auto assignment =
                maya::protection::assign_controllet(func.selected_id, func.event_cookie);
            func.cluster_id = assignment.cluster_id;
            func.controllet_family = assignment.family;
#if MAYA_ENABLE_V3
            if (ctx.options.profile == ProtectionProfile::ExperimentalV3)
                func.controllet_family = (func.controllet_family + v3_family_rotation) %
                                         maya::protection::kV3ShardFamilyCount;
            if (func.native_variants_enabled ||
                ctx.options.profile == ProtectionProfile::ExperimentalV3) {
                func.v3_owner_namespace = maya::protection::derive_opaque128(
                    ctx.build_seed, "runtime-vm-owner", func.selected_id, func.cluster_id);
            }
            if (ctx.options.profile == ProtectionProfile::ExperimentalV3) {
                func.v3_control_enabled = true;
                const auto entry = maya::protection::derive_opaque128(
                    ctx.build_seed, "event-entry", func.selected_id, func.cluster_id);
                uint32_t selector = 0;
                std::memcpy(&selector, entry.data(), sizeof(selector));
                func.v3_event_gateway_offset = 0x100 + ((selector % 0x300) & ~uint32_t(3));
                func.v3_gateway_abi_family = (selector >> 16) % 4;
            }
#endif
        }
    }
#if MAYA_ENABLE_V3
    for (auto& func : protected_funcs) {
        if (!func.native_variants_enabled)
            continue;
        for (auto& fragment : func.fragments) {
            fragment.variants.resize(maya::protection::kNativeVariantLimit);
        }
    }
    const auto v3_target_capacity = static_cast<uint32_t>(
        std::count_if(protected_funcs.begin(), protected_funcs.end(),
                      [](const auto& func) { return func.cfg_execution_enabled; }));
    for (auto& func : protected_funcs)
        if (func.v3_control_enabled)
            func.v3_target_capacity = v3_target_capacity;
    if (ctx.options.profile == ProtectionProfile::ExperimentalV3) {
        std::stable_sort(
            protected_funcs.begin(), protected_funcs.end(), [&](const auto& lhs, const auto& rhs) {
                return maya::protection::derive_opaque128(ctx.build_seed, "placement-function",
                                                          lhs.selected_id, lhs.cluster_id) <
                       maya::protection::derive_opaque128(ctx.build_seed, "placement-function",
                                                          rhs.selected_id, rhs.cluster_id);
            });
    } else
#endif
    {
        // V2's compact target ABI addresses entry stubs by a shared stride.
        // Derive that stride from the largest generated semantic object in
        // this build instead of imposing a fixed per-function reservation.
        uint64_t v2_entry_stride = maya::protection::kEntryStubSize;
        for (const auto& func : protected_funcs)
            if (func.cfg_execution_enabled)
                v2_entry_stride =
                    std::max(v2_entry_stride, maya::protection::semantic_entry_stub_capacity(func));
        for (auto& func : protected_funcs)
            func.entry_stub_capacity = v2_entry_stride;
    }
    const uint64_t requested_vaddr = maya::protection::choose_payload_vaddr(ctx);
    maya::protection::assign_layout(protected_funcs, layout, requested_vaddr,
                                    ctx.runtime_features.slot_strategy);

    const uint64_t placed_vaddr =
        maya::protection::reserve_payload_vaddr(ctx, requested_vaddr, layout.total_size);
    if (placed_vaddr != requested_vaddr) {
        const int64_t delta =
            static_cast<int64_t>(placed_vaddr) - static_cast<int64_t>(requested_vaddr);
        maya::protection::shift_layout(protected_funcs, layout, delta);
    }
    if (ctx.final_image_shift != 0) {
        for (auto& func : protected_funcs) {
            for (auto& fragment : func.fragments) {
                for (auto& exit : fragment.exits) {
                    if (exit.kind == maya::protection::FragmentExitKind::CallExternal ||
                        exit.kind == maya::protection::FragmentExitKind::SetjmpExternal ||
                        exit.kind == maya::protection::FragmentExitKind::LongjmpExternal) {
                        exit.compatibility_target += ctx.final_image_shift;
                    }
                }
            }
        }
    }
    for (auto& func : protected_funcs) {
        maya::protection::relocate_fde_clone(ctx, func);
    }

    maya::protection::patch_function_bodies(ctx, protected_funcs, callsites);
#if MAYA_ENABLE_V3
    if (ctx.options.profile == ProtectionProfile::ExperimentalV3) {
        build_v3_shards(ctx, protected_funcs);
    }
#endif
    maya::protection::prepare_fragment_execution(protected_funcs);
    for (auto& func : protected_funcs) {
        if (!func.cfg_execution_enabled)
            continue;
#if MAYA_ENABLE_V3
        if (ctx.options.profile == ProtectionProfile::ExperimentalV3) {
            func.metadata_shard.clear();
            func.metadata_shard_mask = 0;
            continue;
        }
#endif
        std::vector<maya::protection::ShardRecord> records;
        for (const auto& fragment : func.fragments) {
            for (size_t i = 0; i < fragment.state_token_values.size(); ++i)
                records.push_back({func.id, fragment.fragment_id, static_cast<uint32_t>(i),
                                   fragment.state_token_values[i]});
        }
        func.metadata_shard = maya::protection::serialize_metadata_shard(
            func.controllet_family, func.cluster_id, ctx.fragment_binary_salt, records);
        func.metadata_shard_mask =
            maya::protection::metadata_shard_mask(func.cluster_id, ctx.fragment_binary_salt);
        const auto decoded = maya::protection::parse_metadata_shard(
            func.controllet_family, func.cluster_id, ctx.fragment_binary_salt, func.metadata_shard);
        if (decoded.size() != records.size())
            throw std::runtime_error("Controllet shard verification count mismatch");
        for (size_t i = 0; i < records.size(); ++i)
            if (decoded[i].owner_function != records[i].owner_function ||
                decoded[i].fragment_id != records[i].fragment_id ||
                decoded[i].kind != records[i].kind || decoded[i].value != records[i].value)
                throw std::runtime_error("Controllet shard verification value mismatch");
    }
    seal_authenticated_leaves(ctx, protected_funcs);
    try {
        maya::protection::validate_function_pointer_refs(ctx, protected_funcs);
    } catch (...) {
        merge_protected_results(selected_funcs, protected_funcs);
        maya::protection::write_report(ctx, selected_funcs, callsites);
        throw;
    }
    std::vector<uint8_t> payload(layout.total_size, 0);
    maya::protection::emit_payload(ctx, protected_funcs, layout, callsites, payload);
    maya::protection::patch_eh_frame_header(ctx, protected_funcs);
    maya::protection::patch_original_entries(ctx, protected_funcs);
    maya::protection::add_payload_segment(ctx, layout, payload);

    if (maya::protection::is_protected_start(protected_funcs, ctx.original_entry_point)) {
        ctx.binary->header().entrypoint(ctx.original_entry_point);
    }

    maya::protection::verify_plaintext_removed(ctx, protected_funcs, payload);
    merge_protected_results(selected_funcs, protected_funcs);
    maya::protection::write_report(ctx, selected_funcs, callsites);
    Log::info("Maya protection complete for " + std::to_string(protected_funcs.size()) +
              " protected functions.");
}
