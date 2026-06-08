#include "core/ProtectionPipeline.hpp"

#include <LIEF/ELF.hpp>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/Logger.hpp"
#include "core/RuntimeSchema.hpp"
#include "protection/CodeRelocation.hpp"
#include "protection/ExceptionFrames.hpp"
#include "protection/FunctionLayout.hpp"
#include "protection/PayloadImage.hpp"

namespace {

void initialize_options(ProtectionContext& ctx) {
    if (ctx.options.output_filename.empty()) {
        ctx.options.output_filename = ctx.filename + ".protected";
    }
    if (ctx.options.report_filename.empty()) {
        ctx.options.report_filename = ctx.filename + ".protection.tsv";
    }
}

void detect_runtime_features(ProtectionContext& ctx) {
    ctx.runtime_features.has_interpreter = ctx.binary->has_interpreter();
    ctx.runtime_features.binary_kind = ctx.runtime_features.has_interpreter
        ? BinaryKind::PositionIndependentExecutable
        : BinaryKind::StaticExecutable;
    ctx.runtime_features.has_eh_frame = ctx.binary->get_section(".eh_frame") != nullptr;
    ctx.runtime_features.has_gcc_except_table = ctx.binary->get_section(".gcc_except_table") != nullptr;
    ctx.runtime_features.upx_compatible_layout = ctx.options.require_upx_compatible_layout;
    ctx.runtime_features.slot_strategy = ctx.options.slot_strategy;

    for (const auto& sym : ctx.binary->symbols()) {
        if (sym.name().find("__gxx_personality_v0") != std::string::npos) {
            ctx.runtime_features.has_cpp_personality = true;
            break;
        }
    }
}

bool has_cpp_eh(const ProtectionContext& ctx) {
    return ctx.runtime_features.has_gcc_except_table && ctx.runtime_features.has_cpp_personality;
}

void validate_input(const ProtectionContext& ctx) {
    if (!ctx.is_aarch64) {
        throw std::runtime_error("Input is not an AArch64 ELF.");
    }
    if (ctx.runtime_features.binary_kind == BinaryKind::PositionIndependentExecutable && !ctx.options.allow_pie) {
        throw std::runtime_error("PIE input is disabled by protection options.");
    }
    if (ctx.runtime_features.has_gcc_except_table && !ctx.options.enable_cpp_exceptions) {
        throw std::runtime_error("C++ exception metadata detected but exception support is disabled.");
    }
    if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator && has_cpp_eh(ctx)) {
        throw std::runtime_error(
            "SlotStrategy::RuntimeAllocator does not yet support C++ EH functions. "
            "The current EH entry path does not unwind through the normal slot cleanup stub. "
            "Re-run C++ exception binaries with --slot-strategy fixed-per-function or "
            "MAYA_SLOT_STRATEGY=fixed-per-function."
        );
    }
}

void log_pipeline_features(const ProtectionContext& ctx) {
    Log::info("Maya protection pipeline:");
    Log::info("  binary-kind=" + maya::binary_kind_name(ctx.runtime_features.binary_kind));
    Log::info("  slots=" + maya::slot_strategy_name(ctx.runtime_features.slot_strategy));
    Log::info(std::string("  cxx-exceptions=") + (has_cpp_eh(ctx) ? "detected" : "not-detected"));
    Log::info(std::string("  upx-compatible-layout=") + (ctx.runtime_features.upx_compatible_layout ? "requested" : "disabled"));
    Log::info(std::string("  symbol-selection=") + (ctx.options.aggressive_symbols ? "aggressive" : "conservative"));
}

} // namespace

void ProtectionPipeline::protect(ProtectionContext& ctx) {
    initialize_options(ctx);
    detect_runtime_features(ctx);
    validate_input(ctx);
    log_pipeline_features(ctx);

    auto funcs = maya::protection::collect_functions(ctx);
    if (funcs.empty()) {
        throw std::runtime_error("No eligible protected functions found.");
    }

    maya::protection::Layout layout;
    std::vector<maya::protection::CallsiteMeta> callsites;
    maya::protection::prepare_eh_frame_clones(ctx, funcs);
    const uint64_t requested_vaddr = maya::protection::choose_payload_vaddr(ctx);
    maya::protection::assign_layout(funcs, layout, requested_vaddr, ctx.runtime_features.slot_strategy);

    const uint64_t placed_vaddr = maya::protection::reserve_payload_vaddr(ctx, requested_vaddr, layout.total_size);
    if (placed_vaddr != requested_vaddr) {
        const int64_t delta = static_cast<int64_t>(placed_vaddr) - static_cast<int64_t>(requested_vaddr);
        maya::protection::shift_layout(funcs, layout, delta);
    }
    for (auto& func : funcs) {
        maya::protection::relocate_fde_clone(ctx, func);
    }

    maya::protection::patch_function_bodies(ctx, funcs, callsites);
    maya::protection::validate_function_pointer_refs(ctx, funcs);
    std::vector<uint8_t> payload(layout.total_size, 0);
    maya::protection::emit_payload(ctx, funcs, layout, callsites, payload);
    maya::protection::patch_eh_frame_header(ctx, funcs);
    maya::protection::patch_original_entries(ctx, funcs);
    maya::protection::add_payload_segment(ctx, layout, payload);

    if (maya::protection::is_protected_start(funcs, ctx.original_entry_point)) {
        ctx.binary->header().entrypoint(ctx.original_entry_point);
    }

    maya::protection::verify_plaintext_removed(ctx, funcs, payload);
    maya::protection::write_report(ctx, funcs, callsites);
    Log::info("Maya protection complete for " + std::to_string(funcs.size()) + " functions.");
}
