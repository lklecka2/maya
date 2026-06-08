#include "core/Context.hpp"
#include "core/Logger.hpp"
#include "core/ProtectionPipeline.hpp"
#include "core/UpxLayout.hpp"
#include <LIEF/ELF.hpp>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <string>

namespace {

auto usage(const char* argv0) -> std::string {
    return std::string("Usage: ") + argv0 +
           " [--aggressive-symbols]"
           " [--slot-strategy runtime-allocator|fixed-per-function]"
           " [--output <path>]"
           " [--report <path>]"
           " <aarch64_elf_binary>";
}

auto parse_slot_strategy(const std::string& value) -> SlotStrategy {
    if (value == "runtime-allocator") {
        return SlotStrategy::RuntimeAllocator;
    }
    if (value == "fixed-per-function") {
        return SlotStrategy::FixedPerFunction;
    }
    throw std::runtime_error(
        "Unsupported slot strategy '" + value +
        "'. Expected runtime-allocator or fixed-per-function."
    );
}

auto require_value(int& index, int argc, char** argv, const std::string& option) -> std::string {
    if (index + 1 >= argc) {
        throw std::runtime_error(option + " requires a value.");
    }
    return argv[++index];
}

void apply_environment_options(ProtectionOptions& options) {
    if (const char* aggressive = std::getenv("MAYA_AGGRESSIVE_SYMBOLS")) {
        options.aggressive_symbols = std::strcmp(aggressive, "0") != 0;
    }
    if (const char* slot_strategy = std::getenv("MAYA_SLOT_STRATEGY")) {
        options.slot_strategy = parse_slot_strategy(slot_strategy);
    }
}

auto parse_args(int argc, char** argv) -> ProtectionContext {
    if (argc < 2) {
        throw std::runtime_error(usage(argv[0]));
    }

    ProtectionContext ctx;
    apply_environment_options(ctx.options);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--output" || arg == "-o") {
            ctx.options.output_filename = require_value(i, argc, argv, "--output");
        } else if (arg == "--report") {
            ctx.options.report_filename = require_value(i, argc, argv, "--report");
        } else if (arg == "--aggressive-symbols") {
            ctx.options.aggressive_symbols = true;
        } else if (arg == "--slot-strategy") {
            ctx.options.slot_strategy = parse_slot_strategy(require_value(i, argc, argv, "--slot-strategy"));
        } else if (!arg.empty() && arg[0] == '-') {
            throw std::runtime_error("Unknown option: " + arg);
        } else if (ctx.filename.empty()) {
            ctx.filename = arg;
        } else {
            throw std::runtime_error("Only one input binary may be provided.");
        }
    }

    if (ctx.filename.empty()) {
        throw std::runtime_error(usage(argv[0]));
    }
    return ctx;
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        ProtectionContext ctx = parse_args(argc, argv);
        ctx.binary = LIEF::ELF::Parser::parse(ctx.filename);
        if (!ctx.binary) {
            throw std::runtime_error("LIEF failed to parse the binary.");
        }

        ctx.is_aarch64 = (ctx.binary->header().machine_type() == LIEF::ELF::ARCH::AARCH64);
        ctx.original_entry_point = ctx.binary->entrypoint();

        Log::info("Successfully loaded: " + ctx.filename);

        ProtectionPipeline::protect(ctx);
        ctx.binary->write(ctx.options.output_filename);
        if (ctx.options.require_upx_compatible_layout) {
            UpxLayout::compact_program_headers(ctx.options.output_filename);
        }
        Log::info("Successfully wrote protected binary.");

    } catch (const std::exception& e) {
        Log::error(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}
