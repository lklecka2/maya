#include "core/Cli.hpp"

#include <optional>
#include <string>

namespace {

template <typename T>
void set_consistent(std::optional<T>& destination, T value, const std::string& option) {
    if (destination && *destination != value) {
        throw CliError(option + " was repeated with conflicting values.");
    }
    destination = std::move(value);
}

std::string require_value(int& index, int argc, char** argv, const std::string& option) {
    if (index + 1 >= argc)
        throw CliError(option + " requires a value.");
    return argv[++index];
}

#if MAYA_ENABLE_V3
ProtectionProfile parse_profile(const std::string& value) {
    if (value == "standard")
        return ProtectionProfile::Standard;
    if (value == "experimental-v3")
        return ProtectionProfile::ExperimentalV3;
    throw CliError("Unsupported profile '" + value + "'. Expected standard or experimental-v3.");
}
#endif

BackendPolicy parse_backend(const std::string& value) {
    if (value == "auto")
        return BackendPolicy::Auto;
    if (value == "fragments-only")
        return BackendPolicy::FragmentsOnly;
    if (value == "compatibility")
        return BackendPolicy::Compatibility;
    throw CliError("Unsupported backend '" + value +
                   "'. Expected auto, fragments-only, or compatibility.");
}

[[noreturn]] void throw_legacy_option(const std::string& option) {
    if (option == "--analyze-only") {
        throw CliError("--analyze-only was removed; use 'maya analyze INPUT'.");
    }
    if (option == "--hardening" || option == "--control-hardening") {
#if MAYA_ENABLE_V3
        throw CliError(option + " was removed; use '--profile standard|experimental-v3'.");
#else
        throw CliError(option + " was removed.");
#endif
    }
    if (option == "--mode" || option == "--slot-strategy") {
        throw CliError(option + " was removed; use '--backend auto|fragments-only|compatibility'.");
    }
    if (option == "--fragment-variants") {
#if MAYA_ENABLE_V3
        throw CliError("--fragment-variants was removed; native variants are part of "
                       "'--profile experimental-v3'.");
#else
        throw CliError("--fragment-variants was removed.");
#endif
    }
    if (option == "--include-symbol" || option == "--exclude-symbol") {
        throw CliError(option + " was removed; use '--functions GLOB' or '--exclude GLOB'.");
    }
    throw CliError("Unknown option: " + option);
}

} // namespace

std::string maya_usage() {
    std::string usage = "Maya Protector\n"
                        "\n"
                        "Usage:\n"
                        "  maya protect INPUT [options]\n"
                        "  maya analyze INPUT [options]\n"
                        "  maya --help\n"
                        "  maya --version\n"
                        "\n"
                        "Common options:\n"
                        "  -o, --output PATH       Protected ELF path (protect only)\n"
                        "  --report PATH           Detailed TSV report path\n";
#if MAYA_ENABLE_V3
    usage += "  --profile PROFILE       standard (default) or experimental-v3\n";
#endif
    usage += "  --functions GLOB        Protect only matching symbols; repeatable\n"
             "  --exclude GLOB          Exclude matching symbols; repeatable\n"
             "  --backend POLICY        auto (default), fragments-only, or compatibility\n"
             "  --seed HEX              Reproducible 256-bit seed (64 hex characters)\n";
#if MAYA_ENABLE_V3
    usage += "  --native-variants       Enable proven native variants (advanced)\n"
             "  --no-native-variants    Disable variants selected by a profile (advanced)\n";
#endif
    usage += "  --upx-compatible-layout Request a UPX-compatible ELF layout\n"
             "  --verbose               Show per-function analysis and layout details\n";
    return usage;
}

ProtectionContext parse_protector_args(int argc, char** argv) {
    ProtectionContext ctx;
    if (argc < 2)
        throw CliError(maya_usage());

    const std::string first = argv[1];
    if (first == "--help" || first == "-h" || first == "help") {
        ctx.options.command = CliCommand::Help;
        return ctx;
    }
    if (first == "--version" || first == "version") {
        ctx.options.command = CliCommand::Version;
        return ctx;
    }
    if (first == "protect") {
        ctx.options.command = CliCommand::Protect;
    } else if (first == "analyze") {
        ctx.options.command = CliCommand::Analyze;
    } else {
        throw CliError("Expected a command before the input path. Use 'maya protect INPUT' "
                       "or 'maya analyze INPUT'.\n\n" +
                       maya_usage());
    }

#if MAYA_ENABLE_V3
    std::optional<ProtectionProfile> profile;
#endif
    std::optional<BackendPolicy> backend;
    std::optional<std::string> output;
    std::optional<std::string> report;
    std::optional<std::string> seed;
#if MAYA_ENABLE_V3
    std::optional<bool> native_variants;
#endif

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            ctx.options.command = CliCommand::Help;
            return ctx;
        }
        if (arg == "--output" || arg == "-o") {
            set_consistent(output, require_value(i, argc, argv, "--output"), "--output");
        } else if (arg == "--report") {
            set_consistent(report, require_value(i, argc, argv, "--report"), "--report");
        }
#if MAYA_ENABLE_V3
        else if (arg == "--profile") {
            set_consistent(profile, parse_profile(require_value(i, argc, argv, "--profile")),
                           "--profile");
        }
#endif
        else if (arg == "--backend") {
            set_consistent(backend, parse_backend(require_value(i, argc, argv, "--backend")),
                           "--backend");
        } else if (arg == "--functions") {
            ctx.options.include_symbols.push_back(require_value(i, argc, argv, "--functions"));
        } else if (arg == "--exclude") {
            ctx.options.exclude_symbols.push_back(require_value(i, argc, argv, "--exclude"));
        } else if (arg == "--seed") {
            set_consistent(seed, require_value(i, argc, argv, "--seed"), "--seed");
        }
#if MAYA_ENABLE_V3
        else if (arg == "--native-variants") {
            set_consistent(native_variants, true, "--native-variants");
        } else if (arg == "--no-native-variants") {
            set_consistent(native_variants, false, "--no-native-variants");
        }
#endif
        else if (arg == "--upx-compatible-layout") {
            ctx.options.require_upx_compatible_layout = true;
        } else if (arg == "--verbose") {
            ctx.options.verbose = true;
        } else if (!arg.empty() && arg[0] == '-') {
            throw_legacy_option(arg);
        } else if (ctx.filename.empty()) {
            ctx.filename = arg;
        } else {
            throw CliError("Only one input binary may be provided.");
        }
    }

    if (ctx.filename.empty())
        throw CliError("Missing input binary.\n\n" + maya_usage());
    if (ctx.options.command == CliCommand::Analyze && output) {
        throw CliError("--output is only valid with 'maya protect'.");
    }

    ctx.options.backend_policy = backend.value_or(BackendPolicy::Auto);
    ctx.options.seed_hex = seed.value_or("");
#if MAYA_ENABLE_V3
    ctx.options.profile = profile.value_or(ProtectionProfile::Standard);
    ctx.options.native_variants =
        native_variants.value_or(ctx.options.profile == ProtectionProfile::ExperimentalV3);
#else
    ctx.options.profile = ProtectionProfile::Standard;
    ctx.options.native_variants = false;
#endif

    switch (ctx.options.backend_policy) {
    case BackendPolicy::Auto:
        ctx.options.execution_mode = ExecutionMode::FragmentAuto;
        ctx.options.slot_strategy = SlotStrategy::RuntimeAllocator;
        break;
    case BackendPolicy::FragmentsOnly:
        ctx.options.execution_mode = ExecutionMode::FragmentRequired;
        ctx.options.slot_strategy = SlotStrategy::RuntimeAllocator;
        break;
    case BackendPolicy::Compatibility:
        ctx.options.execution_mode = ExecutionMode::Legacy;
        ctx.options.slot_strategy = SlotStrategy::FixedPerFunction;
        break;
    }

    if (output) {
        ctx.options.output_filename = *output;
    } else if (ctx.options.command != CliCommand::Analyze) {
        ctx.options.output_filename = ctx.filename + ".protected";
    }
    if (report) {
        ctx.options.report_filename = *report;
    } else if (ctx.options.command == CliCommand::Analyze) {
        ctx.options.report_filename = ctx.filename + ".analysis.tsv";
    } else if (output) {
        ctx.options.report_filename = *output + ".protection.tsv";
    } else {
        ctx.options.report_filename = ctx.filename + ".protection.tsv";
    }
    return ctx;
}
