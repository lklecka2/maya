#include "core/Cli.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

ProtectionContext parse(std::vector<std::string> arguments) {
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    return parse_protector_args(static_cast<int>(argv.size()), argv.data());
}

void expect_failure(const std::vector<std::string>& arguments, const std::string& needle) {
    try {
        (void)parse(arguments);
    } catch (const CliError& error) {
        if (std::string(error.what()).find(needle) != std::string::npos)
            return;
        throw;
    }
    throw std::runtime_error("CLI parse unexpectedly succeeded");
}

} // namespace

int main() {
    const auto defaults = parse({"maya", "protect", "input.elf"});
    if (defaults.options.command != CliCommand::Protect ||
        defaults.options.profile != ProtectionProfile::Standard ||
        defaults.options.backend_policy != BackendPolicy::Auto ||
        defaults.options.native_variants ||
        defaults.options.output_filename != "input.elf.protected" ||
        defaults.options.report_filename != "input.elf.protection.tsv")
        return 1;

#if MAYA_ENABLE_V3
    const auto experimental =
        parse({"maya", "protect", "input.elf", "--profile", "experimental-v3"});
    if (experimental.options.profile != ProtectionProfile::ExperimentalV3 ||
        !experimental.options.native_variants)
        return 2;
#else
    expect_failure({"maya", "protect", "input.elf", "--profile", "experimental-v3"},
                   "Unknown option");
    expect_failure({"maya", "protect", "input.elf", "--native-variants"}, "Unknown option");
#endif

    const auto analyze =
        parse({"maya", "analyze", "input.elf", "--functions", "main", "--exclude", "cold_*"});
    if (analyze.options.command != CliCommand::Analyze ||
        analyze.options.report_filename != "input.elf.analysis.tsv" ||
        analyze.options.include_symbols != std::vector<std::string>{"main"} ||
        analyze.options.exclude_symbols != std::vector<std::string>{"cold_*"})
        return 3;

    const auto custom = parse({"maya", "protect", "--output", "dist/app", "input.elf"});
    if (custom.options.output_filename != "dist/app" ||
        custom.options.report_filename != "dist/app.protection.tsv")
        return 4;

    const auto fragments = parse({"maya", "protect", "input.elf", "--backend", "fragments-only"});
    if (fragments.options.execution_mode != ExecutionMode::FragmentRequired ||
        fragments.options.slot_strategy != SlotStrategy::RuntimeAllocator)
        return 5;

    const auto compatibility =
        parse({"maya", "protect", "input.elf", "--backend", "compatibility"});
    if (compatibility.options.execution_mode != ExecutionMode::Legacy ||
        compatibility.options.slot_strategy != SlotStrategy::FixedPerFunction)
        return 6;

    if (parse({"maya", "--help"}).options.command != CliCommand::Help)
        return 7;
    if (parse({"maya", "--version"}).options.command != CliCommand::Version)
        return 8;

    expect_failure({"maya", "input.elf"}, "Expected a command");
    expect_failure({"maya", "protect"}, "Missing input");
    expect_failure({"maya", "analyze", "input.elf", "-o", "out"}, "only valid");
#if MAYA_ENABLE_V3
    expect_failure({"maya", "protect", "input.elf", "--profile", "bad"}, "Unsupported profile");
#endif
    expect_failure({"maya", "protect", "input.elf", "--backend", "bad"}, "Unsupported backend");
    expect_failure({"maya", "protect", "input.elf", "--hardening", "v2"}, "was removed");
    expect_failure({"maya", "protect", "input.elf", "--analyze-only"}, "was removed");
    expect_failure({"maya", "protect", "one", "two"}, "Only one input");
#if MAYA_ENABLE_V3
    expect_failure(
        {"maya", "protect", "input.elf", "--profile", "standard", "--profile", "experimental-v3"},
        "conflicting");
#endif

    std::cout << "CLI tests passed\n";
    return 0;
}
