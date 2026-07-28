#include "core/Cli.hpp"
#include "core/Context.hpp"
#include "core/Logger.hpp"
#include "core/ProtectionPipeline.hpp"
#include "core/UpxLayout.hpp"
#include "core/protection/FragmentCrypto.hpp"
#include <LIEF/ELF.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

void apply_deferred_file_writes(const ProtectionContext& ctx, const fs::path& path) {
    if (ctx.deferred_file_writes.empty())
        return;
    std::fstream out(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!out)
        throw std::runtime_error("Failed to reopen output for static-PIE payload writes.");
    for (const auto& [offset, bytes] : ctx.deferred_file_writes) {
        out.seekp(static_cast<std::streamoff>(offset));
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out)
            throw std::runtime_error("Failed to write deferred static-PIE payload bytes.");
    }
    out.flush();
    out.clear();
    out.seekg(0);
    std::array<uint8_t, 64> ehdr{};
    out.read(reinterpret_cast<char*>(ehdr.data()), ehdr.size());
    uint64_t phoff = 0;
    uint16_t phentsize = 0, phnum = 0;
    std::memcpy(&phoff, ehdr.data() + 0x20, sizeof(phoff));
    std::memcpy(&phentsize, ehdr.data() + 0x36, sizeof(phentsize));
    std::memcpy(&phnum, ehdr.data() + 0x38, sizeof(phnum));
    std::vector<std::vector<uint8_t>> headers(phnum, std::vector<uint8_t>(phentsize));
    out.seekg(static_cast<std::streamoff>(phoff));
    for (auto& header : headers)
        out.read(reinterpret_cast<char*>(header.data()), header.size());
    auto type = [](const auto& header) {
        uint32_t value = 0;
        std::memcpy(&value, header.data(), 4);
        return value;
    };
    std::stable_sort(headers.begin(), headers.end(), [&](const auto& lhs, const auto& rhs) {
        return (type(lhs) == 1) > (type(rhs) == 1);
    });
    out.seekp(static_cast<std::streamoff>(phoff));
    for (const auto& header : headers)
        out.write(reinterpret_cast<const char*>(header.data()), header.size());
}

fs::path normalized_absolute(const fs::path& path) { return fs::absolute(path).lexically_normal(); }

fs::path temporary_sibling(const fs::path& destination) {
    std::random_device random;
    std::ostringstream suffix;
    suffix << ".maya-tmp-" << std::hex << random() << random();
    return destination.parent_path() / (destination.filename().string() + suffix.str());
}

std::string file_sha256(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("Failed to hash artifact: " + path.string());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    const auto digest = maya::protection::sha256_bytes(bytes);
    std::ostringstream value;
    value << std::hex << std::setfill('0');
    for (const auto byte : digest)
        value << std::setw(2) << static_cast<unsigned>(byte);
    return value.str();
}

unsigned permission_bits(const fs::path& path) {
    return static_cast<unsigned>(fs::status(path).permissions()) & 0777u;
}

void append_artifact_report(const ProtectionContext& ctx, bool has_output) {
    std::ofstream report(ctx.options.report_filename, std::ios::app);
    if (!report) {
        throw std::runtime_error("Failed to append artifact metadata to report: " +
                                 ctx.options.report_filename);
    }
    const fs::path input = ctx.filename;
    report << "run_record\tstatus\tmaya_version\n";
    report << "run_record\tsuccess\t" << MAYA_VERSION << "\n";
    report << "artifact_record\tkind\tpath\tbytes\tsha256\tpermissions\n";
    report << "artifact_record\tinput\t" << input.string() << "\t" << fs::file_size(input) << "\t"
           << file_sha256(input) << "\t" << std::oct << permission_bits(input) << std::dec << "\n";
    if (has_output) {
        const fs::path output = ctx.options.output_filename;
        report << "artifact_record\toutput\t" << output.string() << "\t" << fs::file_size(output)
               << "\t" << file_sha256(output) << "\t" << std::oct << permission_bits(output)
               << std::dec << "\n";
        report << "artifact_delta_record\tmetric\tvalue\n";
        report << "artifact_delta_record\tsize_bytes\t"
               << static_cast<int64_t>(fs::file_size(output)) -
                      static_cast<int64_t>(fs::file_size(input))
               << "\n";
    }
}

void print_summary(const ProtectionContext& ctx, bool has_output) {
    const auto& summary = ctx.summary;
    std::cout << "\n" << (has_output ? "Protected" : "Analyzed") << " " << ctx.filename;
    if (has_output)
        std::cout << " -> " << ctx.options.output_filename;
    std::cout << "\n  functions: " << summary.protected_functions << " protected";
    if (summary.fallbacks)
        std::cout << ", " << summary.fallbacks << " compatibility";
    if (summary.rejections)
        std::cout << ", " << summary.rejections << " rejected";
    std::cout << "\n  fragments: " << summary.fragments
              << ", native variants: " << summary.native_variants;
    if (has_output) {
        const auto input_size = fs::file_size(ctx.filename);
        const auto output_size = fs::file_size(ctx.options.output_filename);
        const auto delta = static_cast<int64_t>(output_size) - static_cast<int64_t>(input_size);
        std::cout << "\n  size: " << output_size << " bytes (" << (delta >= 0 ? "+" : "") << delta
                  << ")";
    }
    std::cout << "\n  report: " << ctx.options.report_filename << "\n";
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        ProtectionContext ctx = parse_protector_args(argc, argv);
        if (ctx.options.command == CliCommand::Help) {
            std::cout << maya_usage();
            return 0;
        }
        if (ctx.options.command == CliCommand::Version) {
            std::cout << "maya " << MAYA_VERSION << "\n";
            return 0;
        }
        const fs::path input_path = normalized_absolute(ctx.filename);
        const fs::path report_path = normalized_absolute(ctx.options.report_filename);
        if (input_path == report_path) {
            throw CliError("Input and report paths must be different.");
        }
        if (ctx.options.command != CliCommand::Analyze &&
            normalized_absolute(ctx.options.output_filename) == report_path) {
            throw CliError("Output and report paths must be different.");
        }
        if (!report_path.parent_path().empty() && !fs::exists(report_path.parent_path())) {
            throw std::runtime_error("Report directory does not exist: " +
                                     report_path.parent_path().string());
        }
        if (ctx.options.command != CliCommand::Analyze) {
            const fs::path output = normalized_absolute(ctx.options.output_filename);
            if (input_path == output) {
                throw CliError("Input and output paths must be different.");
            }
            if (!output.parent_path().empty() && !fs::exists(output.parent_path())) {
                throw std::runtime_error("Output directory does not exist: " +
                                         output.parent_path().string());
            }
        }
        ctx.binary = LIEF::ELF::Parser::parse(ctx.filename);
        if (!ctx.binary) {
            throw std::runtime_error("LIEF failed to parse the binary.");
        }

        ctx.is_aarch64 = (ctx.binary->header().machine_type() == LIEF::ELF::ARCH::AARCH64);
        ctx.original_entry_point = ctx.binary->entrypoint();

        Log::info("Successfully loaded: " + ctx.filename);

        maya::protect_binary(ctx);
        if (ctx.options.command == CliCommand::Analyze) {
            append_artifact_report(ctx, false);
            print_summary(ctx, false);
            return 0;
        }

        const fs::path input = normalized_absolute(ctx.filename);
        const fs::path output = normalized_absolute(ctx.options.output_filename);
        const fs::path temporary = temporary_sibling(output);
        struct TemporaryGuard {
            fs::path path;
            ~TemporaryGuard() {
                std::error_code error;
                fs::remove(path, error);
            }
        } guard{temporary};

        ctx.binary->write(temporary.string());
        apply_deferred_file_writes(ctx, temporary);
        if (ctx.options.require_upx_compatible_layout) {
            maya::compact_upx_program_headers(temporary.string());
        }
        fs::permissions(temporary, fs::status(input).permissions(), fs::perm_options::replace);
        std::error_code rename_error;
        fs::rename(temporary, output, rename_error);
        if (rename_error) {
            throw std::runtime_error("Failed to atomically replace output: " +
                                     rename_error.message());
        }
        guard.path.clear();
        append_artifact_report(ctx, true);
        print_summary(ctx, true);

    } catch (const CliError& e) {
        Log::error(std::string("Error: ") + e.what());
        return 2;
    } catch (const std::exception& e) {
        Log::error(std::string("Error: ") + e.what());
        return 1;
    }
    return 0;
}
