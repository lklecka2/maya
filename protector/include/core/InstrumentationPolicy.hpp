#pragma once
#include <string>
#include <vector>
#include <algorithm>

class InstrumentationPolicy {
public:
    static auto should_instrument(const std::string& name, uint64_t addr, uint64_t text_start, uint64_t text_end, uint64_t user_code_cutoff, bool aggressive_symbols = false) -> bool {
        // Only instrument if it's in the .text section
        if (addr < text_start || addr >= text_end) {
            return false;
        }

        // Limit instrumentation to user code that appears before the libc startup boundary.
        if (addr >= user_code_cutoff) {
            return false;
        }

        if (aggressive_symbols) {
            return !name.empty() && name.find("__") == std::string::npos &&
                   name.find("_dl_") == std::string::npos &&
                   name != "_start" &&
                   name != "_init" &&
                   name != "_fini";
        }

        if (name.rfind("asio_", 0) == 0) {
            return false;
        }

        // Skip startup/runtime helper symbols and internal functions.
        static const std::vector<std::string> blacklist = {
            "_dl_", "_start", "__", "_init", "_fini",
            "frame_dummy", "register_tm_clones", "deregister_tm_clones",
            "__do_global_dtors_aux", "call_weak_fn", "call_fini", "__wrap_main"
        };

        const bool cxx_mangled_user_symbol = name.rfind("_Z", 0) == 0;
        if (!name.empty() && name[0] == '_' && !cxx_mangled_user_symbol) {
            return false;
        }

        if (cxx_mangled_user_symbol) {
            static const std::vector<std::string> cxx_support_prefixes = {
                "_ZSt", "_ZNSt", "_ZNKSt", "_ZNSa", "_ZN9__gnu_cxx", "_ZNK9__gnu_cxx",
                "_ZN4asio", "_ZNK4asio", "_ZN13asio_", "_ZNK13asio_", "_ZN14asio_",
                "_ZNK14asio_", "_ZN15asio_", "_ZNK15asio_", "_ZN25asio_", "_ZNK25asio_",
                "_ZN26asio_", "_ZN27asio_", "_Zn", "_Zd", "_ZTh", "_ZTv", "_ZGV", "_ZTV",
                "_ZTI", "_ZTS", "_ZTT"
            };
            if (name.rfind("_ZZ", 0) == 0) {
                return false;
            }
            if (std::any_of(cxx_support_prefixes.begin(), cxx_support_prefixes.end(), [&](const std::string& prefix) {
                    return name.rfind(prefix, 0) == 0;
                })) {
                return false;
            }
        }

        return std::none_of(blacklist.begin(), blacklist.end(), [&](const std::string& forbidden) {
            return name.find(forbidden) != std::string::npos;
        });
    }
};
