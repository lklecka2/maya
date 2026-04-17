#pragma once
#include <string>
#include <vector>
#include <algorithm>

class InstrumentationPolicy {
public:
    static auto should_instrument(const std::string& name, uint64_t addr, uint64_t text_start, uint64_t text_end, uint64_t user_code_cutoff) -> bool {
        // Only instrument if it's in the .text section
        if (addr < text_start || addr >= text_end) {
            return false;
        }

        // Limit instrumentation to user code that appears before the libc startup boundary.
        if (addr >= user_code_cutoff) {
            return false;
        }

        // Skip startup/runtime helper symbols and internal functions.
        static const std::vector<std::string> blacklist = {
            "_dl_", "_start", "__", "_init", "_fini",
            "frame_dummy", "register_tm_clones", "deregister_tm_clones",
            "__do_global_dtors_aux", "call_weak_fn", "call_fini", "__wrap_main"
        };

        if (!name.empty() && name[0] == '_') {
            return false;
        }

        return std::none_of(blacklist.begin(), blacklist.end(), [&](const std::string& forbidden) {
            return name.find(forbidden) != std::string::npos;
        });
    }
};
