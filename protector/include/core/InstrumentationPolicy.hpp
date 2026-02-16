#pragma once
#include <string>
#include <vector>
#include <algorithm>

class InstrumentationPolicy {
public:
    static auto should_instrument(const std::string& name, uint64_t addr, uint64_t text_start, uint64_t text_end) -> bool {
        // Only instrument if it's in the .text section
        if (addr < text_start || addr >= text_end) {
            return false;
        }

        // Filter out dangerous functions that might cause recursion or are early init
        static const std::vector<std::string> blacklist = {
            "_dl_", "_start"
        };

        return std::none_of(blacklist.begin(), blacklist.end(), [&](const std::string& forbidden) {
            return name.find(forbidden) != std::string::npos;
        });
    }
};
