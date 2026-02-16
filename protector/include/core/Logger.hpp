#pragma once
#include <iostream>
#include <string>

namespace Log {
    inline void info(const std::string& msg) {
        std::cout << "[*] " << msg << std::endl;
    }
    inline void warn(const std::string& msg) {
        std::cerr << "[!] " << msg << std::endl;
    }
    inline void error(const std::string& msg) {
        std::cerr << "[-] " << msg << std::endl;
    }
}
