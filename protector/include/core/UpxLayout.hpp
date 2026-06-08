#pragma once

#include <string>

class UpxLayout {
public:
    static void compact_program_headers(const std::string& protected_binary_path);
};
