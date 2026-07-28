#pragma once

#include <stdexcept>
#include <string>

#include "Context.hpp"

class CliError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

std::string maya_usage();
ProtectionContext parse_protector_args(int argc, char** argv);
