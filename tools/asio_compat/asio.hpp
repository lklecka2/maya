#pragma once

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

namespace asio {
using namespace boost::asio;
using error_code = boost::system::error_code;
} // namespace asio
