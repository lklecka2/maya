cmake_minimum_required(VERSION 3.20)
project(maya VERSION 0.1.0 LANGUAGES C CXX)
include(CTest)
option(MAYA_ENABLE_SANITIZERS "Build parser/decoder fuzz tests with ASan and UBSan" OFF)
option(MAYA_ENABLE_V3 "Build experimental V3 protection and Z3-backed native variants" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LIEF REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(capstone REQUIRED)
find_package(keystone REQUIRED)
if(NOT MAYA_MBEDTLS_ROOT)
    message(FATAL_ERROR "MAYA_MBEDTLS_ROOT must be provided by Conan")
endif()
target_include_directories(MbedTLS::mbedcrypto INTERFACE
    "${MAYA_MBEDTLS_ROOT}/include")
if(MAYA_ENABLE_V3)
    find_package(Z3 REQUIRED)
endif()

add_subdirectory(protector)
