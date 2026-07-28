set(PROTECTOR_SOURCES
    src/main.cpp
    src/core/Cli.cpp
    src/core/ProtectionPipeline.cpp
    src/core/UpxLayout.cpp
    src/core/protection/CodeRelocation.cpp
    src/core/protection/Controllets.cpp
    src/core/protection/ExceptionFrames.cpp
    src/core/protection/FragmentAnalysis.cpp
    src/core/protection/FragmentCfg.cpp
    src/core/protection/FragmentCrypto.cpp
    src/core/protection/FragmentEvents.cpp
    src/core/protection/FragmentExecution.cpp
    src/core/protection/FragmentImage.cpp
    src/core/protection/FunctionLayout.cpp
    src/core/protection/PayloadImage.cpp
    src/core/protection/RuntimeStubs.cpp
    src/core/protection/StateBinding.cpp
)
if(MAYA_ENABLE_V3)
    list(APPEND PROTECTOR_SOURCES
        src/core/protection/NativeVariants.cpp
        src/core/protection/V3Capabilities.cpp
        src/core/protection/V3Lifecycle.cpp
        src/core/protection/V3Shards.cpp
        src/core/protection/V3Vm.cpp
    )
endif()
if(MAYA_ENABLE_V3)
    set(MAYA_ENABLE_V3_VALUE 1)
else()
    set(MAYA_ENABLE_V3_VALUE 0)
endif()
add_compile_definitions(MAYA_ENABLE_V3=${MAYA_ENABLE_V3_VALUE})

set(MAYA_RUNTIME_DIR ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
set(MAYA_RUNTIME_GEN ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(MAYA_RUNTIME_OBJ ${MAYA_RUNTIME_GEN}/maya_runtime.o)
set(MAYA_RUNTIME_CRYPTO_OBJ ${MAYA_RUNTIME_GEN}/maya_runtime_crypto.o)
set(MAYA_RUNTIME_STATE_OBJ ${MAYA_RUNTIME_GEN}/maya_runtime_state.o)
set(MAYA_RUNTIME_KDF_OBJ ${MAYA_RUNTIME_GEN}/maya_runtime_kdf.o)
set(MAYA_RUNTIME_ELF ${MAYA_RUNTIME_GEN}/maya_runtime.elf)
set(MAYA_RUNTIME_BIN ${MAYA_RUNTIME_GEN}/maya_runtime.bin)
set(MAYA_RUNTIME_HEADER ${MAYA_RUNTIME_GEN}/maya_runtime_blob.hpp)
set(MAYA_RUNTIME_MANIFEST ${MAYA_RUNTIME_GEN}/maya_runtime.relocations)
set(MAYA_RUNTIME_SYMBOLS ${MAYA_RUNTIME_GEN}/maya_runtime_symbols.hpp)

add_custom_command(
    OUTPUT ${MAYA_RUNTIME_HEADER} ${MAYA_RUNTIME_MANIFEST} ${MAYA_RUNTIME_SYMBOLS}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MAYA_RUNTIME_GEN}
    COMMAND aarch64-linux-gnu-gcc -c -Os -ffreestanding -fPIC -fno-stack-protector -mno-outline-atomics
            -fno-asynchronous-unwind-tables -fno-unwind-tables
            ${MAYA_RUNTIME_DIR}/runtime.c -o ${MAYA_RUNTIME_OBJ}
    COMMAND aarch64-linux-gnu-gcc -c -Os -ffreestanding -fPIC -fno-stack-protector
            -fno-asynchronous-unwind-tables -fno-unwind-tables
            ${MAYA_RUNTIME_DIR}/xchacha20poly1305.c -o ${MAYA_RUNTIME_CRYPTO_OBJ}
    COMMAND aarch64-linux-gnu-gcc -c -Os -ffreestanding -fPIC -fno-stack-protector
            -fno-asynchronous-unwind-tables -fno-unwind-tables
            ${MAYA_RUNTIME_DIR}/state_binding.c -o ${MAYA_RUNTIME_STATE_OBJ}
    COMMAND aarch64-linux-gnu-gcc -c -Os -ffreestanding -fPIC -fno-stack-protector
            -fno-asynchronous-unwind-tables -fno-unwind-tables
            -DMAYA_ENABLE_V3=${MAYA_ENABLE_V3_VALUE}
            ${MAYA_RUNTIME_DIR}/runtime_kdf.c -o ${MAYA_RUNTIME_KDF_OBJ}
    COMMAND aarch64-linux-gnu-ld -nostdlib -T ${MAYA_RUNTIME_DIR}/runtime.ld
            ${MAYA_RUNTIME_OBJ} ${MAYA_RUNTIME_CRYPTO_OBJ} ${MAYA_RUNTIME_STATE_OBJ} ${MAYA_RUNTIME_KDF_OBJ} -o ${MAYA_RUNTIME_ELF}
    COMMAND ${CMAKE_COMMAND} -DREADELF=aarch64-linux-gnu-readelf -DELF=${MAYA_RUNTIME_ELF}
            -DMANIFEST=${MAYA_RUNTIME_MANIFEST} -P ${MAYA_RUNTIME_DIR}/check_relocations.cmake
    COMMAND ${CMAKE_COMMAND} -DNM=aarch64-linux-gnu-nm -DELF=${MAYA_RUNTIME_ELF}
            -DOUTPUT=${MAYA_RUNTIME_SYMBOLS} -DMAYA_ENABLE_V3=${MAYA_ENABLE_V3_VALUE}
            -P ${MAYA_RUNTIME_DIR}/generate_symbols.cmake
    COMMAND aarch64-linux-gnu-objcopy -O binary ${MAYA_RUNTIME_ELF} ${MAYA_RUNTIME_BIN}
    COMMAND xxd -i -n maya_runtime_blob ${MAYA_RUNTIME_BIN} ${MAYA_RUNTIME_HEADER}
    DEPENDS ${MAYA_RUNTIME_DIR}/runtime.c ${MAYA_RUNTIME_DIR}/xchacha20poly1305.c
            ${MAYA_RUNTIME_DIR}/state_binding.c ${MAYA_RUNTIME_DIR}/state_binding.h
            ${MAYA_RUNTIME_DIR}/runtime_kdf.c ${MAYA_RUNTIME_DIR}/runtime_kdf.h
            ${MAYA_RUNTIME_DIR}/xchacha20poly1305.h ${MAYA_RUNTIME_DIR}/runtime.ld
            ${MAYA_RUNTIME_DIR}/check_relocations.cmake ${MAYA_RUNTIME_DIR}/generate_symbols.cmake
    VERBATIM)
add_custom_target(maya_runtime_blob DEPENDS ${MAYA_RUNTIME_HEADER} ${MAYA_RUNTIME_MANIFEST} ${MAYA_RUNTIME_SYMBOLS})

add_executable(maya ${PROTECTOR_SOURCES})
target_sources(maya PRIVATE ${MAYA_RUNTIME_DIR}/state_binding.c ${MAYA_RUNTIME_DIR}/runtime_kdf.c)
add_dependencies(maya maya_runtime_blob)

target_include_directories(maya PRIVATE include ${MAYA_RUNTIME_GEN} ${MAYA_RUNTIME_DIR})
target_compile_definitions(maya PRIVATE
    MAYA_VERSION="${PROJECT_VERSION}"
    MAYA_ENABLE_V3=${MAYA_ENABLE_V3_VALUE})

target_link_libraries(maya
    PRIVATE
        LIEF::LIEF
        capstone::capstone
        keystone::keystone
        MbedTLS::mbedcrypto
)
if(MAYA_ENABLE_V3)
    target_link_libraries(maya PRIVATE z3::libz3)
endif()

install(TARGETS maya RUNTIME DESTINATION bin)

function(maya_add_test target)
    cmake_parse_arguments(TEST "" "" "SOURCES;LIBRARIES" ${ARGN})
    add_executable(${target} ${TEST_SOURCES})
    target_include_directories(${target} PRIVATE include src runtime)
    target_compile_definitions(${target} PRIVATE
        MAYA_ENABLE_V3=${MAYA_ENABLE_V3_VALUE})
    if(TEST_LIBRARIES)
        target_link_libraries(${target} PRIVATE ${TEST_LIBRARIES})
    endif()
    add_test(NAME ${target} COMMAND ${target})
endfunction()

function(maya_enable_sanitizers target)
    if(MAYA_ENABLE_SANITIZERS)
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE
            -fsanitize=address,undefined
            -static-libasan
            -static-libubsan)
        set_tests_properties(${target} PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
    endif()
endfunction()

if(BUILD_TESTING)
    maya_add_test(cli_tests
        SOURCES tests/CliTests.cpp src/core/Cli.cpp
        LIBRARIES LIEF::LIEF)
    maya_add_test(fragment_image_tests
        SOURCES tests/FragmentImageTests.cpp
                src/core/protection/FragmentImage.cpp
        LIBRARIES LIEF::LIEF)
    maya_add_test(fragment_crypto_tests
        SOURCES tests/FragmentCryptoTests.cpp
                src/core/protection/FragmentCrypto.cpp
                runtime/xchacha20poly1305.c
                runtime/runtime_kdf.c
        LIBRARIES MbedTLS::mbedcrypto)
    maya_add_test(fragment_cfg_tests
        SOURCES tests/FragmentCfgTests.cpp
                src/core/protection/FragmentCfg.cpp
        LIBRARIES LIEF::LIEF)
    maya_add_test(fragment_event_tests
        SOURCES tests/FragmentEventsTests.cpp
                src/core/protection/FragmentEvents.cpp
        LIBRARIES LIEF::LIEF)
    maya_add_test(state_binding_tests
        SOURCES tests/StateBindingTests.cpp
                src/core/protection/StateBinding.cpp
                runtime/state_binding.c
                runtime/runtime_kdf.c)
    maya_add_test(controllet_tests
        SOURCES tests/ControlletTests.cpp
                src/core/protection/Controllets.cpp
                src/core/protection/FragmentCrypto.cpp
                runtime/xchacha20poly1305.c
        LIBRARIES MbedTLS::mbedcrypto)

    if(MAYA_ENABLE_V3)
        maya_add_test(v3_capability_tests
            SOURCES tests/V3CapabilityTests.cpp
                    src/core/protection/V3Capabilities.cpp
                    src/core/protection/FragmentCrypto.cpp
                    runtime/runtime_kdf.c
            LIBRARIES MbedTLS::mbedcrypto)
        maya_add_test(v3_shard_tests
            SOURCES tests/V3ShardTests.cpp
                    src/core/protection/V3Shards.cpp
                    src/core/protection/V3Capabilities.cpp
                    src/core/protection/FragmentCrypto.cpp
                    runtime/runtime_kdf.c
            LIBRARIES MbedTLS::mbedcrypto)
        maya_add_test(v3_vm_tests
            SOURCES tests/V3VmTests.cpp
                    src/core/protection/V3Vm.cpp
                    src/core/protection/V3Capabilities.cpp
                    src/core/protection/FragmentCrypto.cpp
                    runtime/runtime_kdf.c
            LIBRARIES MbedTLS::mbedcrypto)
        maya_add_test(v3_lifecycle_tests
            SOURCES tests/V3LifecycleTests.cpp
                    src/core/protection/V3Lifecycle.cpp)
        maya_add_test(v3_fuzz_tests
            SOURCES tests/V3FuzzTests.cpp
                    src/core/protection/V3Shards.cpp
                    src/core/protection/V3Vm.cpp
                    src/core/protection/V3Capabilities.cpp
                    src/core/protection/FragmentCrypto.cpp
                    src/core/protection/FragmentImage.cpp
                    src/core/protection/Controllets.cpp
                    runtime/runtime_kdf.c
            LIBRARIES MbedTLS::mbedcrypto LIEF::LIEF)
        maya_enable_sanitizers(v3_fuzz_tests)
        maya_add_test(native_variant_tests
            SOURCES tests/NativeVariantTests.cpp
                    src/core/protection/NativeVariants.cpp
            LIBRARIES capstone::capstone z3::libz3)
    endif()

    maya_add_test(exception_frames_tests
        SOURCES tests/ExceptionFramesTests.cpp
                src/core/protection/ExceptionFrames.cpp
        LIBRARIES LIEF::LIEF)
    target_compile_definitions(exception_frames_tests PRIVATE
        MAYA_EH_TEST_BINARY="${CMAKE_SOURCE_DIR}/samples/cpp_exceptions.exceptions.elf")
    maya_enable_sanitizers(exception_frames_tests)
endif()
