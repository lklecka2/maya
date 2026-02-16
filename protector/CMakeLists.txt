file(GLOB_RECURSE PROTECTOR_SOURCES CONFIGURE_DEPENDS "src/*.cpp")
add_executable(protector ${PROTECTOR_SOURCES})

target_include_directories(protector PRIVATE include)

target_link_libraries(protector
    PRIVATE
        LIEF::LIEF
        capstone::capstone
        keystone::keystone
)
