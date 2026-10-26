cmake_minimum_required(VERSION 3.24)

project(cs2_manual_map VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This project builds only on Windows.")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "Use the MSVC toolchain with the Visual Studio generator.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Configure an x64 generator (for example: -A x64).")
endif()

if(CMAKE_GENERATOR_PLATFORM AND NOT CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
    message(FATAL_ERROR "The selected generator platform must be x64.")
endif()

add_executable(cs2-manual-map
    src/main.cpp
    src/remote_loader.cpp
    include/remote_loader.hpp
)

target_compile_features(cs2-manual-map PRIVATE cxx_std_20)
target_include_directories(cs2-manual-map PRIVATE include)
target_link_libraries(cs2-manual-map PRIVATE advapi32)
target_compile_definitions(cs2-manual-map PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_compile_options(cs2-manual-map PRIVATE
    /W4
    /permissive-
    /EHsc
    /Zc:__cplusplus
    /utf-8
)

# RemoteLoader is copied byte-for-byte into another process. These options keep
# that translation unit free of stack-cookie helpers, CFG dispatch thunks,
# COMDAT folding, LTCG rewrites, and optimizer-generated out-of-line helpers.
set_source_files_properties(src/remote_loader.cpp PROPERTIES
    COMPILE_OPTIONS "/Od;/Ob0;/GS-;/guard:cf-;/Gy-;/GL-"
)

target_link_options(cs2-manual-map PRIVATE
    /INCREMENTAL:NO
    /LTCG:OFF
    /OPT:NOICF
    /GUARD:NO
)

set_property(TARGET cs2-manual-map PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(BUILD_TEST_PAYLOAD "Build the benign manual-map smoke-test DLL" ON)
if(BUILD_TEST_PAYLOAD)
    add_library(manual-map-test SHARED examples/test_payload.cpp)
    target_compile_features(manual-map-test PRIVATE cxx_std_20)
    target_compile_definitions(manual-map-test PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    target_compile_options(manual-map-test PRIVATE /W4 /permissive- /utf-8)
    set_property(TARGET manual-map-test PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
