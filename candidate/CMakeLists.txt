# VISS — vissapp exercise.
#
# Builds a static core library, the `vissapp` CLI, and the test binary.
# Only libcrypto is required; cJSON is vendored in tree, exactly as it is
# in viss_gui.

cmake_minimum_required(VERSION 3.16)
project(vissapp LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(OpenSSL REQUIRED)

add_library(vissapp_core STATIC
    src/hashtree.cpp
    src/ecdsa.cpp
    src/pubkey.cpp
    src/token.cpp
    src/keyring.cpp
    src/crypto_util.cpp
    src/json.cpp
    vendors/cjson/cJSON.c
)
target_include_directories(vissapp_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vendors/cjson
)
target_link_libraries(vissapp_core PUBLIC OpenSSL::Crypto)
target_compile_options(vissapp_core PRIVATE -Wall -Wextra)

add_executable(vissapp src/main.cpp)
target_link_libraries(vissapp PRIVATE vissapp_core)
target_compile_options(vissapp PRIVATE -Wall -Wextra)

option(VISS_BUILD_TESTS "Build unit tests (viss-tests + ctest integration)" ON)
if(VISS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
