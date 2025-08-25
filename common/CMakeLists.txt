cmake_minimum_required(VERSION 3.16)
project(CommonLibrary VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# Common library source files
set(COMMON_SOURCES
    crypto/encryption.cpp
    crypto/key_manager.cpp
    crypto/hash_utils.cpp
    protocol/message.cpp
    protocol/packet_handler.cpp
    protocol/command_parser.cpp
    utils/string_utils.cpp
    utils/time_utils.cpp
    utils/network_utils.cpp
    utils/base64.cpp
    utils/json_utils.cpp
)

# Create common library
add_library(common-library STATIC ${COMMON_SOURCES})

# Include directories
target_include_directories(common-library
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(common-library
    PUBLIC
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Compiler definitions
target_compile_definitions(common-library
    PUBLIC
    COMMON_LIB_VERSION="${PROJECT_VERSION}"
    PRIVATE
    $<$<CONFIG:Debug>:DEBUG_BUILD>
)

# Export the library for use in other projects
set_target_properties(common-library PROPERTIES
    PUBLIC_HEADER "crypto/encryption.h;crypto/key_manager.h;protocol/message.h;utils/string_utils.h"
)
