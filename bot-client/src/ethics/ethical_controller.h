#pragma once

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../../../common/protocol/message.h"
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace ethics {

/**
 * @brief Ethical controller for research compliance and safety
 * 
 * Enforces ethical boundaries, legal compliance, and research safety
 * across all bot operations. Single codebase for all platforms.
 */
class EthicalController {
public:
    enum class ViolationType {
        UNAUTHORIZED_ACCESS,
        GEOGRAPHIC_VIOLATION,
        TIME_RESTRICTION_VIOLATION,
        COMMAND_NOT_APPROVED,
        DATA_EXFILTRATION_ATTEMPT,
        DESTRUCTIVE_OPERATION,
        EXCESSIVE_RESOURCE_USE,
        PERSISTENCE_VIOLATION,
        STEALTH_VIOLATION,
        RESEARCH_BOUNDARY_EXCEEDED
    };

    enum class ComplianceLevel {
        STRICT,         // Maximum restrictions (default for research)
        MODERATE,       // Balanced restrictions
        PERMISSIVE,     // Minimal restrictions (NOT for research)
        CUSTOM         // User-defined restrictions
    };

    struct EthicalConstraints {
        // Geographic restrictions
        std::vector<std::string> allowed_countries;
        std::vector<std::string> blocked_countries;
        bool enforce_geographic_restrictions;
        
        // Time restrictions
        std::chrono::hours max_session_duration;
        std::chrono::hours daily_operation_limit;
        std::vector<std::pair<int, int>> allowed_time_windows; // hour ranges
        bool enforce_time_restrictions;
        
        // Command restrictions
        std::vector<std::string> approved_commands;
        std::vector<std::string> blocked_commands;
        std::map<std::string, nlohmann::json> command_parameters_limits;
        bool require_explicit_approval;
        
        // Resource restrictions
        uint64_t max_memory_usage;
        double max_cpu_usage;
        uint64_t max_network_bandwidth;
        uint32_t max_file_operations_per_hour;
        
        // Research specific
        std::string research_session_id;
        std::string institutional_approval_id;
        std::string principal_investigator;
        std::chrono::system_clock::time_point research_expiry;
        bool require_research_logging;
        
        // Safety mechanisms
        bool enable_emergency_stop;
        bool enable_automatic_cleanup;
        bool enable_compliance_reporting;
        std::chrono::minutes violation_timeout;
    };

    struct ViolationRecord {
        ViolationType type;
        std::string description;
        std::chrono::system_clock::time_point timestamp;
        std::string command_attempted;
        nlohmann::json violation_details;
        std::string corrective_action;
        bool auto_resolved;
        std::string session_id;
    };

    struct ComplianceReport {
        std::chrono::system_clock::time_point generated_at;
        std::string session_id;
        uint32_t total_commands_executed;
        uint32_t violations_detected;
        uint32_t violations_blocked;
        std::vector<ViolationRecord> violations;
        nlohmann::json resource_usage;
        bool overall_compliance;
        std::vector<std::string> recommendations;
    };

public:
    EthicalController();
    ~EthicalController();

    // Initialization and configuration
    bool Initialize(const EthicalConstraints& constraints);
    bool UpdateConstraints(const EthicalConstraints& new_constraints);
    EthicalConstraints GetCurrentConstraints() const;
    
    // Core validation functions
    bool ValidateCommand(const protocol::CommandRequest& command);
    bool ValidateOperation(const std::string& operation_type, const nlohmann::json& parameters);
    bool CheckResourceUsage(uint64_t memory_mb, double cpu_percent, uint64_t network_bytes);
    bool CheckGeographicCompliance();
    bool CheckTimeRestrictions();
    
    // Research session management
    bool StartResearchSession(const std::string& session_id, 
                             const std::string& approval_id,
                             const std::string& principal_investigator);
    bool EndResearchSession();
    bool IsResearchSessionActive() const;
    std::string GetActiveResearchSession() const;
    
    // Violation handling
    void ReportViolation(ViolationType type, const std::string& description, 
                        const nlohmann::json& details = {});
    std::vector<ViolationRecord> GetViolationHistory() const;
    uint32_t GetViolationCount(ViolationType type) const;
    bool HasCriticalViolations() const;
    
    // Emergency procedures
    void TriggerEmergencyStop(const std::string& reason);
    bool IsEmergencyStopTriggered() const;
    std::string GetEmergencyStopReason() const;
    void ResetEmergencyStop();
    
    // Compliance reporting
    ComplianceReport GenerateComplianceReport() const;
    bool ExportComplianceReport(const std::string& file_path) const;
    void ScheduleComplianceReporting(std::chrono::hours interval);
    
    // Configuration presets
    static EthicalConstraints GetStrictResearchConstraints();
    static EthicalConstraints GetEducationalConstraints();
    static EthicalConstraints GetPenetrationTestingConstraints();
    
    // Logging and monitoring
    void EnableComplianceLogging(bool enabled);
    std::vector<std::string> GetComplianceLogs() const;
    void SetViolationCallback(std::function<void(const ViolationRecord&)> callback);

private:
    EthicalConstraints constraints_;
    mutable std::mutex constraints_mutex_;
    
    // Session tracking
    std::string active_research_session_;
    std::chrono::system_clock::time_point session_start_time_;
    std::chrono::system_clock::time_point last_activity_time_;
    
    // Violation tracking
    std::vector<ViolationRecord> violation_history_;
    mutable std::mutex violations_mutex_;
    std::map<ViolationType, uint32_t> violation_counts_;
    
    // Emergency state
    std::atomic<bool> emergency_stop_triggered_;
    std::string emergency_stop_reason_;
    
    // Resource monitoring
    std::chrono::system_clock::time_point last_resource_check_;
    uint64_t cumulative_memory_usage_;
    double average_cpu_usage_;
    uint64_t cumulative_network_usage_;
    uint32_t file_operations_count_;
    std::chrono::system_clock::time_point hour_start_;
    
    // Compliance logging
    bool compliance_logging_enabled_;
    std::vector<std::string> compliance_logs_;
    mutable std::mutex logs_mutex_;
    
    // Callbacks
    std::function<void(const ViolationRecord&)> violation_callback_;
    
    // Validation helpers
    bool ValidateCommandName(const std::string& command_name);
    bool ValidateCommandParameters(const std::string& command_name, const nlohmann::json& parameters);
    bool CheckParameterLimits(const std::string& command_name, const nlohmann::json& parameters);
    
    // Geographic validation
    std::string GetCurrentCountryCode() const;
    bool IsCountryAllowed(const std::string& country_code) const;
    
    // Time validation
    bool IsCurrentTimeAllowed() const;
    bool IsWithinTimeWindow() const;
    bool HasExceededSessionDuration() const;
    bool HasExceededDailyLimit() const;
    
    // Resource validation
    void UpdateResourceUsage(uint64_t memory_mb, double cpu_percent, uint64_t network_bytes);
    bool IsResourceUsageExcessive() const;
    void ResetHourlyCounters();
    
    // Research validation
    bool IsResearchSessionValid() const;
    bool IsResearchSessionExpired() const;
    bool ValidateResearchApproval(const std::string& approval_id) const;
    
    // Logging helpers
    void LogComplianceEvent(const std::string& event_type, const std::string& description);
    void LogViolation(const ViolationRecord& violation);
    
    // Enforcement actions
    void EnforceViolation(const ViolationRecord& violation);
    void ApplyCorrectiveAction(ViolationType type);
    void NotifyViolation(const ViolationRecord& violation);
};

/**
 * @brief Geographic compliance checker
 */
class GeographicCompliance {
public:
    static std::string GetCurrentCountryCode();
    static std::string GetCurrentRegion();
    static bool IsLocationAllowed(const std::string& country_code, 
                                 const std::vector<std::string>& allowed_countries);
    static bool IsLocationBlocked(const std::string& country_code,
                                 const std::vector<std::string>& blocked_countries);
    
    // IP geolocation
    static std::string GetCountryFromIP(const std::string& ip_address);
    static bool ValidateIPLocation(const std::string& ip_address,
                                  const std::vector<std::string>& allowed_countries);

private:
    static std::string GetCountryFromOS();
    static std::string GetCountryFromTimezone();
    static std::string GetCountryFromLocale();
    static std::string GetCountryFromRegistry(); // Windows
    static std::string GetCountryFromSystemFiles(); // Linux/macOS
};

/**
 * @brief Time restriction enforcer
 */
class TimeRestrictionEnforcer {
public:
    struct TimeWindow {
        int start_hour;    // 0-23
        int end_hour;      // 0-23
        bool crosses_midnight;
    };

public:
    static bool IsCurrentTimeAllowed(const std::vector<TimeWindow>& allowed_windows);
    static bool IsWithinTimeWindow(const TimeWindow& window);
    static std::chrono::seconds GetTimeUntilNextAllowedWindow(const std::vector<TimeWindow>& windows);
    
    // Business hours detection
    static bool IsBusinessHours();
    static bool IsWeekend();
    static TimeWindow GetBusinessHoursWindow();
    
    // Session duration tracking
    static bool HasExceededDuration(std::chrono::system_clock::time_point start_time,
                                   std::chrono::hours max_duration);
    static std::chrono::hours GetRemainingSessionTime(std::chrono::system_clock::time_point start_time,
                                                     std::chrono::hours max_duration);

private:
    static std::chrono::system_clock::time_point GetCurrentLocalTime();
    static int GetCurrentHour();
    static bool IsTimeInWindow(int current_hour, const TimeWindow& window);
};

/**
 * @brief Resource usage monitor
 */
class ResourceUsageMonitor {
public:
    struct ResourceMetrics {
        uint64_t memory_usage_mb;
        double cpu_usage_percent;
        uint64_t network_bytes_sent;
        uint64_t network_bytes_received;
        uint32_t file_operations_count;
        std::chrono::system_clock::time_point measurement_time;
    };

public:
    ResourceUsageMonitor();
    ~ResourceUsageMonitor();

    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const;
    
    ResourceMetrics GetCurrentMetrics() const;
    std::vector<ResourceMetrics> GetMetricsHistory() const;
    
    // Threshold checking
    bool IsMemoryUsageExcessive(uint64_t threshold_mb) const;
    bool IsCPUUsageExcessive(double threshold_percent) const;
    bool IsNetworkUsageExcessive(uint64_t threshold_bytes_per_hour) const;
    
    // Alerts
    void SetMemoryThreshold(uint64_t threshold_mb);
    void SetCPUThreshold(double threshold_percent);
    void SetNetworkThreshold(uint64_t threshold_bytes_per_hour);
    void SetThresholdCallback(std::function<void(const std::string&)> callback);

private:
    std::atomic<bool> monitoring_active_;
    std::vector<ResourceMetrics> metrics_history_;
    mutable std::mutex metrics_mutex_;
    
    // Thresholds
    uint64_t memory_threshold_mb_;
    double cpu_threshold_percent_;
    uint64_t network_threshold_bytes_per_hour_;
    
    // Monitoring thread
    std::unique_ptr<std::thread> monitor_thread_;
    std::function<void(const std::string&)> threshold_callback_;
    
    void MonitoringLoop();
    ResourceMetrics CollectCurrentMetrics() const;
    void CheckThresholds(const ResourceMetrics& metrics);
    
    // Platform-specific resource collection
    ResourceMetrics CollectWindowsMetrics() const;
    ResourceMetrics CollectLinuxMetrics() const;
    ResourceMetrics CollectMacOSMetrics() const;
};

/**
 * @brief Research compliance validator
 */
class ResearchComplianceValidator {
public:
    struct ResearchSession {
        std::string session_id;
        std::string approval_id;
        std::string principal_investigator;
        std::string institution;
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point expiry_time;
        std::vector<std::string> approved_operations;
        bool active;
    };

public:
    static bool ValidateResearchSession(const ResearchSession& session);
    static bool IsOperationApproved(const std::string& operation, const ResearchSession& session);
    static bool IsSessionExpired(const ResearchSession& session);
    static bool ValidateInstitutionalApproval(const std::string& approval_id);
    
    // IRB (Institutional Review Board) validation
    static bool ValidateIRBApproval(const std::string& irb_number);
    static std::vector<std::string> GetRequiredEthicalDocuments();
    static bool CheckEthicalCompliance(const ResearchSession& session);

private:
    static bool ValidateSessionID(const std::string& session_id);
    static bool ValidateApprovalID(const std::string& approval_id);
    static bool ValidatePrincipalInvestigator(const std::string& pi_name);
    static std::vector<std::string> GetApprovedInstitutions();
};

/**
 * @brief Emergency stop controller
 */
class EmergencyStopController {
public:
    enum class StopReason {
        ETHICAL_VIOLATION,
        LEGAL_VIOLATION,
        SECURITY_BREACH,
        RESOURCE_EXHAUSTION,
        USER_REQUEST,
        SYSTEM_ERROR,
        RESEARCH_ENDED,
        EXTERNAL_COMMAND
    };

public:
    EmergencyStopController();
    ~EmergencyStopController();

    void TriggerEmergencyStop(StopReason reason, const std::string& details);
    bool IsEmergencyStopActive() const;
    StopReason GetStopReason() const;
    std::string GetStopDetails() const;
    std::chrono::system_clock::time_point GetStopTime() const;
    
    void ResetEmergencyStop();
    void SetStopCallback(std::function<void(StopReason, const std::string&)> callback);
    
    // Automatic triggers
    void SetupAutomaticTriggers();
    void CheckViolationThresholds(uint32_t violation_count);
    void CheckResourceExhaustion(const ResourceUsageMonitor::ResourceMetrics& metrics);

private:
    std::atomic<bool> emergency_stop_active_;
    StopReason stop_reason_;
    std::string stop_details_;
    std::chrono::system_clock::time_point stop_time_;
    std::function<void(StopReason, const std::string&)> stop_callback_;
    
    mutable std::mutex stop_mutex_;
    
    void ExecuteEmergencyStop();
    void NotifyEmergencyStop();
    void LogEmergencyStop();
    
    std::string StopReasonToString(StopReason reason) const;
};

/**
 * @brief Compliance reporter for audit and documentation
 */
class ComplianceReporter {
public:
    ComplianceReporter();
    ~ComplianceReporter();

    bool GenerateReport(const EthicalController::ComplianceReport& report,
                       const std::string& output_path);
    bool GenerateJSONReport(const EthicalController::ComplianceReport& report,
                           const std::string& output_path);
    bool GenerateXMLReport(const EthicalController::ComplianceReport& report,
                          const std::string& output_path);
    bool GenerateHTMLReport(const EthicalController::ComplianceReport& report,
                           const std::string& output_path);
    
    // Real-time reporting
    void EnableRealTimeReporting(bool enabled);
    void SetReportingInterval(std::chrono::minutes interval);
    void SetReportingEndpoint(const std::string& endpoint);
    
    // Report archival
    void ArchiveReport(const std::string& report_path);
    std::vector<std::string> GetArchivedReports() const;

private:
    bool real_time_reporting_enabled_;
    std::chrono::minutes reporting_interval_;
    std::string reporting_endpoint_;
    
    std::string GenerateReportContent(const EthicalController::ComplianceReport& report);
    nlohmann::json SerializeReport(const EthicalController::ComplianceReport& report);
    
    void SendRealTimeReport(const EthicalController::ComplianceReport& report);
    bool ValidateReportPath(const std::string& path);
};

} // namespace ethics
} // namespace client
} // namespace botnet
