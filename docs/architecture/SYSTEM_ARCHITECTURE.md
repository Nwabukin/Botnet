# System Architecture Design
## Dockerized C++ Botnet Implementation for Educational Research

**Version**: 1.0  
**Date**: January 2025  
**Purpose**: Educational cybersecurity research with ethical controls

---

## 🏗️ Architecture Overview

This system implements a **hybrid architecture** that combines:
- **Containerized C2 Infrastructure**: Centralized, scalable, and easily managed
- **Standalone Bot Clients**: Cross-platform executables deployable to any machine

The architecture ensures **maximum flexibility** while maintaining **ethical research controls** and **operational security**.

## 🎯 Core Design Principles

### 1. **Separation of Concerns**
- **C2 Infrastructure**: Containerized for easy deployment, scaling, and management
- **Bot Clients**: Standalone executables for maximum portability and realistic deployment
- **Communication Layer**: Encrypted, authenticated, and obfuscated channels

### 2. **Cross-Platform Compatibility**
- **Windows**: Native executables with Windows-specific features (Registry, Services)
- **Linux**: Static binaries with systemd integration and POSIX compliance
- **macOS**: Native binaries with macOS-specific persistence mechanisms

### 3. **Security-First Design**
- **End-to-end encryption** for all communications
- **Multi-layer authentication** with certificate pinning
- **Traffic obfuscation** to evade detection
- **Built-in kill switches** for research safety

### 4. **Ethical Research Framework**
- **Research mode controls** limiting capabilities
- **Comprehensive logging** for analysis and audit
- **Geographic restrictions** preventing unauthorized use
- **Automatic cleanup** mechanisms

---

## 🔧 Component Architecture

### A. **C2 Server Infrastructure (Dockerized)**

#### **Core Services Layer**

**1. C2 Command Server**
```cpp
// Technology: C++ with Boost.Asio
// Responsibilities:
- Bot registration and authentication
- Command dispatch and response handling  
- Session management and heartbeat monitoring
- Encryption key management and rotation
- Research controls and safety mechanisms
```

**2. Web Dashboard**
```typescript
// Technology: React/TypeScript with Material-UI
// Features:
- Real-time bot monitoring and statistics
- Command execution interface
- Research data visualization
- Security event dashboards
- Ethical compliance monitoring
```

**3. REST API Gateway**
```cpp
// Technology: C++ with HTTP/HTTPS support
// Endpoints:
- /api/v1/bots         # Bot management
- /api/v1/commands     # Command execution
- /api/v1/research     # Research data
- /api/v1/monitoring   # System health
- /api/v1/emergency    # Emergency controls
```

**4. WebSocket Gateway**
```cpp
// Technology: WebSocket++ with Boost.Asio
// Capabilities:
- Real-time bot communication
- Live dashboard updates
- Research event streaming
- Emergency broadcasting
```

#### **Data Layer**

**PostgreSQL Database Schema**
```sql
-- Core tables for bot management
bots (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE,
    platform VARCHAR(50),
    ip_address INET,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    status VARCHAR(50),
    research_session_id UUID
);

-- Command tracking
commands (
    id UUID PRIMARY KEY,
    bot_id UUID REFERENCES bots(id),
    command_type VARCHAR(100),
    payload TEXT,
    executed_at TIMESTAMP,
    response TEXT,
    research_approved BOOLEAN
);

-- Research session management
research_sessions (
    id UUID PRIMARY KEY,
    researcher_id VARCHAR(255),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    ethical_approval_id VARCHAR(255),
    purpose TEXT
);
```

**Redis Caching Strategy**
```
# Session management
session:{bot_id} -> bot_session_data
session:{user_id} -> user_session_data

# Real-time metrics
metrics:bots:count -> current_bot_count
metrics:commands:rate -> commands_per_minute

# Configuration cache
config:encryption_keys -> current_key_set
config:research_limits -> ethical_constraints
```

#### **Monitoring and Logging**

**Prometheus Metrics**
```yaml
# System metrics
- botnet_bots_total
- botnet_commands_executed_total
- botnet_research_sessions_active
- botnet_network_bytes_transferred
- botnet_errors_total

# Security metrics
- botnet_authentication_failures
- botnet_encryption_key_rotations
- botnet_emergency_stops_triggered
```

**ELK Stack Configuration**
```yaml
# Elasticsearch indices
- botnet-commands-{YYYY.MM.DD}
- botnet-network-{YYYY.MM.DD}
- botnet-research-{YYYY.MM.DD}
- botnet-security-{YYYY.MM.DD}

# Kibana dashboards
- Research Activity Dashboard
- Security Events Dashboard
- Network Traffic Analysis
- Ethical Compliance Monitor
```

### B. **Bot Client Architecture (Standalone)**

#### **Core Bot Structure**

```cpp
class BotClient {
private:
    // Core components
    std::unique_ptr<CommunicationManager> comm_manager_;
    std::unique_ptr<PersistenceManager> persistence_manager_;
    std::unique_ptr<StealthManager> stealth_manager_;
    std::unique_ptr<ModuleManager> module_manager_;
    std::unique_ptr<ConfigManager> config_manager_;
    
    // Research controls
    std::unique_ptr<EthicalController> ethical_controller_;
    std::unique_ptr<SafetyMonitor> safety_monitor_;
    
public:
    // Lifecycle management
    bool Initialize(const Config& config);
    void Run();
    void Shutdown();
    
    // Research specific
    void EnableResearchMode();
    void SetResearchLimits(const ResearchLimits& limits);
    void EmergencyStop();
};
```

#### **Communication Manager**

```cpp
class CommunicationManager {
private:
    // Multiple communication channels
    std::unique_ptr<HTTPSClient> https_client_;
    std::unique_ptr<DNSTunnelClient> dns_client_;
    std::unique_ptr<WebSocketClient> websocket_client_;
    
    // Security components
    std::unique_ptr<EncryptionHandler> encryption_;
    std::unique_ptr<AuthenticationHandler> auth_;
    
public:
    // Primary communication
    bool RegisterWithC2();
    bool SendHeartbeat();
    CommandResponse ExecuteCommand(const Command& cmd);
    
    // Fallback mechanisms
    bool TryFallbackChannel();
    void UpdateC2Endpoints(const std::vector<Endpoint>& endpoints);
    
    // Research controls
    void SetResearchMode(bool enabled);
    void LogCommunication(const CommEvent& event);
};
```

#### **Platform-Specific Modules**

**Windows Implementation**
```cpp
class WindowsPersistenceManager : public PersistenceManager {
public:
    // Registry persistence
    bool AddRegistryStartup();
    bool CreateScheduledTask();
    
    // Service installation
    bool InstallAsService();
    bool StartService();
    
    // Research controls
    bool CreateResearchMarkers();
    void SetTestingMode(bool enabled);
};

class WindowsStealthManager : public StealthManager {
public:
    // Process hiding
    bool HideFromTaskManager();
    bool InjectIntoExplorer();
    
    // Anti-analysis
    bool DetectVirtualMachine();
    bool DetectDebugger();
    
    // Research safety
    void DisableHidingInResearchMode();
    void LogStealthAttempts();
};
```

**Linux Implementation**
```cpp
class LinuxPersistenceManager : public PersistenceManager {
public:
    // Systemd integration
    bool CreateSystemdService();
    bool EnableSystemdService();
    
    // Cron persistence
    bool AddCronJob();
    
    // Init system detection
    bool DetectInitSystem();
    
    // Research controls
    bool CreateResearchIdentifiers();
};

class LinuxStealthManager : public StealthManager {
public:
    // Process hiding
    bool HideFromPS();
    bool ModifyProcFS();
    
    // Network hiding
    bool HideNetworkConnections();
    
    // Research safety
    void PreserveProcEntries();
    void LogSystemModifications();
};
```

---

## 🔐 Security Architecture

### **Encryption and Authentication**

#### **Multi-Layer Encryption**
```
Application Layer: AES-256-GCM (Data encryption)
     ↓
Transport Layer: TLS 1.3 (Channel encryption)
     ↓
Network Layer: Optional VPN/Proxy (Traffic routing)
```

#### **Authentication Flow**
```
1. Bot generates RSA-4096 key pair
2. Bot sends public key + system fingerprint to C2
3. C2 validates and issues signed certificate
4. All future communications use certificate + session keys
5. Regular key rotation every 24 hours (configurable)
```

#### **Certificate Pinning**
```cpp
class CertificatePinning {
private:
    std::vector<std::string> pinned_certificates_;
    std::string expected_ca_fingerprint_;
    
public:
    bool ValidateCertificate(const X509Certificate& cert);
    void UpdatePinnedCertificates(const std::vector<std::string>& new_pins);
    bool PerformEmergencyValidation();
};
```

### **Traffic Obfuscation**

#### **Domain Generation Algorithm (DGA)**
```cpp
class DomainGenerator {
private:
    uint32_t seed_;
    std::string tld_list_[10] = {".com", ".net", ".org", /*...*/};
    
public:
    std::vector<std::string> GenerateDomains(uint32_t date_seed, int count);
    bool ValidateDomainSeed(const std::string& domain, uint32_t expected_seed);
    void UpdateSeedAlgorithm(const AlgorithmParams& params);
};
```

#### **HTTP Traffic Mimicking**
```cpp
class TrafficObfuscator {
public:
    // Make C2 traffic look like normal web browsing
    std::string CreateFakeUserAgent();
    std::map<std::string, std::string> CreateFakeHeaders();
    std::string EncodePayloadAsForm();
    std::string EncodePayloadAsJSON();
    
    // Research mode: clearly mark traffic as research
    void EnableResearchMarking();
    void AddResearchHeaders();
};
```

### **Research Safety Controls**

#### **Ethical Controller**
```cpp
class EthicalController {
private:
    ResearchLimits limits_;
    GeographicRestrictions geo_restrictions_;
    std::chrono::steady_clock::time_point session_start_;
    
public:
    bool ValidateCommand(const Command& cmd);
    bool CheckGeographicCompliance();
    bool CheckTimeRestrictions();
    void TriggerEmergencyStop(const std::string& reason);
    
    // Built-in restrictions
    bool IsDestructiveCommand(const Command& cmd);
    bool IsDataExfiltrationAllowed();
    bool IsNetworkAttackPermitted();
};
```

---

## 🌐 Communication Protocols

### **Primary Protocol: HTTPS/TLS**

#### **Command Structure**
```json
{
  "version": "1.0",
  "timestamp": "2025-01-25T15:30:00Z",
  "bot_id": "bot_12345678-1234-1234-1234-123456789abc",
  "session_id": "session_87654321-4321-4321-4321-210987654321",
  "encrypted_payload": "base64_encrypted_data",
  "signature": "rsa_signature_of_payload",
  "research_session": "research_12345",
  "compliance_token": "ethical_approval_token"
}
```

#### **Response Structure**
```json
{
  "version": "1.0",
  "timestamp": "2025-01-25T15:30:05Z",
  "response_to": "command_id_12345",
  "status": "success|error|pending",
  "encrypted_result": "base64_encrypted_response",
  "signature": "rsa_signature_of_result",
  "next_checkin": "2025-01-25T15:35:00Z",
  "emergency_stop": false
}
```

### **Fallback Protocol: DNS Tunneling**

#### **DNS Query Encoding**
```
# Command request
cmd.[base32_encoded_command].[domain_suffix]

# Data exfiltration (research mode only)
data.[chunk_id].[base32_encoded_data].[domain_suffix]

# Heartbeat
hb.[bot_id_hash].[timestamp].[domain_suffix]
```

#### **DNS Response Encoding**
```
# TXT record response
"v=1;cmd=base64_command;sig=signature;next=300"

# A record response (IP encoding)
192.168.[command_id].[response_code]
```

### **Real-time Protocol: WebSocket**

#### **WebSocket Message Format**
```json
{
  "type": "command|response|heartbeat|emergency",
  "payload": {
    "encrypted_data": "base64_data",
    "metadata": {
      "priority": "high|medium|low",
      "requires_response": true,
      "research_approved": true
    }
  }
}
```

---

## 🐳 Docker Container Architecture

### **Container Layout**

```yaml
# docker-compose.yml structure
services:
  # Core C2 services
  c2-server:          # Main C++ C2 server
  web-dashboard:      # React frontend
  api-gateway:        # HTTP/HTTPS API
  websocket-gateway:  # WebSocket handling
  
  # Data layer
  postgres:           # Primary database
  redis:             # Caching and sessions
  
  # Monitoring
  prometheus:         # Metrics collection
  grafana:           # Visualization
  elasticsearch:      # Log storage
  kibana:            # Log analysis
  
  # Security
  vault:             # Secrets management (optional)
  nginx:             # Reverse proxy and load balancer
```

### **Network Architecture**

```yaml
networks:
  # Internal network for C2 services
  c2-internal:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.0.0/24
  
  # External network for bot communication
  c2-external:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
  
  # Monitoring network
  monitoring:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

### **Volume Management**

```yaml
volumes:
  # Persistent data
  postgres_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/botnet-research/data/postgres
  
  # Configuration and secrets
  config_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/botnet-research/config
  
  # Research logs (for analysis)
  research_logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/botnet-research/logs
  
  # SSL certificates
  ssl_certs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/botnet-research/certs
```

---

## 📊 Deployment Architecture

### **Development Environment**
```
Developer Machine
├── Docker Desktop
├── Visual Studio Code / CLion
├── Git repository
└── Local testing environment
    ├── Isolated VM network
    ├── Test bot clients
    └── C2 infrastructure (containerized)
```

### **Research Environment**
```
Isolated Research Network
├── C2 Infrastructure Server
│   ├── Docker containers
│   ├── Monitoring stack
│   └── Research data storage
├── Test Target Machines
│   ├── Windows VM (bot client)
│   ├── Linux VM (bot client)
│   └── macOS VM (bot client)
└── Analysis Workstation
    ├── Traffic analysis tools
    ├── Malware analysis sandbox
    └── Research documentation
```

### **Cross-Platform Deployment**

#### **Bot Client Distribution**
```
Release Packages/
├── Windows/
│   ├── botnet-client-windows-x64-v1.0.0.zip
│   ├── botnet-client-windows-x64-v1.0.0.msi
│   └── checksums.sha256
├── Linux/
│   ├── botnet-client-linux-x64-v1.0.0.tar.gz
│   ├── botnet-client-linux-x64-v1.0.0.deb
│   └── checksums.sha256
└── macOS/
    ├── botnet-client-macos-x64-v1.0.0.tar.gz
    ├── botnet-client-macos-x64-v1.0.0.dmg
    └── checksums.sha256
```

---

## ⚡ Performance and Scalability

### **Horizontal Scaling**
- **C2 Server**: Multiple instances behind load balancer
- **Database**: PostgreSQL with read replicas
- **Caching**: Redis cluster for session management
- **Bot Capacity**: Designed for 10,000+ concurrent bots

### **Resource Requirements**

#### **Minimum C2 Infrastructure**
```
- CPU: 4 cores
- RAM: 8 GB
- Storage: 100 GB SSD
- Network: 100 Mbps
```

#### **Recommended C2 Infrastructure**
```
- CPU: 8 cores
- RAM: 16 GB
- Storage: 500 GB SSD
- Network: 1 Gbps
```

#### **Bot Client Footprint**
```
- Windows: ~2 MB executable, ~10 MB RAM
- Linux: ~1.5 MB executable, ~8 MB RAM  
- macOS: ~2.5 MB executable, ~12 MB RAM
```

---

## 🛡️ Security Considerations

### **Attack Surface Minimization**
1. **Container isolation** prevents lateral movement
2. **Network segmentation** limits blast radius
3. **Principle of least privilege** for all components
4. **Regular security updates** and patching

### **Research Safety Mechanisms**
1. **Geographic fencing** prevents global deployment
2. **Time-based restrictions** limit research sessions
3. **Command validation** prevents destructive actions
4. **Emergency stop** mechanisms at multiple layers

### **Monitoring and Alerting**
1. **Real-time security monitoring** of all components
2. **Anomaly detection** for unusual bot behavior
3. **Compliance monitoring** for ethical violations
4. **Incident response** procedures for breaches

---

## 📋 Compliance and Ethics

### **Built-in Compliance Features**
- **Research session tracking** with approval workflows
- **Audit logging** of all commands and responses
- **Data retention policies** with automatic cleanup
- **Geographic restrictions** preventing unauthorized deployment

### **Ethical Safeguards**
- **Researcher authentication** and authorization
- **Command approval** workflows for sensitive operations
- **Victim protection** mechanisms preventing real harm
- **Transparency reporting** for research oversight

---

This architecture provides a **robust, scalable, and ethically-controlled platform** for cybersecurity research while ensuring that bot clients can be **deployed as standalone executables** to any machine, exactly as requested. The design balances research needs with ethical responsibilities and technical excellence.
