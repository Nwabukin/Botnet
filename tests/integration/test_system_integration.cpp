#include "../unit/test_framework.h"
#include "../../c2-server/src/c2_server.h"
#include "../../bot-client/src/bot_client.h"
#include "../../common/crypto/encryption.h"
#include <thread>
#include <chrono>

using namespace botnet::testing;
using namespace std::chrono_literals;

/**
 * @brief Comprehensive system integration tests
 * 
 * Tests the complete botnet system including C2 server, bot clients,
 * database integration, monitoring, and research compliance.
 */
class SystemIntegrationTest : public BotnetTestBase {
protected:
    void SetUp() override {
        BotnetTestBase::SetUp();
        
        // Enable research mode for all integration tests
        EnableResearchMode("integration_test_session");
        
        // Setup test environment
        SetupTestInfrastructure();
        
        // Start test services
        StartTestServices();
        
        // Wait for services to be ready
        WaitForServicesReady();
    }
    
    void TearDown() override {
        // Stop test services
        StopTestServices();
        
        // Cleanup test data
        CleanupTestData();
        
        BotnetTestBase::TearDown();
    }
    
    void SetupTestInfrastructure() {
        // Create test directories
        std::filesystem::create_directories("test_data");
        std::filesystem::create_directories("test_logs");
        std::filesystem::create_directories("test_certs");
        
        // Generate test SSL certificates
        GenerateTestCertificates();
        
        // Setup test database
        SetupTestDatabase();
        
        // Configure test environment
        ConfigureTestEnvironment();
    }
    
    void StartTestServices() {
        // Start test C2 server
        c2_server_ = std::make_unique<C2Server>();
        auto c2_config = GenerateC2Config();
        ASSERT_TRUE(c2_server_->Initialize(c2_config));
        ASSERT_TRUE(c2_server_->Start());
        
        // Start test database
        database_manager_ = std::make_unique<DatabaseManager>();
        ASSERT_TRUE(database_manager_->Connect(test_database_url_));
        
        // Start monitoring services
        StartMonitoringServices();
    }
    
    void WaitForServicesReady() {
        // Wait for C2 server to be ready
        for (int i = 0; i < 30; ++i) {
            if (TestC2ServerHealth()) {
                break;
            }
            std::this_thread::sleep_for(1s);
            if (i == 29) {
                FAIL() << "C2 server failed to start within timeout";
            }
        }
        
        // Wait for database to be ready
        for (int i = 0; i < 10; ++i) {
            if (TestDatabaseHealth()) {
                break;
            }
            std::this_thread::sleep_for(1s);
            if (i == 9) {
                FAIL() << "Database failed to start within timeout";
            }
        }
    }
    
private:
    std::unique_ptr<C2Server> c2_server_;
    std::unique_ptr<DatabaseManager> database_manager_;
    std::string test_database_url_ = "postgresql://test:test@localhost:5433/test_botnet";
    std::string c2_server_url_ = "https://localhost:8444";
};

/**
 * @brief Test complete bot registration and communication workflow
 */
TEST_F(SystemIntegrationTest, BotRegistrationAndCommunicationWorkflow) {
    // Create test bot client
    auto bot_client = std::make_unique<BotClient>();
    auto bot_config = GenerateTestBotConfig();
    
    // Test bot initialization
    ASSERT_TRUE(bot_client->Initialize(bot_config));
    
    // Test bot connection to C2
    EXPECT_PERFORMANCE_WITHIN(
        ASSERT_TRUE(bot_client->ConnectToC2(c2_server_url_)),
        5000  // 5 seconds max
    );
    
    // Verify bot is registered in database
    std::this_thread::sleep_for(2s);  // Allow registration to complete
    auto registered_bots = database_manager_->GetRegisteredBots();
    EXPECT_GT(registered_bots.size(), 0);
    
    // Test heartbeat mechanism
    ASSERT_TRUE(bot_client->SendHeartbeat());
    
    // Verify heartbeat is recorded
    std::this_thread::sleep_for(1s);
    auto bot_status = database_manager_->GetBotStatus(bot_client->GetBotId());
    EXPECT_TRUE(bot_status["online"].get<bool>());
    
    // Test command execution workflow
    nlohmann::json test_command = {
        {"type", "system_info"},
        {"research_mode", true},
        {"compliance_required", true}
    };
    
    ASSERT_TRUE(c2_server_->SendCommandToBot(bot_client->GetBotId(), test_command));
    
    // Wait for command execution
    std::this_thread::sleep_for(3s);
    
    // Verify command was executed and results received
    auto command_results = database_manager_->GetCommandResults(bot_client->GetBotId());
    EXPECT_GT(command_results.size(), 0);
    EXPECT_EQ(command_results[0]["type"].get<std::string>(), "system_info");
    
    // Test research compliance logging
    auto compliance_logs = database_manager_->GetComplianceLogs(test_session_id_);
    EXPECT_GT(compliance_logs.size(), 0);
    
    // Cleanup
    bot_client->Disconnect();
    EXPECT_RESEARCH_COMPLIANT(bot_client->GetOperationLogs());
}

/**
 * @brief Test encrypted communication security
 */
TEST_F(SystemIntegrationTest, EncryptedCommunicationSecurity) {
    // Create bot with encryption enabled
    auto bot_client = std::make_unique<BotClient>();
    auto bot_config = GenerateTestBotConfig();
    bot_config["encryption"]["enabled"] = true;
    bot_config["encryption"]["algorithm"] = "AES-256-GCM";
    
    ASSERT_TRUE(bot_client->Initialize(bot_config));
    ASSERT_TRUE(bot_client->ConnectToC2(c2_server_url_));
    
    // Test encrypted command transmission
    nlohmann::json encrypted_command = {
        {"type", "encrypted_test"},
        {"data", "sensitive_test_data_12345"},
        {"encryption_required", true}
    };
    
    // Send command and capture network traffic
    auto traffic_capture = StartTrafficCapture();
    ASSERT_TRUE(c2_server_->SendCommandToBot(bot_client->GetBotId(), encrypted_command));
    std::this_thread::sleep_for(2s);
    auto captured_traffic = StopTrafficCapture();
    
    // Verify traffic is encrypted
    EXPECT_TRUE(SecurityTestUtils::ValidateTrafficEncryption(captured_traffic));
    
    // Verify no plaintext sensitive data in traffic
    for (const auto& packet : captured_traffic) {
        EXPECT_EQ(packet.find("sensitive_test_data_12345"), std::string::npos)
            << "Sensitive data found in plaintext in network traffic";
    }
    
    // Test SSL/TLS configuration
    EXPECT_TRUE(SecurityTestUtils::ValidateSSLConfiguration(
        "test_certs/server.crt", 
        "test_certs/server.key"
    ));
    
    // Test key rotation
    ASSERT_TRUE(c2_server_->RotateEncryptionKeys());
    
    // Verify communication still works after key rotation
    ASSERT_TRUE(bot_client->SendHeartbeat());
    
    bot_client->Disconnect();
}

/**
 * @brief Test database integration and data persistence
 */
TEST_F(SystemIntegrationTest, DatabaseIntegrationAndPersistence) {
    // Test database schema validation
    EXPECT_TRUE(database_manager_->ValidateSchema());
    
    // Test bot data persistence
    auto bot_data = TestDataGenerator::GenerateBotInfo();
    ASSERT_TRUE(database_manager_->StoreBotInfo(bot_data));
    
    // Verify data retrieval
    auto retrieved_data = database_manager_->GetBotInfo(bot_data["bot_id"].get<std::string>());
    EXPECT_EQ(retrieved_data["bot_id"], bot_data["bot_id"]);
    EXPECT_EQ(retrieved_data["hostname"], bot_data["hostname"]);
    
    // Test command history persistence
    auto command_data = TestDataGenerator::GenerateBotCommands(5);
    for (const auto& command : command_data) {
        ASSERT_TRUE(database_manager_->StoreCommand(command));
    }
    
    // Verify command retrieval
    auto stored_commands = database_manager_->GetCommandHistory(
        bot_data["bot_id"].get<std::string>()
    );
    EXPECT_EQ(stored_commands.size(), 5);
    
    // Test audit trail persistence
    auto audit_events = TestDataGenerator::GenerateComplianceEvents();
    for (const auto& event : audit_events) {
        ASSERT_TRUE(database_manager_->LogAuditEvent(event, test_session_id_));
    }
    
    // Verify audit trail integrity
    auto audit_trail = database_manager_->GetAuditTrail(test_session_id_);
    EXPECT_EQ(audit_trail.size(), audit_events.size());
    
    // Test data anonymization for research compliance
    auto anonymized_data = database_manager_->GetAnonymizedBotData();
    for (const auto& bot : anonymized_data) {
        EXPECT_TRUE(ComplianceTestUtils::ValidateDataAnonymization(bot));
    }
    
    // Test database backup and restore
    ASSERT_TRUE(database_manager_->CreateBackup("test_backup.sql"));
    ASSERT_TRUE(database_manager_->RestoreFromBackup("test_backup.sql"));
    
    // Verify data integrity after restore
    auto restored_data = database_manager_->GetBotInfo(bot_data["bot_id"].get<std::string>());
    EXPECT_EQ(restored_data["bot_id"], bot_data["bot_id"]);
}

/**
 * @brief Test monitoring and alerting integration
 */
TEST_F(SystemIntegrationTest, MonitoringAndAlertingIntegration) {
    // Test Prometheus metrics integration
    EXPECT_TRUE(IntegrationTestUtils::TestPrometheusIntegration());
    
    // Generate test metrics
    c2_server_->IncrementMetric("bots_connected", 1);
    c2_server_->RecordMetric("response_time_ms", 150.5);
    c2_server_->SetMetric("memory_usage_mb", 256.7);
    
    // Verify metrics are exposed
    auto metrics_response = GetPrometheusMetrics();
    EXPECT_NE(metrics_response.find("bots_connected"), std::string::npos);
    EXPECT_NE(metrics_response.find("response_time_ms"), std::string::npos);
    EXPECT_NE(metrics_response.find("memory_usage_mb"), std::string::npos);
    
    // Test Grafana integration
    EXPECT_TRUE(IntegrationTestUtils::TestGrafanaIntegration());
    
    // Test ELK stack integration
    EXPECT_TRUE(IntegrationTestUtils::TestElasticsearchIntegration());
    EXPECT_TRUE(IntegrationTestUtils::TestLogstashIntegration());
    
    // Generate test logs
    for (int i = 0; i < 10; ++i) {
        c2_server_->LogEvent({
            {"level", "info"},
            {"message", "Test log message " + std::to_string(i)},
            {"research_session", test_session_id_},
            {"timestamp", std::chrono::system_clock::now()}
        });
    }
    
    // Wait for log processing
    std::this_thread::sleep_for(5s);
    
    // Verify logs in Elasticsearch
    auto elasticsearch_logs = QueryElasticsearchLogs(test_session_id_);
    EXPECT_GE(elasticsearch_logs.size(), 10);
    
    // Test alerting mechanism
    // Trigger a test alert condition
    c2_server_->SetMetric("bot_connection_errors", 15);  // Above threshold
    
    // Wait for alert processing
    std::this_thread::sleep_for(3s);
    
    // Verify alert was generated
    auto alerts = GetActiveAlerts();
    bool found_bot_connection_alert = false;
    for (const auto& alert : alerts) {
        if (alert.find("bot_connection_errors") != std::string::npos) {
            found_bot_connection_alert = true;
            break;
        }
    }
    EXPECT_TRUE(found_bot_connection_alert) << "Expected bot connection error alert not found";
}

/**
 * @brief Test research compliance and ethical controls
 */
TEST_F(SystemIntegrationTest, ResearchComplianceAndEthicalControls) {
    // Test research mode enforcement
    EXPECT_TRUE(IsResearchModeEnabled());
    
    // Validate compliance configuration
    auto compliance_report = ComplianceTestUtils::ValidateResearchCompliance(test_session_id_);
    EXPECT_TRUE(compliance_report.ethical_controls_active);
    EXPECT_TRUE(compliance_report.logging_comprehensive);
    EXPECT_TRUE(compliance_report.emergency_controls_functional);
    
    // Test ethical boundary enforcement
    nlohmann::json restricted_operation = {
        {"type", "data_destruction"},
        {"target", "all_files"},
        {"research_mode", false}  // Not in research mode
    };
    
    EXPECT_FALSE(ComplianceTestUtils::TestEthicalBoundaries(restricted_operation.dump()));
    
    // Test approved research operation
    nlohmann::json approved_operation = {
        {"type", "system_info"},
        {"purpose", "security_research"},
        {"research_session", test_session_id_},
        {"ethical_approval", true}
    };
    
    EXPECT_TRUE(ComplianceTestUtils::TestEthicalBoundaries(approved_operation.dump()));
    
    // Test emergency stop mechanism
    EXPECT_TRUE(ComplianceTestUtils::TestEmergencyStopMechanism());
    
    // Trigger emergency stop
    c2_server_->TriggerEmergencyStop("compliance_test");
    
    // Verify all operations are halted
    std::this_thread::sleep_for(2s);
    EXPECT_FALSE(c2_server_->IsAcceptingCommands());
    
    // Test audit trail validation
    EXPECT_TRUE(ComplianceTestUtils::ValidateAuditTrail(test_session_id_));
    
    // Test data retention policies
    EXPECT_TRUE(ComplianceTestUtils::TestDataRetentionPolicies());
    
    // Test consent mechanisms
    EXPECT_TRUE(ComplianceTestUtils::TestConsentMechanisms());
    
    // Test data protection compliance (GDPR-like)
    EXPECT_TRUE(ComplianceTestUtils::ValidateDataProtectionCompliance());
}

/**
 * @brief Test system performance under load
 */
TEST_F(SystemIntegrationTest, SystemPerformanceUnderLoad) {
    // Test concurrent bot connections
    const size_t num_bots = 50;
    std::vector<std::unique_ptr<BotClient>> bot_clients;
    
    // Create multiple bot clients
    for (size_t i = 0; i < num_bots; ++i) {
        auto bot = std::make_unique<BotClient>();
        auto config = GenerateTestBotConfig();
        config["bot_id"] = "test_bot_" + std::to_string(i);
        
        ASSERT_TRUE(bot->Initialize(config));
        bot_clients.push_back(std::move(bot));
    }
    
    // Test concurrent connections
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::thread> connection_threads;
    for (auto& bot : bot_clients) {
        connection_threads.emplace_back([&bot, this]() {
            EXPECT_TRUE(bot->ConnectToC2(c2_server_url_));
        });
    }
    
    // Wait for all connections
    for (auto& thread : connection_threads) {
        thread.join();
    }
    
    auto connection_time = std::chrono::high_resolution_clock::now() - start_time;
    auto connection_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(connection_time);
    
    // Verify connection performance
    EXPECT_LT(connection_duration_ms.count(), 30000)  // 30 seconds max
        << "Bot connections took too long: " << connection_duration_ms.count() << "ms";
    
    // Test system metrics under load
    auto performance_metrics = PerformanceTestUtils::TestLoadCapacity(num_bots);
    EXPECT_TRUE(performance_metrics.meets_requirements);
    EXPECT_LT(performance_metrics.response_time.count(), 1000);  // < 1 second response time
    EXPECT_LT(performance_metrics.memory_usage_mb, 2048);       // < 2GB memory usage
    EXPECT_LT(performance_metrics.cpu_usage_percent, 80.0);    // < 80% CPU usage
    
    // Test concurrent command execution
    nlohmann::json load_test_command = {
        {"type", "load_test"},
        {"message", "Performance test command"},
        {"timestamp", std::chrono::system_clock::now()}
    };
    
    start_time = std::chrono::high_resolution_clock::now();
    
    // Send commands to all bots
    for (const auto& bot : bot_clients) {
        c2_server_->SendCommandToBot(bot->GetBotId(), load_test_command);
    }
    
    // Wait for command completion
    std::this_thread::sleep_for(10s);
    
    auto command_time = std::chrono::high_resolution_clock::now() - start_time;
    auto command_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(command_time);
    
    // Verify command execution performance
    EXPECT_LT(command_duration_ms.count(), 15000)  // 15 seconds max
        << "Command execution took too long: " << command_duration_ms.count() << "ms";
    
    // Verify all commands were processed
    auto processed_commands = database_manager_->GetProcessedCommandsCount();
    EXPECT_GE(processed_commands, num_bots);
    
    // Test graceful degradation under extreme load
    auto extreme_load_metrics = PerformanceTestUtils::TestLoadCapacity(200);
    // System should handle graceful degradation, not crash
    EXPECT_TRUE(c2_server_->IsRunning());
    
    // Cleanup connections
    for (auto& bot : bot_clients) {
        bot->Disconnect();
    }
}

/**
 * @brief Test Docker container integration
 */
TEST_F(SystemIntegrationTest, DockerContainerIntegration) {
    // Test container communication
    EXPECT_TRUE(IntegrationTestUtils::TestDockerContainerCommunication());
    
    // Test service orchestration
    EXPECT_TRUE(IntegrationTestUtils::TestServiceOrchestration());
    
    // Test health check integration
    EXPECT_TRUE(IntegrationTestUtils::TestHealthCheckIntegration());
    
    // Test volume integration
    EXPECT_TRUE(IntegrationTestUtils::TestVolumeIntegration());
    
    // Test container networking
    EXPECT_TRUE(TestContainerNetworkIsolation());
    
    // Test container scaling
    EXPECT_TRUE(TestContainerScaling());
    
    // Test container failover
    EXPECT_TRUE(TestContainerFailover());
}

/**
 * @brief Test security validation
 */
TEST_F(SystemIntegrationTest, SecurityValidation) {
    // Test encryption strength
    auto encrypted_data = GenerateTestEncryptedData();
    EXPECT_TRUE(SecurityTestUtils::TestEncryptionStrength(encrypted_data));
    
    // Test network security
    EXPECT_TRUE(SecurityTestUtils::TestNetworkIsolation("c2-network"));
    EXPECT_TRUE(SecurityTestUtils::TestFirewallRules(GetFirewallRules()));
    
    // Test authentication security
    auto jwt_token = GenerateTestJWT();
    EXPECT_TRUE(SecurityTestUtils::TestJWTValidation(jwt_token));
    
    // Test SQL injection protection
    std::vector<std::string> sql_injection_tests = {
        "'; DROP TABLE bots; --",
        "' OR '1'='1",
        "'; SELECT * FROM audit_log; --"
    };
    
    for (const auto& injection_test : sql_injection_tests) {
        EXPECT_TRUE(SecurityTestUtils::TestSQLInjectionProtection(injection_test));
    }
    
    // Test XSS protection
    std::vector<std::string> xss_tests = {
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>"
    };
    
    for (const auto& xss_test : xss_tests) {
        EXPECT_TRUE(SecurityTestUtils::TestXSSProtection(xss_test));
    }
    
    // Test vulnerability scanning
    auto vulnerabilities = SecurityTestUtils::ScanForVulnerabilities("c2_server");
    EXPECT_EQ(vulnerabilities.size(), 0) << "Security vulnerabilities found: " 
                                        << nlohmann::json(vulnerabilities).dump();
}

// Test main function
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // Setup global test environment
    auto test_env = std::make_unique<TestEnvironment>();
    ::testing::AddGlobalTestEnvironment(test_env.release());
    
    // Run all tests
    return RUN_ALL_TESTS();
}
