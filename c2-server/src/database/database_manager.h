#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace c2 {
namespace database {

/**
 * @brief Database manager for C2 server - single codebase approach
 * 
 * Handles all database operations for bot tracking, command logging,
 * and operational data. Supports multiple database backends.
 */
class DatabaseManager {
public:
    enum class DatabaseType {
        POSTGRESQL,
        MYSQL,
        SQLITE,
        MONGODB
    };

    struct DatabaseConfig {
        DatabaseType type;
        std::string host;
        uint16_t port;
        std::string database_name;
        std::string username;
        std::string password;
        uint32_t connection_pool_size;
        std::chrono::seconds connection_timeout;
        bool enable_ssl;
        std::string ssl_ca_file;
        std::string ssl_cert_file;
        std::string ssl_key_file;
    };

    struct BotRecord {
        std::string bot_id;
        std::string ip_address;
        std::string hostname;
        std::string platform;
        std::string version;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_seen;
        std::string country_code;
        std::string region;
        bool research_mode;
        std::string research_session_id;
        nlohmann::json system_info;
        nlohmann::json capabilities;
        uint32_t total_commands;
        bool active;
    };

    struct CommandRecord {
        std::string command_id;
        std::string command_type;
        nlohmann::json parameters;
        std::vector<std::string> target_bots;
        std::chrono::system_clock::time_point issued_at;
        std::chrono::system_clock::time_point expires_at;
        std::string issued_by;
        bool research_approved;
        std::string approval_reference;
        uint32_t responses_received;
        uint32_t responses_expected;
        bool completed;
    };

    struct CommandResponseRecord {
        std::string response_id;
        std::string command_id;
        std::string bot_id;
        std::chrono::system_clock::time_point received_at;
        bool success;
        nlohmann::json result_data;
        std::string error_message;
        std::chrono::milliseconds execution_time;
        uint64_t data_size;
    };

    struct AuditLogRecord {
        std::string log_id;
        std::chrono::system_clock::time_point timestamp;
        std::string event_type;
        std::string source;
        std::string target;
        std::string description;
        nlohmann::json event_data;
        std::string severity;
        bool research_related;
        std::string session_id;
    };

    struct AnalyticsData {
        uint32_t total_bots;
        uint32_t active_bots;
        uint32_t commands_issued_today;
        uint32_t successful_commands_today;
        std::map<std::string, uint32_t> bots_by_platform;
        std::map<std::string, uint32_t> bots_by_country;
        std::map<std::string, uint32_t> commands_by_type;
        std::chrono::system_clock::time_point last_updated;
    };

public:
    DatabaseManager();
    ~DatabaseManager();

    // Initialization
    bool Initialize(const DatabaseConfig& config);
    bool TestConnection();
    bool CreateTables();
    bool MigrateSchema();
    void Shutdown();

    // Bot management
    bool SaveBot(const BotRecord& bot);
    bool UpdateBot(const BotRecord& bot);
    bool DeleteBot(const std::string& bot_id);
    BotRecord GetBot(const std::string& bot_id);
    std::vector<BotRecord> GetAllBots();
    std::vector<BotRecord> GetActiveBots();
    std::vector<BotRecord> GetBotsByPlatform(const std::string& platform);
    std::vector<BotRecord> GetBotsByCountry(const std::string& country_code);
    std::vector<BotRecord> GetResearchBots();
    bool UpdateBotLastSeen(const std::string& bot_id);

    // Command management
    bool SaveCommand(const CommandRecord& command);
    bool UpdateCommand(const CommandRecord& command);
    bool DeleteCommand(const std::string& command_id);
    CommandRecord GetCommand(const std::string& command_id);
    std::vector<CommandRecord> GetPendingCommands();
    std::vector<CommandRecord> GetCommandsForBot(const std::string& bot_id);
    std::vector<CommandRecord> GetCommandsByType(const std::string& command_type);
    std::vector<CommandRecord> GetCommandsInTimeRange(std::chrono::system_clock::time_point start,
                                                     std::chrono::system_clock::time_point end);

    // Command response management
    bool SaveCommandResponse(const CommandResponseRecord& response);
    bool DeleteCommandResponse(const std::string& response_id);
    CommandResponseRecord GetCommandResponse(const std::string& response_id);
    std::vector<CommandResponseRecord> GetCommandResponses(const std::string& command_id);
    std::vector<CommandResponseRecord> GetBotResponses(const std::string& bot_id);
    std::vector<CommandResponseRecord> GetResponsesInTimeRange(std::chrono::system_clock::time_point start,
                                                              std::chrono::system_clock::time_point end);

    // Audit logging
    bool LogEvent(const AuditLogRecord& log_record);
    std::vector<AuditLogRecord> GetAuditLogs(std::chrono::system_clock::time_point start,
                                            std::chrono::system_clock::time_point end);
    std::vector<AuditLogRecord> GetAuditLogsByType(const std::string& event_type);
    std::vector<AuditLogRecord> GetResearchAuditLogs(const std::string& session_id);
    bool PurgeOldAuditLogs(std::chrono::hours max_age);

    // Analytics and reporting
    AnalyticsData GetAnalytics();
    nlohmann::json GenerateReport(const std::string& report_type,
                                 std::chrono::system_clock::time_point start,
                                 std::chrono::system_clock::time_point end);
    nlohmann::json GetBotStatistics();
    nlohmann::json GetCommandStatistics();
    nlohmann::json GetPerformanceMetrics();

    // Research compliance
    bool LogResearchActivity(const std::string& session_id, const std::string& activity,
                           const nlohmann::json& details);
    std::vector<AuditLogRecord> GetResearchComplianceReport(const std::string& session_id);
    bool ValidateResearchCompliance(const std::string& session_id);

    // Data management
    bool BackupDatabase(const std::string& backup_path);
    bool RestoreDatabase(const std::string& backup_path);
    bool ExportData(const std::string& export_path, const std::string& format = "json");
    bool ImportData(const std::string& import_path);
    bool PurgeOldData(std::chrono::hours max_age);

    // Transaction management
    bool BeginTransaction();
    bool CommitTransaction();
    bool RollbackTransaction();

private:
    DatabaseConfig config_;
    std::unique_ptr<class DatabaseConnection> connection_;
    std::unique_ptr<class ConnectionPool> connection_pool_;
    mutable std::mutex db_mutex_;

    // Database-specific implementations
    std::unique_ptr<class PostgreSQLAdapter> postgresql_adapter_;
    std::unique_ptr<class MySQLAdapter> mysql_adapter_;
    std::unique_ptr<class SQLiteAdapter> sqlite_adapter_;
    std::unique_ptr<class MongoDBAdapter> mongodb_adapter_;

    // Schema management
    bool CreateBotsTable();
    bool CreateCommandsTable();
    bool CreateCommandResponsesTable();
    bool CreateAuditLogTable();
    bool CreateIndexes();

    // Query builders
    std::string BuildBotQuery(const std::map<std::string, std::string>& filters);
    std::string BuildCommandQuery(const std::map<std::string, std::string>& filters);
    std::string BuildAuditLogQuery(const std::map<std::string, std::string>& filters);

    // Data serialization
    nlohmann::json SerializeBotRecord(const BotRecord& bot);
    BotRecord DeserializeBotRecord(const nlohmann::json& json);
    nlohmann::json SerializeCommandRecord(const CommandRecord& command);
    CommandRecord DeserializeCommandRecord(const nlohmann::json& json);

    // Error handling
    void HandleDatabaseError(const std::string& operation, const std::string& error);
    bool RetryOperation(std::function<bool()> operation, uint32_t max_retries = 3);
};

/**
 * @brief Database connection abstraction
 */
class DatabaseConnection {
public:
    virtual ~DatabaseConnection() = default;
    
    virtual bool Connect(const DatabaseManager::DatabaseConfig& config) = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    
    virtual bool ExecuteQuery(const std::string& query) = 0;
    virtual nlohmann::json ExecuteSelectQuery(const std::string& query) = 0;
    virtual std::string EscapeString(const std::string& str) = 0;
    
    virtual bool BeginTransaction() = 0;
    virtual bool CommitTransaction() = 0;
    virtual bool RollbackTransaction() = 0;
};

/**
 * @brief PostgreSQL database adapter
 */
class PostgreSQLAdapter : public DatabaseConnection {
public:
    PostgreSQLAdapter();
    ~PostgreSQLAdapter() override;

    bool Connect(const DatabaseManager::DatabaseConfig& config) override;
    void Disconnect() override;
    bool IsConnected() const override;

    bool ExecuteQuery(const std::string& query) override;
    nlohmann::json ExecuteSelectQuery(const std::string& query) override;
    std::string EscapeString(const std::string& str) override;

    bool BeginTransaction() override;
    bool CommitTransaction() override;
    bool RollbackTransaction() override;

private:
    void* connection_; // PGconn*
    bool connected_;
    mutable std::mutex connection_mutex_;

    void HandlePostgreSQLError(const std::string& operation);
    nlohmann::json ConvertResultToJSON(void* result); // PGresult*
};

/**
 * @brief SQLite database adapter (for lightweight deployments)
 */
class SQLiteAdapter : public DatabaseConnection {
public:
    SQLiteAdapter();
    ~SQLiteAdapter() override;

    bool Connect(const DatabaseManager::DatabaseConfig& config) override;
    void Disconnect() override;
    bool IsConnected() const override;

    bool ExecuteQuery(const std::string& query) override;
    nlohmann::json ExecuteSelectQuery(const std::string& query) override;
    std::string EscapeString(const std::string& str) override;

    bool BeginTransaction() override;
    bool CommitTransaction() override;
    bool RollbackTransaction() override;

private:
    void* database_; // sqlite3*
    bool connected_;
    mutable std::mutex db_mutex_;

    void HandleSQLiteError(const std::string& operation, int error_code);
    nlohmann::json ConvertRowToJSON(void* stmt, int column_count); // sqlite3_stmt*
};

/**
 * @brief Connection pool for high-performance database access
 */
class ConnectionPool {
public:
    explicit ConnectionPool(uint32_t pool_size);
    ~ConnectionPool();

    bool Initialize(const DatabaseManager::DatabaseConfig& config);
    void Shutdown();

    std::shared_ptr<DatabaseConnection> GetConnection();
    void ReturnConnection(std::shared_ptr<DatabaseConnection> connection);

    uint32_t GetActiveConnections() const;
    uint32_t GetAvailableConnections() const;

private:
    std::vector<std::shared_ptr<DatabaseConnection>> connections_;
    std::queue<std::shared_ptr<DatabaseConnection>> available_connections_;
    mutable std::mutex pool_mutex_;
    std::condition_variable pool_condition_;

    uint32_t pool_size_;
    std::atomic<uint32_t> active_connections_;

    std::shared_ptr<DatabaseConnection> CreateConnection(const DatabaseManager::DatabaseConfig& config);
};

/**
 * @brief Database migration manager
 */
class MigrationManager {
public:
    struct Migration {
        uint32_t version;
        std::string description;
        std::string up_script;
        std::string down_script;
        std::chrono::system_clock::time_point created_at;
    };

public:
    explicit MigrationManager(DatabaseManager& db_manager);
    ~MigrationManager();

    bool RunMigrations();
    bool RollbackMigration(uint32_t target_version);
    uint32_t GetCurrentVersion();
    std::vector<Migration> GetPendingMigrations();

private:
    DatabaseManager& db_manager_;
    std::vector<Migration> migrations_;

    void LoadMigrations();
    bool CreateMigrationTable();
    bool ApplyMigration(const Migration& migration);
    bool RecordMigration(const Migration& migration);
    bool RemoveMigration(uint32_t version);
};

/**
 * @brief Database query builder for complex queries
 */
class QueryBuilder {
public:
    QueryBuilder();
    ~QueryBuilder();

    // SELECT queries
    QueryBuilder& Select(const std::vector<std::string>& columns = {"*"});
    QueryBuilder& From(const std::string& table);
    QueryBuilder& Where(const std::string& condition);
    QueryBuilder& And(const std::string& condition);
    QueryBuilder& Or(const std::string& condition);
    QueryBuilder& OrderBy(const std::string& column, bool ascending = true);
    QueryBuilder& Limit(uint32_t limit);
    QueryBuilder& Offset(uint32_t offset);

    // INSERT queries
    QueryBuilder& InsertInto(const std::string& table);
    QueryBuilder& Values(const std::map<std::string, std::string>& values);

    // UPDATE queries
    QueryBuilder& Update(const std::string& table);
    QueryBuilder& Set(const std::map<std::string, std::string>& values);

    // DELETE queries
    QueryBuilder& DeleteFrom(const std::string& table);

    // JOIN operations
    QueryBuilder& Join(const std::string& table, const std::string& condition);
    QueryBuilder& LeftJoin(const std::string& table, const std::string& condition);
    QueryBuilder& RightJoin(const std::string& table, const std::string& condition);

    // Build final query
    std::string Build() const;
    void Reset();

private:
    std::string query_;
    std::vector<std::string> select_columns_;
    std::string from_table_;
    std::vector<std::string> where_conditions_;
    std::vector<std::string> order_by_columns_;
    uint32_t limit_value_;
    uint32_t offset_value_;
    bool has_limit_;
    bool has_offset_;

    std::string BuildSelectQuery() const;
    std::string BuildInsertQuery() const;
    std::string BuildUpdateQuery() const;
    std::string BuildDeleteQuery() const;
};

/**
 * @brief Database performance monitor
 */
class DatabasePerformanceMonitor {
public:
    struct QueryMetrics {
        std::string query_type;
        std::chrono::milliseconds execution_time;
        std::chrono::system_clock::time_point timestamp;
        bool success;
        std::string error_message;
    };

    struct PerformanceStats {
        uint32_t total_queries;
        uint32_t successful_queries;
        uint32_t failed_queries;
        std::chrono::milliseconds average_execution_time;
        std::chrono::milliseconds max_execution_time;
        std::chrono::milliseconds min_execution_time;
        std::map<std::string, uint32_t> queries_by_type;
        std::chrono::system_clock::time_point last_reset;
    };

public:
    DatabasePerformanceMonitor();
    ~DatabasePerformanceMonitor();

    void RecordQuery(const QueryMetrics& metrics);
    PerformanceStats GetStatistics() const;
    void ResetStatistics();

    // Alerting
    void SetSlowQueryThreshold(std::chrono::milliseconds threshold);
    void SetFailureRateThreshold(double threshold_percent);
    void SetAlertCallback(std::function<void(const std::string&)> callback);

private:
    std::vector<QueryMetrics> query_history_;
    mutable std::mutex metrics_mutex_;

    PerformanceStats stats_;
    std::chrono::milliseconds slow_query_threshold_;
    double failure_rate_threshold_;
    std::function<void(const std::string&)> alert_callback_;

    void UpdateStatistics(const QueryMetrics& metrics);
    void CheckAlerts();
};

} // namespace database
} // namespace c2
} // namespace botnet
