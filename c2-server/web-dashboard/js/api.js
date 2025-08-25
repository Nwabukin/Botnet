/**
 * API Client for C2 Dashboard
 * Simple implementation for cloud deployment
 */

// Set demo authentication token
if (!localStorage.getItem('c2_auth_token')) {
    localStorage.setItem('c2_auth_token', 'demo_token_research_mode');
}

// Simple API client
window.api = {
    baseUrl: window.location.origin,
    
    async request(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.baseUrl}/api${endpoint}`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`API request failed: ${response.statusText}`);
            }
            
            return response.json();
        } catch (error) {
            console.error('API request failed:', error);
            return null;
        }
    },
    
    async getServerInfo() {
        return this.request('/status');
    },
    
    async getStatistics() {
        return this.request('/status');
    },
    
    async getBots() {
        return [];
    },
    
    async getRecentActivity() {
        return [{
            timestamp: new Date().toISOString(),
            type: 'INFO',
            description: 'Dashboard loaded successfully'
        }];
    }
};
