/**
 * Maps for C2 Dashboard
 * Simple Leaflet implementation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize map when map section is shown
    const mapContainer = document.getElementById('botMap');
    if (mapContainer) {
        // Initialize map
        const map = L.map('botMap').setView([40.7128, -74.0060], 2);
        
        // Add tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);
        
        // Add sample markers for demonstration
        const sampleLocations = [
            { lat: 40.7128, lng: -74.0060, city: 'New York', count: 0 },
            { lat: 51.5074, lng: -0.1278, city: 'London', count: 0 },
            { lat: 35.6762, lng: 139.6503, city: 'Tokyo', count: 0 }
        ];
        
        sampleLocations.forEach(location => {
            if (location.count > 0) {
                L.marker([location.lat, location.lng])
                    .addTo(map)
                    .bindPopup(`${location.city}: ${location.count} bots`);
            }
        });
    }
    
    // Update country stats
    const countryStats = document.getElementById('countryStats');
    if (countryStats) {
        countryStats.innerHTML = `
            <div class="d-flex justify-content-between py-2">
                <span>🇺🇸 United States</span>
                <span class="badge bg-primary">0</span>
            </div>
            <div class="d-flex justify-content-between py-2">
                <span>🇬🇧 United Kingdom</span>
                <span class="badge bg-primary">0</span>
            </div>
            <div class="d-flex justify-content-between py-2">
                <span>🇯🇵 Japan</span>
                <span class="badge bg-primary">0</span>
            </div>
        `;
    }
});
