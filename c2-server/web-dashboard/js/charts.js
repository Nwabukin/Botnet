/**
 * Charts for C2 Dashboard
 * Simple Chart.js implementation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Activity Chart
    const activityCtx = document.getElementById('activityChart');
    if (activityCtx) {
        new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Bot Activity',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                },
                scales: {
                    x: { ticks: { color: '#ffffff' } },
                    y: { ticks: { color: '#ffffff' } }
                }
            }
        });
    }

    // Platform Chart
    const platformCtx = document.getElementById('platformChart');
    if (platformCtx) {
        new Chart(platformCtx, {
            type: 'doughnut',
            data: {
                labels: ['Windows', 'Linux', 'macOS'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#e74c3c', '#27ae60', '#f39c12']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                }
            }
        });
    }

    // Timezone Chart
    const timezoneCtx = document.getElementById('timezoneChart');
    if (timezoneCtx) {
        new Chart(timezoneCtx, {
            type: 'bar',
            data: {
                labels: ['UTC-8', 'UTC-5', 'UTC+0', 'UTC+1', 'UTC+8'],
                datasets: [{
                    label: 'Bots by Timezone',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: '#3498db'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                },
                scales: {
                    x: { ticks: { color: '#ffffff' } },
                    y: { ticks: { color: '#ffffff' } }
                }
            }
        });
    }
});
