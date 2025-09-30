// Dashboard Configuration
const config = {
    apiBaseUrl: window.location.origin,
    updateInterval: 5000, // 5 seconds
    maxDataPoints: 20, // Number of data points to show in charts
    alertLevels: {
        critical: { color: 'red', icon: '⚠️' },
        warning: { color: 'yellow', icon: '⚠️' },
        info: { color: 'blue', icon: 'ℹ️' }
    }
};

// State
let state = {
    requestsData: Array(config.maxDataPoints).fill(0),
    responseTimeData: Array(config.maxDataPoints).fill(0),
    activeAlerts: [],
    activityLogs: [],
    lastUpdate: null,
    charts: {}
};

// DOM Elements
const elements = {
    totalRequests: document.getElementById('total-requests'),
    requestChange: document.getElementById('request-change'),
    avgResponseTime: document.getElementById('avg-response-time'),
    responseTimeChange: document.getElementById('response-time-change'),
    activeAlerts: document.getElementById('active-alerts'),
    alertsChange: document.getElementById('alerts-change'),
    uptime: document.getElementById('uptime'),
    lastRestart: document.getElementById('last-restart'),
    cpuUsage: document.getElementById('cpu-usage'),
    cpuBar: document.getElementById('cpu-bar'),
    memoryUsage: document.getElementById('memory-usage'),
    memoryBar: document.getElementById('memory-bar'),
    activeConnections: document.getElementById('active-connections'),
    connectionsBar: document.getElementById('connections-bar'),
    proxyStatus: document.getElementById('proxy-status'),
    httpsStatus: document.getElementById('https-status'),
    lastUpdated: document.getElementById('last-updated'),
    alertsList: document.getElementById('alerts-list'),
    activityLog: document.getElementById('activity-log'),
    refreshBtn: document.getElementById('refresh-btn'),
    viewAllAlerts: document.getElementById('view-all-alerts'),
    viewAllLogs: document.getElementById('view-all-logs'),
    connectionStatus: document.getElementById('connection-status')
};

// Initialize WebSocket connection
let socket;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
        // Request initial data
        fetchInitialData();
    };

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleRealtimeUpdate(data);
    };

    socket.onclose = () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        // Try to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };

    socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus(false);
    };
}

// Initialize charts
function initCharts() {
    // Requests Chart
    const requestsCtx = document.getElementById('requests-chart').getContext('2d');
    state.charts.requests = new Chart(requestsCtx, {
        type: 'line',
        data: {
            labels: Array(config.maxDataPoints).fill(''),
            datasets: [{
                label: 'Requests per second',
                data: state.requestsData,
                borderColor: 'rgb(59, 130, 246)',
                tension: 0.1,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Requests'
                    }
                },
                x: {
                    display: false
                }
            },
            animation: {
                duration: 0
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Update charts with new data
function updateCharts() {
    if (state.charts.requests) {
        state.charts.requests.data.datasets[0].data = state.requestsData;
        state.charts.requests.update('none');
    }
}

// Fetch initial data from the API
async function fetchInitialData() {
    try {
        const [stats, alerts, logs] = await Promise.all([
            fetch(`${config.apiBaseUrl}/api/monitoring`).then(res => res.json()),
            fetch(`${config.apiBaseUrl}/api/alerts`).then(res => res.json()),
            fetch(`${config.apiBaseUrl}/api/logs`).then(res => res.json())
        ]);

        updateDashboard(stats);
        updateAlerts(alerts);
        updateActivityLogs(logs);
    } catch (error) {
        console.error('Error fetching initial data:', error);
        showError('Failed to load dashboard data');
    }
}

// Handle real-time updates from WebSocket
function handleRealtimeUpdate(data) {
    state.lastUpdate = new Date();
    
    // Update data arrays
    state.requestsData.shift();
    state.requestsData.push(data.requestsPerSecond || 0);
    
    state.responseTimeData.shift();
    state.responseTimeData.push(data.avgResponseTime || 0);
    
    // Update UI
    updateDashboard(data);
    updateCharts();
    
    // Check for new alerts
    if (data.alerts && data.alerts.length > 0) {
        addNewAlerts(data.alerts);
    }
    
    // Update activity log
    if (data.logs && data.logs.length > 0) {
        addNewLogs(data.logs);
    }
}

// Update dashboard metrics
function updateDashboard(data) {
    // Update stats
    elements.totalRequests.textContent = data.totalRequests?.toLocaleString() || '0';
    elements.avgResponseTime.textContent = `${Math.round(data.avgResponseTime || 0)}ms`;
    elements.activeAlerts.textContent = data.activeAlerts || '0';
    
    // Update system status
    if (data.system) {
        const { cpu, memory, connections } = data.system;
        
        // CPU
        const cpuPercent = Math.round(cpu.usage * 100);
        elements.cpuUsage.textContent = `${cpuPercent}%`;
        elements.cpuBar.style.width = `${cpuPercent}%`;
        elements.cpuBar.className = `h-2.5 rounded-full ${getUsageColorClass(cpuPercent)}`;
        
        // Memory
        const memoryUsedMB = Math.round(memory.used / 1024 / 1024);
        const memoryTotalMB = Math.round(memory.total / 1024 / 1024);
        const memoryPercent = Math.round((memory.used / memory.total) * 100);
        elements.memoryUsage.textContent = `${memoryUsedMB} MB / ${memoryTotalMB} MB`;
        elements.memoryBar.style.width = `${memoryPercent}%`;
        elements.memoryBar.className = `h-2.5 rounded-full ${getUsageColorClass(memoryPercent)}`;
        
        // Connections
        elements.activeConnections.textContent = connections.active;
        const maxConnections = connections.max || 1000; // Default max connections
        const connectionsPercent = Math.min(100, Math.round((connections.active / maxConnections) * 100));
        elements.connectionsBar.style.width = `${connectionsPercent}%`;
        elements.connectionsBar.className = `h-2.5 rounded-full ${getUsageColorClass(connectionsPercent)}`;
    }
    
    // Update timestamps
    if (data.timestamp) {
        elements.lastUpdated.textContent = formatTimeAgo(new Date(data.timestamp));
    }
    
    if (data.startedAt) {
        elements.uptime.textContent = formatUptime(new Date(data.startedAt));
        elements.lastRestart.textContent = `Since ${formatDateTime(new Date(data.startedAt))}`;
    }
    
    // Update status indicators
    updateStatusIndicators(data);
}

// Update alerts list
function updateAlerts(alerts) {
    state.activeAlerts = alerts || [];
    renderAlerts();
}

// Add new alerts
function addNewAlerts(newAlerts) {
    state.activeAlerts = [...newAlerts, ...state.activeAlerts].slice(0, 50); // Keep only the 50 most recent
    renderAlerts();
    
    // Show desktop notification for critical alerts
    if (Notification.permission === 'granted') {
        newAlerts
            .filter(alert => alert.level === 'critical')
            .forEach(alert => {
                new Notification('Critical Alert', {
                    body: alert.message,
                    icon: '/alert-icon.png'
                });
            });
    }
}

// Render alerts in the UI
function renderAlerts() {
    if (state.activeAlerts.length === 0) {
        elements.alertsList.innerHTML = `
            <div class="p-4 text-center text-gray-500">
                No active alerts
            </div>
        `;
        return;
    }
    
    elements.alertsList.innerHTML = state.activeAlerts
        .slice(0, 5) // Show only the 5 most recent
        .map(alert => `
            <div class="p-4 border-l-4 ${getAlertBorderClass(alert.level)}">
                <div class="flex">
                    <div class="flex-shrink-0">
                        ${getAlertIcon(alert.level)}
                    </div>
                    <div class="ml-3">
                        <p class="text-sm font-medium text-gray-900">
                            ${alert.title || 'Alert'}
                        </p>
                        <p class="text-sm text-gray-500">
                            ${alert.message}
                        </p>
                        <div class="mt-1 text-xs text-gray-500">
                            ${formatDateTime(new Date(alert.timestamp))}
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
}

// Update activity logs
function updateActivityLogs(logs) {
    state.activityLogs = logs || [];
    renderActivityLogs();
}

// Add new logs
function addNewLogs(newLogs) {
    state.activityLogs = [...state.activityLogs, ...newLogs].slice(-50); // Keep only the 50 most recent
    renderActivityLogs();
}

// Render activity logs in the UI
function renderActivityLogs() {
    if (state.activityLogs.length === 0) {
        elements.activityLog.innerHTML = `
            <div class="p-4 text-center text-gray-500">
                No recent activity
            </div>
        `;
        return;
    }
    
    elements.activityLog.innerHTML = state.activityLogs
        .slice(-5) // Show only the 5 most recent
        .map(log => `
            <div class="p-4">
                <div class="flex items-center">
                    <div class="min-w-0 flex-1">
                        <p class="text-sm font-medium text-gray-900 truncate">
                            ${log.message}
                        </p>
                        <p class="text-xs text-gray-500">
                            ${formatDateTime(new Date(log.timestamp))} • ${log.ip || 'N/A'}
                        </p>
                    </div>
                    <div class="ml-2 flex-shrink-0 flex">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            log.type === 'error' ? 'bg-red-100 text-red-800' : 
                            log.type === 'warning' ? 'bg-yellow-100 text-yellow-800' : 
                            'bg-blue-100 text-blue-800'
                        }">
                            ${log.type || 'info'}
                        </span>
                    </div>
                </div>
            </div>
        `).join('');
}

// Update status indicators
function updateStatusIndicators(data) {
    // Proxy status
    if (data.proxyStatus === 'running') {
        elements.proxyStatus.innerHTML = `
            <span class="w-2 h-2 mr-1 bg-green-500 rounded-full"></span>
            Running
        `;
        elements.proxyStatus.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800';
    } else {
        elements.proxyStatus.innerHTML = `
            <span class="w-2 h-2 mr-1 bg-red-500 rounded-full"></span>
            Stopped
        `;
        elements.proxyStatus.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800';
    }
    
    // HTTPS status
    if (data.httpsEnabled) {
        elements.httpsStatus.innerHTML = `
            <span class="w-2 h-2 mr-1 bg-green-500 rounded-full"></span>
            Enabled
        `;
        elements.httpsStatus.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800';
    } else {
        elements.httpsStatus.innerHTML = `
            <span class="w-2 h-2 mr-1 bg-yellow-500 rounded-full"></span>
            Disabled
        `;
        elements.httpsStatus.className = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800';
    }
}

// Update connection status indicator
function updateConnectionStatus(connected) {
    if (connected) {
        elements.connectionStatus.innerHTML = `
            <span class="w-2 h-2 mr-2 bg-green-500 rounded-full"></span>
            Connected
        `;
        elements.connectionStatus.className = 'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800';
    } else {
        elements.connectionStatus.innerHTML = `
            <span class="w-2 h-2 mr-2 bg-red-500 rounded-full"></span>
            Disconnected
        `;
        elements.connectionStatus.className = 'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800';
    }
}

// Show error message
function showError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'fixed bottom-4 right-4 bg-red-500 text-white px-4 py-2 rounded-md shadow-lg';
    alertDiv.textContent = message;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Helper functions
function formatDateTime(date) {
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    }).format(date);
}

function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 10) return 'Just now';
    if (seconds < 60) return `${seconds} seconds ago`;
    
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    
    const days = Math.floor(hours / 24);
    return `${days} day${days === 1 ? '' : 's'} ago`;
}

function formatUptime(startTime) {
    const seconds = Math.floor((new Date() - new Date(startTime)) / 1000);
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    return `${days}d ${hours}h ${minutes}m`;
}

function getAlertBorderClass(level) {
    switch (level) {
        case 'critical': return 'border-red-500';
        case 'warning': return 'border-yellow-500';
        default: return 'border-blue-500';
    }
}

function getAlertIcon(level) {
    const icon = config.alertLevels[level]?.icon || 'ℹ️';
    return `<span class="text-${config.alertLevels[level]?.color || 'blue'}-500">${icon}</span>`;
}

function getUsageColorClass(percent) {
    if (percent > 90) return 'bg-red-600';
    if (percent > 70) return 'bg-yellow-500';
    return 'bg-green-500';
}

// Request notification permission
function requestNotificationPermission() {
    if (Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize
    initCharts();
    connectWebSocket();
    requestNotificationPermission();
    
    // Set up refresh button
    elements.refreshBtn.addEventListener('click', fetchInitialData);
    
    // Set up view all buttons
    elements.viewAllAlerts.addEventListener('click', () => {
        // Navigate to full alerts page
        window.location.href = '/alerts';
    });
    
    elements.viewAllLogs.addEventListener('click', () => {
        // Navigate to full logs page
        window.location.href = '/logs';
    });
    
    // Set up auto-refresh
    setInterval(fetchInitialData, config.updateInterval);
});

// Expose for debugging
window.dashboard = {
    state,
    config,
    refresh: fetchInitialData
};
