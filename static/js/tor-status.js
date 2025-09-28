/**
 * Tor Status and Visualization
 * 
 * This script handles the Tor status page functionality, including:
 * - Real-time status updates
 * - Circuit visualization using D3.js
 * - Interactive controls for managing Tor connections
 */

// Global variables
let torStatusInterval;
let visualizationData = null;
let isVisualizationInitialized = false;

// DOM Elements
const elements = {
    connectionStatus: document.getElementById('connection-status-badge'),
    torVersion: document.getElementById('tor-version'),
    connectionType: document.getElementById('connection-type'),
    bandwidthUsed: document.getElementById('bandwidth-used'),
    bandwidthUsedText: document.getElementById('bandwidth-used-text'),
    bandwidthLimit: document.getElementById('bandwidth-limit'),
    activeCircuits: document.getElementById('active-circuits'),
    activeStreams: document.getElementById('active-streams'),
    circuitHealth: document.getElementById('circuit-health'),
    newIdentityBtn: document.getElementById('new-identity-btn'),
    refreshVizBtn: document.getElementById('refresh-viz-btn'),
    refreshCircuitsBtn: document.getElementById('refresh-circuits-btn'),
    visualizationUpdated: document.getElementById('visualization-updated'),
    circuitsTableBody: document.getElementById('circuits-table-body'),
    newCircuitBtn: document.getElementById('new-circuit-btn')
};

// Visualization constants
const VIZ_CONSTANTS = {
    WIDTH: document.getElementById('tor-visualization').offsetWidth,
    HEIGHT: 400,
    NODE_RADIUS: 12,
    NODE_PADDING: 10,
    LINK_DISTANCE: 120,
    CHARGE_STRENGTH: -500,
    TICK_LENGTH: 300
};

// Color scheme
const COLORS = {
    client: '#4e79a7',
    entry: '#59a14f',
    middle: '#edc949',
    exit: '#e15759',
    destination: '#af7aa1',
    link: '#888',
    linkHighlight: '#ff7f0e',
    background: '#f8f9fa',
    text: '#333',
    online: '#2ecc71',
    offline: '#e74c3c',
    warning: '#f39c12'
};

/**
 * Initialize the Tor status page
 */
function initTorStatus() {
    // Set up event listeners
    setupEventListeners();
    
    // Load initial data
    updateTorStatus();
    updateCircuits();
    
    // Set up periodic updates
    torStatusInterval = setInterval(updateTorStatus, 5000);
    
    // Initialize visualization
    initVisualization();
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // New Identity button
    if (elements.newIdentityBtn) {
        elements.newIdentityBtn.addEventListener('click', requestNewIdentity);
    }
    
    // Refresh visualization button
    if (elements.refreshVizBtn) {
        elements.refreshVizBtn.addEventListener('click', updateVisualization);
    }
    
    // Refresh circuits button
    if (elements.refreshCircuitsBtn) {
        elements.refreshCircuitsBtn.addEventListener('click', updateCircuits);
    }
    
    // New circuit button
    if (elements.newCircuitBtn) {
        elements.newCircuitBtn.addEventListener('click', createNewCircuit);
    }
    
    // Window resize handler for responsive visualization
    window.addEventListener('resize', debounce(handleResize, 250));
}

/**
 * Update Tor connection status
 */
async function updateTorStatus() {
    try {
        const response = await fetch('/tor/status');
        const data = await response.json();
        
        if (data.success) {
            updateStatusUI(data.status);
        } else {
            showError('Failed to update Tor status');
        }
    } catch (error) {
        console.error('Error updating Tor status:', error);
        showError('Connection error');
    }
}

/**
 * Update the UI with the latest status
 */
function updateStatusUI(status) {
    // Update connection status badge
    if (status.connected) {
        elements.connectionStatus.innerHTML = '<i class="fas fa-check-circle me-1"></i> Connected';
        elements.connectionStatus.className = 'badge bg-success';
    } else {
        elements.connectionStatus.innerHTML = '<i class="fas fa-times-circle me-1"></i> Disconnected';
        elements.connectionStatus.className = 'badge bg-danger';
    }
    
    // Update Tor version
    elements.torVersion.textContent = status.tor_version || 'Unknown';
    
    // Update connection type
    elements.connectionType.textContent = status.isolation_enabled ? 'Isolated' : 'Direct';
    
    // Update bandwidth
    const used = status.bandwidth?.bytes_read || 0;
    const total = status.bandwidth?.bytes_written || 0;
    const totalBytes = used + total;
    const usedMB = (totalBytes / (1024 * 1024)).toFixed(2);
    
    elements.bandwidthUsedText.textContent = `${usedMB} MB`;
    
    // If there's a limit, show percentage, otherwise just show usage
    if (status.bandwidth?.limit && status.bandwidth.limit > 0) {
        const percent = Math.min(100, Math.round((totalBytes / status.bandwidth.limit) * 100));
        elements.bandwidthUsed.style.width = `${percent}%`;
        elements.bandwidthLimit.textContent = `${(status.bandwidth.limit / (1024 * 1024)).toFixed(2)} MB`;
    } else {
        elements.bandwidthUsed.style.width = '100%';
        elements.bandwidthLimit.textContent = 'Unlimited';
    }
    
    // Update circuit and stream counts
    elements.activeCircuits.textContent = status.circuit_count || 0;
    elements.activeStreams.textContent = status.active_streams || 0;
    
    // Update circuit health (simple heuristic based on number of circuits)
    const healthPercent = Math.min(100, (status.circuit_count || 0) * 25);
    elements.circuitHealth.style.width = `${healthPercent}%`;
    elements.circuitHealth.className = `progress-bar ${
        healthPercent > 75 ? 'bg-success' : 
        healthPercent > 25 ? 'bg-warning' : 'bg-danger'
    }`;
    
    // Enable/disable buttons based on connection status
    if (elements.newIdentityBtn) {
        elements.newIdentityBtn.disabled = !status.is_newnym_available;
    }
}

/**
 * Update the circuits table
 */
async function updateCircuits() {
    try {
        const response = await fetch('/tor/circuits');
        const data = await response.json();
        
        if (data.success) {
            updateCircuitsTable(data.circuits);
        } else {
            showError('Failed to update circuits');
        }
    } catch (error) {
        console.error('Error updating circuits:', error);
        showError('Failed to load circuits');
    }
}

/**
 * Update the circuits table with the latest data
 */
function updateCircuitsTable(circuits) {
    if (!elements.circuitsTableBody) return;
    
    if (!circuits || circuits.length === 0) {
        elements.circuitsTableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4">
                    <i class="fas fa-info-circle me-2"></i>
                    No active circuits found
                </td>
            </tr>
        `;
        return;
    }
    
    // Sort circuits by ID
    circuits.sort((a, b) => parseInt(a.id) - parseInt(b.id));
    
    // Generate table rows
    const rows = circuits.map(circuit => {
        const age = new Date() - new Date(circuit.time_created * 1000);
        const ageMinutes = Math.floor(age / 60000);
        const ageSeconds = Math.floor((age % 60000) / 1000);
        const ageText = ageMinutes > 0 ? 
            `${ageMinutes}m ${ageSeconds}s` : 
            `${ageSeconds}s`;
        
        const statusBadge = circuit.built ? 
            '<span class="badge bg-success">Active</span>' : 
            '<span class="badge bg-warning">Building</span>';
        
        const pathText = circuit.path ? 
            circuit.path.map(node => node.substring(0, 8)).join(' → ') : 
            'Unknown';
        
        return `
            <tr>
                <td>${circuit.id}</td>
                <td>${circuit.purpose || 'general'}</td>
                <td>
                    <span class="text-truncate d-inline-block" style="max-width: 200px;" 
                          title="${pathText}">
                        ${pathText}
                    </span>
                </td>
                <td>${ageText}</td>
                <td>${statusBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary view-circuit" 
                            data-circuit-id="${circuit.id}">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger close-circuit" 
                            data-circuit-id="${circuit.id}">
                        <i class="fas fa-times"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    elements.circuitsTableBody.innerHTML = rows.join('');
    
    // Add event listeners to the action buttons
    document.querySelectorAll('.view-circuit').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const circuitId = e.target.closest('button').dataset.circuitId;
            viewCircuitDetails(circuitId);
        });
    });
    
    document.querySelectorAll('.close-circuit').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const circuitId = e.target.closest('button').dataset.circuitId;
            closeCircuit(circuitId);
        });
    });
}

/**
 * Request a new Tor identity
 */
async function requestNewIdentity() {
    if (!confirm('This will create a new Tor circuit. Continue?')) {
        return;
    }
    
    const btn = elements.newIdentityBtn;
    const originalHtml = btn.innerHTML;
    
    try {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span> Processing...';
        
        const response = await fetch('/tor/new-identity', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Success', 'New Tor identity requested', 'success');
            // Refresh the data
            updateTorStatus();
            updateCircuits();
            updateVisualization();
        } else {
            throw new Error(data.error || 'Failed to request new identity');
        }
    } catch (error) {
        console.error('Error requesting new identity:', error);
        showToast('Error', error.message, 'danger');
    } finally {
        btn.innerHTML = originalHtml;
        btn.disabled = false;
    }
}

/**
 * Create a new circuit
 */
async function createNewCircuit() {
    try {
        // This would be implemented based on your backend API
        showToast('Info', 'Creating new circuit...', 'info');
        
        // Simulate circuit creation
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Refresh the data
        updateCircuits();
        updateVisualization();
        
        showToast('Success', 'New circuit created', 'success');
    } catch (error) {
        console.error('Error creating new circuit:', error);
        showToast('Error', 'Failed to create circuit', 'danger');
    }
}

/**
 * Close a circuit
 */
async function closeCircuit(circuitId) {
    if (!confirm(`Close circuit ${circuitId}?`)) {
        return;
    }
    
    try {
        // This would be implemented based on your backend API
        showToast('Info', `Closing circuit ${circuitId}...`, 'info');
        
        // Simulate circuit closure
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Refresh the data
        updateCircuits();
        updateVisualization();
        
        showToast('Success', `Circuit ${circuitId} closed`, 'success');
    } catch (error) {
        console.error(`Error closing circuit ${circuitId}:`, error);
        showToast('Error', `Failed to close circuit ${circuitId}`, 'danger');
    }
}

/**
 * View circuit details
 */
function viewCircuitDetails(circuitId) {
    // This would show a modal with detailed circuit information
    alert(`Viewing details for circuit ${circuitId}`);
}

/**
 * Initialize the network visualization
 */
function initVisualization() {
    // Set up the SVG container
    const container = d3.select('#tor-visualization');
    
    // Clear any existing content
    container.html('');
    
    // Add loading indicator
    container.append('div')
        .attr('class', 'd-flex justify-content-center align-items-center h-100')
        .html(`
            <div class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2 mb-0">Loading network visualization...</p>
            </div>
        `);
    
    // Mark as initialized
    isVisualizationInitialized = true;
    
    // Load initial data
    updateVisualization();
}

/**
 * Update the network visualization
 */
async function updateVisualization() {
    if (!isVisualizationInitialized) return;
    
    try {
        const response = await fetch('/tor/visualization');
        const data = await response.json();
        
        if (data.success) {
            visualizationData = data.visualization;
            renderVisualization(visualizationData);
            
            // Update the "last updated" timestamp
            if (elements.visualizationUpdated) {
                const now = new Date().toLocaleTimeString();
                elements.visualizationUpdated.textContent = `Last updated: ${now}`;
            }
        } else {
            throw new Error(data.error || 'Failed to load visualization data');
        }
    } catch (error) {
        console.error('Error updating visualization:', error);
        showError('Failed to update visualization');
    }
}

/**
 * Render the network visualization using D3.js
 */
function renderVisualization(data) {
    const container = d3.select('#tor-visualization');
    
    // Clear the container
    container.html('');
    
    // Create SVG
    const svg = container.append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${VIZ_CONSTANTS.WIDTH} ${VIZ_CONSTANTS.HEIGHT}`)
        .attr('preserveAspectRatio', 'xMidYMid meet');
    
    // Add a group for zoom/pan
    const g = svg.append('g');
    
    // Add a background rectangle
    g.append('rect')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('fill', COLORS.background);
    
    // Check if we have data
    if (!data || !data.nodes || data.nodes.length === 0) {
        g.append('text')
            .attr('x', VIZ_CONSTANTS.WIDTH / 2)
            .attr('y', VIZ_CONSTANTS.HEIGHT / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', COLORS.text)
            .text('No circuit data available');
        return;
    }
    
    // Process the nodes and links
    const nodes = data.nodes.map(d => ({ ...d }));
    const links = data.links.map(d => ({ ...d }));
    
    // Create the simulation
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(VIZ_CONSTANTS.LINK_DISTANCE))
        .force('charge', d3.forceManyBody().strength(VIZ_CONSTANTS.CHARGE_STRENGTH))
        .force('center', d3.forceCenter(VIZ_CONSTANTS.WIDTH / 2, VIZ_CONSTANTS.HEIGHT / 2))
        .force('collision', d3.forceCollide().radius(VIZ_CONSTANTS.NODE_RADIUS * 1.5));
    
    // Create the links
    const link = g.append('g')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('stroke', COLORS.link)
        .attr('stroke-width', 1.5);
    
    // Create a group for the nodes
    const node = g.append('g')
        .selectAll('.node')
        .data(nodes)
        .enter().append('g')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add circles for the nodes
    node.append('circle')
        .attr('r', VIZ_CONSTANTS.NODE_RADIUS)
        .attr('fill', d => {
            switch (d.type) {
                case 'client': return COLORS.client;
                case 'entry': return COLORS.entry;
                case 'middle': return COLORS.middle;
                case 'exit': return COLORS.exit;
                case 'destination': return COLORS.destination;
                default: return '#999';
            }
        })
        .attr('stroke', '#fff')
        .attr('stroke-width', 1.5);
    
    // Add node labels
    node.append('text')
        .attr('dy', VIZ_CONSTANTS.NODE_RADIUS * 2 + 5)
        .attr('text-anchor', 'middle')
        .attr('fill', COLORS.text)
        .style('font-size', '10px')
        .text(d => d.name);
    
    // Add node type indicators
    node.append('text')
        .attr('dy', 4)
        .attr('text-anchor', 'middle')
        .attr('fill', '#fff')
        .style('font-size', '10px')
        .style('font-weight', 'bold')
        .style('pointer-events', 'none')
        .text(d => {
            switch (d.type) {
                case 'client': return 'U';
                case 'entry': return 'E';
                case 'middle': return 'M';
                case 'exit': return 'X';
                case 'destination': return 'D';
                default: return '?';
            }
        });
    
    // Add tooltips
    node.append('title')
        .text(d => `${d.name}\nType: ${d.type}\nStatus: ${d.status}`);
    
    // Update positions on each tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.WIDTH - VIZ_CONSTANTS.NODE_RADIUS, d.source.x)))
            .attr('y1', d => Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.HEIGHT - VIZ_CONSTANTS.NODE_RADIUS, d.source.y)))
            .attr('x2', d => Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.WIDTH - VIZ_CONSTANTS.NODE_RADIUS, d.target.x)))
            .attr('y2', d => Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.HEIGHT - VIZ_CONSTANTS.NODE_RADIUS, d.target.y)));
        
        node.attr('transform', d => {
            const x = Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.WIDTH - VIZ_CONSTANTS.NODE_RADIUS, d.x));
            const y = Math.max(VIZ_CONSTANTS.NODE_RADIUS, Math.min(VIZ_CONSTANTS.HEIGHT - VIZ_CONSTANTS.NODE_RADIUS, d.y));
            return `translate(${x},${y})`;
        });
    });
    
    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
    svg.call(zoom);
    
    // Reset zoom button
    const resetZoom = () => {
        svg.transition()
            .duration(500)
            .call(zoom.transform, d3.zoomIdentity);
    };
    
    // Add reset zoom button
    svg.append('foreignObject')
        .attr('x', 10)
        .attr('y', 10)
        .attr('width', 100)
        .attr('height', 30)
        .append('xhtml:div')
        .html(`
            <button class="btn btn-sm btn-outline-secondary" id="reset-zoom">
                <i class="fas fa-search"></i> Reset Zoom
            </button>
        `);
    
    document.getElementById('reset-zoom')?.addEventListener('click', resetZoom);
    
    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

/**
 * Handle window resize
 */
function handleResize() {
    if (visualizationData) {
        renderVisualization(visualizationData);
    }
}

/**
 * Show an error message
 */
function showError(message) {
    console.error(message);
    // You could implement a more sophisticated error display here
    alert(`Error: ${message}`);
}

/**
 * Show a toast notification
 */
function showToast(title, message, type = 'info') {
    // This is a simplified version - you might want to use a proper toast library
    const toast = document.createElement('div');
    toast.className = `toast show align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong><br>${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    const toastContainer = document.getElementById('toast-container') || (() => {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '1100';
        document.body.appendChild(container);
        return container;
    })();
    
    toastContainer.appendChild(toast);
    
    // Auto-remove the toast after 5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 150);
    }, 5000);
}

/**
 * Debounce function to limit the rate at which a function can fire
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize when the DOM is fully loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTorStatus);
} else {
    initTorStatus();
}
