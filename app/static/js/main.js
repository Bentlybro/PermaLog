/**
 * PermaLog - Main JavaScript
 * Handles WebSocket connections and UI interactions
 */

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips and popovers if Bootstrap is loaded
    if (typeof bootstrap !== 'undefined') {
        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Initialize popovers
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(function(popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });
    }
    
    // Format timestamps
    formatTimestamps();
    
    // Add copy functionality to code blocks
    addCopyToClipboard();
});

/**
 * Format ISO timestamps to local date/time
 */
function formatTimestamps() {
    document.querySelectorAll('.timestamp').forEach(function(element) {
        const timestamp = element.getAttribute('data-timestamp');
        if (timestamp) {
            const date = new Date(timestamp);
            element.textContent = date.toLocaleString();
        }
    });
}

/**
 * Add copy-to-clipboard functionality to code blocks
 */
function addCopyToClipboard() {
    document.querySelectorAll('.copy-btn').forEach(function(button) {
        button.addEventListener('click', function() {
            const codeBlock = this.closest('.code-container').querySelector('code');
            const textToCopy = codeBlock.textContent;
            
            navigator.clipboard.writeText(textToCopy).then(function() {
                // Success - show feedback
                button.textContent = 'Copied!';
                setTimeout(function() {
                    button.textContent = 'Copy';
                }, 2000);
            }, function() {
                // Failure - show error
                button.textContent = 'Failed to copy';
                setTimeout(function() {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });
    });
}

/**
 * Create a new log entry element
 * @param {Object} log - The log data
 * @returns {HTMLElement} - The log entry element
 */
function createLogEntry(log) {
    // Create log entry container
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry p-2 mb-2 border-bottom';
    
    // Format timestamp
    const timestamp = new Date(log.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Determine badge color based on log level
    let badgeClass = 'bg-secondary';
    switch(log.level.toLowerCase()) {
        case 'info':
            badgeClass = 'bg-info';
            break;
        case 'warning':
            badgeClass = 'bg-warning text-dark';
            break;
        case 'error':
            badgeClass = 'bg-danger';
            break;
        case 'debug':
            badgeClass = 'bg-secondary';
            break;
        case 'critical':
            badgeClass = 'bg-dark';
            break;
    }
    
    // Build log entry HTML
    logEntry.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div>
                <span class="badge ${badgeClass}">${log.level}</span>
                <strong>${log.message}</strong>
            </div>
            <small class="text-muted">${formattedTime}</small>
        </div>
        ${log.source ? `<div class="small text-muted">Source: ${log.source}</div>` : ''}
        ${log.metadata ? `<div class="small mt-1"><pre class="mb-0 p-1 bg-light rounded">${JSON.stringify(log.metadata, null, 2)}</pre></div>` : ''}
    `;
    
    return logEntry;
} 