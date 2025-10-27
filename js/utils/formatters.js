/**
 * Data formatting utilities
 */

/**
 * Format Unix timestamp to readable date string
 * @param {number} timestamp - Unix timestamp in seconds
 * @returns {string} Formatted date string
 */
export function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

/**
 * Get relative time string (e.g., "2 hours ago")
 * @param {number} timestamp - Unix timestamp in seconds
 * @returns {string} Relative time string
 */
export function timeAgo(timestamp) {
    if (!timestamp) return 'N/A';
    
    const now = Math.floor(Date.now() / 1000);
    const seconds = now - timestamp;
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
    if (seconds < 2592000) return `${Math.floor(seconds / 86400)} days ago`;
    if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} months ago`;
    return `${Math.floor(seconds / 31536000)} years ago`;
}

/**
 * Format file size in bytes to human-readable string
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted size string
 */
export function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${units[i]}`;
}

/**
 * Format number with thousands separator
 * @param {number} num - Number to format
 * @returns {string} Formatted number string
 */
export function formatNumber(num) {
    if (num === null || num === undefined) return 'N/A';
    return num.toLocaleString();
}

/**
 * Truncate string with ellipsis
 * @param {string} str - String to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated string
 */
export function truncate(str, maxLength = 50) {
    if (!str) return '';
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
}

/**
 * Format hash with spacing for readability
 * @param {string} hash - Hash string
 * @returns {string} Formatted hash
 */
export function formatHash(hash) {
    if (!hash) return '';
    // Add space every 8 characters for readability
    return hash.match(/.{1,8}/g)?.join(' ') || hash;
}

/**
 * Get status color class based on category
 * @param {string} category - Status category
 * @returns {string} CSS class name
 */
export function getStatusClass(category) {
    const classes = {
        malicious: 'status-malicious',
        suspicious: 'status-suspicious',
        undetected: 'status-undetected',
        harmless: 'status-harmless',
        clean: 'status-clean',
        timeout: 'status-undetected',
        failure: 'status-undetected'
    };
    return classes[category] || 'status-undetected';
}

/**
 * Get detection severity level
 * @param {number} malicious - Number of malicious detections
 * @param {number} total - Total number of scans
 * @returns {string} Severity: 'clean', 'suspicious', 'malicious'
 */
export function getDetectionSeverity(malicious, total) {
    if (!malicious || malicious === 0) return 'clean';
    const percentage = (malicious / total) * 100;
    if (percentage > 30) return 'malicious';
    return 'suspicious';
}

/**
 * Escape HTML to prevent XSS
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
export function escapeHtml(str) {
    if (!str) return '';
    if (typeof str !== 'string') str = String(str);
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} Success status
 */
export async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
    }
}
