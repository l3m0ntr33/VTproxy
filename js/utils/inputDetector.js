/**
 * Detect input type (hash, url, domain, ip)
 */

/**
 * Detect the type of input
 * @param {string} input - User input string
 * @returns {string} Type: 'hash', 'url', 'domain', 'ip', or 'unknown'
 */
export function detectInputType(input) {
    if (!input || typeof input !== 'string') {
        return 'unknown';
    }
    
    const trimmed = input.trim();
    
    // Hash: 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) {
        return 'hash';
    }
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) {
        return 'hash';
    }
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
        return 'hash';
    }
    
    // URL: starts with http:// or https://
    if (/^https?:\/\//i.test(trimmed)) {
        return 'url';
    }
    
    // IPv4: xxx.xxx.xxx.xxx
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
        // Validate IP ranges (0-255)
        const parts = trimmed.split('.');
        if (parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        })) {
            return 'ip';
        }
    }
    
    // IPv6: contains colons and hex characters
    if (/^[0-9a-fA-F:]+$/.test(trimmed) && trimmed.includes(':')) {
        return 'ip';
    }
    
    // Domain: alphanumeric with dots and hyphens
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(trimmed)) {
        return 'domain';
    }
    
    return 'unknown';
}

/**
 * Get a human-readable label for input type
 * @param {string} type - Input type
 * @returns {string} Human-readable label
 */
export function getTypeLabel(type) {
    const labels = {
        hash: 'File Hash',
        url: 'URL',
        domain: 'Domain',
        ip: 'IP Address',
        unknown: 'Unknown'
    };
    return labels[type] || 'Unknown';
}

/**
 * Validate input before search
 * @param {string} input - User input
 * @returns {{valid: boolean, type: string, message: string}}
 */
export function validateInput(input) {
    if (!input || !input.trim()) {
        return {
            valid: false,
            type: 'unknown',
            message: 'Please enter a file hash, URL, domain, or IP address'
        };
    }
    
    const type = detectInputType(input);
    
    if (type === 'unknown') {
        return {
            valid: false,
            type: 'unknown',
            message: 'Invalid input format. Please enter a valid file hash, URL, domain, or IP address'
        };
    }
    
    return {
        valid: true,
        type,
        message: `Detected: ${getTypeLabel(type)}`
    };
}
