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
 * Detect specific hash type (MD5, SHA-1, or SHA-256)
 * @param {string} input - User input string
 * @returns {string|null} Hash type: 'md5', 'sha1', 'sha256', or null if not a hash
 */
export function detectHashType(input) {
    if (!input || typeof input !== 'string') {
        return null;
    }
    
    const trimmed = input.trim();
    
    // MD5: 32 hex characters
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) {
        return 'md5';
    }
    // SHA-1: 40 hex characters
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) {
        return 'sha1';
    }
    // SHA-256: 64 hex characters
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
        return 'sha256';
    }
    
    return null;
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
