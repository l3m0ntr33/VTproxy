/**
 * URL encoding utilities for VirusTotal API
 * VT requires URL-safe base64 encoding without padding (RFC 4648 section 3.2)
 */

/**
 * Encode URL for VirusTotal API (URL-safe base64 without padding)
 * @param {string} url - URL to encode
 * @returns {string} Base64-encoded URL ID
 */
export function encodeUrlForVT(url) {
    if (!url) return '';
    
    try {
        // Standard base64 encode
        const base64 = btoa(url);
        
        // Convert to URL-safe base64
        const urlSafe = base64
            .replace(/\+/g, '-')  // Replace + with -
            .replace(/\//g, '_')  // Replace / with _
            .replace(/=/g, '');   // Remove padding
        
        return urlSafe;
    } catch (error) {
        console.error('Error encoding URL:', error);
        throw new Error('Failed to encode URL');
    }
}

/**
 * Decode URL from VirusTotal format
 * @param {string} encoded - Base64-encoded URL ID
 * @returns {string} Decoded URL
 */
export function decodeUrlFromVT(encoded) {
    if (!encoded) return '';
    
    try {
        // Convert URL-safe base64 back to standard base64
        let base64 = encoded
            .replace(/-/g, '+')   // Replace - with +
            .replace(/_/g, '/');  // Replace _ with /
        
        // Add padding if needed
        const padding = '='.repeat((4 - (base64.length % 4)) % 4);
        base64 += padding;
        
        // Decode base64
        return atob(base64);
    } catch (error) {
        console.error('Error decoding URL:', error);
        return encoded; // Return original if decode fails
    }
}

/**
 * Validate if string is a valid base64-encoded URL ID
 * @param {string} str - String to validate
 * @returns {boolean} True if valid URL ID
 */
export function isValidUrlId(str) {
    if (!str || typeof str !== 'string') return false;
    
    // URL-safe base64 should only contain: A-Z, a-z, 0-9, -, _
    return /^[A-Za-z0-9_-]+$/.test(str);
}
