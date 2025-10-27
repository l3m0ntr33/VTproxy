/**
 * LocalStorage management for API key
 */

const API_KEY_STORAGE_KEY = 'vt_api_key';

/**
 * Save API key to localStorage
 * @param {string} key - VirusTotal API key
 */
export function saveApiKey(key) {
    if (!key || typeof key !== 'string') {
        throw new Error('Invalid API key');
    }
    localStorage.setItem(API_KEY_STORAGE_KEY, key.trim());
}

/**
 * Get API key from localStorage
 * @returns {string|null} API key or null if not found
 */
export function getApiKey() {
    return localStorage.getItem(API_KEY_STORAGE_KEY);
}

/**
 * Clear API key from localStorage
 */
export function clearApiKey() {
    localStorage.removeItem(API_KEY_STORAGE_KEY);
}

/**
 * Check if API key is stored
 * @returns {boolean} True if API key exists
 */
export function hasApiKey() {
    return getApiKey() !== null;
}
