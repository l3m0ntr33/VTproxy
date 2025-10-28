/**
 * VTproxy - Landing Page
 */

import { getApiKey, saveApiKey, clearApiKey, hasApiKey } from './utils/storage.js';
import { detectInputType, validateInput, getTypeLabel, detectHashType } from './utils/inputDetector.js';
import { encodeUrlForVT } from './api/urlEncoder.js';

// DOM Elements
const searchInput = document.getElementById('search-input');
const searchBtn = document.getElementById('search-btn');
const vtBtn = document.getElementById('vt-btn');
const typeIndicator = document.getElementById('type-indicator');
const apiKeyBtn = document.getElementById('api-key-btn');
const apiKeyModal = document.getElementById('api-key-modal');
const modalClose = document.getElementById('modal-close');
const apiKeyInput = document.getElementById('api-key-input');
const saveApiKeyBtn = document.getElementById('save-api-key');
const clearApiKeyBtn = document.getElementById('clear-api-key');
const apiKeyStatus = document.getElementById('api-key-status');
const toast = document.getElementById('toast');
const hashWarningModal = document.getElementById('hash-warning-modal');
const hashWarningClose = document.getElementById('hash-warning-close');
const hashWarningMessage = document.getElementById('hash-warning-message');
const hashWarningContinue = document.getElementById('hash-warning-continue');
const hashWarningCancel = document.getElementById('hash-warning-cancel');

// State
let isApiDisabledDueToCors = false;
let pendingSearchData = null; // Store search data when showing hash warning

// ==================== Initialization ====================

/**
 * Check if running on localhost
 */
function isLocalhost() {
    const hostname = window.location.hostname;
    return hostname === 'localhost' || 
           hostname === '127.0.0.1' || 
           hostname === '[::1]' ||
           hostname === '' ||
           hostname.startsWith('192.168.') ||
           hostname.startsWith('10.') ||
           hostname.startsWith('172.');
}

/**
 * Check if running in Tauri desktop app
 */
function isTauri() {
    return typeof window !== 'undefined' && window.__TAURI__ !== undefined;
}

/**
 * Check environment and show CORS warning if needed
 */
function checkEnvironment() {
    const tauri = isTauri();
    const localhost = isLocalhost();
    
    // Debug mode: force CORS warning with ?debug-cors=true
    const urlParams = new URLSearchParams(window.location.search);
    const debugCors = urlParams.get('debug-cors') === 'true';
    
    if (debugCors) {
        console.log('🧪 Debug mode: Forcing CORS warning');
    }
    
    if (!tauri && (!localhost || debugCors)) {
        // Running in browser on non-localhost domain - API won't work due to CORS
        isApiDisabledDueToCors = true;
        
        searchBtn.disabled = true;
        searchBtn.title = 'API search disabled - CORS restriction';
        searchBtn.style.opacity = '0.5';
        searchBtn.style.cursor = 'not-allowed';
        
        // Disable API key settings button
        apiKeyBtn.disabled = true;
        apiKeyBtn.title = 'API settings disabled - Not available on hosted domains due to CORS restrictions. Use localhost or desktop app.';
        apiKeyBtn.style.opacity = '0.5';
        apiKeyBtn.style.cursor = 'not-allowed';
        
        // Show warning message
        showToast('⚠️ API search disabled: VirusTotal blocks API requests from non-localhost domains due to CORS policy. Use the VT button to open in VirusTotal, or download the desktop app for full functionality.', 'warning', 10000);
        
        // Add persistent warning below search
        const warning = document.createElement('div');
        warning.className = 'cors-warning';
        warning.innerHTML = `
            <strong>⚠️ Limited Functionality</strong><br>
            API search is disabled because VirusTotal's CORS policy blocks requests from hosted domains.<br>
            <strong>Solutions:</strong>
            <ul>
                <li>✅ Use the <strong>VT button</strong> to open results in VirusTotal directly (or press <strong>Enter</strong>)</li>
                <li>✅ <a href="https://github.com/l3m0ntr33/VTproxy/releases" target="_blank" rel="noopener noreferrer" style="color: #ff6b35; text-decoration: underline;">Download the <strong>desktop app</strong></a> for full API access without restrictions</li>
                <li>✅ Run locally: <code>python3 -m http.server 8000</code> on localhost</li>
            </ul>
        `;
        warning.style.cssText = `
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(255, 107, 53, 0.1);
            border: 1px solid rgba(255, 107, 53, 0.3);
            border-radius: 8px;
            color: #ff6b35;
            font-size: 0.9rem;
            line-height: 1.6;
        `;
        warning.querySelector('ul').style.cssText = `
            margin: 0.5rem 0 0 1.5rem;
            padding: 0;
        `;
        searchInput.parentElement.parentElement.appendChild(warning);
        
        // Update placeholder to hint at Enter behavior
        searchInput.placeholder = 'Enter hash, URL, domain, or IP (press Enter to open in VirusTotal)';
        
        console.warn('🌐 Running on non-localhost domain - API features disabled due to CORS');
    } else if (tauri) {
        console.log('🚀 Running in Tauri desktop app - Full API access enabled');
    } else {
        console.log('🏠 Running on localhost - API access enabled');
    }
}

/**
 * Initialize the application
 */
function init() {
    // Check environment and show CORS warning if needed
    checkEnvironment();
    
    // Check if API key exists
    checkApiKey();
    
    // Event listeners
    searchInput.addEventListener('input', handleInputChange);
    searchInput.addEventListener('keypress', handleKeyPress);
    searchBtn.addEventListener('click', handleSearch);
    vtBtn.addEventListener('click', handleOpenInVT);
    apiKeyBtn.addEventListener('click', openApiKeyModal);
    modalClose.addEventListener('click', closeApiKeyModal);
    saveApiKeyBtn.addEventListener('click', handleSaveApiKey);
    clearApiKeyBtn.addEventListener('click', handleClearApiKey);
    hashWarningClose.addEventListener('click', closeHashWarningModal);
    hashWarningContinue.addEventListener('click', handleHashWarningContinue);
    hashWarningCancel.addEventListener('click', closeHashWarningModal);
    
    // Close modal on overlay click
    apiKeyModal.addEventListener('click', (e) => {
        if (e.target === apiKeyModal || e.target.classList.contains('modal-overlay')) {
            closeApiKeyModal();
        }
    });
    
    // Close hash warning modal on overlay click
    hashWarningModal.addEventListener('click', (e) => {
        if (e.target === hashWarningModal || e.target.classList.contains('modal-overlay')) {
            closeHashWarningModal();
        }
    });
    
    // Focus search input
    searchInput.focus();
}

// ==================== API Key Management ====================

/**
 * Check if API key is configured
 */
function checkApiKey() {
    if (!hasApiKey()) {
        // Show modal after a short delay
        setTimeout(() => {
            showToast('Please configure your VirusTotal API key to get started', 'info');
        }, 1000);
    }
}

/**
 * Open API key modal
 */
function openApiKeyModal() {
    const currentKey = getApiKey();
    if (currentKey) {
        apiKeyInput.value = currentKey;
    }
    apiKeyModal.classList.remove('hidden');
    apiKeyInput.focus();
    apiKeyStatus.classList.remove('success', 'error');
    apiKeyStatus.textContent = '';
}

/**
 * Close API key modal
 */
function closeApiKeyModal() {
    apiKeyModal.classList.add('hidden');
    apiKeyInput.value = '';
    apiKeyStatus.classList.remove('success', 'error');
    apiKeyStatus.textContent = '';
}

/**
 * Save API key
 */
function handleSaveApiKey() {
    const key = apiKeyInput.value.trim();
    
    if (!key) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = 'Please enter an API key';
        return;
    }
    
    // Basic validation: VT API keys are 64 characters hex
    if (!/^[a-fA-F0-9]{64}$/.test(key)) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = 'Invalid API key format. VT API keys are 64 hexadecimal characters.';
        return;
    }
    
    try {
        saveApiKey(key);
        apiKeyStatus.classList.remove('error');
        apiKeyStatus.classList.add('success');
        apiKeyStatus.textContent = 'API key saved successfully!';
        
        showToast('API key saved successfully', 'success');
        
        setTimeout(() => {
            closeApiKeyModal();
        }, 1500);
    } catch (error) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = error.message;
    }
}

/**
 * Clear API key
 */
function handleClearApiKey() {
    if (confirm('Are you sure you want to clear your API key?')) {
        clearApiKey();
        apiKeyInput.value = '';
        apiKeyStatus.classList.remove('error');
        apiKeyStatus.classList.add('success');
        apiKeyStatus.textContent = 'API key cleared';
        
        showToast('API key cleared', 'info');
        
        setTimeout(() => {
            closeApiKeyModal();
        }, 1500);
    }
}

// ==================== Search Functionality ====================

/**
 * Handle input change - detect type
 */
function handleInputChange() {
    const input = searchInput.value.trim();
    
    if (!input) {
        typeIndicator.classList.add('hidden');
        return;
    }
    
    const type = detectInputType(input);
    if (type !== 'unknown') {
        typeIndicator.textContent = `Detected: ${getTypeLabel(type)}`;
        typeIndicator.classList.remove('hidden');
    } else {
        typeIndicator.classList.add('hidden');
    }
}

/**
 * Handle Enter key press
 */
function handleKeyPress(e) {
    if (e.key === 'Enter') {
        // If API is disabled due to CORS, use VT button instead
        if (isApiDisabledDueToCors) {
            handleOpenInVT();
        } else {
            handleSearch();
        }
    }
}

/**
 * Handle search
 */
function handleSearch() {
    const input = searchInput.value.trim();
    
    // Validate input
    const validation = validateInput(input);
    if (!validation.valid) {
        showToast(validation.message, 'error');
        return;
    }
    
    // Check if API key exists
    if (!hasApiKey()) {
        showToast('Please configure your API key first', 'error');
        openApiKeyModal();
        return;
    }
    
    // Navigate to results page
    navigateToResults(validation.type, input);
}

/**
 * Navigate to results page
 * @param {string} type - Entity type
 * @param {string} input - User input
 */
function navigateToResults(type, input) {
    let id = input;
    
    // For URLs, encode them
    if (type === 'url') {
        try {
            id = encodeUrlForVT(input);
        } catch (error) {
            showToast('Failed to encode URL', 'error');
            return;
        }
    }
    
    // Navigate to results page with parameters
    window.location.href = `result.html?type=${type}&id=${encodeURIComponent(id)}`;
}

/**
 * Handle opening in VirusTotal
 */
async function handleOpenInVT() {
    const input = searchInput.value.trim();
    
    // Validate input
    const validation = validateInput(input);
    if (!validation.valid) {
        showToast(validation.message, 'error');
        return;
    }
    
    // Check if it's MD5 or SHA-1 hash and show warning
    if (validation.type === 'hash') {
        const hashType = detectHashType(input);
        if (hashType === 'md5' || hashType === 'sha1') {
            showHashWarning(hashType, validation.type, input);
            return;
        }
    }
    
    // Open in VirusTotal
    openInVirusTotal(validation.type, input);
}

/**
 * Generate VirusTotal URL based on type
 * @param {string} type - Entity type (ip, domain, url, hash)
 * @param {string} input - User input
 * @returns {string} VirusTotal URL
 */
function generateVTUrl(type, input) {
    const baseUrl = 'https://www.virustotal.com/gui';
    
    switch (type) {
        case 'ip':
            return `${baseUrl}/ip-address/${input}`;
        
        case 'domain':
            return `${baseUrl}/domain/${input}`;
        
        case 'hash':
            return `${baseUrl}/file/${input}`;
        
        case 'url':
            // For URLs, we need to encode them to get the URL ID
            try {
                const urlId = encodeUrlForVT(input);
                return `${baseUrl}/url/${urlId}`;
            } catch (error) {
                throw new Error('Failed to encode URL for VirusTotal');
            }
        
        default:
            throw new Error('Unknown input type');
    }
}

// ==================== Hash Warning Modal ====================

/**
 * Open in VirusTotal (actual implementation)
 */
async function openInVirusTotal(type, input) {
    // Generate VT URL based on type
    const vtUrl = generateVTUrl(type, input);
    
    // Open in new tab/browser
    try {
        if (window.__TAURI__) {
            // Use Tauri shell API for desktop app
            const { open } = window.__TAURI__.shell;
            await open(vtUrl);
            showToast('Opening in VirusTotal...', 'success');
        } else {
            // Use window.open for browser
            window.open(vtUrl, '_blank');
            showToast('Opening in VirusTotal...', 'info');
        }
    } catch (error) {
        console.error('Failed to open VirusTotal:', error);
        showToast('Failed to open VirusTotal', 'error');
    }
}

/**
 * Show hash warning modal for MD5/SHA-1
 */
function showHashWarning(hashType, type, input) {
    const hashTypeLabel = hashType.toUpperCase();
    hashWarningMessage.innerHTML = `You are about to open a ${hashTypeLabel} hash in VirusTotal. This will consume your search quota if you have a Premium VirusTotal API account. <strong style="color: #ff6b35;">Consider using SHA-256 instead</strong> for direct file access without quota consumption.`;
    
    // Store pending search data
    pendingSearchData = { type, input };
    
    hashWarningModal.classList.remove('hidden');
}

/**
 * Close hash warning modal
 */
function closeHashWarningModal() {
    hashWarningModal.classList.add('hidden');
    pendingSearchData = null;
}

/**
 * Continue with opening in VT after hash warning
 */
function handleHashWarningContinue() {
    if (pendingSearchData) {
        const { type, input } = pendingSearchData;
        closeHashWarningModal();
        openInVirusTotal(type, input);
    }
}

// ==================== Toast Notifications ====================

/**
 * Show toast notification
 * @param {string} message - Toast message
 * @param {string} type - Toast type: 'success', 'error', 'info', 'warning'
 * @param {number} duration - Duration in milliseconds (default: 3000)
 */
function showToast(message, type = 'info', duration = 3000) {
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    
    // Auto-hide after specified duration
    setTimeout(() => {
        toast.classList.add('hidden');
    }, duration);
}

// ==================== Start Application ====================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
