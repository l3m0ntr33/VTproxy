/**
 * VTproxy - Landing Page
 */

import { getApiKey, saveApiKey, clearApiKey, hasApiKey } from './utils/storage.js';
import { detectInputType, validateInput, getTypeLabel } from './utils/inputDetector.js';
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

// ==================== Initialization ====================

/**
 * Initialize the application
 */
function init() {
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
    
    // Close modal on overlay click
    apiKeyModal.addEventListener('click', (e) => {
        if (e.target === apiKeyModal || e.target.classList.contains('modal-overlay')) {
            closeApiKeyModal();
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
        handleSearch();
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
function handleOpenInVT() {
    const input = searchInput.value.trim();
    
    // Validate input
    const validation = validateInput(input);
    if (!validation.valid) {
        showToast(validation.message, 'error');
        return;
    }
    
    // Generate VT URL based on type
    const vtUrl = generateVTUrl(validation.type, input);
    
    // Open in new tab
    window.open(vtUrl, '_blank');
    showToast('Opening in VirusTotal...', 'info');
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

// ==================== Toast Notifications ====================

/**
 * Show toast notification
 * @param {string} message - Toast message
 * @param {string} type - Toast type: 'success', 'error', 'info'
 */
function showToast(message, type = 'info') {
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    
    // Auto-hide after 3 seconds
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

// ==================== Start Application ====================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
