/**
 * VTproxy - Landing Page
 */

import { getApiKey, saveApiKey, clearApiKey, hasApiKey } from './utils/storage.js';
import { detectInputType, validateInput, getTypeLabel, detectHashType } from './utils/inputDetector.js';
import { encodeUrlForVT } from './api/urlEncoder.js';
import { processDefangedInput, getDefangingMessage } from './utils/defanger.js';
import { 
    parseMultilineInput, 
    processBatchInput, 
    isBatchInput, 
    getBatchSummary, 
    getBatchErrorDetails,
    processBatchForVT,
    openMultipleTabs
} from './utils/batchProcessor.js';

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
let isBatchMode = false; // Track if we're in batch mode

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
    searchInput.addEventListener('paste', handlePaste);
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
    // Don't prompt for API key if CORS is disabled (API won't work anyway)
    if (isApiDisabledDueToCors) {
        return;
    }
    
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
        isBatchMode = false;
        return;
    }
    
    // Check if we're in batch mode
    isBatchMode = isBatchInput(input);
    
    if (isBatchMode) {
        // Process batch input
        const batchResults = processBatchInput(input);
        const summary = getBatchSummary(batchResults);
        
        typeIndicator.textContent = summary;
        typeIndicator.classList.remove('hidden');
        
        // Show defanged restoration message for batch if any items were defanged
        const defangedItems = batchResults.valid.filter(item => item.wasDefanged);
        if (defangedItems.length > 0) {
            // List the defanged items that were restored
            const defangedList = defangedItems.map(item => `"${item.originalLine}" → "${item.processed.input}"`).join(', ');
            showToast(`${defangedItems.length} defanged input${defangedItems.length > 1 ? 's' : ''} restored: ${defangedList}`, 'info', 3000);
        }
    } else {
        // Single input mode
        const processed = processDefangedInput(input);
        const type = detectInputType(processed.input);
        
        if (type !== 'unknown') {
            let message = `Detected: ${getTypeLabel(type)}`;
            if (processed.wasDefanged) {
                message += ` (defanged input restored)`;
            }
            typeIndicator.textContent = message;
            typeIndicator.classList.remove('hidden');
            
            // Show defanged restoration message in toast if defanged
            if (processed.wasDefanged) {
                const defangingMessage = getDefangingMessage(processed.original, processed.input);
                if (defangingMessage) {
                    // Briefly show the defanging message
                    showToast(defangingMessage, 'info', 2000);
                }
            }
        } else {
            typeIndicator.classList.add('hidden');
        }
    }
}

/**
 * Handle paste event to detect batch content
 */
function handlePaste(e) {
    // Use setTimeout to get the pasted content after it's inserted
    setTimeout(() => {
        handleInputChange();
    }, 10);
}

/**
 * Handle Enter key press
 */
function handleKeyPress(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        // Prevent default to avoid new line in single-item mode
        e.preventDefault();
        
        // If API is disabled due to CORS, use VT button instead
        if (isApiDisabledDueToCors) {
            handleOpenInVT();
        } else {
            handleSearch();
        }
    }
    // Allow Shift+Enter to create new lines in textarea
}

/**
 * Handle search
 */
function handleSearch() {
    const input = searchInput.value.trim();
    
    if (!input) {
        showToast('Please enter a file hash, URL, domain, or IP address', 'error');
        return;
    }
    
    if (isBatchMode) {
        // Handle batch search
        handleBatchSearch();
    } else {
        // Handle single search
        handleSingleSearch();
    }
}

/**
 * Handle single item search
 */
function handleSingleSearch() {
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
    
    // Use the processed input for navigation
    const processedInput = validation.processed || input;
    
    // Show defanged message if applicable
    if (validation.wasDefanged) {
        const defangingMessage = getDefangingMessage(validation.original, validation.processed);
        if (defangingMessage) {
            showToast(defangingMessage, 'info', 3000);
        }
    }
    
    // Navigate to results page
    navigateToResults(validation.type, processedInput);
}

/**
 * Handle batch search
 */
async function handleBatchSearch() {
    const input = searchInput.value.trim();
    
    // Process batch input
    const batchResults = processBatchInput(input);
    
    if (batchResults.valid.length === 0) {
        showToast('No valid items found to process', 'error');
        return;
    }
    
    // Show error details for invalid items if any
    if (batchResults.invalid.length > 0) {
        const errorDetails = getBatchErrorDetails(batchResults.invalid);
        showToast(errorDetails, 'warning', 5000);
    }
    
    // Check if API key exists
    if (!hasApiKey()) {
        showToast('Please configure your API key first', 'error');
        openApiKeyModal();
        return;
    }
    
    // Show progress message
    showToast(`Processing ${batchResults.valid.length} items...`, 'info');
    
    // Process batch and open results
    try {
        await processBatchAndOpenResults(batchResults.valid);
    } catch (error) {
        console.error('Batch processing failed:', error);
        showToast('Batch processing failed. Please try again.', 'error');
    }
}

/**
 * Process batch items and open results in multiple tabs
 */
async function processBatchAndOpenResults(validItems) {
    const urls = [];
    
    // Generate URLs for all valid items
    for (const item of validItems) {
        const baseUrl = 'result.html';
        let id = item.processed.input;
        
        // For URLs, encode them
        if (item.validation.type === 'url') {
            try {
                id = encodeUrlForVT(item.processed.input);
            } catch (error) {
                console.error('Failed to encode URL:', item.processed.input);
                continue;
            }
        }
        
        const url = `${baseUrl}?type=${item.validation.type}&id=${encodeURIComponent(id)}`;
        urls.push(url);
    }
    
    // Try to open tabs, fallback to clipboard if blocked
    let openedCount = 0;
    const totalCount = urls.length;
    let popupBlocked = false;
    
    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        
        try {
            const newWindow = window.open(url, '_blank');
            if (newWindow === null || typeof newWindow === 'undefined') {
                popupBlocked = true;
                break;
            }
            openedCount++;
            
            // Update progress
            if (i === 0 || i === urls.length - 1 || i % 5 === 0) {
                showToast(`Opened ${openedCount}/${totalCount} tabs...`, 'info', 1000);
            }
        } catch (error) {
            console.error('Failed to open tab:', url, error);
            popupBlocked = true;
            break;
        }
        
        // Add small delay between openings
        if (i < urls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }
    
    // If popup was blocked, offer clipboard alternative
    if (popupBlocked && urls.length > openedCount) {
        const remainingUrls = urls.slice(openedCount);
        await offerClipboardAlternative(remainingUrls, totalCount, openedCount);
    } else {
        // Show final success message
        showToast(`Successfully opened ${openedCount} tabs`, 'success', 3000);
    }
}

/**
 * Offer clipboard alternative when popup blocker is detected
 */
async function offerClipboardAlternative(urls, totalCount, openedCount) {
    const urlsText = urls.join('\n');
    
    try {
        await navigator.clipboard.writeText(urlsText);
        
        const message = `Popup blocker detected! ${openedCount} tabs opened successfully.\n\n` +
                       `The remaining ${urls.length} URLs have been copied to your clipboard.\n\n` +
                       `You can paste them in your browser to open them manually.`;
        
        showToast(message, 'warning', 8000);
        
        // Also show in a more user-friendly way
        setTimeout(() => {
            alert(`${message}\n\nURLs copied to clipboard:\n${urlsText}`);
        }, 1000);
        
    } catch (clipboardError) {
        console.error('Failed to copy to clipboard:', clipboardError);
        
        // Fallback: show URLs in a modal or alert
        const message = `Popup blocker detected! ${openedCount} tabs opened successfully.\n\n` +
                       `Please copy these URLs manually to open the remaining ${urls.length} items:`;
        
        alert(`${message}\n\n${urlsText}`);
    }
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
    
    if (!input) {
        showToast('Please enter a file hash, URL, domain, or IP address', 'error');
        return;
    }
    
    if (isBatchMode) {
        // Handle batch VT opening
        await handleBatchOpenInVT();
    } else {
        // Handle single VT opening
        await handleSingleOpenInVT();
    }
}

/**
 * Handle single item VT opening
 */
async function handleSingleOpenInVT() {
    const input = searchInput.value.trim();
    
    // Validate input
    const validation = validateInput(input);
    if (!validation.valid) {
        showToast(validation.message, 'error');
        return;
    }
    
    // Use the processed input for VT
    const vtInput = validation.processed || input;
    
    // Show defanged message if applicable
    if (validation.wasDefanged) {
        const defangingMessage = getDefangingMessage(validation.original, validation.processed);
        if (defangingMessage) {
            showToast(defangingMessage, 'info', 3000);
        }
    }
    
    // Check if it's MD5 or SHA-1 hash and show warning
    if (validation.type === 'hash') {
        const hashType = detectHashType(vtInput);
        if (hashType === 'md5' || hashType === 'sha1') {
            showHashWarning(hashType, validation.type, vtInput);
            return;
        }
    }
    
    // Open in VirusTotal
    openInVirusTotal(validation.type, vtInput);
}

/**
 * Handle batch VT opening
 */
async function handleBatchOpenInVT() {
    const input = searchInput.value.trim();
    
    // Process batch input
    const batchResults = processBatchInput(input);
    
    if (batchResults.valid.length === 0) {
        showToast('No valid items found to process', 'error');
        return;
    }
    
    // Show error details for invalid items if any
    if (batchResults.invalid.length > 0) {
        const errorDetails = getBatchErrorDetails(batchResults.invalid);
        showToast(errorDetails, 'warning', 5000);
    }
    
    // Show progress message
    showToast(`Opening ${batchResults.valid.length} items in VirusTotal...`, 'info');
    
    // Generate VT URLs and open tabs
    const urls = [];
    
    for (const item of batchResults.valid) {
        try {
            const url = generateVTUrl(item.validation.type, item.processed.input);
            urls.push(url);
        } catch (error) {
            console.error('Failed to generate VT URL for item:', item, error);
        }
    }
    
    // Open all VT URLs with progress feedback
    let openedCount = 0;
    const totalCount = urls.length;
    let popupBlocked = false;
    
    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        
        try {
            const newWindow = window.open(url, '_blank');
            if (newWindow === null || typeof newWindow === 'undefined') {
                popupBlocked = true;
                break;
            }
            openedCount++;
            
            // Update progress
            if (i === 0 || i === urls.length - 1 || i % 3 === 0) {
                showToast(`Opened ${openedCount}/${totalCount} VT tabs...`, 'info', 1000);
            }
        } catch (error) {
            console.error('Failed to open VT tab:', url, error);
            popupBlocked = true;
            break;
        }
        
        // Add delay between VT openings
        if (i < urls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 200));
        }
    }
    
    // If popup was blocked, offer clipboard alternative
    if (popupBlocked && urls.length > openedCount) {
        const remainingUrls = urls.slice(openedCount);
        await offerClipboardAlternative(remainingUrls, totalCount, openedCount);
    } else {
        // Show final success message
        showToast(`Successfully opened ${openedCount} VirusTotal tabs`, 'success', 3000);
    }
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
