/**
 * VTproxy - Results Page
 */

import { VTClient } from '../api/client.js';
import { getApiKey, saveApiKey, clearApiKey } from '../utils/storage.js';
import { decodeUrlFromVT, encodeUrlForVT } from '../api/urlEncoder.js';
import { 
    formatTimestamp, 
    timeAgo, 
    formatFileSize, 
    getDetectionSeverity,
    getStatusClass,
    formatNumber
} from '../utils/formatters.js';
import {
    createPropertyRow,
    createExpandableSection,
    createKeyValueList,
    createEmptyState,
    createList,
    escapeHtml
} from '../components/dataDisplay.js';

// DOM Elements
const loading = document.getElementById('loading');
const errorContainer = document.getElementById('error-container');
const errorTitle = document.getElementById('error-title');
const errorMessage = document.getElementById('error-message');
const retryBtn = document.getElementById('retry-btn');
const resultsContainer = document.getElementById('results-container');
const detectionCircle = document.getElementById('detection-circle');
const entityInfo = document.getElementById('entity-info');
const entityMeta = document.getElementById('entity-meta');
const alertBanner = document.getElementById('alert-banner');
const tabNav = document.getElementById('tab-nav');
const tabContent = document.getElementById('tab-content');
const toast = document.getElementById('toast');

// API Key Modal elements
const apiKeyBtn = document.getElementById('api-key-btn');
const apiKeyModal = document.getElementById('api-key-modal');
const modalClose = document.getElementById('modal-close');
const apiKeyInput = document.getElementById('api-key-input');
const saveApiKeyBtn = document.getElementById('save-api-key');
const clearApiKeyBtn = document.getElementById('clear-api-key');
const apiKeyStatus = document.getElementById('api-key-status');

// Header search elements
const headerSearchInput = document.getElementById('header-search-input');
const headerSearchBtn = document.getElementById('header-search-btn');

// Global state
let currentData = null;
let currentType = null;
let currentId = null;
let vtClient = null;

// ==================== Initialization ====================

/**
 * Initialize results page
 */
async function init() {
    // Set up event listeners
    setupEventListeners();
    
    // Get URL parameters
    const params = getUrlParams();
    if (!params.type || !params.id) {
        showError('Invalid URL', 'Missing type or ID parameter');
        return;
    }
    
    currentType = params.type;
    currentId = params.id;
    
    // Check API key
    const apiKey = getApiKey();
    if (!apiKey) {
        showError('API Key Required', 'Please configure your VirusTotal API key');
        openApiKeyModal();
        return;
    }
    
    // Initialize VT client
    vtClient = new VTClient(apiKey);
    
    // Load data
    await loadData();
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    retryBtn.addEventListener('click', () => location.reload());
    apiKeyBtn.addEventListener('click', openApiKeyModal);
    modalClose.addEventListener('click', closeApiKeyModal);
    saveApiKeyBtn.addEventListener('click', handleSaveApiKey);
    clearApiKeyBtn.addEventListener('click', handleClearApiKey);
    headerSearchBtn.addEventListener('click', handleHeaderSearch);
    headerSearchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleHeaderSearch();
    });
    
    // Close modal on overlay click
    apiKeyModal.addEventListener('click', (e) => {
        if (e.target === apiKeyModal || e.target.classList.contains('modal-overlay')) {
            closeApiKeyModal();
        }
    });
}

/**
 * Get URL parameters
 * @returns {{type: string, id: string}}
 */
function getUrlParams() {
    const params = new URLSearchParams(window.location.search);
    return {
        type: params.get('type'),
        id: params.get('id')
    };
}

// ==================== Data Loading ====================

/**
 * Load data based on type
 */
async function loadData() {
    showLoading();
    
    try {
        let data;
        
        switch (currentType) {
            case 'file':
            case 'hash':
                data = await vtClient.getFile(currentId);
                break;
            case 'url':
                data = await vtClient.getUrl(currentId);
                break;
            case 'domain':
                data = await vtClient.getDomain(currentId);
                break;
            case 'ip':
                data = await vtClient.getIp(currentId);
                break;
            default:
                throw new Error('Unknown entity type');
        }
        
        currentData = data.data;
        renderResults();
    } catch (error) {
        console.error('Error loading data:', error);
        showError('Error Loading Data', error.message);
    }
}

// ==================== Rendering ====================

/**
 * Render results
 */
function renderResults() {
    hideLoading();
    hideError();
    resultsContainer.classList.remove('hidden');
    
    // Render detection circle
    renderDetectionCircle();
    
    // Render entity info
    renderEntityInfo();
    
    // Render alert banner
    renderAlertBanner();
    
    // Render tabs
    renderTabs();
}

/**
 * Render detection circle
 */
function renderDetectionCircle() {
    const stats = currentData.attributes.last_analysis_stats;
    if (!stats) return;
    
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const harmless = stats.harmless || 0;
    
    const total = malicious + suspicious + undetected + harmless;
    const percentage = total > 0 ? (malicious / total) * 100 : 0;
    const severity = getDetectionSeverity(malicious, total);
    const offset = 283 - (283 * percentage / 100);
    
    detectionCircle.innerHTML = `
        <div class="detection-circle ${severity}">
            <svg width="120" height="120" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="45" class="circle-bg"/>
                <circle cx="50" cy="50" r="45" class="circle-fill" 
                    style="stroke-dashoffset: ${offset}"/>
            </svg>
            <div class="circle-text">
                <span class="score">${malicious}</span>
                <span class="divider">/</span>
                <span class="total">${total}</span>
            </div>
        </div>
    `;
}

/**
 * Render entity info
 */
function renderEntityInfo() {
    let title = '';
    let subtitle = '';
    let extraBadges = '';
    const attrs = currentData.attributes;
    
    switch (currentType) {
        case 'file':
        case 'hash':
            title = attrs.meaningful_name || 
                    attrs.names?.[0] || 
                    currentData.id;
            subtitle = `SHA-256: ${escapeHtml(attrs.sha256 || currentData.id)}`;
            break;
        case 'url':
            const decodedUrl = decodeUrlFromVT(currentId);
            title = attrs.url || decodedUrl;
            
            // Extract hostname from URL and create clickable link
            try {
                const urlObj = new URL(title);
                const hostname = urlObj.hostname;
                
                // Detect if hostname is an IP address or domain
                const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
                const linkType = isIp ? 'ip' : 'domain';
                const linkHref = `result.html?type=${linkType}&id=${encodeURIComponent(hostname)}`;
                
                subtitle = `<a href="${linkHref}" class="hostname-link">${escapeHtml(hostname)}</a>`;
            } catch (e) {
                // If URL parsing fails, just show the URL
                subtitle = attrs.url || decodedUrl;
            }
            
            // Build badges for tags only (below URL)
            const badges = [];
            
            // Tags (limit to first 8 tags)
            if (attrs.tags && attrs.tags.length > 0) {
                const tagsToShow = attrs.tags.slice(0, 8);
                tagsToShow.forEach(tag => {
                    badges.push(`<span class="info-badge badge-tag">${escapeHtml(tag)}</span>`);
                });
                
                // Show "+X more" if there are additional tags
                if (attrs.tags.length > 8) {
                    const remaining = attrs.tags.length - 8;
                    badges.push(`<span class="info-badge badge-more">+${remaining} more</span>`);
                }
            }
            
            if (badges.length > 0) {
                extraBadges = `<div class="info-badges">${badges.join('')}</div>`;
            }
            break;
        case 'domain':
            title = currentId;
            subtitle = 'Domain';
            break;
        case 'ip':
            title = currentId;
            subtitle = 'IP Address';
            break;
    }
    
    entityInfo.innerHTML = `
        <h2>${escapeHtml(title)}</h2>
        <p class="text-secondary">${subtitle}</p>
        ${extraBadges}
    `;
    
    // Render metadata badges
    renderEntityMeta();
}

/**
 * Render entity metadata badges (right side only)
 */
function renderEntityMeta() {
    const badges = [];
    const attrs = currentData.attributes;
    
    // File-specific metadata
    if (currentType === 'file' || currentType === 'hash') {
        if (attrs.size) {
            badges.push(`<span class="meta-badge">${formatFileSize(attrs.size)}</span>`);
        }
        if (attrs.type_description) {
            badges.push(`<span class="meta-badge">${escapeHtml(attrs.type_description)}</span>`);
        }
    }
    
    // URL-specific metadata
    if (currentType === 'url') {
        // Content-Type - extract from headers to match what's shown in Headers section
        let contentType = 'N/A';
        
        if (attrs.last_http_response_headers) {
            // Try different header key variations
            const headers = attrs.last_http_response_headers;
            contentType = headers['Content-Type'] || 
                         headers['content-type'] || 
                         headers['Content-type'] || 
                         attrs.last_http_response_content_type ||
                         'N/A';
        } else if (attrs.last_http_response_content_type) {
            contentType = attrs.last_http_response_content_type;
        }
        
        badges.push(`<span class="meta-badge">Content-Type: ${escapeHtml(contentType)}</span>`);
        
        // HTTP Status Code with proper status classes
        if (attrs.last_http_response_code) {
            let statusClass = '';
            const code = attrs.last_http_response_code;
            if (code >= 200 && code < 300) {
                statusClass = 'status-success';
            } else if (code >= 300 && code < 500) {
                statusClass = 'status-warning';
            } else if (code >= 500) {
                statusClass = 'status-error';
            }
            badges.push(`<span class="meta-badge ${statusClass}">Status: ${code}</span>`);
        }
    }
    
    // Last analysis date with hover tooltip
    if (attrs.last_analysis_date) {
        const fullDate = formatTimestamp(attrs.last_analysis_date);
        const relativeDate = timeAgo(attrs.last_analysis_date);
        badges.push(`<span class="meta-badge" title="${escapeHtml(fullDate)}">Last analyzed: ${relativeDate}</span>`);
    }
    
    // Optional: Reputation badge (for URLs)
    if (currentType === 'url' && attrs.reputation !== undefined && attrs.reputation !== null) {
        const reputation = attrs.reputation;
        let reputationClass = '';
        if (reputation < 0) {
            reputationClass = 'status-error'; // Negative = malicious
        } else if (reputation > 0) {
            reputationClass = 'status-success'; // Positive = good
        }
        badges.push(`<span class="meta-badge ${reputationClass}">Reputation: ${reputation}</span>`);
    }
    
    // Optional: Times Submitted badge (for URLs)
    if (currentType === 'url' && attrs.times_submitted) {
        badges.push(`<span class="meta-badge">Submissions: ${formatNumber(attrs.times_submitted)}</span>`);
    }
    
    entityMeta.innerHTML = badges.join('');
}

/**
 * Render alert banner
 */
function renderAlertBanner() {
    const stats = currentData.attributes.last_analysis_stats;
    if (!stats) return;
    
    const malicious = stats.malicious || 0;
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + 
                  (stats.undetected || 0) + (stats.harmless || 0);
    const severity = getDetectionSeverity(malicious, total);
    
    let message = '';
    if (malicious > 0) {
        message = `${malicious} security vendor${malicious > 1 ? 's' : ''} flagged this ${currentType} as malicious`;
    } else if (stats.suspicious > 0) {
        message = `${stats.suspicious} security vendor${stats.suspicious > 1 ? 's' : ''} flagged this ${currentType} as suspicious`;
    } else {
        message = `No security vendors flagged this ${currentType} as malicious`;
    }
    
    alertBanner.className = `alert-banner ${severity}`;
    alertBanner.textContent = message;
    alertBanner.classList.remove('hidden');
}

/**
 * Render tabs
 */
function renderTabs() {
    const tabs = getTabsForType();
    
    // Render tab buttons
    tabNav.innerHTML = tabs.map((tab, index) => `
        <button class="tab-btn ${index === 0 ? 'active' : ''}" data-tab="${tab.id}">
            ${tab.label}
        </button>
    `).join('');
    
    // Render tab content
    tabContent.innerHTML = tabs.map((tab, index) => `
        <div class="tab-panel ${index === 0 ? 'active' : ''}" data-panel="${tab.id}">
            ${tab.content}
        </div>
    `).join('');
    
    // Add tab click listeners
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
}

/**
 * Get tabs configuration for entity type
 * @returns {Array} Tab configuration
 */
function getTabsForType() {
    const baseTabs = [
        { id: 'detection', label: 'Detection', content: renderDetectionTab() },
        { id: 'details', label: 'Details', content: renderDetailsTab() },
    ];
    
    const communityTab = { id: 'community', label: 'Community', content: renderCommunityTab() };
    
    // File-specific tabs
    if (currentType === 'file' || currentType === 'hash') {
        return [
            ...baseTabs,
            { id: 'behavior', label: 'Behavior', content: renderBehaviorTab() },
            communityTab
        ];
    }
    
    // URL-specific tabs
    if (currentType === 'url') {
        return [
            ...baseTabs,
            { id: 'relations', label: 'Relations', content: renderRelationsTab() },
            { id: 'content', label: 'Content', content: renderContentTab() },
            communityTab
        ];
    }
    
    // Domain and IP tabs
    return [
        ...baseTabs,
        { id: 'relations', label: 'Relations', content: renderRelationsTab() },
        communityTab
    ];
}

/**
 * Switch active tab
 * @param {string} tabId - Tab ID to activate
 */
function switchTab(tabId) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    
    // Update tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.dataset.panel === tabId);
    });
}

// ==================== Tab Content Renderers ====================

/**
 * Render detection tab content
 */
function renderDetectionTab() {
    const results = currentData.attributes.last_analysis_results;
    const stats = currentData.attributes.last_analysis_stats;
    const analysisDate = currentData.attributes.last_analysis_date;
    
    if (!results) {
        return '<p class="text-muted">No detection results available</p>';
    }
    
    // Sort vendors by detection
    const vendors = Object.entries(results).map(([name, result]) => ({
        name,
        ...result
    })).sort((a, b) => {
        const order = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout', 'failure'];
        return order.indexOf(a.category) - order.indexOf(b.category);
    });
    
    // Split vendors into two columns
    const midpoint = Math.ceil(vendors.length / 2);
    const leftColumn = vendors.slice(0, midpoint);
    const rightColumn = vendors.slice(midpoint);
    
    const leftRows = leftColumn.map(vendor => `
        <tr>
            <td>${escapeHtml(vendor.engine_name || vendor.name)}</td>
            <td class="${getStatusClass(vendor.category)}">
                ${escapeHtml(vendor.result || vendor.category || 'Undetected')}
            </td>
        </tr>
    `).join('');
    
    const rightRows = rightColumn.map(vendor => `
        <tr>
            <td>${escapeHtml(vendor.engine_name || vendor.name)}</td>
            <td class="${getStatusClass(vendor.category)}">
                ${escapeHtml(vendor.result || vendor.category || 'Undetected')}
            </td>
        </tr>
    `).join('');
    
    // Analysis timestamp header
    const timestampHeader = analysisDate 
        ? `<div class="analysis-timestamp">Last analysis: ${formatTimestamp(analysisDate)}</div>`
        : '';
    
    // Detection summary stats cards
    let statsCards = '';
    if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        const timeout = stats.timeout || 0;
        
        statsCards = `
            <div class="detection-stats-cards">
                <div class="stat-card stat-card-malicious">
                    <div class="stat-label">Malicious</div>
                    <div class="stat-value">${malicious}</div>
                </div>
                <div class="stat-card stat-card-suspicious">
                    <div class="stat-label">Suspicious</div>
                    <div class="stat-value">${suspicious}</div>
                </div>
                <div class="stat-card stat-card-harmless">
                    <div class="stat-label">Harmless</div>
                    <div class="stat-value">${harmless}</div>
                </div>
                <div class="stat-card stat-card-undetected">
                    <div class="stat-label">Undetected</div>
                    <div class="stat-value">${undetected}</div>
                </div>
                <div class="stat-card stat-card-timeout">
                    <div class="stat-label">Timeout</div>
                    <div class="stat-value">${timeout}</div>
                </div>
            </div>
        `;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Security Vendors' Analysis</h3>
            </div>
            <div class="card-body">
                ${timestampHeader}
                ${statsCards}
                <div class="vendors-grid">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Vendor</th>
                                <th>Detection</th>
                            </tr>
                        </thead>
                        <tbody>${leftRows}</tbody>
                    </table>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Vendor</th>
                                <th>Detection</th>
                            </tr>
                        </thead>
                        <tbody>${rightRows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Render details tab content
 */
function renderDetailsTab() {
    const attrs = currentData.attributes;
    
    switch (currentType) {
        case 'file':
        case 'hash':
            return renderFileDetails(attrs);
        case 'url':
            return renderUrlDetails(attrs);
        case 'domain':
            return renderDomainDetails(attrs);
        case 'ip':
            return renderIpDetails(attrs);
        default:
            return createEmptyState('No details available');
    }
}

/**
 * Render file details
 */
function renderFileDetails(attrs) {
    // Basic properties
    const basicProps = [
        createPropertyRow('MD5', attrs.md5, true),
        createPropertyRow('SHA-1', attrs.sha1, true),
        createPropertyRow('SHA-256', attrs.sha256, true),
        createPropertyRow('File size', formatFileSize(attrs.size)),
        createPropertyRow('File type', attrs.type_description),
        createPropertyRow('Magic', attrs.magic),
        createPropertyRow('TrID', attrs.trid?.[0]?.file_type),
    ].join('');
    
    // Names
    const names = attrs.names && attrs.names.length > 0
        ? createList(attrs.names, 5)
        : createEmptyState('No file names available');
    
    // Timestamps
    const timestamps = [
        createPropertyRow('First submission', formatTimestamp(attrs.first_submission_date)),
        createPropertyRow('Last submission', formatTimestamp(attrs.last_submission_date)),
        createPropertyRow('Last analysis', formatTimestamp(attrs.last_analysis_date)),
        createPropertyRow('Last modification', formatTimestamp(attrs.last_modification_date)),
    ].join('');
    
    // Signature info
    let signatureSection = '';
    if (attrs.signature_info) {
        const sigProps = [
            createPropertyRow('Signed', attrs.signature_info.verified || 'No'),
            createPropertyRow('Signers', attrs.signature_info.signers),
            createPropertyRow('Subject', attrs.signature_info.subject),
        ].join('');
        signatureSection = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Signature Information</h3>
                </div>
                <div class="card-body">${sigProps}</div>
            </div>
        `;
    }
    
    // PE info (if available)
    let peSection = '';
    if (attrs.pe_info) {
        const peProps = [
            createPropertyRow('Entry point', attrs.pe_info.entry_point),
            createPropertyRow('Machine type', attrs.pe_info.machine_type),
            createPropertyRow('Compilation timestamp', formatTimestamp(attrs.pe_info.timestamp)),
            createPropertyRow('Imphash', attrs.pe_info.imphash, true),
        ].join('');
        peSection = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">PE Information</h3>
                </div>
                <div class="card-body">${peProps}</div>
            </div>
        `;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Basic Properties</h3>
            </div>
            <div class="card-body">${basicProps}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">File Names</h3>
            </div>
            <div class="card-body">${names}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">History</h3>
            </div>
            <div class="card-body">${timestamps}</div>
        </div>
        
        ${signatureSection}
        ${peSection}
    `;
}

/**
 * Render URL details (matching VT format)
 */
function renderUrlDetails(attrs) {
    // Categories section - grid layout like VT
    const categories = attrs.categories || {};
    let categoriesSection = '';
    if (Object.keys(categories).length > 0) {
        const categoryGrid = Object.entries(categories)
            .map(([vendor, category]) => `
                <div class="category-item">
                    <div class="category-vendor">${escapeHtml(vendor)}</div>
                    <div class="category-label">${escapeHtml(category)}</div>
                </div>
            `).join('');
        categoriesSection = `<div class="categories-grid">${categoryGrid}</div>`;
    } else {
        categoriesSection = createEmptyState('No categories available');
    }
    
    // History section - use UTC format
    const formatUTC = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp * 1000);
        return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
    };
    
    const historyProps = [
        createPropertyRow('First submission', formatUTC(attrs.first_submission_date)),
        createPropertyRow('Last submission', formatUTC(attrs.last_submission_date)),
        createPropertyRow('Last modification', formatUTC(attrs.last_modification_date || attrs.last_analysis_date)),
    ].join('');
    
    // HTTP Response section
    // Serving IP with fetch button
    const servingIpButton = `
        <button id="fetch-serving-ip-btn" class="btn-fetch-small" onclick="fetchServingIpOnDemand('${currentId}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"></path>
                <path d="M21 3v5h-5"></path>
            </svg>
            Fetch IP
        </button>
    `;
    
    const httpResponseProps = [
        createPropertyRow('Final URL', attrs.last_final_url || attrs.url),
        `<div class="property-row">
            <div class="property-label">Serving IP Address</div>
            <div class="property-value" id="serving-ip-value">${servingIpButton}</div>
        </div>`,
        createPropertyRow('Status Code', attrs.last_http_response_code),
        createPropertyRow('Body Length', attrs.last_http_response_content_length ? formatFileSize(attrs.last_http_response_content_length) : 'N/A'),
        createPropertyRow('Body SHA-256', attrs.last_http_response_content_sha256, true),
    ].join('');
    
    // Headers section
    let headersSection = '';
    if (attrs.last_http_response_headers) {
        const headers = Object.entries(attrs.last_http_response_headers)
            .map(([key, value]) => createPropertyRow(key, value))
            .join('');
        headersSection = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Headers</h3>
                </div>
                <div class="card-body">${headers}</div>
            </div>
        `;
    }
    
    // HTML Info section (Title + Meta Tags)
    let htmlInfoSection = '';
    const htmlInfoItems = [];
    
    if (attrs.title) {
        htmlInfoItems.push(createPropertyRow('Title', attrs.title));
    }
    
    // Meta Tags - values are arrays, show first element
    if (attrs.html_meta && Object.keys(attrs.html_meta).length > 0) {
        htmlInfoItems.push('<div style="margin-top: 1rem;"><strong>Meta Tags</strong></div>');
        Object.entries(attrs.html_meta).forEach(([key, value]) => {
            // Values are arrays, extract first element
            const displayValue = Array.isArray(value) ? value[0] : value;
            htmlInfoItems.push(createPropertyRow(key, displayValue || 'N/A'));
        });
    }
    
    if (htmlInfoItems.length > 0) {
        htmlInfoSection = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">HTML Info</h3>
                </div>
                <div class="card-body">${htmlInfoItems.join('')}</div>
            </div>
        `;
    }
    
    // Redirection chain section
    let redirectionSection = '';
    if (attrs.redirection_chain && attrs.redirection_chain.length > 0) {
        if (attrs.redirection_chain.length > 1) {
            // Multiple redirects - show with arrows
            const redirectList = attrs.redirection_chain
                .map((url, index) => `
                    <div class="redirect-item">
                        <span class="redirect-index">${index + 1}.</span>
                        <span class="redirect-url">${escapeHtml(url)}</span>
                    </div>
                    ${index < attrs.redirection_chain.length - 1 ? '<div class="redirect-arrow">↓</div>' : ''}
                `).join('');
            redirectionSection = `
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Redirection chain</h3>
                    </div>
                    <div class="card-body">
                        <div class="redirection-chain">${redirectList}</div>
                    </div>
                </div>
            `;
        } else {
            // Single URL - just show it
            redirectionSection = `
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Redirection chain</h3>
                    </div>
                    <div class="card-body">
                        <div class="redirect-url" style="font-family: 'Courier New', monospace; word-break: break-all;">${escapeHtml(attrs.redirection_chain[0])}</div>
                    </div>
                </div>
            `;
        }
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Categories</h3>
            </div>
            <div class="card-body">${categoriesSection}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">History</h3>
            </div>
            <div class="card-body">${historyProps}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">HTTP Response</h3>
            </div>
            <div class="card-body">${httpResponseProps}</div>
        </div>
        
        ${headersSection}
        ${htmlInfoSection}
        ${redirectionSection}
    `;
}

/**
 * Render domain details
 */
function renderDomainDetails(attrs) {
    const basicProps = [
        createPropertyRow('Domain', currentId),
        createPropertyRow('Registrar', attrs.registrar),
        createPropertyRow('Creation date', formatTimestamp(attrs.creation_date)),
        createPropertyRow('Last update', formatTimestamp(attrs.last_update_date)),
        createPropertyRow('Categories', Object.keys(attrs.categories || {}).join(', ')),
        createPropertyRow('Popularity rank', attrs.popularity_ranks?.Alexa?.rank || 'N/A'),
    ].join('');
    
    const whoisProps = attrs.whois ? [
        createPropertyRow('Registrant', attrs.whois_registrant),
        createPropertyRow('Admin', attrs.whois_admin),
    ].join('') : createEmptyState('WHOIS data not available');
    
    const timestamps = [
        createPropertyRow('Last analysis', formatTimestamp(attrs.last_analysis_date)),
        createPropertyRow('Last DNS records', formatTimestamp(attrs.last_dns_records_date)),
        createPropertyRow('Last update', formatTimestamp(attrs.last_update_date)),
    ].join('');
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Basic Properties</h3>
            </div>
            <div class="card-body">${basicProps}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">WHOIS Information</h3>
            </div>
            <div class="card-body">${whoisProps}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">History</h3>
            </div>
            <div class="card-body">${timestamps}</div>
        </div>
    `;
}

/**
 * Render IP details
 */
function renderIpDetails(attrs) {
    const basicProps = [
        createPropertyRow('IP Address', currentId),
        createPropertyRow('Country', attrs.country),
        createPropertyRow('Continent', attrs.continent),
        createPropertyRow('Network', attrs.network),
        createPropertyRow('ASN', attrs.asn),
        createPropertyRow('AS Owner', attrs.as_owner),
    ].join('');
    
    const timestamps = [
        createPropertyRow('Last analysis', formatTimestamp(attrs.last_analysis_date)),
        createPropertyRow('Last modification', formatTimestamp(attrs.last_modification_date)),
    ].join('');
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Basic Properties</h3>
            </div>
            <div class="card-body">${basicProps}</div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">History</h3>
            </div>
            <div class="card-body">${timestamps}</div>
        </div>
    `;
}

/**
 * Render behavior tab content (files only)
 */
function renderBehaviorTab() {
    if (currentType !== 'file' && currentType !== 'hash') {
        return createEmptyState('Behavior analysis is only available for files');
    }
    
    // Placeholder for behavior data - will load on demand
    return `
        <div id="behavior-content">
            <button id="load-behavior-btn" class="btn-primary" onclick="loadBehaviorData()">
                Load Behavior Analysis
            </button>
            <p class="text-muted" style="margin-top: 1rem;">Click to load sandbox behavior data</p>
        </div>
    `;
}

/**
 * Render relations tab content
 */
function renderRelationsTab() {
    if (currentType !== 'url') {
        return createEmptyState('Relations view is only available for URLs');
    }
    
    const attrs = currentData.attributes;
    let sectionsHtml = '';
    
    // 1. Outgoing Links (from primary endpoint - always available)
    sectionsHtml += renderOutgoingLinks(attrs);
    
    // 2. URLs Related by Tracker ID (lazy load section)
    sectionsHtml += renderLazyLoadSection(
        'urls-related-tracker',
        'URLs related by tracker ID',
        'Load related URLs',
        'Premium feature: URLs sharing common tracker IDs'
    );
    
    // 3. Embedded JS Files (lazy load section)
    sectionsHtml += renderLazyLoadSection(
        'embedded-js-files',
        'Embedded JS Files',
        'Load JS files',
        'Premium feature: JavaScript files found in the page'
    );
    
    // 4. Downloaded Files (lazy load section)
    sectionsHtml += renderLazyLoadSection(
        'downloaded-files',
        'Downloaded Files',
        'Load files',
        'Premium feature: Files downloaded from this URL'
    );
    
    // 5. Communicating Files (lazy load section)
    sectionsHtml += renderLazyLoadSection(
        'communicating-files',
        'Communicating Files',
        'Load files',
        'Premium feature: Files that communicate with this URL'
    );
    
    return sectionsHtml;
}

/**
 * Render Outgoing Links section
 */
function renderOutgoingLinks(attrs) {
    const outgoingLinks = attrs.outgoing_links || [];
    
    if (outgoingLinks.length === 0) {
        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Outgoing Links (0)</h3>
                </div>
                <div class="card-body">
                    ${createEmptyState('No outgoing links found')}
                </div>
            </div>
        `;
    }
    
    const linksList = outgoingLinks
        .map(url => {
            // Encode URL for VT analysis
            const encodedUrl = encodeUrlForVT(url);
            return `
                <div class="outgoing-link-item">
                    <a href="result.html?type=url&id=${encodedUrl}" class="outgoing-link">
                        ${escapeHtml(url)}
                    </a>
                </div>
            `;
        }).join('');
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Outgoing Links (${outgoingLinks.length})</h3>
            </div>
            <div class="card-body">
                <div class="outgoing-links-list">${linksList}</div>
            </div>
        </div>
    `;
}

/**
 * Render lazy load section template
 */
function renderLazyLoadSection(sectionId, title, buttonText, description) {
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title" id="${sectionId}-title">${title}</h3>
            </div>
            <div class="card-body">
                <div id="${sectionId}-content" class="lazy-section-content">
                    <button class="btn-secondary" onclick="load${toCamelCase(sectionId)}()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"></path>
                            <path d="M21 3v5h-5"></path>
                        </svg>
                        ${buttonText}
                    </button>
                    <p class="text-muted" style="margin-top: 0.5rem; font-size: 0.875rem;">${description}</p>
                </div>
            </div>
        </div>
    `;
}

/**
 * Helper: Convert kebab-case to camelCase for function names
 */
function toCamelCase(str) {
    return str.replace(/-([a-z])/g, (g) => g[1].toUpperCase())
              .replace(/^./, (s) => s.toUpperCase());
}

/**
 * Render related URLs table
 */
function renderRelatedUrlsTable(urls) {
    const rows = urls.map(urlObj => {
        const attrs = urlObj.attributes;
        const stats = attrs.last_analysis_stats || {};
        
        // Calculate detection ratio
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((sum, val) => sum + (val || 0), 0);
        
        // Determine status class
        let statusClass = 'status-clean';
        if (malicious > 5) statusClass = 'status-malicious';
        else if (malicious > 0) statusClass = 'status-suspicious';
        
        // Format tags (limit to first 5)
        const tags = attrs.tags || [];
        const displayTags = tags.slice(0, 5).map(tag => 
            `<span class="relation-tag">${escapeHtml(tag)}</span>`
        ).join('');
        const moreTags = tags.length > 5 ? `<span class="relation-tag-more">+${tags.length - 5}</span>` : '';
        
        // Format date
        const date = attrs.last_analysis_date ? 
            new Date(attrs.last_analysis_date * 1000).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC') :
            'N/A';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <div class="relation-url">
                        <a href="result.html?type=url&id=${encodeURIComponent(urlObj.id)}">${escapeHtml(attrs.url || urlObj.id)}</a>
                    </div>
                    ${displayTags || moreTags ? `<div class="relation-tags">${displayTags}${moreTags}</div>` : ''}
                </div>
                <div class="relation-meta">
                    <span class="relation-detections ${statusClass}">${malicious} / ${total}</span>
                    <span class="relation-date">${date}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render embedded JS files table
 */
function renderEmbeddedJsFilesTable(files) {
    const rows = files.map(fileObj => {
        const hasError = fileObj.error !== undefined;
        const context = fileObj.context_attributes || {};
        
        // Format date from context
        const date = context.timestamp ? 
            new Date(context.timestamp * 1000).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC') :
            'N/A';
        
        if (hasError) {
            // File not in VT database
            return `
                <div class="relation-row file-row-error">
                    <div class="relation-main">
                        <div class="relation-hash">
                            <code>${escapeHtml(fileObj.id.substring(0, 16))}...</code>
                        </div>
                        <div class="relation-filename">
                            <span class="file-icon">⚠️</span> ${escapeHtml(context.filename || 'Unknown')}
                        </div>
                        <div class="relation-tags">
                            <span class="relation-tag relation-tag-error">Not in database</span>
                        </div>
                    </div>
                    <div class="relation-meta">
                        <span class="relation-detections status-unknown">-</span>
                        <span class="relation-type">JavaScript</span>
                        <span class="relation-date">${date}</span>
                    </div>
                </div>
            `;
        }
        
        // File with full data
        const attrs = fileObj.attributes;
        const stats = attrs.last_analysis_stats || {};
        
        // Calculate detection ratio
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((sum, val) => sum + (val || 0), 0);
        
        // Determine status class
        let statusClass = 'status-clean';
        if (malicious > 3) statusClass = 'status-malicious';
        else if (malicious > 0) statusClass = 'status-suspicious';
        
        // Get filename
        const filename = attrs.meaningful_name || context.filename || attrs.names?.[0] || 'Unknown';
        
        // Format tags (limit to first 5)
        const tags = attrs.tags || [];
        const displayTags = tags.slice(0, 5).map(tag => 
            `<span class="relation-tag">${escapeHtml(tag)}</span>`
        ).join('');
        const moreTags = tags.length > 5 ? `<span class="relation-tag-more">+${tags.length - 5}</span>` : '';
        
        // Format file size
        const sizeText = attrs.size ? formatFileSize(attrs.size) : '';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <div class="relation-hash">
                        <code>${escapeHtml(fileObj.id.substring(0, 16))}...</code>
                    </div>
                    <div class="relation-filename">
                        <span class="file-icon">📄</span> 
                        <a href="result.html?type=file&id=${encodeURIComponent(fileObj.id)}">${escapeHtml(filename)}</a>
                    </div>
                    ${displayTags || moreTags ? `<div class="relation-tags">${displayTags}${moreTags}</div>` : ''}
                </div>
                <div class="relation-meta">
                    <span class="relation-detections ${statusClass}">${malicious} / ${total}</span>
                    <span class="relation-type">${escapeHtml(attrs.type_description || 'JavaScript')}${sizeText ? ' • ' + sizeText : ''}</span>
                    <span class="relation-date">${date}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render generic files table (for downloaded/communicating files)
 */
function renderFilesTable(files, showDownloadContext = false) {
    const rows = files.map(fileObj => {
        const attrs = fileObj.attributes || {};
        const context = fileObj.context_attributes || {};
        const stats = attrs.last_analysis_stats || {};
        
        // Calculate detection ratio
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((sum, val) => sum + (val || 0), 0);
        
        // Determine status class and risk level
        let statusClass = 'status-clean';
        let riskIcon = '📄';
        if (malicious > 20) {
            statusClass = 'status-malicious';
            riskIcon = '🚨';
        } else if (malicious > 5) {
            statusClass = 'status-suspicious';
            riskIcon = '⚠️';
        }
        
        // Get filename
        const filename = attrs.meaningful_name || attrs.names?.[0] || 'Unknown';
        
        // Format tags (limit to first 5)
        const tags = attrs.tags || [];
        const displayTags = tags.slice(0, 5).map(tag => 
            `<span class="relation-tag">${escapeHtml(tag)}</span>`
        ).join('');
        const moreTags = tags.length > 5 ? `<span class="relation-tag-more">+${tags.length - 5}</span>` : '';
        
        // Format file size and type
        const sizeText = attrs.size ? formatFileSize(attrs.size) : '';
        const typeText = attrs.type_description || 'Unknown';
        
        // Context info (for downloaded files)
        let contextInfo = '';
        if (showDownloadContext && context.first_seen) {
            const firstSeen = new Date(context.first_seen * 1000).toISOString().split('T')[0];
            const lastSeen = new Date(context.last_seen * 1000).toISOString().split('T')[0];
            contextInfo = `
                <div class="file-context-info">
                    <span>First: ${firstSeen}</span>
                    ${context.first_seen !== context.last_seen ? `<span>Last: ${lastSeen}</span>` : ''}
                    ${context.count ? `<span>${context.count}× downloaded</span>` : ''}
                </div>
            `;
        }
        
        return `
            <div class="relation-row ${malicious > 20 ? 'file-row-high-risk' : ''}">
                <div class="relation-main">
                    <div class="relation-hash">
                        <code>${escapeHtml(fileObj.id.substring(0, 16))}...</code>
                    </div>
                    <div class="relation-filename">
                        <span class="file-icon">${riskIcon}</span> 
                        <a href="result.html?type=file&id=${encodeURIComponent(fileObj.id)}">${escapeHtml(filename)}</a>
                    </div>
                    ${displayTags || moreTags ? `<div class="relation-tags">${displayTags}${moreTags}</div>` : ''}
                    ${contextInfo}
                </div>
                <div class="relation-meta">
                    <span class="relation-detections ${statusClass}">${malicious} / ${total}</span>
                    <span class="relation-type">${escapeHtml(typeText)}${sizeText ? ' • ' + sizeText : ''}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render content tab content (URLs only)
 */
function renderContentTab() {
    if (currentType !== 'url') {
        return createEmptyState('Content view is only available for URLs');
    }
    
    // Placeholder for content data - will load on demand
    return `
        <div id="content-tab-content">
            <button id="load-content-btn" class="btn-primary" onclick="loadContentData()">
                Load Page Content
            </button>
            <p class="text-muted" style="margin-top: 1rem;">Click to load page screenshot and HTML content</p>
        </div>
    `;
}

/**
 * Render community tab content
 */
function renderCommunityTab() {
    // Load votes immediately, but comments on demand
    setTimeout(() => loadVotesSummary(), 100);
    
    return `
        <div id="community-votes-section">
            <div class="loading-spinner" style="margin: 2rem auto;"></div>
            <p class="text-muted text-center">Loading votes...</p>
        </div>
        <div id="community-comments-section">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Comments</h3>
                </div>
                <div class="card-body">
                    <button class="btn-secondary" onclick="loadCommentsSection()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                        </svg>
                        Load Comments
                    </button>
                    <p class="text-muted" style="margin-top: 0.5rem; font-size: 0.875rem;">Click to load community comments and threat intelligence</p>
                </div>
            </div>
        </div>
    `;
}

// ==================== Load Additional Data ====================

/**
 * Fetch serving IP address for URL on demand
 */
window.fetchServingIpOnDemand = async function(urlId) {
    const ipElement = document.getElementById('serving-ip-value');
    if (!ipElement) return;
    
    // Show loading state
    ipElement.innerHTML = '<span class="loading-text">Loading...</span>';
    
    try {
        const response = await vtClient.getUrlLastServingIp(urlId);
        const ipAddress = response.data?.id || 'N/A';
        
        // Update with clickable IP link
        if (ipAddress && ipAddress !== 'N/A') {
            ipElement.innerHTML = `<a href="result.html?type=ip&id=${encodeURIComponent(ipAddress)}" class="ip-link">${escapeHtml(ipAddress)}</a>`;
        } else {
            ipElement.textContent = 'N/A';
        }
    } catch (error) {
        console.error('Error fetching serving IP:', error);
        ipElement.innerHTML = '<span class="text-error">Failed to fetch IP</span>';
    }
}

// ==================== Lazy Load Relationship Functions ====================

/**
 * Load URLs related by tracker ID
 */
window.loadUrlsRelatedTracker = async function() {
    const contentDiv = document.getElementById('urls-related-tracker-content');
    const titleElement = document.getElementById('urls-related-tracker-title');
    if (!contentDiv) return;
    
    // Show loading state
    contentDiv.innerHTML = '<div class="loading-spinner" style="margin: 2rem auto;"></div><p class="text-muted text-center">Loading related URLs...</p>';
    
    try {
        const response = await vtClient.getUrlRelationship(currentId, 'urls_related_by_tracker_id', 10);
        const relatedUrls = response.data || [];
        const totalCount = response.meta?.count || relatedUrls.length;
        
        // Update title with count
        if (titleElement) {
            titleElement.textContent = `URLs related by tracker ID (${relatedUrls.length}/${totalCount})`;
        }
        
        // Render results
        if (relatedUrls.length === 0) {
            contentDiv.innerHTML = createEmptyState('No related URLs found');
            return;
        }
        
        contentDiv.innerHTML = renderRelatedUrlsTable(relatedUrls);
        
        showToast(`Loaded ${relatedUrls.length} related URLs`, 'success');
        
    } catch (error) {
        console.error('Error loading related URLs:', error);
        
        // Handle premium feature error
        if (error.message.includes('premium') || error.message.includes('forbidden')) {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Premium Feature</strong></p>
                    <p>This feature requires a Premium VirusTotal API key.</p>
                </div>
            `;
        } else {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Error</strong></p>
                    <p>${escapeHtml(error.message)}</p>
                    <button class="btn-secondary" onclick="loadUrlsRelatedTracker()" style="margin-top: 1rem;">Retry</button>
                </div>
            `;
        }
        
        showToast('Failed to load related URLs', 'error');
    }
}

/**
 * Load embedded JS files
 */
window.loadEmbeddedJsFiles = async function() {
    const contentDiv = document.getElementById('embedded-js-files-content');
    const titleElement = document.getElementById('embedded-js-files-title');
    if (!contentDiv) return;
    
    // Show loading state
    contentDiv.innerHTML = '<div class="loading-spinner" style="margin: 2rem auto;"></div><p class="text-muted text-center">Loading JS files...</p>';
    
    try {
        const response = await vtClient.getUrlRelationship(currentId, 'embedded_js_files', 10);
        const jsFiles = response.data || [];
        const totalCount = response.meta?.count || jsFiles.length;
        
        // Update title with count
        if (titleElement) {
            titleElement.textContent = `Embedded JS Files (${jsFiles.length}${totalCount > jsFiles.length ? '/' + totalCount : ''})`;
        }
        
        // Render results
        if (jsFiles.length === 0) {
            contentDiv.innerHTML = createEmptyState('No embedded JavaScript files found');
            return;
        }
        
        contentDiv.innerHTML = renderEmbeddedJsFilesTable(jsFiles);
        
        showToast(`Loaded ${jsFiles.length} JS files`, 'success');
        
    } catch (error) {
        console.error('Error loading embedded JS files:', error);
        
        // Handle premium feature error
        if (error.message.includes('premium') || error.message.includes('forbidden')) {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Premium Feature</strong></p>
                    <p>This feature requires a Premium VirusTotal API key.</p>
                </div>
            `;
        } else {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Error</strong></p>
                    <p>${escapeHtml(error.message)}</p>
                    <button class="btn-secondary" onclick="loadEmbeddedJsFiles()" style="margin-top: 1rem;">Retry</button>
                </div>
            `;
        }
        
        showToast('Failed to load JS files', 'error');
    }
}

/**
 * Load downloaded files
 */
window.loadDownloadedFiles = async function() {
    const contentDiv = document.getElementById('downloaded-files-content');
    const titleElement = document.getElementById('downloaded-files-title');
    if (!contentDiv) return;
    
    // Show loading state
    contentDiv.innerHTML = '<div class="loading-spinner" style="margin: 2rem auto;"></div><p class="text-muted text-center">Loading files...</p>';
    
    try {
        const response = await vtClient.getUrlRelationship(currentId, 'downloaded_files', 10);
        const files = response.data || [];
        const totalCount = response.meta?.count || files.length;
        
        // Update title with count
        if (titleElement) {
            titleElement.textContent = `Downloaded Files (${files.length}${totalCount > files.length ? '/' + totalCount : ''})`;
        }
        
        // Render results
        if (files.length === 0) {
            contentDiv.innerHTML = createEmptyState('No downloaded files found');
            return;
        }
        
        contentDiv.innerHTML = renderFilesTable(files, true); // true = show download context
        
        showToast(`Loaded ${files.length} files`, 'success');
        
    } catch (error) {
        console.error('Error loading downloaded files:', error);
        
        // Handle premium feature error
        if (error.message.includes('premium') || error.message.includes('forbidden')) {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Premium Feature</strong></p>
                    <p>This feature requires a Premium VirusTotal API key.</p>
                </div>
            `;
        } else {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Error</strong></p>
                    <p>${escapeHtml(error.message)}</p>
                    <button class="btn-secondary" onclick="loadDownloadedFiles()" style="margin-top: 1rem;">Retry</button>
                </div>
            `;
        }
        
        showToast('Failed to load files', 'error');
    }
}

/**
 * Load communicating files
 */
window.loadCommunicatingFiles = async function() {
    const contentDiv = document.getElementById('communicating-files-content');
    const titleElement = document.getElementById('communicating-files-title');
    if (!contentDiv) return;
    
    // Show loading state
    contentDiv.innerHTML = '<div class="loading-spinner" style="margin: 2rem auto;"></div><p class="text-muted text-center">Loading files...</p>';
    
    try {
        const response = await vtClient.getUrlRelationship(currentId, 'communicating_files', 10);
        const files = response.data || [];
        const totalCount = response.meta?.count || files.length;
        
        // Update title with count
        if (titleElement) {
            titleElement.textContent = `Communicating Files (${files.length}${totalCount > files.length ? '/' + totalCount : ''})`;
        }
        
        // Render results
        if (files.length === 0) {
            contentDiv.innerHTML = createEmptyState('No communicating files found');
            return;
        }
        
        contentDiv.innerHTML = renderFilesTable(files, false); // false = no download context
        
        showToast(`Loaded ${files.length} files`, 'success');
        
    } catch (error) {
        console.error('Error loading communicating files:', error);
        
        // Handle premium feature error
        if (error.message.includes('premium') || error.message.includes('forbidden')) {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Premium Feature</strong></p>
                    <p>This feature requires a Premium VirusTotal API key.</p>
                </div>
            `;
        } else {
            contentDiv.innerHTML = `
                <div class="error-message">
                    <p><strong>Error</strong></p>
                    <p>${escapeHtml(error.message)}</p>
                    <button class="btn-secondary" onclick="loadCommunicatingFiles()" style="margin-top: 1rem;">Retry</button>
                </div>
            `;
        }
        
        showToast('Failed to load files', 'error');
    }
}

/**
 * Load relations data on demand
 */
window.loadRelationsData = async function() {
    const container = document.getElementById('relations-content');
    container.innerHTML = '<div class="loading-placeholder"><div class="loading-spinner"></div><p class="text-muted">Loading relations...</p></div>';
    
    try {
        let relationsHtml = '';
        const attrs = currentData.attributes;
        
        // For URLs, check attributes first (embedded data)
        if (currentType === 'url') {
            // Outgoing Links (from attributes.outgoing_links)
            if (attrs.outgoing_links && attrs.outgoing_links.length > 0) {
                const outgoingLinksData = attrs.outgoing_links.map(url => ({
                    id: url,
                    attributes: { url: url }
                }));
                relationsHtml += renderRelationSection({
                    title: 'Outgoing Links',
                    key: 'outgoing_links',
                    data: outgoingLinksData,
                    meta: { count: outgoingLinksData.length }
                });
            }
            
            // Redirection Chain as a relation section (if exists and has multiple URLs)
            if (attrs.redirection_chain && attrs.redirection_chain.length > 1) {
                const redirectChainData = attrs.redirection_chain.map(url => ({
                    id: url,
                    attributes: { url: url }
                }));
                relationsHtml += renderRelationSection({
                    title: 'Redirection Chain',
                    key: 'redirection_chain',
                    data: redirectChainData,
                    meta: { count: redirectChainData.length }
                });
            }
        }
        
        // Define relationship types based on entity type
        // Based on VT API docs: https://docs.virustotal.com/reference/url-object
        const relationshipConfig = {
            url: [
                { key: 'redirects_to', title: 'Redirects To', icon: '↪' },
                { key: 'downloaded_files', title: 'Http Response Contents', icon: '📄' },
                { key: 'contacted_domains', title: 'Contacted Domains', icon: '🌐' },
                { key: 'contacted_ips', title: 'Contacted IPs', icon: '📡' },
                { key: 'redirecting_urls', title: 'Redirecting URLs', icon: '⬅' },
                { key: 'communicating_files', title: 'Communicating Files', icon: '💬' },
            ],
            domain: [
                { key: 'communicating_files', title: 'Communicating Files', icon: '📄' },
                { key: 'downloaded_files', title: 'Downloaded Files', icon: '💾' },
                { key: 'urls', title: 'URLs', icon: '🔗' },
                { key: 'subdomains', title: 'Subdomains', icon: '🌐' },
                { key: 'resolutions', title: 'Resolutions', icon: '🔍' },
            ],
            ip: [
                { key: 'communicating_files', title: 'Communicating Files', icon: '📄' },
                { key: 'downloaded_files', title: 'Downloaded Files', icon: '💾' },
                { key: 'urls', title: 'URLs', icon: '🔗' },
                { key: 'resolutions', title: 'Resolutions', icon: '🔍' },
            ],
            file: [
                { key: 'contacted_domains', title: 'Contacted Domains', icon: '🌐' },
                { key: 'contacted_ips', title: 'Contacted IPs', icon: '📡' },
                { key: 'contacted_urls', title: 'Contacted URLs', icon: '🔗' },
            ]
        };
        
        const entityTypeKey = currentType === 'hash' ? 'file' : currentType;
        const relationships = relationshipConfig[entityTypeKey] || [];
        
        // Fetch all relationships in parallel
        const relationPromises = relationships.map(async (rel) => {
            try {
                let response;
                console.log(`Fetching ${rel.key} for ${currentType}...`);
                
                if (currentType === 'url') {
                    response = await vtClient.getUrlRelationship(currentId, rel.key, 40);
                } else if (currentType === 'domain') {
                    response = await vtClient.getDomainRelationship(currentId, rel.key, 40);
                } else if (currentType === 'ip') {
                    response = await vtClient.getIpRelationship(currentId, rel.key, 40);
                } else if (currentType === 'file' || currentType === 'hash') {
                    response = await vtClient.getFileRelationship(currentId, rel.key, 40);
                }
                
                console.log(`✓ ${rel.key}: ${response.data?.length || 0} items`);
                
                return {
                    ...rel,
                    data: response.data || [],
                    meta: response.meta || {}
                };
            } catch (error) {
                console.error(`✗ Error loading ${rel.key}:`, {
                    message: error.message,
                    status: error.status,
                    response: error.response,
                    fullError: error
                });
                
                // Only show error in UI if it's not a 404 (no data)
                const shouldShowError = error.status !== 404;
                
                return {
                    ...rel,
                    data: [],
                    meta: {},
                    error: shouldShowError ? error.message : null
                };
            }
        });
        
        const relationResults = await Promise.all(relationPromises);
        
        // Log results for debugging
        console.log('Relations loaded:', relationResults);
        
        // Render each relationship section (skip empty ones without errors)
        relationResults.forEach(rel => {
            console.log(`Rendering ${rel.key}: ${rel.data.length} items, error: ${rel.error || 'none'}`);
            if (rel.data.length > 0) {
                relationsHtml += renderRelationSection(rel);
            } else if (rel.error) {
                // Only show errors that aren't 404s
                console.log(`Skipping ${rel.key} - no data or error`);
            }
        });
        
        if (!relationsHtml) {
            relationsHtml = createEmptyState('No relations found. This URL may not have any related entities, or they may require additional API permissions.');
        }
        
        container.innerHTML = relationsHtml;
    } catch (error) {
        console.error('Error loading relations:', error);
        container.innerHTML = `<div class="empty-state"><p class="text-muted">${error.message}</p></div>`;
    }
};

/**
 * Render a relation section
 */
function renderRelationSection(relation) {
    const { title, data, meta, error } = relation;
    const count = data.length;
    const total = meta.count || count;
    
    if (error) {
        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${escapeHtml(title)} (Error)</h3>
                </div>
                <div class="card-body">
                    <p class="text-muted">Error loading data: ${escapeHtml(error)}</p>
                </div>
            </div>
        `;
    }
    
    if (count === 0) return '';
    
    // Render based on relationship key (type field often not present in relationship responses)
    let contentHtml = '';
    
    const sampleType = data[0]?.type;
    console.log(`Rendering ${relation.key} with data type: ${sampleType || 'none'}`);
    
    // Determine renderer based on relationship key name
    if (relation.key.includes('file')) {
        // Files - show with hash and analyze button
        console.log(`Using file renderer for ${relation.key}`);
        contentHtml = renderFileRelations(data);
    } else if (relation.key.includes('url') || relation.key.includes('redirect') || relation.key.includes('link') || relation.key.includes('chain')) {
        // URLs - show with tags and detections
        console.log(`Using URL renderer for ${relation.key}`);
        contentHtml = renderUrlRelations(data);
    } else if (relation.key.includes('domain')) {
        // Domains - show with detections
        console.log(`Using domain renderer for ${relation.key}`);
        contentHtml = renderDomainRelations(data);
    } else if (relation.key.includes('ip')) {
        // IPs - show with detections
        console.log(`Using IP renderer for ${relation.key}`);
        contentHtml = renderIpRelations(data);
    } else if (relation.key === 'resolutions') {
        // DNS resolutions
        console.log(`Using resolution renderer for ${relation.key}`);
        contentHtml = renderResolutionRelations(data);
    } else {
        // Generic rendering - show basic info
        console.warn(`Using generic rendering for ${relation.key}`);
        contentHtml = renderGenericRelations(data);
    }
    
    return `
        <div class="card relation-card">
            <div class="card-header">
                <h3 class="card-title">${escapeHtml(title)} (${count}/${total})</h3>
            </div>
            <div class="card-body">
                ${contentHtml}
            </div>
        </div>
    `;
}

/**
 * Render URL relations
 */
function renderUrlRelations(data) {
    const rows = data.map(item => {
        const attrs = item.attributes || {};
        // Get URL - try multiple fields
        const url = attrs.url || attrs.last_final_url || item.context_attributes?.url || item.id || 'N/A';
        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const tags = attrs.tags || [];
        const relationDate = attrs.last_modification_date ? formatTimestamp(attrs.last_modification_date) : '';
        
        const tagBadges = tags.slice(0, 3).map(tag => 
            `<span class="relation-tag">${escapeHtml(tag)}</span>`
        ).join('');
        
        // Show detections only if we have stats
        const detectionsHtml = total > 0 ? `<span class="relation-detections">${malicious}/${total}</span>` : '';
        const dateHtml = relationDate ? `<span class="relation-date">${relationDate}</span>` : '';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <div class="relation-url">
                        <a href="result.html?type=url&id=${encodeURIComponent(item.id)}" target="_blank">
                            ${escapeHtml(url)}
                        </a>
                    </div>
                    ${tagBadges ? `<div class="relation-tags">${tagBadges}</div>` : ''}
                </div>
                <div class="relation-meta">
                    ${detectionsHtml}
                    ${dateHtml}
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render file relations
 */
function renderFileRelations(data) {
    const rows = data.map(item => {
        const attrs = item.attributes || {};
        const hash = item.id || 'N/A';
        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const fileType = attrs.type_description || 'Unknown';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <div class="relation-hash">
                        <code>${escapeHtml(hash)}</code>
                    </div>
                </div>
                <div class="relation-meta">
                    <span class="relation-detections">${malicious}/${total}</span>
                    <span class="relation-type">${escapeHtml(fileType)}</span>
                    <a href="result.html?type=hash&id=${encodeURIComponent(hash)}" target="_blank" class="btn-analyze">
                        Analyze
                    </a>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render domain relations
 */
function renderDomainRelations(data) {
    const rows = data.map(item => {
        const domain = item.id || 'N/A';
        const attrs = item.attributes || {};
        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <a href="result.html?type=domain&id=${encodeURIComponent(domain)}" target="_blank">
                        ${escapeHtml(domain)}
                    </a>
                </div>
                <div class="relation-meta">
                    <span class="relation-detections">${malicious}/${total}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render IP relations
 */
function renderIpRelations(data) {
    const rows = data.map(item => {
        const ip = item.id || 'N/A';
        const attrs = item.attributes || {};
        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const country = attrs.country || '';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <a href="result.html?type=ip&id=${encodeURIComponent(ip)}" target="_blank">
                        ${escapeHtml(ip)}
                    </a>
                    ${country ? `<span class="relation-country">${escapeHtml(country)}</span>` : ''}
                </div>
                <div class="relation-meta">
                    <span class="relation-detections">${malicious}/${total}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render resolution relations
 */
function renderResolutionRelations(data) {
    const rows = data.map(item => {
        const attrs = item.attributes || {};
        const ipAddress = attrs.ip_address || item.id || 'N/A';
        const date = attrs.date ? formatTimestamp(attrs.date) : 'N/A';
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <a href="result.html?type=ip&id=${encodeURIComponent(ipAddress)}" target="_blank">
                        ${escapeHtml(ipAddress)}
                    </a>
                </div>
                <div class="relation-meta">
                    <span class="relation-date">${date}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Render generic relations (fallback for unknown types)
 */
function renderGenericRelations(data) {
    const rows = data.map(item => {
        const id = item.id || 'N/A';
        const attrs = item.attributes || {};
        const type = item.type || 'unknown';
        
        // Try to get some meaningful info
        const name = attrs.name || attrs.url || attrs.meaningful_name || id;
        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        
        return `
            <div class="relation-row">
                <div class="relation-main">
                    <div>${escapeHtml(name)}</div>
                    ${type !== 'unknown' ? `<small class="text-muted">Type: ${escapeHtml(type)}</small>` : ''}
                </div>
                ${total > 0 ? `<div class="relation-meta"><span class="relation-detections">${malicious}/${total}</span></div>` : ''}
            </div>
        `;
    }).join('');
    
    return `<div class="relation-list">${rows}</div>`;
}

/**
 * Load content data on demand (URLs only)
 */
window.loadContentData = async function() {
    const container = document.getElementById('content-tab-content');
    container.innerHTML = '<div class="loading-placeholder"><div class="loading-spinner"></div><p class="text-muted">Loading content...</p></div>';
    
    try {
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Page Content</h3>
                </div>
                <div class="card-body">
                    <p class="text-muted">Content preview feature will be implemented in the next phase.</p>
                    <p class="text-muted">Will show: Page screenshot, HTML source, JavaScript resources, etc.</p>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading content:', error);
        container.innerHTML = `<div class="empty-state"><p class="text-muted">${error.message}</p></div>`;
    }
};

/**
 * Load behavior data on demand
 */
window.loadBehaviorData = async function() {
    const container = document.getElementById('behavior-content');
    container.innerHTML = '<div class="loading-placeholder"><div class="loading-spinner"></div><p class="text-muted">Loading behavior data...</p></div>';
    
    try {
        const behaviorData = await vtClient.getFileBehaviorSummary(currentId);
        container.innerHTML = renderBehaviorContent(behaviorData.data);
    } catch (error) {
        console.error('Error loading behavior:', error);
        container.innerHTML = `<div class="empty-state"><p class="text-muted">${error.message}</p></div>`;
    }
};

/**
 * Render behavior content
 */
function renderBehaviorContent(behavior) {
    if (!behavior || !behavior.attributes) {
        return createEmptyState('No behavior data available');
    }
    
    const attrs = behavior.attributes;
    
    // Summary stats
    const stats = `
        <div class="behavior-summary">
            <div class="behavior-stat">
                <div class="behavior-stat-value">${formatNumber(attrs.dns_lookups?.length || 0)}</div>
                <div class="behavior-stat-label">DNS Lookups</div>
            </div>
            <div class="behavior-stat">
                <div class="behavior-stat-value">${formatNumber(attrs.http_conversations?.length || 0)}</div>
                <div class="behavior-stat-label">HTTP Requests</div>
            </div>
            <div class="behavior-stat">
                <div class="behavior-stat-value">${formatNumber(attrs.files_written?.length || 0)}</div>
                <div class="behavior-stat-label">Files Written</div>
            </div>
            <div class="behavior-stat">
                <div class="behavior-stat-value">${formatNumber(attrs.processes_created?.length || 0)}</div>
                <div class="behavior-stat-label">Processes</div>
            </div>
        </div>
    `;
    
    // DNS lookups
    let dnsSection = '';
    if (attrs.dns_lookups && attrs.dns_lookups.length > 0) {
        const dnsList = attrs.dns_lookups.map(dns => 
            `<li><strong>${escapeHtml(dns.hostname)}</strong> → ${escapeHtml(dns.resolved_ips?.join(', ') || 'N/A')}</li>`
        ).join('');
        dnsSection = createExpandableSection('DNS Lookups', `<ul class="simple-list">${dnsList}</ul>`);
    }
    
    // HTTP requests
    let httpSection = '';
    if (attrs.http_conversations && attrs.http_conversations.length > 0) {
        const httpList = attrs.http_conversations.map(http => 
            `<li><strong>${escapeHtml(http.request_method || 'GET')}</strong> ${escapeHtml(http.url)}</li>`
        ).join('');
        httpSection = createExpandableSection('HTTP Requests', `<ul class="simple-list">${httpList}</ul>`);
    }
    
    // Files written
    let filesSection = '';
    if (attrs.files_written && attrs.files_written.length > 0) {
        filesSection = createExpandableSection('Files Written', createList(attrs.files_written, 20));
    }
    
    // Processes
    let processSection = '';
    if (attrs.processes_created && attrs.processes_created.length > 0) {
        processSection = createExpandableSection('Processes Created', createList(attrs.processes_created, 20));
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Behavior Summary</h3>
            </div>
            <div class="card-body">${stats}</div>
        </div>
        ${dnsSection}
        ${httpSection}
        ${filesSection}
        ${processSection}
    `;
}

/**
 * Load votes summary only
 */
window.loadVotesSummary = async function() {
    const container = document.getElementById('community-votes-section');
    if (!container) return;
    
    try {
        const votesResponse = await loadVotes();
        container.innerHTML = renderVotesSummary(votesResponse);
    } catch (error) {
        console.error('Error loading votes:', error);
        container.innerHTML = `<div class="empty-state"><p class="text-muted">Failed to load votes</p></div>`;
    }
};

/**
 * Load comments section on demand
 */
window.loadCommentsSection = async function() {
    const container = document.getElementById('community-comments-section');
    if (!container) return;
    
    // Show loading state
    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Comments</h3>
            </div>
            <div class="card-body">
                <div class="loading-spinner" style="margin: 2rem auto;"></div>
                <p class="text-muted text-center">Loading comments...</p>
            </div>
        </div>
    `;
    
    try {
        const commentsResponse = await loadComments();
        container.innerHTML = renderComments(commentsResponse);
        showToast(`Loaded ${commentsResponse.data?.length || 0} comments`, 'success');
    } catch (error) {
        console.error('Error loading comments:', error);
        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Comments</h3>
                </div>
                <div class="card-body">
                    <div class="error-message">
                        <p><strong>Error</strong></p>
                        <p>${escapeHtml(error.message)}</p>
                        <button class="btn-secondary" onclick="loadCommentsSection()" style="margin-top: 1rem;">Retry</button>
                    </div>
                </div>
            </div>
        `;
        showToast('Failed to load comments', 'error');
    }
};

/**
 * Load community data on demand (legacy - kept for compatibility)
 */
window.loadCommunityData = async function() {
    await loadVotesSummary();
    await loadCommentsSection();
};

/**
 * Load comments based on entity type
 */
async function loadComments() {
    switch (currentType) {
        case 'file':
        case 'hash':
            return await vtClient.getFileComments(currentId, 40);
        case 'url':
            return await vtClient.getUrlComments(currentId, 40);
        case 'domain':
            return await vtClient.getDomainComments(currentId, 40);
        case 'ip':
            return await vtClient.getIpComments(currentId, 40);
        default:
            throw new Error('Unknown entity type');
    }
}

/**
 * Load votes based on entity type
 */
async function loadVotes() {
    switch (currentType) {
        case 'file':
        case 'hash':
            return await vtClient.getFileVotes(currentId);
        case 'url':
            return await vtClient.getUrlVotes(currentId);
        case 'domain':
            return await vtClient.getDomainVotes(currentId);
        case 'ip':
            return await vtClient.getIpVotes(currentId);
        default:
            throw new Error('Unknown entity type');
    }
}

/**
 * Render community content
 */
function renderCommunityContent(commentsData, votesData) {
    // Render votes summary
    const votesHtml = renderVotesSummary(votesData);
    
    // Render comments
    const commentsHtml = renderComments(commentsData);
    
    return `${votesHtml}${commentsHtml}`;
}

/**
 * Render votes summary
 */
function renderVotesSummary(votesData) {
    if (!votesData || !votesData.data) {
        return createEmptyState('No votes available');
    }
    
    const harmless = votesData.data.attributes?.harmless || 0;
    const malicious = votesData.data.attributes?.malicious || 0;
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Community Votes</h3>
            </div>
            <div class="card-body">
                <div class="votes-summary">
                    <div class="vote-card">
                        <div class="vote-count positive">${harmless}</div>
                        <div class="vote-label">Harmless</div>
                    </div>
                    <div class="vote-card">
                        <div class="vote-count negative">${malicious}</div>
                        <div class="vote-label">Malicious</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Render comments
 */
function renderComments(commentsData) {
    if (!commentsData || !commentsData.data || commentsData.data.length === 0) {
        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Comments</h3>
                </div>
                <div class="card-body">
                    ${createEmptyState('No comments yet')}
                </div>
            </div>
        `;
    }
    
    const comments = commentsData.data.map(comment => {
        const attrs = comment.attributes;
        
        // Format tags if present
        const tagsHtml = attrs.tags && attrs.tags.length > 0 ? `
            <div class="comment-tags">
                ${attrs.tags.map(tag => `<span class="comment-tag">${escapeHtml(tag)}</span>`).join('')}
            </div>
        ` : '';
        
        return `
            <div class="comment">
                <div class="comment-header">
                    <span class="comment-author">${escapeHtml(attrs.author || 'Anonymous')}</span>
                    <span class="comment-date">${timeAgo(attrs.date)}</span>
                </div>
                <div class="comment-body">${escapeHtml(attrs.text || '')}</div>
                ${tagsHtml}
                ${attrs.votes ? `
                    <div class="comment-votes">
                        <span class="positive">👍 ${attrs.votes.positive || 0}</span>
                        <span class="negative">👎 ${attrs.votes.negative || 0}</span>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
    
    return `
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Comments (${commentsData.data.length})</h3>
            </div>
            <div class="card-body">${comments}</div>
        </div>
    `;
}

// ==================== UI State Management ====================

/**
 * Show loading state
 */
function showLoading() {
    loading.classList.remove('hidden');
    errorContainer.classList.add('hidden');
    resultsContainer.classList.add('hidden');
}

/**
 * Hide loading state
 */
function hideLoading() {
    loading.classList.add('hidden');
}

/**
 * Show error
 */
function showError(title, message) {
    hideLoading();
    resultsContainer.classList.add('hidden');
    errorTitle.textContent = title;
    errorMessage.textContent = message;
    errorContainer.classList.remove('hidden');
}

/**
 * Hide error
 */
function hideError() {
    errorContainer.classList.add('hidden');
}

/**
 * Show toast notification
 * @param {string} message - Toast message
 * @param {string} type - Toast type
 */
function showToast(message, type = 'info') {
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

// ==================== API Key Modal ====================

function openApiKeyModal() {
    const currentKey = getApiKey();
    if (currentKey) {
        apiKeyInput.value = currentKey;
    }
    apiKeyModal.classList.remove('hidden');
    apiKeyInput.focus();
}

function closeApiKeyModal() {
    apiKeyModal.classList.add('hidden');
    apiKeyInput.value = '';
    apiKeyStatus.classList.remove('success', 'error');
    apiKeyStatus.textContent = '';
}

function handleSaveApiKey() {
    const key = apiKeyInput.value.trim();
    
    if (!key) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = 'Please enter an API key';
        return;
    }
    
    if (!/^[a-fA-F0-9]{64}$/.test(key)) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = 'Invalid API key format';
        return;
    }
    
    try {
        saveApiKey(key);
        apiKeyStatus.classList.remove('error');
        apiKeyStatus.classList.add('success');
        apiKeyStatus.textContent = 'API key saved! Reloading...';
        
        setTimeout(() => {
            location.reload();
        }, 1000);
    } catch (error) {
        apiKeyStatus.classList.remove('success');
        apiKeyStatus.classList.add('error');
        apiKeyStatus.textContent = error.message;
    }
}

function handleClearApiKey() {
    if (confirm('Clear API key?')) {
        clearApiKey();
        showToast('API key cleared', 'info');
        setTimeout(() => closeApiKeyModal(), 1000);
    }
}

// ==================== Header Search ====================

function handleHeaderSearch() {
    const query = headerSearchInput.value.trim();
    if (query) {
        window.location.href = `index.html#search=${encodeURIComponent(query)}`;
    }
}

// ==================== Start Application ====================

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
