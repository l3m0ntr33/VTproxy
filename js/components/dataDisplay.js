/**
 * Reusable components for data display
 */

import { escapeHtml } from '../utils/formatters.js';

// Export escapeHtml for use in other modules
export { escapeHtml };

/**
 * Create a property row for details display
 * @param {string} label - Property label
 * @param {string|number} value - Property value
 * @param {boolean} monospace - Use monospace font
 * @returns {string} HTML string
 */
export function createPropertyRow(label, value, monospace = false) {
    const displayValue = value || 'N/A';
    const valueClass = monospace ? 'code-block' : '';
    
    return `
        <div class="property-row">
            <div class="property-label">${escapeHtml(label)}</div>
            <div class="property-value ${valueClass}">${escapeHtml(String(displayValue))}</div>
        </div>
    `;
}

/**
 * Create a section with collapsible content
 * @param {string} title - Section title
 * @param {string} content - Section content HTML
 * @param {boolean} expanded - Initial state
 * @returns {string} HTML string
 */
export function createExpandableSection(title, content, expanded = false) {
    return `
        <div class="expandable-section ${expanded ? 'expanded' : ''}">
            <div class="section-header" onclick="toggleSection(this)">
                <h3>${escapeHtml(title)}</h3>
                <span class="chevron">▼</span>
            </div>
            <div class="section-content">
                ${content}
            </div>
        </div>
    `;
}

/**
 * Create a badge
 * @param {string} text - Badge text
 * @param {string} type - Badge type: primary, success, danger, warning, secondary
 * @returns {string} HTML string
 */
export function createBadge(text, type = 'secondary') {
    return `<span class="badge badge-${type}">${escapeHtml(text)}</span>`;
}

/**
 * Create a key-value list
 * @param {Object} data - Key-value pairs
 * @returns {string} HTML string
 */
export function createKeyValueList(data) {
    const rows = Object.entries(data)
        .filter(([_, value]) => value !== null && value !== undefined)
        .map(([key, value]) => {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            return createPropertyRow(label, value);
        })
        .join('');
    
    return `<div class="property-list">${rows}</div>`;
}

/**
 * Create an empty state message
 * @param {string} message - Message to display
 * @returns {string} HTML string
 */
export function createEmptyState(message) {
    return `
        <div class="empty-state">
            <p class="text-muted">${escapeHtml(message)}</p>
        </div>
    `;
}

/**
 * Create a loading placeholder
 * @returns {string} HTML string
 */
export function createLoadingPlaceholder() {
    return `
        <div class="loading-placeholder">
            <div class="loading-spinner"></div>
            <p class="text-muted">Loading...</p>
        </div>
    `;
}

/**
 * Create a list of items
 * @param {Array<string>} items - List items
 * @param {number} maxItems - Maximum items to show before "show more"
 * @returns {string} HTML string
 */
export function createList(items, maxItems = 10) {
    if (!items || items.length === 0) {
        return createEmptyState('No items');
    }
    
    const displayItems = items.slice(0, maxItems);
    const hasMore = items.length > maxItems;
    
    const listItems = displayItems
        .map(item => `<li>${escapeHtml(String(item))}</li>`)
        .join('');
    
    const moreText = hasMore 
        ? `<li class="text-muted">... and ${items.length - maxItems} more</li>`
        : '';
    
    return `<ul class="simple-list">${listItems}${moreText}</ul>`;
}

/**
 * Create a table from array of objects
 * @param {Array<Object>} data - Table data
 * @param {Array<string>} columns - Column keys to display
 * @returns {string} HTML string
 */
export function createTable(data, columns) {
    if (!data || data.length === 0) {
        return createEmptyState('No data available');
    }
    
    const headers = columns
        .map(col => {
            const label = col.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            return `<th>${escapeHtml(label)}</th>`;
        })
        .join('');
    
    const rows = data
        .map(row => {
            const cells = columns
                .map(col => `<td>${escapeHtml(String(row[col] || 'N/A'))}</td>`)
                .join('');
            return `<tr>${cells}</tr>`;
        })
        .join('');
    
    return `
        <table class="table">
            <thead><tr>${headers}</tr></thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

/**
 * Toggle expandable section (global function for onclick)
 * @param {HTMLElement} header - Section header element
 */
window.toggleSection = function(header) {
    const section = header.closest('.expandable-section');
    section.classList.toggle('expanded');
};
