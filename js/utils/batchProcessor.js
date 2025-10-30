/**
 * Batch processing utility for handling multiple search inputs
 */

import { validateInput } from './inputDetector.js';
import { getDefangingMessage, processDefangedInput } from './defanger.js';
import { encodeUrlForVT } from '../api/urlEncoder.js';

/**
 * Parse multiline input into individual lines
 * @param {string} input - Multiline input text
 * @returns {string[]} Array of non-empty lines
 */
export function parseMultilineInput(input) {
    if (!input || typeof input !== 'string') {
        return [];
    }
    
    // Split by lines and filter out empty lines and whitespace-only lines
    return input
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);
}

/**
 * Process multiple inputs and validate them
 * @param {string} multilineInput - Raw multiline input
 * @returns {{valid: Array, invalid: Array, all: Array}} Processed results
 */
export function processBatchInput(multilineInput) {
    const lines = parseMultilineInput(multilineInput);
    
    const results = {
        valid: [],
        invalid: [],
        all: []
    };
    
    lines.forEach((line, index) => {
        const validation = validateInput(line);
        const processed = processDefangedInput(line);
        
        const item = {
            originalLine: line,
            lineNumber: index + 1,
            validation: validation,
            processed: processed,
            wasDefanged: processed.wasDefanged
        };
        
        results.all.push(item);
        
        if (validation.valid) {
            results.valid.push(item);
        } else {
            results.invalid.push(item);
        }
    });
    
    return results;
}

/**
 * Check if input contains multiple lines (batch mode)
 * @param {string} input - Input text
 * @returns {boolean} True if input has multiple valid lines
 */
export function isBatchInput(input) {
    const lines = parseMultilineInput(input);
    return lines.length > 1;
}

/**
 * Get batch summary message with type breakdown
 * @param {{valid: Array, invalid: Array}} results - Batch processing results
 * @returns {string} Summary message with type details
 */
export function getBatchSummary(results) {
    const total = results.all.length;
    const valid = results.valid.length;
    const invalid = results.invalid.length;
    
    if (total === 0) {
        return 'No valid input found';
    }
    
    if (valid === 0) {
        return `${invalid} invalid items found`;
    }
    
    // Count types for valid items
    const typeCounts = {};
    results.valid.forEach(item => {
        const type = item.validation.type;
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    // Build type summary
    const typeParts = [];
    if (typeCounts.url) typeParts.push(`${typeCounts.url} URL${typeCounts.url > 1 ? 's' : ''}`);
    if (typeCounts.domain) typeParts.push(`${typeCounts.domain} domain${typeCounts.domain > 1 ? 's' : ''}`);
    if (typeCounts.ip) typeParts.push(`${typeCounts.ip} IP${typeCounts.ip > 1 ? 's' : ''}`);
    if (typeCounts.hash) typeParts.push(`${typeCounts.hash} hash${typeCounts.hash > 1 ? 'es' : ''}`);
    
    let message = typeParts.join(', ');
    
    if (invalid > 0) {
        message += ` (+ ${invalid} invalid)`;
    }
    
    return message;
}

/**
 * Generate batch error details
 * @param {Array} invalidItems - Array of invalid items
 * @returns {string} Formatted error message
 */
export function getBatchErrorDetails(invalidItems) {
    if (invalidItems.length === 0) {
        return '';
    }
    
    let message = `Invalid items found:\n`;
    invalidItems.forEach(item => {
        message += `Line ${item.lineNumber}: "${item.originalLine}" - ${item.validation.message}\n`;
    });
    
    return message;
}

/**
 * Process items for batch opening in VirusTotal
 * @param {Array} validItems - Array of valid items to process
 * @param {Function} progressCallback - Callback for progress updates
 * @returns {Promise<Array>} Results of processing
 */
export async function processBatchForVT(validItems, progressCallback) {
    const results = [];
    
    for (let i = 0; i < validItems.length; i++) {
        const item = validItems[i];
        
        // Update progress
        if (progressCallback) {
            progressCallback(i + 1, validItems.length, item);
        }
        
        // Add small delay to prevent overwhelming the browser
        if (i > 0) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        results.push({
            ...item,
            processed: true,
            url: generateVTUrl(item.validation.type, item.processed.input)
        });
    }
    
    return results;
}

/**
 * Generate VirusTotal URL for an item
 * @param {string} type - Entity type
 * @param {string} input - Processed input
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
            // For URLs, use the proper encoder
            try {
                const urlId = encodeUrlForVT(input);
                return `${baseUrl}/url/${urlId}`;
            } catch (error) {
                throw new Error(`Failed to encode URL: ${input}`);
            }
        
        default:
            throw new Error('Unknown input type');
    }
}

/**
 * Open multiple URLs in new tabs
 * @param {Array} urls - Array of URLs to open
 * @param {Function} progressCallback - Callback for progress updates
 */
export async function openMultipleTabs(urls, progressCallback) {
    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        
        // Update progress
        if (progressCallback) {
            progressCallback(i + 1, urls.length, url);
        }
        
        try {
            if (window.__TAURI__) {
                // Use Tauri shell API for desktop app
                const { open } = window.__TAURI__.shell;
                await open(url);
            } else {
                // Use window.open for browser
                window.open(url, '_blank');
            }
        } catch (error) {
            console.error('Failed to open URL:', url, error);
        }
        
        // Add small delay between openings
        if (i < urls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 200));
        }
    }
}
