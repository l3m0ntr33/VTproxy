/**
 * Defanging utility functions
 * Handles detection and restoration of defanged URLs, IPs, and domains
 */

/**
 * Check if input appears to be defanged
 * @param {string} input - User input string
 * @returns {boolean} True if input appears to be defanged
 */
export function isDefanged(input) {
    if (!input || typeof input !== 'string') {
        return false;
    }
    
    const trimmed = input.trim();
    
    // Common defanging patterns
    const defangingPatterns = [
        // URL defanging
        /hxxps?:\/\//i,  // hxxp:// or hxxps://
        /\[\/\]/g,  // [//] instead of //
        /:\/\[\//g,  // :/[//] instead of ://
        
        // IP defanging - only bracketed dots
        /\[\.\]/g,  // 192[.]168[.]1[.]1
        
        // Domain defanging
        /\[\.com\]/i,  // example[.com]
        /\[\.org\]/i,  // example[.org]
        /\[\.net\]/i,  // example[.net]
        /\[\.edu\]/i,  // example[.edu]
        /\[\.gov\]/i,  // example[.gov]
        /\[\.io\]/i,  // example[.io]
        /\[\.co\]/i,  // example[.co]
        /\[\.uk\]/i,  // example[.uk]
        /\[\.de\]/i,  // example[.de]
        /\[\.fr\]/i,  // example[.fr]
        /\[\.jp\]/i,  // example[.jp]
        /\[\.cn\]/i,  // example[.cn]
        /\[\.ru\]/i,  // example[.ru]
        
        // Protocol defanging
        /hxxp/i,       // hxxp instead of http
        /fxp/i,        // fxp instead of ftp
        
        // Common defanging brackets and separators
        /\[.*?\]/g,    // Any brackets [dot], [point], etc.
        /\(.*?\)/g,    // Parentheses (dot), (point), etc.
        /\{.*?\}/g,    // Curly braces {dot}, {point}, etc.
    ];
    
    // Check if any defanging patterns are present
    for (const pattern of defangingPatterns) {
        if (pattern.test(trimmed)) {
            return true;
        }
    }
    
    // Check for text-based defanging
    const textDefangingPatterns = [
        /\[dot\]/i,
        /\[point\]/i,
        /\(dot\)/i,
        /\(point\)/i,
        /\{dot\}/i,
        /\{point\}/i,
        / DOT /i,
        / POINT /i,
        /-dot-/i,
        /-point-/i,
        /\s+dot\s+/i,
        /\s+point\s+/i,
    ];
    
    for (const pattern of textDefangingPatterns) {
        if (pattern.test(trimmed)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Restore defanged input to its original form
 * @param {string} input - Defanged input string
 * @returns {string} Restored input string
 */
export function restoreDefanged(input) {
    if (!input || typeof input !== 'string') {
        return input;
    }
    
    let restored = input.trim();
    let wasDefanged = false;
    
    // Store original for comparison
    const original = restored;
    
    // Protocol restoration
    restored = restored.replace(/hxxps?:\/\//gi, (match) => {
        wasDefanged = true;
        return match.replace('hxxp', 'http').replace('hxxps', 'https');
    });
    
    restored = restored.replace(/fxp:\/\//gi, 'ftp://');
    
    // Bracket and text-based defanging restoration
    const replacements = [
        // Remove brackets around dots and common TLDs
        { pattern: /\[\.\]/g, replacement: '.' },
        { pattern: /\[\.com\]/gi, replacement: '.com' },
        { pattern: /\[\.org\]/gi, replacement: '.org' },
        { pattern: /\[\.net\]/gi, replacement: '.net' },
        { pattern: /\[\.edu\]/gi, replacement: '.edu' },
        { pattern: /\[\.gov\]/gi, replacement: '.gov' },
        { pattern: /\[\.io\]/gi, replacement: '.io' },
        { pattern: /\[\.co\]/gi, replacement: '.co' },
        { pattern: /\[\.uk\]/gi, replacement: '.uk' },
        { pattern: /\[\.de\]/gi, replacement: '.de' },
        { pattern: /\[\.fr\]/gi, replacement: '.fr' },
        { pattern: /\[\.jp\]/gi, replacement: '.jp' },
        { pattern: /\[\.cn\]/gi, replacement: '.cn' },
        { pattern: /\[\.ru\]/gi, replacement: '.ru' },
        
        // Text-based defanging
        { pattern: /\[dot\]/gi, replacement: '.' },
        { pattern: /\[point\]/gi, replacement: '.' },
        { pattern: /\(dot\)/gi, replacement: '.' },
        { pattern: /\(point\)/gi, replacement: '.' },
        { pattern: /\{dot\}/gi, replacement: '.' },
        { pattern: /\{point\}/gi, replacement: '.' },
        { pattern: / DOT /gi, replacement: '.' },
        { pattern: / POINT /gi, replacement: '.' },
        { pattern: /-dot-/gi, replacement: '.' },
        { pattern: /-point-/gi, replacement: '.' },
        { pattern: /\s+dot\s+/gi, replacement: '.' },
        { pattern: /\s+point\s+/gi, replacement: '.' },
        
        // Protocol separators
        { pattern: /\[\/\]/g, replacement: '//' },
        { pattern: /:\/\[\//g, replacement: '://' },
        
        // Remove any remaining brackets around common separators
        { pattern: /\[\/\]/g, replacement: '/' },
        { pattern: /\[:\]/g, replacement: ':' },
        
        // Clean up extra spaces around dots
        { pattern: /\s*\.\s*/g, replacement: '.' },
        
        // Handle cases like "example .com" -> "example.com"
        { pattern: /\s+\./g, replacement: '.' },
        { pattern: /\.\s+/g, replacement: '.' },
    ];
    
    // Apply all replacements
    for (const { pattern, replacement } of replacements) {
        if (pattern.test(restored)) {
            wasDefanged = true;
            restored = restored.replace(pattern, replacement);
        }
    }
    
    // Clean up any remaining brackets that might contain other text
    restored = restored.replace(/\[([^\]]+)\]/g, '$1');
    restored = restored.replace(/\(([^)]+)\)/g, '$1');
    restored = restored.replace(/\{([^}]+)\}/g, '$1');
    
    // Clean up extra whitespace
    restored = restored.replace(/\s+/g, ' ').trim();
    
    // If nothing changed, return original
    if (restored === original) {
        return original;
    }
    
    return restored;
}

/**
 * Process input and detect if it was defanged, then restore it
 * @param {string} input - User input string
 * @returns {{input: string, wasDefanged: boolean, original: string}} Processed input with metadata
 */
export function processDefangedInput(input) {
    if (!input || typeof input !== 'string') {
        return {
            input: input,
            wasDefanged: false,
            original: input
        };
    }
    
    const original = input.trim();
    const wasDefanged = isDefanged(original);
    
    if (wasDefanged) {
        const restored = restoreDefanged(original);
        return {
            input: restored,
            wasDefanged: true,
            original: original
        };
    }
    
    return {
        input: original,
        wasDefanged: false,
        original: original
    };
}

/**
 * Get a human-readable message about defanging
 * @param {string} original - Original defanged input
 * @param {string} restored - Restored input
 * @returns {string} Message about the defanging that occurred
 */
export function getDefangingMessage(original, restored) {
    if (original === restored) {
        return '';
    }
    
    return `Defanged input detected and restored: "${original}" → "${restored}"`;
}
