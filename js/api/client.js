/**
 * VirusTotal API v3 Client
 */

const BASE_URL = 'https://www.virustotal.com/api/v3';

/**
 * VirusTotal API Client
 */
export class VTClient {
    /**
     * Create VT API client
     * @param {string} apiKey - VirusTotal API key
     */
    constructor(apiKey) {
        if (!apiKey) {
            throw new Error('API key is required');
        }
        this.apiKey = apiKey;
    }
    
    /**
     * Make API request
     * @param {string} endpoint - API endpoint (e.g., '/files/abc123')
     * @returns {Promise<Object>} API response data
     */
    async fetch(endpoint) {
        const url = `${BASE_URL}${endpoint}`;
        
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            
            // Handle rate limiting
            if (response.status === 429) {
                throw new Error('API rate limit exceeded. Please wait a moment and try again.');
            }
            
            // Handle other HTTP errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                
                // Parse VT error response
                if (errorData.error) {
                    throw new Error(this.parseErrorMessage(errorData.error));
                }
                
                throw new Error(`API request failed: ${response.status} ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            // Network errors or other fetch failures
            if (error.message.includes('Failed to fetch')) {
                throw new Error('Network error. Please check your internet connection.');
            }
            throw error;
        }
    }
    
    /**
     * Parse VT error message
     * @param {Object} error - VT error object
     * @returns {string} User-friendly error message
     */
    parseErrorMessage(error) {
        const { code, message } = error;
        
        switch (code) {
            case 'NotFoundError':
                return 'Resource not found. This hash/URL/domain/IP may not exist in VirusTotal database.';
            case 'AuthenticationRequiredError':
                return 'Invalid API key. Please check your API key in settings.';
            case 'ForbiddenError':
                return 'Access forbidden. This resource may require a premium API key.';
            case 'QuotaExceededError':
                return 'API quota exceeded. Please wait or upgrade your API plan.';
            case 'BadRequestError':
                return `Bad request: ${message}`;
            default:
                return message || 'An error occurred while fetching data from VirusTotal.';
        }
    }
    
    // ==================== File Endpoints ====================
    
    /**
     * Get file report by hash
     * @param {string} hash - File hash (MD5, SHA-1, or SHA-256)
     * @returns {Promise<Object>} File analysis data
     */
    async getFile(hash) {
        return this.fetch(`/files/${hash}`);
    }
    
    /**
     * Get file comments
     * @param {string} hash - File hash
     * @param {number} limit - Number of comments to fetch
     * @returns {Promise<Object>} Comments data
     */
    async getFileComments(hash, limit = 10) {
        return this.fetch(`/files/${hash}/comments?limit=${limit}`);
    }
    
    /**
     * Get file votes
     * @param {string} hash - File hash
     * @returns {Promise<Object>} Votes data
     */
    async getFileVotes(hash) {
        return this.fetch(`/files/${hash}/votes`);
    }
    
    /**
     * Get file behavior summary
     * @param {string} hash - File hash
     * @returns {Promise<Object>} Behavior summary data
     */
    async getFileBehaviorSummary(hash) {
        return this.fetch(`/files/${hash}/behaviour_summary`);
    }
    
    /**
     * Get all file behaviors
     * @param {string} hash - File hash
     * @returns {Promise<Object>} All behavior reports
     */
    async getFileBehaviors(hash) {
        return this.fetch(`/files/${hash}/behaviours`);
    }
    
    /**
     * Get file relationships
     * @param {string} hash - File hash
     * @param {string} relationship - Relationship type
     * @param {number} limit - Number of items to fetch
     * @returns {Promise<Object>} Relationship data
     */
    async getFileRelationship(hash, relationship, limit = 40) {
        return this.fetch(`/files/${hash}/${relationship}?limit=${limit}`);
    }
    
    // ==================== URL Endpoints ====================
    
    /**
     * Get URL report by URL ID
     * @param {string} urlId - Base64-encoded URL or SHA-256 hash
     * @returns {Promise<Object>} URL analysis data
     */
    async getUrl(urlId) {
        return this.fetch(`/urls/${urlId}`);
    }
    
    /**
     * Get URL comments
     * @param {string} urlId - URL ID
     * @param {number} limit - Number of comments
     * @returns {Promise<Object>} Comments data
     */
    async getUrlComments(urlId, limit = 10) {
        return this.fetch(`/urls/${urlId}/comments?limit=${limit}`);
    }
    
    /**
     * Get URL votes
     * @param {string} urlId - URL ID
     * @returns {Promise<Object>} Votes data
     */
    async getUrlVotes(urlId) {
        return this.fetch(`/urls/${urlId}/votes`);
    }
    
    /**
     * Get URL last serving IP address
     * @param {string} urlId - URL ID
     * @returns {Promise<Object>} IP address data
     */
    async getUrlLastServingIp(urlId) {
        return this.fetch(`/urls/${urlId}/last_serving_ip_address`);
    }
    
    /**
     * Get URL relationships
     * @param {string} urlId - URL ID
     * @param {string} relationship - Relationship type
     * @param {number} limit - Number of items
     * @returns {Promise<Object>} Relationship data
     */
    async getUrlRelationship(urlId, relationship, limit = 40) {
        return this.fetch(`/urls/${urlId}/${relationship}?limit=${limit}`);
    }
    
    // ==================== Domain Endpoints ====================
    
    /**
     * Get domain report
     * @param {string} domain - Domain name
     * @returns {Promise<Object>} Domain analysis data
     */
    async getDomain(domain) {
        return this.fetch(`/domains/${domain}`);
    }
    
    /**
     * Get domain comments
     * @param {string} domain - Domain name
     * @param {number} limit - Number of comments
     * @returns {Promise<Object>} Comments data
     */
    async getDomainComments(domain, limit = 10) {
        return this.fetch(`/domains/${domain}/comments?limit=${limit}`);
    }
    
    /**
     * Get domain votes
     * @param {string} domain - Domain name
     * @returns {Promise<Object>} Votes data
     */
    async getDomainVotes(domain) {
        return this.fetch(`/domains/${domain}/votes`);
    }
    
    /**
     * Get domain relationships
     * @param {string} domain - Domain name
     * @param {string} relationship - Relationship type
     * @param {number} limit - Number of items
     * @returns {Promise<Object>} Relationship data
     */
    async getDomainRelationship(domain, relationship, limit = 40) {
        return this.fetch(`/domains/${domain}/${relationship}?limit=${limit}`);
    }
    
    // ==================== IP Endpoints ====================
    
    /**
     * Get IP address report
     * @param {string} ip - IP address (IPv4 or IPv6)
     * @returns {Promise<Object>} IP analysis data
     */
    async getIp(ip) {
        return this.fetch(`/ip_addresses/${ip}`);
    }
    
    /**
     * Get IP comments
     * @param {string} ip - IP address
     * @param {number} limit - Number of comments
     * @returns {Promise<Object>} Comments data
     */
    async getIpComments(ip, limit = 10) {
        return this.fetch(`/ip_addresses/${ip}/comments?limit=${limit}`);
    }
    
    /**
     * Get IP votes
     * @param {string} ip - IP address
     * @returns {Promise<Object>} Votes data
     */
    async getIpVotes(ip) {
        return this.fetch(`/ip_addresses/${ip}/votes`);
    }
    
    /**
     * Get IP relationships
     * @param {string} ip - IP address
     * @param {string} relationship - Relationship type
     * @param {number} limit - Number of items
     * @returns {Promise<Object>} Relationship data
     */
    async getIpRelationship(ip, relationship, limit = 40) {
        return this.fetch(`/ip_addresses/${ip}/${relationship}?limit=${limit}`);
    }
}
