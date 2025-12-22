'use strict';

/**
 * Helper functions for postal-mime email parsing
 * Provides utilities to bridge API differences from mailparser
 */

const PostalMime = require('postal-mime');

/**
 * Get header values by key from postal-mime headers array
 * @param {Array} headers - Array of {key, value} objects
 * @param {string} key - Header key (case-insensitive)
 * @returns {Array} Array of header values
 */
const getHeader = (headers, key) => {
    const normalizedKey = key.toLowerCase();
    return (headers || []).filter(h => h.key === normalizedKey).map(h => h.value);
};

/**
 * Check if header exists in postal-mime headers array
 * @param {Array} headers - Array of {key, value} objects
 * @param {string} key - Header key (case-insensitive)
 * @returns {boolean}
 */
const hasHeader = (headers, key) => {
    const normalizedKey = key.toLowerCase();
    return (headers || []).some(h => h.key === normalizedKey);
};

/**
 * Convert ArrayBuffer/Uint8Array content to string
 * @param {ArrayBuffer|Uint8Array|string|Buffer} content
 * @returns {string}
 */
const contentToString = content => {
    if (!content) return '';
    if (typeof content === 'string') return content;
    if (content instanceof ArrayBuffer || content instanceof Uint8Array) {
        return Buffer.from(content).toString();
    }
    return content.toString();
};

/**
 * Convert ArrayBuffer/Uint8Array content to base64
 * @param {ArrayBuffer|Uint8Array|string|Buffer} content
 * @returns {string}
 */
const contentToBase64 = content => {
    if (!content) return '';
    if (typeof content === 'string') return Buffer.from(content).toString('base64');
    if (content instanceof ArrayBuffer || content instanceof Uint8Array) {
        return Buffer.from(content).toString('base64');
    }
    return content.toString('base64');
};

/**
 * Parse email using postal-mime
 * Wrapper for consistent API across the codebase
 * @param {Buffer|string|ArrayBuffer} source - Email source
 * @param {Object} options - postal-mime options
 * @returns {Promise<Object>} Parsed email
 */
const parseEmail = async (source, options = {}) => {
    // Always force RFC822 attachments to be exposed (equivalent to mailparser's keepDeliveryStatus)
    // This ensures DSN parts and embedded messages are available for bounce/complaint detection
    return PostalMime.parse(source, {
        forceRfc822Attachments: true,
        ...options
    });
};

module.exports = {
    getHeader,
    hasHeader,
    contentToString,
    contentToBase64,
    parseEmail
};
