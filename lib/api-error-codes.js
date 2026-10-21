'use strict';

// Machine-readable `code` values for API error responses whose throw site did not set one.
// Dependency-free, so workers/api.js and the tests can share it.
//
// A 404 used to carry `code: 'NotFound'` only when it came from throwNotFound() or one of the
// lib-level update() methods. The others - an unknown export, queued message, blocklist entry,
// account log or account (lib/account.js throws a bare Boom 404) - came back without a code,
// because handleError() passes Boom errors through untouched, so a client could not branch on
// `code` for the most common error there is. Filled in once, where the JSON error body is built,
// so a 404 thrown by any route, now or later, carries it.

const DEFAULT_ERROR_CODES = {
    404: 'NotFound'
};

/**
 * Sets the default `code` on an API error payload that has none
 * @param {Object} payload - Boom output payload ({ statusCode, error, message, ... }), modified in place
 * @returns {Object} The same payload
 */
function addDefaultErrorCode(payload) {
    if (!payload || typeof payload !== 'object' || payload.code) {
        return payload;
    }
    const code = DEFAULT_ERROR_CODES[payload.statusCode];
    if (code) {
        payload.code = code;
    }
    return payload;
}

/**
 * Hapi onPreResponse step that fills in the default code of an error response. Registered by
 * workers/api.js ahead of the handler that renders error pages and JSON errors, and by the route
 * tests' bare servers, so a route test sees the same error body a client does
 * @param {Object} request - Hapi request
 * @param {Object} h - Hapi response toolkit
 * @returns {Symbol} h.continue
 */
function errorCodeExt(request, h) {
    const response = request.response;
    if (response && response.isBoom) {
        addDefaultErrorCode(response.output.payload);
    }
    return h.continue;
}

module.exports = { addDefaultErrorCode, errorCodeExt, DEFAULT_ERROR_CODES };
