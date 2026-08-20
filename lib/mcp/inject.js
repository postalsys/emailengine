'use strict';

// Dispatches an in-process API request on behalf of an MCP caller.
//
// server.inject() rather than any internal shortcut, so the injected request is a real API
// request: the api-token strategy re-validates the caller's credential, and scope checks, token
// permissions, account binding, IP restrictions, rate limits and the token audit log all apply
// exactly as they would over REST. This is the single dispatch path for MCP tools and resources -
// there is deliberately no second one that skips any of it.

/**
 * @param {Object} opts
 * @param {Object} opts.server - the Hapi server
 * @param {Object} opts.request - the outer /mcp request (credential, client IP, timeout header)
 * @param {String} opts.method - HTTP method of the API route
 * @param {String} opts.url - path (plus query string) of the API route
 * @param {Object} [opts.payload] - JSON payload
 * @returns {Promise<Object>} the Hapi injection response
 */
async function apiInject({ server, request, method, url, payload }) {
    const headers = {};

    // The credential of the MCP request itself, whichever way it arrived - the strategy accepts
    // ?access_token= too, and the injected request must carry the same credential rather than a
    // copy of the transport it came in on. The `preauth` caller of the disableTokens mode
    // carries no credential and needs none on the inner request either.
    const token = request.auth && request.auth.credentials && request.auth.credentials.token;
    if (token) {
        headers.authorization = `Bearer ${token}`;
    }

    if (request.headers['x-ee-timeout']) {
        headers['x-ee-timeout'] = request.headers['x-ee-timeout'];
    }

    if (payload !== undefined) {
        headers['content-type'] = 'application/json';
    }

    return server.inject({
        method,
        url,
        headers,
        payload,
        // The resolved client address of the outer request, so token IP allowlists and the audit
        // trail see the real caller rather than the loopback address of an internal dispatch
        remoteAddress: (request.app && request.app.ip) || undefined,
        // Marks the request as MCP-dispatched for the api-token strategy: the `mcp` surface
        // scope is honored only on requests carrying this flag, and request.app cannot be set
        // from the network, so the marker is not forgeable. The license info rides along so the
        // inner run's onRequest does not repeat an IPC for an answer that cannot differ.
        app: { mcpInternal: true, licenseInfo: request.app && request.app.licenseInfo }
    });
}

module.exports = { apiInject };
