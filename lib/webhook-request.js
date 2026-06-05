'use strict';

/**
 * Performs a single webhook HTTP delivery and always drains the response body.
 *
 * The webhook response body is never used, but with undici's keepAlive dispatcher
 * a connection is only returned to the pool once its body has been consumed.
 * Draining on every path (success and failure) prevents successful deliveries -
 * the common, high-volume case - from pinning pooled sockets.
 *
 * @param {Function} fetchImpl - fetch implementation (undici fetch)
 * @param {string} url - Destination URL
 * @param {Object} options - fetch options (method, body, headers, dispatcher)
 * @returns {Promise<number>} Resolves with the HTTP status code on success
 * @throws {Error} On a non-2xx response; the error carries a `statusCode` property
 */
async function sendWebhookRequest(fetchImpl, url, options) {
    const res = await fetchImpl(url, options);

    // Drain the body regardless of status so the socket can be reused.
    try {
        await res.text();
    } catch (err) {
        // ignore drain errors
    }

    if (!res.ok) {
        let err = new Error(res.statusText || `Invalid response: ${res.status} ${res.statusText}`);
        err.statusCode = res.status;
        throw err;
    }

    return res.status;
}

module.exports = { sendWebhookRequest };
