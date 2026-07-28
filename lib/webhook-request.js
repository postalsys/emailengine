'use strict';

const { DEFAULT_WEBHOOK_REQUEST_TIMEOUT } = require('./consts');

/**
 * Builds the error for a redirect that was deliberately not followed.
 *
 * Carries `statusCode` like every other non-2xx failure, because that is the field the admin UI
 * webhook error block prints as "HTTP response"; without it the operator is told a redirect
 * happened but not which one.
 *
 * @param {number} status - The 3xx status the endpoint answered with
 * @returns {Error} Error tagged with code EREDIRECTNOTFOLLOWED
 */
function redirectNotFollowedError(status) {
    let err = new Error('Webhook endpoint returned a redirect, which is not followed. Configure the webhook to use the final URL.');
    err.code = 'EREDIRECTNOTFOLLOWED';
    err.statusCode = status;
    return err;
}

/**
 * Performs a single webhook HTTP delivery and always drains the response body.
 *
 * The webhook response body is never used, but with undici's keepAlive dispatcher
 * a connection is only returned to the pool once its body has been consumed.
 * Draining on every path (success and failure) prevents successful deliveries -
 * the common, high-volume case - from pinning pooled sockets.
 *
 * Every attempt is capped by a wall-clock timeout (options.timeout, falling back
 * to DEFAULT_WEBHOOK_REQUEST_TIMEOUT). The notify worker runs with concurrency 1
 * by default, so an unbounded request against a hung endpoint would stall all
 * webhook deliveries; the abort signal also covers reading the response body.
 *
 * @param {Function} fetchImpl - fetch implementation (undici fetch)
 * @param {string} url - Destination URL
 * @param {Object} options - fetch options (method, body, headers, dispatcher) plus
 *   an optional `timeout` in milliseconds
 * @returns {Promise<number>} Resolves with the HTTP status code on success
 * @throws {Error} On a non-2xx response the error carries a `statusCode` property;
 *   on timeout the error carries code 'ETIMEDOUT'; on an unfollowed redirect both,
 *   see redirectNotFollowedError()
 */
async function sendWebhookRequest(fetchImpl, url, options) {
    let { timeout, validateTarget, ...fetchOptions } = options || {};
    timeout = timeout || DEFAULT_WEBHOOK_REQUEST_TIMEOUT;

    if (validateTarget) {
        // fetch() follows redirects on its own, which would let a permitted destination hand us a
        // Location pointing at one the policy rejects. There is no hook to vet the intermediate
        // hops, so redirects are surfaced to the operator instead of followed. Deliveries are
        // machine-to-machine POSTs; a receiver that redirects should be reconfigured to publish
        // its final URL. Setting the egress policy to `off` restores the previous behavior.
        fetchOptions.redirect = 'manual';
        await validateTarget(url);
    }

    // Armed after the target check so a slow DNS resolution is not charged against the delivery's
    // own timeout budget
    fetchOptions.signal = AbortSignal.timeout(timeout);

    const isTimeoutError = err => err && (err.name === 'TimeoutError' || (err.cause && err.cause.name === 'TimeoutError'));

    const throwTimeout = () => {
        let err = new Error(`Webhook request timed out after ${Math.round(timeout / 1000)}s`);
        err.code = 'ETIMEDOUT';
        throw err;
    };

    let res;
    try {
        res = await fetchImpl(url, fetchOptions);
    } catch (err) {
        if (isTimeoutError(err)) {
            throwTimeout();
        }
        throw err;
    }

    // Drain the body regardless of status so the socket can be reused.
    try {
        await res.text();
    } catch (err) {
        if (isTimeoutError(err)) {
            // a body that never finishes is the same stall as a request that
            // never connects, so surface it instead of ignoring the drain error
            throwTimeout();
        }
        // ignore other drain errors
    }

    // With redirect:'manual' undici hands back the 3xx itself (deliberately, unlike the browser
    // spec's opaque redirect), which would otherwise be reported as a generic non-2xx failure
    // carrying only the status. Name the actual problem instead.
    if (validateTarget && res.status >= 300 && res.status < 400) {
        throw redirectNotFollowedError(res.status);
    }

    if (!res.ok) {
        let err = new Error(res.statusText || `Invalid response: ${res.status} ${res.statusText}`);
        err.statusCode = res.status;
        throw err;
    }

    return res.status;
}

module.exports = { sendWebhookRequest };
