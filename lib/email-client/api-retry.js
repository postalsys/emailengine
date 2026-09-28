'use strict';

// The one retry policy of the Gmail and Graph provider API requests. The OAuth2 clients send
// every provider request exactly once (lib/oauth/gmail.js, lib/oauth/outlook.js dispatch through
// httpAgent.fetch, never the retrying dispatcher), so this is the only place a failed request is
// repeated from. Two layers used to retry independently, and one throttled call turned into up to
// 24 requests.

const timers = require('timers/promises');
const { isTransientNetworkError } = require('./credential-errors');
const { metricsMeta } = require('./base-client');

const MAX_RETRY_ATTEMPTS = 3;
const RETRY_BASE_DELAY = 1000; // first backoff wait, doubled on every retry
const RETRY_JITTER = 500; // random 0..500 ms added to every wait, so a fleet does not retry in step

// Waits are bounded so a request keeps inside the API worker's RPC timeout (10 s by default):
// a caller that has already given up gains nothing from a request that finishes minutes later
const MAX_RETRY_DELAY = 5000; // one wait, also caps a server-requested Retry-After
const MAX_TOTAL_RETRY_DELAY = 8000; // all waits of one request together

// A read that hit a server error is repeated once; a write that failed with a 5xx may still have
// been applied, so it is not
const SERVER_ERROR_RETRIES = 1;

// The only methods a request is re-sent for after the socket failed: the response was lost, and
// re-sending anything else (a send, a move, a delete) may apply the operation a second time
const IDEMPOTENT_METHODS = new Set(['get', 'head']);

/**
 * How long to wait before the next attempt: the server's Retry-After when it sent one, otherwise
 * exponential backoff, plus jitter, never above MAX_RETRY_DELAY
 * @param {Error} err - The error (the transport stores the parsed Retry-After in seconds as err.retryAfter)
 * @param {number} attempt - 0-based attempt index
 * @returns {number} Milliseconds
 */
function retryDelay(err, attempt) {
    const retryAfter = Number(err?.retryAfter ?? err?.oauthRequest?.retryAfter);
    let delay = retryAfter > 0 ? retryAfter * 1000 : RETRY_BASE_DELAY * Math.pow(2, attempt);
    delay += Math.random() * RETRY_JITTER;
    return Math.min(delay, MAX_RETRY_DELAY);
}

/**
 * Decides whether a failed request is repeated: a throttled request (the provider says so, and
 * a 429 means nothing was processed), a network error of an idempotent request, and one retry of
 * a read that hit a server error the provider asks to retry
 * @param {Error} err - The error
 * @param {Object} policy
 * @param {string} policy.method - HTTP method of the request
 * @param {Object} policy.options - Request options (`noRetry` sends exactly once)
 * @param {Object} policy.state - Per-request retry counters
 * @param {Function} policy.isRateLimited - Provider predicate for a throttled response
 * @param {Set<number>} policy.serverErrorStatuses - Statuses the provider asks to retry a read on
 * @returns {string|false} The retry reason, or false
 */
function retryReason(err, { method, options, state, isRateLimited, serverErrorStatuses }) {
    if (options.noRetry) {
        return false;
    }

    const idempotent = IDEMPOTENT_METHODS.has((method || 'get').toLowerCase());

    if (isTransientNetworkError(err)) {
        return idempotent ? 'network' : false;
    }

    if (isRateLimited(err)) {
        return 'rate_limited';
    }

    if (idempotent && serverErrorStatuses.has(err.oauthRequest?.status) && state.serverErrorRetries < SERVER_ERROR_RETRIES) {
        state.serverErrorRetries++;
        return 'server_error';
    }

    return false;
}

/**
 * Runs one provider API request with retries
 *
 * @param {Function} sendOnce - Performs one attempt; resolves with the response or throws
 * @param {Object} policy
 * @param {Object} policy.context - The client (`account` and `logger` are read for the log lines)
 * @param {string} policy.provider - Provider name for the log lines and metrics
 * @param {string} policy.url - Request URL for the log lines
 * @param {string} policy.method - HTTP method
 * @param {Object} [policy.options] - Request options: `maxRetries` overrides the default, `noRetry` sends exactly once
 * @param {Function} policy.isRateLimited - Provider predicate for a throttled response
 * @param {Set<number>} policy.serverErrorStatuses - Statuses the provider asks to retry a read on
 * @returns {Promise<*>} The response
 */
async function requestWithRetry(sendOnce, { context, provider, url, method, options = {}, isRateLimited, serverErrorStatuses }) {
    const maxRetries = options.maxRetries ?? MAX_RETRY_ATTEMPTS;
    const state = { serverErrorRetries: 0 };
    let totalDelay = 0;

    for (let attempt = 0; ; attempt++) {
        try {
            return await sendOnce(attempt);
        } catch (err) {
            const reason = attempt < maxRetries && retryReason(err, { method, options, state, isRateLimited, serverErrorStatuses });
            const delay = reason ? retryDelay(err, attempt) : 0;

            if (!reason || totalDelay + delay > MAX_TOTAL_RETRY_DELAY) {
                throw err;
            }
            totalDelay += delay;

            context.logger.warn({
                msg: 'API request failed, retrying',
                account: context.account,
                provider,
                reason,
                attempt: attempt + 1,
                maxRetries,
                delay: Math.round(delay),
                code: err.code,
                status: err.oauthRequest?.status,
                errorReason: err.oauthRequest?.response?.error?.errors?.[0]?.reason,
                url
            });

            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: reason,
                provider,
                statusCode: String(err.oauthRequest?.status || 0)
            });

            // Looked up on the module at call time, so a test can stand in for the wait
            await timers.setTimeout(delay);
        }
    }
}

module.exports = {
    MAX_RETRY_ATTEMPTS,
    RETRY_BASE_DELAY,
    RETRY_JITTER,
    MAX_RETRY_DELAY,
    MAX_TOTAL_RETRY_DELAY,
    SERVER_ERROR_RETRIES,
    retryDelay,
    retryReason,
    requestWithRetry
};
