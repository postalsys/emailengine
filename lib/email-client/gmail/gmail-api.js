'use strict';

const { metricsMeta, markRejectedAccessToken, renewRejectedAccessToken } = require('../base-client');
const apiRetry = require('../api-retry');

// Gmail API configuration
const GMAIL_API_BASE = 'https://gmail.googleapis.com';

// Maximum concurrent listing requests
const LIST_BATCH_SIZE = 10;

// Gmail answers a busy backend with these, and its documentation asks for a retry
const RETRYABLE_SERVER_STATUSES = new Set([500, 502, 503, 504]);

/**
 * Checks if an error indicates rate limiting. Gmail's usual throttling answer is a 403 with a
 * rate-limit reason, not a 429
 * @param {Object} err - The error object
 * @returns {boolean} True if rate limited
 */
function isRateLimitError(err) {
    const status = err.oauthRequest?.status;
    const errorReason = err.oauthRequest?.response?.error?.errors?.[0]?.reason;

    return status === 429 || errorReason === 'rateLimitExceeded' || errorReason === 'userRateLimitExceeded';
}

/**
 * Makes one authenticated request to the Gmail API, repeated only after a rejected cached token
 *
 * @param {Object} context - The client context (GmailClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} method - HTTP method
 * @param {*} payload - Request payload
 * @param {Object} options - Request options
 * @returns {Promise<*>} API response
 */
async function requestOnce(context, url, method, payload, options) {
    let tokenRenewed = false;

    // Loops only for the single repeat after a rejected cached token
    for (;;) {
        let tokenData;

        try {
            tokenData = await context.getTokenData();
        } catch (err) {
            context.logger.error({ msg: 'Failed to load access token', account: context.account, err });
            throw err;
        }

        try {
            if (!context.oAuth2Client) {
                await context.getClient();
            }

            const result = await context.oAuth2Client.request(tokenData.accessToken, url, method, payload, options);

            // Track successful API request
            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: 'success',
                provider: 'gmail',
                statusCode: '200'
            });

            return result;
        } catch (err) {
            // A rejected cached token is renewed and the request repeated once, see
            // renewRejectedAccessToken()
            if (await renewRejectedAccessToken(context, err, tokenData, tokenRenewed)) {
                tokenRenewed = true;
                continue;
            }

            // Log client errors (4xx) at debug level - these are expected operational errors
            // Log server errors (5xx) and other failures at error level
            const status = err.oauthRequest?.status;
            const isClientError = status >= 400 && status < 500;

            if (isClientError) {
                context.logger.debug({ msg: 'API request failed with client error', account: context.account, err });
            } else {
                context.logger.error({ msg: 'Failed to run API request', account: context.account, err });
            }

            // Track failed API request
            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: 'failure',
                provider: 'gmail',
                statusCode: String(status || 0)
            });

            throw markRejectedAccessToken(err);
        }
    }
}

/**
 * Makes authenticated requests to Gmail API, retried under the policy of lib/email-client/api-retry.js
 *
 * @param {Object} context - The client context (GmailClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} [method='get'] - HTTP method
 * @param {*} [payload] - Request payload
 * @param {Object} [options={}] - Request options. `noRetry` sends the request exactly once
 * @returns {Promise<*>} API response
 */
async function request(context, url, method, payload, options = {}) {
    return await apiRetry.requestWithRetry(() => requestOnce(context, url, method, payload, options), {
        context,
        provider: 'gmail',
        url,
        method,
        options,
        isRateLimited: isRateLimitError,
        serverErrorStatuses: RETRYABLE_SERVER_STATUSES
    });
}

/**
 * Builds a Gmail API URL for a specific endpoint
 * @param {string} endpoint - The API endpoint path (e.g., '/users/me/messages')
 * @returns {string} Full API URL
 */
function buildApiUrl(endpoint) {
    // Remove leading slash if present to avoid double slashes
    const path = endpoint.startsWith('/') ? endpoint : '/' + endpoint;
    return `${GMAIL_API_BASE}/gmail/v1${path}`;
}

/**
 * Executes batch API requests with concurrency control
 *
 * @param {Object} context - The client context (GmailClient instance)
 * @param {Array<Object>} items - Array of items to process
 * @param {Function} requestFn - Function that takes an item and returns a promise
 * @param {number} [batchSize=LIST_BATCH_SIZE] - Maximum concurrent requests
 * @returns {Promise<Array>} Array of results
 */
async function executeBatchRequests(context, items, requestFn, batchSize = LIST_BATCH_SIZE) {
    const results = [];
    let batch = [];

    const processBatch = async () => {
        if (batch.length === 0) {
            return;
        }

        const batchResults = await Promise.allSettled(batch);

        for (const entry of batchResults) {
            if (entry.status === 'rejected') {
                throw entry.reason;
            }
            if (entry.value) {
                results.push(entry.value);
            }
        }

        batch = [];
    };

    for (const item of items) {
        batch.push(requestFn(item));

        if (batch.length >= batchSize) {
            await processBatch();
        }
    }

    await processBatch();

    return results;
}

module.exports = {
    // Constants
    GMAIL_API_BASE,
    LIST_BATCH_SIZE,
    RETRYABLE_SERVER_STATUSES,

    // Request functions
    request,
    buildApiUrl,
    executeBatchRequests,

    // Error handling
    isRateLimitError
};
