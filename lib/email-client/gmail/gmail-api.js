'use strict';

const { metricsMeta } = require('../base-client');

// Gmail API configuration
const GMAIL_API_BASE = 'https://gmail.googleapis.com';

// Maximum concurrent listing requests
const LIST_BATCH_SIZE = 10;

// Rate limiting configuration
const MAX_RETRY_ATTEMPTS = 3;
const RETRY_BASE_DELAY = 1000; // 1 second base delay

// Gmail API error code mapping to internal error codes
// https://developers.google.com/gmail/api/reference/rest#error-codes
const GMAIL_ERROR_MAP = {
    INVALID_ARGUMENT: { code: 'InvalidArgument', status: 400 },
    FAILED_PRECONDITION: { code: 'FailedPrecondition', status: 400 },
    NOT_FOUND: { code: 'NotFound', status: 404 },
    PERMISSION_DENIED: { code: 'PermissionDenied', status: 403 },
    RESOURCE_EXHAUSTED: { code: 'RateLimitExceeded', status: 429 },
    UNAUTHENTICATED: { code: 'Unauthenticated', status: 401 },
    INTERNAL: { code: 'InternalError', status: 500 },
    UNAVAILABLE: { code: 'ServiceUnavailable', status: 503 }
};

/**
 * Creates an error from a Gmail API error response
 * @param {Object} gmailError - The error object from Gmail API
 * @param {string} gmailErrorStatus - The error status from Gmail API
 * @returns {Error|null} A formatted error object or null if not mappable
 */
function createGmailError(gmailError, gmailErrorStatus) {
    const mappedError = GMAIL_ERROR_MAP[gmailErrorStatus];
    if (!mappedError) {
        return null;
    }

    const error = new Error(gmailError?.message || gmailErrorStatus);
    error.code = mappedError.code;
    error.statusCode = mappedError.status;
    error.gmailErrorStatus = gmailErrorStatus;
    return error;
}

/**
 * Checks if an error indicates rate limiting
 * @param {Object} err - The error object
 * @returns {boolean} True if rate limited
 */
function isRateLimitError(err) {
    const status = err.oauthRequest?.status;
    const errorReason = err.oauthRequest?.response?.error?.errors?.[0]?.reason;

    return status === 429 || errorReason === 'rateLimitExceeded' || errorReason === 'userRateLimitExceeded';
}

/**
 * Calculates retry delay with exponential backoff and jitter
 * @param {Object} err - The error object (may contain Retry-After header)
 * @param {number} attempt - Current attempt number (0-indexed)
 * @returns {number} Delay in milliseconds
 */
function calculateRetryDelay(err, attempt) {
    const retryAfter = err.oauthRequest?.headers?.['retry-after'];

    // Use Retry-After header if available, otherwise exponential backoff
    let delay = retryAfter ? parseInt(retryAfter, 10) * 1000 : RETRY_BASE_DELAY * Math.pow(2, attempt);

    // Add jitter (0-500ms) to prevent synchronized retries
    delay += Math.random() * 500;

    return delay;
}

/**
 * Makes authenticated requests to Gmail API with automatic retry on rate limiting
 * Implements exponential backoff with jitter
 *
 * @param {Object} context - The client context (GmailClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} [method='get'] - HTTP method
 * @param {*} [payload] - Request payload
 * @param {Object} [options={}] - Request options
 * @returns {Promise<*>} API response
 */
async function request(context, url, method, payload, options = {}) {
    const maxRetries = options.maxRetries ?? MAX_RETRY_ATTEMPTS;
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        let result, accessToken;

        try {
            accessToken = await context.getToken();
        } catch (err) {
            context.logger.error({ msg: 'Failed to load access token', account: context.account, err });
            throw err;
        }

        try {
            if (!context.oAuth2Client) {
                await context.getClient();
            }

            result = await context.oAuth2Client.request(accessToken, url, method, payload, options);

            // Track successful API request
            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: 'success',
                provider: 'gmail',
                statusCode: '200'
            });

            return result;
        } catch (err) {
            lastError = err;

            // Check if this is a rate limit error
            if (isRateLimitError(err) && attempt < maxRetries) {
                const delay = calculateRetryDelay(err, attempt);

                context.logger.warn({
                    msg: 'Rate limited by Gmail API, retrying',
                    account: context.account,
                    attempt: attempt + 1,
                    maxRetries,
                    delay,
                    errorReason: err.oauthRequest?.response?.error?.errors?.[0]?.reason
                });

                metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                    status: 'rate_limited',
                    provider: 'gmail',
                    statusCode: '429'
                });

                await new Promise(resolve => setTimeout(resolve, delay));
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
            const statusCode = String(err.oauthRequest?.status || 0);
            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: 'failure',
                provider: 'gmail',
                statusCode
            });

            throw err;
        }
    }

    // If we exhausted all retries, throw the last error
    throw lastError;
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
    MAX_RETRY_ATTEMPTS,
    RETRY_BASE_DELAY,
    GMAIL_ERROR_MAP,

    // Request functions
    request,
    buildApiUrl,
    executeBatchRequests,

    // Error handling
    createGmailError,
    isRateLimitError,
    calculateRetryDelay
};
