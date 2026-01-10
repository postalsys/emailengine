'use strict';

const { metricsMeta } = require('../base-client');

const { OUTLOOK_MAX_BATCH_SIZE, OUTLOOK_MAX_RETRY_ATTEMPTS, OUTLOOK_RETRY_BASE_DELAY, OUTLOOK_RETRY_MAX_DELAY } = require('../../consts');

// Maximum number of operations in a single batch request to Microsoft Graph API
const MAX_BATCH_SIZE = OUTLOOK_MAX_BATCH_SIZE;

// MS Graph API error code mapping to internal error codes
// https://learn.microsoft.com/en-us/graph/errors
const GRAPH_ERROR_MAP = {
    ErrorItemNotFound: { code: 'MessageNotFound', status: 404 },
    ErrorInvalidIdMalformed: { code: 'InvalidMessageId', status: 400 },
    ErrorAccessDenied: { code: 'AccessDenied', status: 403 },
    ErrorQuotaExceeded: { code: 'QuotaExceeded', status: 429 },
    ErrorExecuteSearchStaleData: { code: 'SearchCursorExpired', status: 400 },
    ErrorMailboxNotEnabledForRESTAPI: { code: 'MailboxNotEnabled', status: 403 },
    ErrorInvalidRecipients: { code: 'InvalidRecipients', status: 400 },
    ErrorMessageSizeExceeded: { code: 'MessageTooLarge', status: 413 },
    ErrorSendAsDenied: { code: 'SendAsDenied', status: 403 }
};

/**
 * Creates an error from a Graph API error response
 * @param {Object} graphError - The error object from Graph API
 * @param {string} graphErrorCode - The error code from Graph API
 * @returns {Error} A formatted error object
 */
function createGraphError(graphError, graphErrorCode) {
    const mappedError = GRAPH_ERROR_MAP[graphErrorCode];
    if (!mappedError) {
        return null;
    }

    const error = new Error(graphError?.message || graphErrorCode);
    error.code = mappedError.code;
    error.statusCode = mappedError.status;
    error.graphErrorCode = graphErrorCode;
    return error;
}

/**
 * Makes authenticated requests to Microsoft Graph API
 * Handles token management and error responses
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} method - HTTP method
 * @param {*} payload - Request payload
 * @param {Object} options - Request options
 * @returns {Promise<*>} API response
 */
async function request(context, url, method, payload, options = {}) {
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

        options.headers = options.headers || {};

        // Build Prefer header with multiple preferences
        // Request immutable IDs that don't change when messages are moved between folders
        // https://learn.microsoft.com/en-us/graph/outlook-immutable-id
        let preferValues = ['IdType="ImmutableId"'];

        // If caller already set a Prefer header, merge it
        if (options.headers.Prefer) {
            preferValues.push(options.headers.Prefer);
        }

        options.headers.Prefer = preferValues.join(', ');

        // Construct full API URL if not already absolute
        let apiUrl = /^https:/.test(url) ? url : new URL(`/v1.0${url}`, context.oAuth2Client.apiBase).href;

        result = await context.oAuth2Client.request(accessToken, apiUrl, method, payload, options);

        // Track successful API request
        metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
            status: 'success',
            provider: 'outlook',
            statusCode: '200'
        });
    } catch (err) {
        // Track failed API request
        const statusCode = String(err.oauthRequest?.status || 0);
        metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
            status: 'failure',
            provider: 'outlook',
            statusCode
        });

        // Handle specific Graph API error codes using standardized mapping
        const graphErrorCode = err.oauthRequest?.response?.error?.code;
        const graphError = createGraphError(err.oauthRequest?.response?.error, graphErrorCode);

        if (graphError) {
            context.logger.debug({
                msg: 'Graph API error mapped to internal code',
                account: context.account,
                graphErrorCode,
                internalCode: graphError.code
            });
            throw graphError;
        }

        // Handle HTTP status codes
        const status = err.oauthRequest?.status;
        const isClientError = status >= 400 && status < 500;

        switch (status) {
            case 401:
                context.logger.error({ msg: 'Failed to authenticate API request', account: context.account, accessToken, err });
                throw err;

            case 429:
                // Rate limiting
                context.logger.error({ msg: 'API request was throttled', account: context.account, err });
                throw err;

            default:
                // Log client errors (4xx) at debug level - these are expected operational errors
                // Log server errors (5xx) and other failures at error level
                if (isClientError) {
                    context.logger.debug({ msg: 'API request failed with client error', account: context.account, err });
                } else {
                    context.logger.error({ msg: 'Failed to run API request', account: context.account, err });
                }
                throw err;
        }
    }

    return result;
}

/**
 * Makes authenticated requests to Microsoft Graph API with automatic retry on rate limiting
 * Implements exponential backoff using Retry-After header or default delays
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} method - HTTP method
 * @param {*} payload - Request payload
 * @param {Object} options - Request options
 * @param {number} options.maxRetries - Maximum number of retries (default: 3)
 * @returns {Promise<*>} API response
 */
async function requestWithRetry(context, url, method, payload, options = {}) {
    const maxRetries = options.maxRetries ?? OUTLOOK_MAX_RETRY_ATTEMPTS;
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            return await request(context, url, method, payload, options);
        } catch (err) {
            // Only retry on 429 (rate limit) errors
            if (err.oauthRequest?.status !== 429 || attempt === maxRetries) {
                throw err;
            }

            lastError = err;

            // Use Retry-After header if available, otherwise use exponential backoff
            const retryAfter = err.retryAfter || Math.min(OUTLOOK_RETRY_BASE_DELAY * Math.pow(2, attempt), OUTLOOK_RETRY_MAX_DELAY);

            context.logger.info({
                msg: 'Rate limited, retrying after delay',
                account: context.account,
                attempt: attempt + 1,
                maxRetries,
                retryAfterSeconds: retryAfter,
                url
            });

            await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        }
    }

    throw lastError;
}

/**
 * Creates common headers for batch requests
 * @returns {Object} Headers object with Content-Type and ImmutableId preference
 */
function getBatchHeaders() {
    return {
        'Content-Type': 'application/json',
        Prefer: 'IdType="ImmutableId"'
    };
}

/**
 * Submits a batch request to the Graph API
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {Array} requests - Array of batch request items
 * @returns {Promise<Object>} Batch response with responses array
 */
async function submitBatchRequest(context, requests) {
    return await requestWithRetry(context, '/$batch', 'post', { requests });
}

/**
 * Processes batch responses and categorizes them as successful or failed
 *
 * @param {Object} responseData - The batch response from Graph API
 * @param {Map} messageMap - Map of request IDs to email IDs
 * @param {Object} logger - Logger instance
 * @param {string} account - Account identifier for logging
 * @param {string} operation - Operation name for logging (e.g., 'delete', 'update', 'move')
 * @returns {Object} Object with successIds and failedIds arrays
 */
function processBatchResponses(responseData, messageMap, logger, account, operation) {
    const successIds = [];
    const failedIds = [];

    for (const response of responseData?.responses || []) {
        const emailId = messageMap.get(response.id);
        if (response?.status >= 200 && response?.status < 300) {
            if (emailId) {
                successIds.push(emailId);
            }
        } else {
            if (emailId) {
                failedIds.push(emailId);
            }
            // Log individual batch item failures for debugging
            logger.warn({
                msg: 'Batch item failed',
                account,
                operation,
                emailId,
                status: response?.status,
                error: response?.body?.error
            });
        }
    }

    return { successIds, failedIds };
}

/**
 * Executes batch operations on messages with automatic chunking
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {Array<string>} emailIds - Array of email IDs to process
 * @param {Function} formatRequest - Function that takes (emailId, requestId) and returns a batch request object
 * @param {string} operation - Operation name for logging
 * @returns {Promise<Array<string>>} Array of successfully processed email IDs
 */
async function executeBatchOperation(context, emailIds, formatRequest, operation) {
    let batch = [];
    let idGen = 0;
    let successfulIds = [];
    const messageMap = new Map();

    const submitBatch = async () => {
        if (batch.length === 0) {
            return;
        }

        try {
            const responseData = await submitBatchRequest(context, batch);
            const { successIds } = processBatchResponses(responseData, messageMap, context.logger, context.account, operation);
            successfulIds = successfulIds.concat(successIds);
        } catch (err) {
            context.logger.error({
                msg: 'Failed to run batch operation',
                account: context.account,
                operation,
                err
            });
            throw err;
        } finally {
            batch = [];
            messageMap.clear();
        }
    };

    for (const emailId of emailIds) {
        const reqId = `msg_${++idGen}`;
        messageMap.set(reqId, emailId);
        batch.push(formatRequest(emailId, reqId));

        if (batch.length >= MAX_BATCH_SIZE) {
            await submitBatch();
        }
    }

    // Submit remaining batch
    if (batch.length > 0) {
        await submitBatch();
    }

    return successfulIds;
}

module.exports = {
    // Constants
    GRAPH_ERROR_MAP,
    MAX_BATCH_SIZE,

    // Request functions
    request,
    requestWithRetry,

    // Batch operation helpers
    getBatchHeaders,
    submitBatchRequest,
    processBatchResponses,
    executeBatchOperation,

    // Error handling
    createGraphError
};
