'use strict';

const { metricsMeta, markRejectedAccessToken, renewRejectedAccessToken } = require('../base-client');
const apiRetry = require('../api-retry');
const { parseRetryAfter } = require('../../tools');
const timers = require('timers/promises');

const { OUTLOOK_MAX_BATCH_SIZE } = require('../../consts');

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
    let tokenRenewed = false;

    // Loops only for the single repeat after a rejected cached token
    for (;;) {
        let tokenData;

        try {
            tokenData = await context.getTokenData();
        } catch (err) {
            context.logger.warn({ msg: 'Failed to load access token', account: context.account, err });
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
            // The merge is idempotent: requestWithRetry() and the repeat below reuse the options
            let preferValues = (options.headers.Prefer || '')
                .split(',')
                .map(value => value.trim())
                .filter(value => value && value !== 'IdType="ImmutableId"');
            preferValues.unshift('IdType="ImmutableId"');

            options.headers.Prefer = preferValues.join(', ');

            // Construct full API URL if not already absolute
            let apiUrl = /^https:/.test(url) ? url : new URL(`/v1.0${url}`, context.oAuth2Client.apiBase).href;

            let result = await context.oAuth2Client.request(tokenData.accessToken, apiUrl, method, payload, options);

            // Track successful API request
            metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
                status: 'success',
                provider: context.oAuth2Client?.provider || 'outlook',
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

            throw handleRequestError(context, err);
        }
    }
}

/**
 * Records and maps a failed Graph API request. Always returns an error to throw
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {Error} err - The error raised by the OAuth2 request layer
 * @returns {Error} The error to throw
 */
function handleRequestError(context, err) {
    // Track failed API request
    const statusCode = String(err.oauthRequest?.status || 0);
    metricsMeta({ account: context.account }, context.logger, 'oauth2ApiRequest', 'inc', {
        status: 'failure',
        provider: context.oAuth2Client?.provider || 'outlook',
        statusCode
    });

    // Handle specific Graph API error codes using standardized mapping
    const graphErrorCode = err.oauthRequest?.response?.error?.code;
    const graphError = createGraphError(err.oauthRequest?.response?.error, graphErrorCode);

    if (graphError) {
        // Carry the raw Graph exchange over to the mapped error. Callers in outlook-client.js
        // build their own responses by switching on `err.oauthRequest.response.error.code` and
        // `err.oauthRequest.status`, so dropping it here silently disables every one of those
        // branches and turns a mapped 404 into a generic 400 with an undefined code.
        graphError.oauthRequest = err.oauthRequest;

        context.logger.debug({
            msg: 'Graph API error mapped to internal code',
            account: context.account,
            graphErrorCode,
            internalCode: graphError.code
        });
        return graphError;
    }

    // Handle HTTP status codes
    const status = err.oauthRequest?.status;
    const isClientError = status >= 400 && status < 500;

    switch (status) {
        case 401:
            // NOTE: never include `accessToken` here - this logger persists to the per-account
            // log store (exposed via the account logs API/UI) and to Sentry (security review M3).
            context.logger.warn({ msg: 'Failed to authenticate API request', account: context.account, err });
            return markRejectedAccessToken(err);

        case 429:
            // Rate limiting
            context.logger.warn({ msg: 'API request was throttled', account: context.account, err });
            return err;

        default:
            // Log client errors (4xx) at debug level - these are expected operational errors
            // Log server errors (5xx) and other failures at error level
            if (isClientError) {
                context.logger.debug({ msg: 'API request failed with client error', account: context.account, err });
            } else {
                context.logger.error({ msg: 'Failed to run API request', account: context.account, err });
            }
            return err;
    }
}

// Graph asks for a retry on these
const RETRYABLE_SERVER_STATUSES = new Set([502, 503, 504]);

// $batch items are answered one by one, so a throttled or failed item is retried on its own
const BATCH_ITEM_RETRIES = 2;

/**
 * Whether a failed request was throttled. Graph answers throttling with a 429 only
 * @param {Error} err - The error
 * @returns {boolean}
 */
function isRateLimitError(err) {
    return err.oauthRequest?.status === 429;
}

/**
 * Makes authenticated requests to Microsoft Graph API, retried under the policy of
 * lib/email-client/api-retry.js
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {string} url - API endpoint URL
 * @param {string} method - HTTP method
 * @param {*} payload - Request payload
 * @param {Object} options - Request options
 * @param {number} options.maxRetries - Maximum number of retries (default: 3)
 * @param {boolean} options.noRetry - Send exactly once (sends)
 * @returns {Promise<*>} API response
 */
async function requestWithRetry(context, url, method, payload, options = {}) {
    return await apiRetry.requestWithRetry(() => request(context, url, method, payload, options), {
        context,
        provider: context.oAuth2Client?.provider || 'outlook',
        url,
        method,
        options,
        isRateLimited: isRateLimitError,
        serverErrorStatuses: RETRYABLE_SERVER_STATUSES
    });
}

/**
 * Submits a batch request to the Graph API through the client's own retrying method, so a
 * client subclass or test double sees batch traffic the same way as every other request
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {Array} requests - Array of batch request items
 * @returns {Promise<Object>} Batch response with responses array
 */
async function submitBatchRequest(context, requests) {
    return await context.requestWithRetry('/$batch', 'post', { requests });
}

/**
 * Whether a failed $batch item is worth sending again: throttled (429) or a server error
 * @param {Object} response - One entry of the batch response
 * @returns {boolean}
 */
function isRetryableBatchItem(response) {
    return response?.status === 429 || response?.status >= 500;
}

/**
 * Processes batch responses and categorizes them as successful, failed or retryable
 *
 * @param {Object} responseData - The batch response from Graph API
 * @param {Map} messageMap - Map of request IDs to email IDs
 * @param {Object} logger - Logger instance
 * @param {string} account - Account identifier for logging
 * @param {string} operation - Operation name for logging (e.g., 'delete', 'update', 'move')
 * @param {Object} [opts]
 * @param {boolean} [opts.retryable] - Put throttled and 5xx items in `retryIds` instead of `failedIds`
 * @returns {Object} successIds, failedIds and retryIds arrays, `bodies` (email ID to the response
 *     body of each successful item) and `retryAfter` (largest Retry-After of the retryable items, seconds)
 */
function processBatchResponses(responseData, messageMap, logger, account, operation, opts = {}) {
    const successIds = [];
    const failedIds = [];
    const retryIds = [];
    const bodies = new Map();
    const answered = new Set();
    let retryAfter = 0;

    for (const response of responseData?.responses || []) {
        const emailId = messageMap.get(response?.id);
        if (!emailId) {
            continue;
        }
        answered.add(response.id);

        if (response.status >= 200 && response.status < 300) {
            successIds.push(emailId);
            bodies.set(emailId, response.body);
            continue;
        }

        if (opts.retryable && isRetryableBatchItem(response)) {
            retryIds.push(emailId);
            retryAfter = Math.max(retryAfter, parseRetryAfter(response.headers) || 0);
            continue;
        }

        failedIds.push(emailId);
        // Log individual batch item failures for debugging
        logger.warn({
            msg: 'Batch item failed',
            account,
            operation,
            emailId,
            status: response.status,
            error: response.body?.error
        });
    }

    // An item the batch response does not mention at all was not processed
    for (const [reqId, emailId] of messageMap) {
        if (!answered.has(reqId)) {
            failedIds.push(emailId);
        }
    }

    return { successIds, failedIds, retryIds, bodies, retryAfter };
}

/**
 * Executes batch operations on messages with automatic chunking. Items Graph throttled (429) or
 * failed with a 5xx are collected from every chunk and sent again together, up to
 * BATCH_ITEM_RETRIES times, after one wait per round (their largest Retry-After, or a short
 * backoff, bounded like every other retry wait). They used to be logged and dropped, and the
 * operation reported success for whatever was left; then each chunk waited on its own, so a
 * throttled thousand-message call could sleep once per chunk per round
 *
 * @param {Object} context - The client context (OutlookClient instance)
 * @param {Array<string>} emailIds - Array of email IDs to process
 * @param {Function} formatRequest - Function that takes (emailId, requestId) and returns a batch request object
 * @param {string} operation - Operation name for logging
 * @returns {Promise<Object>} successIds and failedIds arrays, and `bodies` (email ID to the
 *     response body of each successful item)
 */
async function executeBatchOperation(context, emailIds, formatRequest, operation) {
    let idGen = 0;
    const successIds = [];
    const failedIds = [];
    const bodies = new Map();

    let pending = emailIds;
    for (let round = 0; pending.length; round++) {
        const retryable = round < BATCH_ITEM_RETRIES;
        const retryIds = [];
        let retryAfter = 0;

        for (let i = 0; i < pending.length; i += MAX_BATCH_SIZE) {
            const messageMap = new Map();
            const requests = pending.slice(i, i + MAX_BATCH_SIZE).map(emailId => {
                const reqId = `msg_${++idGen}`;
                messageMap.set(reqId, emailId);
                return formatRequest(emailId, reqId);
            });

            let responseData;
            try {
                responseData = await submitBatchRequest(context, requests);
            } catch (err) {
                context.logger.error({
                    msg: 'Failed to run batch operation',
                    account: context.account,
                    operation,
                    err
                });
                throw err;
            }

            const result = processBatchResponses(responseData, messageMap, context.logger, context.account, operation, { retryable });

            successIds.push(...result.successIds);
            failedIds.push(...result.failedIds);
            for (const [emailId, body] of result.bodies) {
                bodies.set(emailId, body);
            }
            retryIds.push(...result.retryIds);
            retryAfter = Math.max(retryAfter, result.retryAfter);
        }

        pending = retryIds;
        if (pending.length) {
            const delay = apiRetry.retryDelay({ retryAfter }, round);
            context.logger.warn({
                msg: 'Batch items were throttled, retrying',
                account: context.account,
                operation,
                items: pending.length,
                delay: Math.round(delay)
            });
            // Looked up on the module at call time, so a test can stand in for the wait
            await timers.setTimeout(delay);
        }
    }

    return { successIds, failedIds, bodies };
}

module.exports = {
    // Constants
    GRAPH_ERROR_MAP,
    MAX_BATCH_SIZE,
    RETRYABLE_SERVER_STATUSES,
    BATCH_ITEM_RETRIES,

    // Request functions
    request,
    requestWithRetry,

    // Batch operation helpers
    submitBatchRequest,
    processBatchResponses,
    executeBatchOperation,

    // Error handling
    createGraphError
};
