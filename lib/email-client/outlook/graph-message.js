'use strict';

// How a Microsoft Graph message is asked for and read back, shared by the single fetch
// (OutlookClient.getMessage()) and the batched one the export uses (getMessages()). Both carried
// their own copy of the field list and the header parsing.

const { pushHeaderValue } = require('../../utils/header-map');

// Every field a formatted message is built from. internetMessageHeaders is not included by
// default, so the full list has to be named
const GRAPH_MESSAGE_SELECT_FULL = [
    'id',
    'conversationId',
    'receivedDateTime',
    'isRead',
    'isDraft',
    'flag',
    'body',
    'subject',
    'from',
    'replyTo',
    'sender',
    'toRecipients',
    'ccRecipients',
    'bccRecipients',
    'internetMessageId',
    'bodyPreview',
    'internetMessageHeaders',
    'parentFolderId',
    'categories'
];

// The attachment list of a message, without the content
const GRAPH_ATTACHMENT_EXPAND = 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)';

// A batch request that failed with one of these is sent again
const BATCH_MAX_RETRIES = 3;
const BATCH_RETRY_BASE_DELAY = 5000;

/**
 * The Prefer header value that asks Graph for a body format. For '*' or nothing Graph returns its default
 * @param {string} [textType] - plain, html or *
 * @returns {string} Empty when no preference is expressed
 */
function bodyPreferHeader(textType) {
    if (textType === 'plain') {
        return 'outlook.body-content-type="text"';
    }
    if (textType === 'html') {
        return 'outlook.body-content-type="html"';
    }
    return '';
}

/**
 * Turns internetMessageHeaders into a `headers` map of lowercase names to value lists, and
 * sets `inReplyTo` from the In-Reply-To header. Nothing is set when Graph sent no headers
 * @param {Object} messageData - Graph message, updated in place
 */
function parseGraphHeaders(messageData) {
    if (!messageData.internetMessageHeaders) {
        return;
    }

    let headers = {};
    for (let header of messageData.internetMessageHeaders || []) {
        let { name, value } = header;
        name = (name || '').toString().trim().toLowerCase();
        value = (value || '').toString().trim();
        if (!pushHeaderValue(headers, name, value)) {
            continue;
        }
        if (name === 'in-reply-to') {
            messageData.inReplyTo = value;
        }
    }
    messageData.headers = headers;
}

/**
 * The error a failed single message fetch is reported with: 404 is an unknown message, 400
 * carries what Graph said
 * @param {Error} err - Error from the Graph request
 * @returns {Error|null} The error to throw, or null when the failure is to be thrown as is
 */
function mapGetMessageError(err) {
    switch (err.oauthRequest?.status) {
        case 404: {
            let error = new Error('Unknown message');
            error.info = {
                response: `Message does not exist`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            return error;
        }

        case 400: {
            let error = new Error('Invalid request');
            error.info = {
                response: err.oauthRequest?.response?.error?.message || `Invalid request`
            };
            error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
            error.statusCode = 400;
            return error;
        }
    }
    return null;
}

/**
 * The requests of one /$batch call, one GET per message
 * @param {string[]} emailIds - Message ids of the batch
 * @param {string} oauth2UserPath - Graph user path ("me" or "users/<id>")
 * @param {string} preferHeader - Prefer header value, empty for none
 * @param {Function} nextRequestId - Returns the next request id, unique across the batches of one call
 * @returns {{requests: Object[], messageMap: Map<string, string>}} The requests, and the message id of each request id
 */
function buildMessageBatchRequests(emailIds, oauth2UserPath, preferHeader, nextRequestId) {
    const selectFields = GRAPH_MESSAGE_SELECT_FULL.join(',');
    const messageMap = new Map();

    const requests = emailIds.map(emailId => {
        const reqId = nextRequestId();
        messageMap.set(reqId, emailId);

        const request = {
            id: reqId,
            method: 'GET',
            url: `/${oauth2UserPath}/messages/${emailId}?$select=${selectFields}&$expand=${GRAPH_ATTACHMENT_EXPAND}`
        };

        // Add Prefer header for body content type if specified
        if (preferHeader) {
            request.headers = { Prefer: preferHeader };
        }

        return request;
    });

    return { requests, messageMap };
}

/**
 * Whether a failed batch call is worth sending again: throttled (429) or a server error (5xx)
 * @param {Error} err - Error from the Graph request
 * @returns {boolean}
 */
function isRetryableBatchError(err) {
    return err.oauthRequest?.status === 429 || (err.oauthRequest?.status >= 500 && err.oauthRequest?.status < 600);
}

/**
 * Reports every request of a batch that got no response, after the ones that did
 * @param {Map<string, string>} messageMap - Message id of each request id
 * @param {Set<string>} respondedIds - Request ids a response was received for
 * @param {Object[]} results - Results, appended to
 */
function reconcileMissingBatchResponses(messageMap, respondedIds, results) {
    for (const [reqId, emailId] of messageMap) {
        if (!respondedIds.has(reqId)) {
            results.push({
                messageId: emailId,
                data: null,
                error: { message: 'No response received from batch API', code: 'EMISSING_RESPONSE' }
            });
        }
    }
}

module.exports = {
    GRAPH_MESSAGE_SELECT_FULL,
    GRAPH_ATTACHMENT_EXPAND,
    BATCH_MAX_RETRIES,
    BATCH_RETRY_BASE_DELAY,
    bodyPreferHeader,
    parseGraphHeaders,
    mapGetMessageError,
    buildMessageBatchRequests,
    isRetryableBatchError,
    reconcileMissingBatchResponses
};
