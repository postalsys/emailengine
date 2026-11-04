'use strict';

// The steps of new-message processing that are the same for every backend. Mailbox.processNew()
// (IMAP) and BaseClient.processNew() (Gmail API, MS Graph) differ in how they fetch content - IMAP
// streams parts with size caps and rethrows a lost connection, the API clients ask for attachments
// by id - but what they do with that content has to agree, and two hand-kept copies had already
// drifted (the web-safe flag was set even when no web-safe copy came out, a classification failure
// was an error on one path and a warning on the other). Those shared decisions live here.

const { camelCaseComplaint } = require('../arf-detect');
const { embedCidImages } = require('../tools');
const { MESSAGE_NEW_NOTIFY, EMAIL_BOUNCE_NOTIFY, EMAIL_COMPLAINT_NOTIFY } = require('../consts');

const BOUNCE_CLASSIFY_TIMEOUT = 2 * 60 * 1000;

/**
 * Whether a parsed bounce reports a failed delivery. A DSN also reports delivered, delayed,
 * relayed and expanded recipients, and none of those is a bounce to store or to fire emailBounce
 * for; a delayed DSN that landed in Junk used to reach the bounce path with its action set
 * @param {Object} bounce - Result of bounceDetect()
 * @returns {boolean}
 */
function isFailedDelivery(bounce) {
    return !!bounce && typeof bounce.action === 'string' && bounce.action.trim().toLowerCase() === 'failed' && !!bounce.recipient && !!bounce.messageId;
}

/**
 * Whether a new message is one the account sent itself, which is never reported as new: it is
 * listed in a Sent folder, resolved to the Sent special use, or (Gmail) carries the \\Sent label,
 * even next to \\Inbox
 * @param {Object} messageData
 * @param {String} [folderSpecialUse] - special use of the folder the message was found in
 * @returns {Boolean}
 */
function isOwnSent(messageData, folderSpecialUse) {
    return (
        folderSpecialUse === '\\Sent' ||
        messageData.messageSpecialUse === '\\Sent' ||
        !!(Array.isArray(messageData.labels) && messageData.labels.includes('\\Sent'))
    );
}

/**
 * Adds the classifier's verdict to a detected bounce's response. Best effort: a failed
 * classification leaves the bounce as it was.
 * @param {Object} bounce - bounceDetect() result, changed in place
 * @param {Function} call - RPC to the main thread, where the classifier runs
 * @param {Object} logger
 */
async function classifyBounce(bounce, call, logger) {
    const message = bounce?.response?.message;
    if (!message) {
        return;
    }
    try {
        const bounceType = await call({ cmd: 'bounceClassify', data: { message }, timeout: BOUNCE_CLASSIFY_TIMEOUT });
        if (bounceType?.label) {
            bounce.response.category = bounceType.label;
        }
        if (bounceType?.action) {
            bounce.response.recommendedAction = bounceType.action;
        }
        if (bounceType?.blocklist) {
            bounce.response.blocklist = bounceType.blocklist;
        }
        if (bounceType?.retryAfter) {
            bounce.response.retryAfter = bounceType.retryAfter;
        }
    } catch (err) {
        // ignore, just do not include this information
        logger.warn({ msg: 'Failed to classify bounce response', bounceResponse: message, err });
    }
}

/**
 * Marks a message that is a failed-delivery bounce and returns the payload of its bounce event
 * @param {Object} bounce - bounceDetect() result
 * @param {Object} messageData - the new message, changed in place
 * @returns {Object|undefined} the emailBounce payload, or nothing when it is no bounce
 */
function bounceNotification(bounce, messageData) {
    if (!isFailedDelivery(bounce)) {
        return undefined;
    }
    messageData.isBounce = true;
    messageData.relatedMessageId = bounce.messageId;
    return Object.assign({ bounceMessage: messageData.id }, bounce);
}

/**
 * Marks a message that is an abuse report naming its recipient and returns the payload of its
 * complaint event
 * @param {Object} report - arfDetect() result
 * @param {Object} messageData - the new message, changed in place
 * @returns {Object|undefined} the emailComplained payload, or nothing when it is no usable report
 */
function complaintNotification(report, messageData) {
    if (!report || !report.arf || !report.arf['original-rcpt-to'] || !report.arf['original-rcpt-to'].length) {
        return undefined;
    }
    const complaint = camelCaseComplaint(report);
    messageData.isComplaint = true;
    if (complaint.headers && complaint.headers.messageId) {
        messageData.relatedMessageId = complaint.headers.messageId;
    }
    return Object.assign({ complaintMessage: messageData.id }, complaint);
}

/**
 * Replaces the Content-ID references of the HTML and of its web-safe copy with data URIs. The
 * web-safe copy is what webhooks deliver in place of the HTML, so it gets the same treatment.
 * @param {Object} text - messageData.text, changed in place
 * @param {Map} attachmentList - contentId -> { attachment, content } (content base64 or null)
 */
function embedInlineImages(text, attachmentList) {
    if (!attachmentList.size) {
        return;
    }
    const embedImages = html =>
        embedCidImages(html, contentId => {
            const { attachment, content } = attachmentList.get(contentId) || {};
            return content && { contentType: attachment.contentType, content };
        });

    text.html = embedImages(text.html);
    if (text._generatedHtml) {
        text._generatedHtml = embedImages(text._generatedHtml);
    }
}

/**
 * Flags the text as web-safe only when a web-safe copy was produced: the webhook delivery swaps the
 * HTML for that copy only when there is one, so a flag without it would mark the raw HTML safe
 * @param {Object} text - messageData.text, changed in place
 */
function markWebSafe(text) {
    if (text._generatedHtml) {
        text.webSafe = true;
    }
}

/**
 * Sends messageNew, then the bounce and complaint events it carries, in that order: a receiver
 * sees the message before the events that refer to it
 * @param {Function} notify - (target, event, data) => Promise
 * @param {Object} target - what messageNew is reported against (a mailbox, or a path and special use)
 * @param {Object} messageData
 * @param {Object} [related]
 * @param {Object} [related.bounceNotifyInfo]
 * @param {Object} [related.complaintNotifyInfo]
 */
async function notifyNewMessage(notify, target, messageData, { bounceNotifyInfo, complaintNotifyInfo } = {}) {
    await notify(target, MESSAGE_NEW_NOTIFY, messageData);
    if (bounceNotifyInfo) {
        await notify(false, EMAIL_BOUNCE_NOTIFY, bounceNotifyInfo);
    }
    if (complaintNotifyInfo) {
        await notify(false, EMAIL_COMPLAINT_NOTIFY, complaintNotifyInfo);
    }
}

module.exports = { isFailedDelivery, isOwnSent, classifyBounce, bounceNotification, complaintNotification, embedInlineImages, markWebSafe, notifyNewMessage };
