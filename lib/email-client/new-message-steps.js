'use strict';

// The steps of new-message processing that are the same for every backend. Mailbox.processNew()
// (IMAP) and BaseClient.processNew() (Gmail API, MS Graph) differ in how they fetch content - IMAP
// streams parts with size caps and rethrows a lost connection, the API clients ask for attachments
// by id - but what they do with that content has to agree, and two hand-kept copies had already
// drifted (the web-safe flag was set even when no web-safe copy came out, a classification failure
// was an error on one path and a warning on the other). Those shared decisions live here.

const { arfDetect, camelCaseComplaint, COMPLAINT_ATTACHMENT_TYPES } = require('../arf-detect');
const { bounceDetect, applyDeliveryReport, PARSER_OPTIONS: DSN_PARSER_OPTIONS } = require('../bounce-detect');
const { parseMessage } = require('../parse-message');
const { llmPreProcess } = require('../llm-pre-process');
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

/**
 * Stores a downloaded part on its attachment without making it part of the payload: the complaint
 * check reads it, the webhook does not carry it. The property is read-only, as it always was
 * @param {Object} attachment - Attachment entry, changed in place
 * @param {*} value - The part's content
 */
function setHiddenContent(attachment, value) {
    Object.defineProperty(attachment, 'content', {
        value,
        enumerable: false
    });
}

/**
 * Logs a failed arrival check, unless the backend says the failure must propagate instead
 * @param {Object} messageInfo
 * @param {Error} err
 * @param {string} msg
 * @param {Object} opts - the runArrivalChecks() options
 */
function arrivalCheckFailed(messageInfo, err, msg, { rethrow, logger }) {
    if (rethrow(err)) {
        throw err;
    }
    logger.error({
        msg,
        id: messageInfo.id,
        uid: messageInfo.uid,
        messageId: messageInfo.messageId,
        err
    });
}

/**
 * The complaint (ARF), delivery report (DSN) and bounce checks of a new message, in that order. The
 * backends differ only in how content is downloaded, which the callbacks supply, and in which
 * failures must not be swallowed: IMAP lets a gone connection propagate so the message stays
 * queued instead of being announced half processed. Runs under whatever lock the caller holds.
 * @param {Object} messageInfo - The new message, changed in place
 * @param {Object} opts
 * @param {Object} opts.detector - Has mightBeAComplaint(), mightBeDSNResponse() and mightBeABounce()
 * @param {Function} opts.loadComplaintPart - async (attachment) => void, sets the hidden content
 * @param {Function} opts.fetchSource - async () => the message source (a stream or a buffer)
 * @param {boolean} [opts.missingIsGone] - An empty source means the message was expunged, and the
 *     bounce check does not ask for it again
 * @param {Function} [opts.rethrow] - (err) => true for a failure that must propagate
 * @param {Function} opts.call - RPC to the main thread, for the bounce classifier
 * @param {Object} opts.logger
 * @returns {Promise<{ bounceNotifyInfo: Object|undefined, complaintNotifyInfo: Object|undefined }>}
 */
async function runArrivalChecks(messageInfo, opts) {
    opts = Object.assign({ rethrow: () => false }, opts);
    const { detector, loadComplaintPart, fetchSource, missingIsGone, call, logger } = opts;

    let bounceNotifyInfo;
    let complaintNotifyInfo;
    let content;
    // Set once a download found the message already expunged
    let messageGone = false;

    if (detector.mightBeAComplaint(messageInfo)) {
        try {
            for (let attachment of messageInfo.attachments || []) {
                if (COMPLAINT_ATTACHMENT_TYPES.includes(attachment.contentType)) {
                    await loadComplaintPart(attachment);
                }
            }

            const report = await arfDetect(messageInfo);

            complaintNotifyInfo = complaintNotification(report, messageInfo);
        } catch (err) {
            arrivalCheckFailed(messageInfo, err, 'Failed to process ARF', opts);
        }
    }

    if (detector.mightBeDSNResponse(messageInfo)) {
        let source;
        try {
            source = await fetchSource();

            // No content means the message was expunged after it was detected (a server-side
            // filter moving it to Junk, for instance), which is a normal race and not a failure.
            // The bounce check below does not ask for it again
            if (!source && missingIsGone) {
                messageGone = true;
            } else {
                let parsed = await parseMessage(source, DSN_PARSER_OPTIONS);
                if (parsed) {
                    content = { parsed };
                    applyDeliveryReport(parsed, messageInfo, logger);
                }
            }
        } catch (err) {
            // A parser failure leaves a streamed download unconsumed
            source?.destroy?.();
            arrivalCheckFailed(messageInfo, err, 'Failed to process DSN', opts);
        }
    }

    if (detector.mightBeABounce(messageInfo)) {
        try {
            if (!content && !messageGone) {
                content = await fetchSource();
            }

            if (content) {
                let bounce = await bounceDetect(content);

                await classifyBounce(bounce, call, logger);
                bounceNotifyInfo = bounceNotification(bounce, messageInfo);

                logger.debug({
                    msg: 'Detected bounce message',
                    id: messageInfo.id,
                    uid: messageInfo.uid,
                    messageId: messageInfo.messageId,
                    bounce
                });
            }
        } catch (err) {
            // A parser failure leaves a streamed download unconsumed, as in the DSN check above
            content?.destroy?.();
            arrivalCheckFailed(messageInfo, err, 'Failed to process potential bounce', opts);
        }
    }

    return { bounceNotifyInfo, complaintNotifyInfo };
}

/**
 * Runs the AI summary for an Inbox message when the pre-processing filter accepts it. A message
 * with no text part has no text object at all, and nothing to summarize
 * @param {Object} messageInfo - The new message, changed in place
 * @param {string} account
 * @param {Function} summarizeOptions - () => the options for llmPreProcess.summarize()
 */
async function runLlmSummary(messageInfo, account, summarizeOptions) {
    if (messageInfo.messageSpecialUse !== '\\Inbox' || !(messageInfo.text?.plain || messageInfo.text?.html)) {
        return;
    }

    let llmMessageData = Object.assign({ account }, messageInfo);

    if (await llmPreProcess.run(llmMessageData)) {
        await llmPreProcess.summarize(messageInfo, summarizeOptions());
    }
}

module.exports = {
    isFailedDelivery,
    isOwnSent,
    classifyBounce,
    bounceNotification,
    complaintNotification,
    embedInlineImages,
    markWebSafe,
    notifyNewMessage,
    setHiddenContent,
    runArrivalChecks,
    runLlmSummary
};
