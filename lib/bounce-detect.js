/* eslint no-control-regex: 0 */
'use strict';

/**
 * Email Bounce Detection Module
 *
 * This module analyzes email messages to detect bounce notifications (Delivery Status Notifications - DSNs).
 * It extracts information about failed deliveries including recipient addresses, failure reasons,
 * SMTP response codes, and original message details.
 *
 * Supports various bounce formats from major email providers including:
 * - Standard RFC 3464 delivery status notifications
 * - Amazon WorkMail
 * - Google Gmail
 * - Microsoft Exchange
 * - Postfix
 * - Zoho Mail
 * - Generic SMTP server bounces
 *
 * @module bounce-detect
 * @requires libmime - For parsing MIME headers
 * @requires mailparser - For parsing email messages
 */

const libmime = require('libmime');
const simpleParser = require('mailparser').simpleParser;

/**
 * Parses a message/delivery-status attachment to extract bounce information
 *
 * @param {string|Buffer} content - The delivery status content
 * @returns {Object} Parsed delivery status information
 * @returns {string} [returns.recipient] - The failed recipient email address
 * @returns {string} [returns.action] - The delivery action (e.g., 'failed', 'delayed')
 * @returns {Object} [returns.response] - SMTP response details
 * @returns {string} [returns.response.message] - The SMTP error message
 * @returns {string} [returns.response.status] - The enhanced status code (e.g., '5.1.1')
 * @returns {string} [returns.response.source] - The source of the diagnostic code
 * @returns {string} [returns.mta] - The reporting MTA hostname
 * @returns {string} [returns.queueId] - The mail queue ID (Postfix specific)
 * @returns {string} [returns.messageId] - The original message ID
 */
function parseDeliveryStatus(content) {
    // Ensure content is a trimmed string
    content = (content || '').toString().trim();

    // Parse RFC 3464 formatted headers
    let entries = libmime.decodeHeaders(content);

    let result = {};

    // Extract recipient address from Final-Recipient header (preferred)
    // Format: "Final-Recipient: rfc822; user@example.com"
    if (entries['final-recipient'] && entries['final-recipient'].length) {
        let rcpt = entries['final-recipient'][0];
        let splitPos = rcpt.indexOf(';');
        if (splitPos >= 0) {
            // Extract address after the address-type (usually 'rfc822;')
            result.recipient = rcpt.substr(splitPos + 1).trim();
        } else {
            // No address-type specified, use the whole value
            result.recipient = rcpt.trim();
        }
    }

    // Fallback to Original-Recipient if Final-Recipient not found
    // This might contain the intended recipient before aliasing/forwarding
    if (!result.recipient && entries['original-recipient'] && entries['original-recipient'].length) {
        let rcpt = entries['original-recipient'][0];
        let splitPos = rcpt.indexOf(';');
        if (splitPos >= 0) {
            result.recipient = rcpt.substr(splitPos + 1).trim();
        } else {
            result.recipient = rcpt.trim();
        }
    }

    // Extract delivery action (e.g., 'failed', 'delayed', 'delivered', 'relayed', 'expanded')
    if (entries.action && entries.action.length) {
        result.action = entries.action[0];
    }

    // Parse Diagnostic-Code header for detailed error information
    // Format: "Diagnostic-Code: smtp; 550 5.1.1 User unknown"
    if (entries['diagnostic-code'] && entries['diagnostic-code'].length) {
        let code = entries['diagnostic-code'][0];
        let splitPos = code.indexOf(';');
        let respSource, respMessage;

        if (splitPos >= 0) {
            // Extract diagnostic-type (e.g., 'smtp')
            respSource = code.substr(0, splitPos).trim();
            respMessage = code.substr(splitPos + 1).trim();
        } else {
            // No diagnostic-type specified
            respMessage = code.trim();
        }

        result.response = {};
        if (respSource) {
            result.response.source = respSource;
        }

        result.response.message = respMessage;
    }

    // Extract enhanced status code (e.g., '5.1.1' for "User unknown")
    // This provides machine-readable failure classification
    if (entries.status && entries.status.length) {
        if (!result.response) {
            result.response = {};
        }
        result.response.status = entries.status[0];
    }

    // Extract Remote-MTA (the MTA that reported the failure)
    // Format: "Remote-MTA: dns; mx.example.com"
    if (entries['remote-mta'] && entries['remote-mta'].length) {
        let mta = entries['remote-mta'][0];
        let splitPos = mta.indexOf(';');
        if (splitPos >= 0) {
            result.mta = mta
                .substr(splitPos + 1)
                .trim()
                .toLowerCase();
        } else {
            result.mta = mta.trim().toLowerCase();
        }
    }

    // Fallback to Reporting-MTA if Remote-MTA not found
    // This is the MTA generating the bounce report
    if (!result.mta && entries['reporting-mta'] && entries['reporting-mta'].length) {
        let mta = entries['reporting-mta'][0];
        let splitPos = mta.indexOf(';');
        if (splitPos >= 0) {
            result.mta = mta
                .substr(splitPos + 1)
                .trim()
                .toLowerCase();
        } else {
            result.mta = mta.trim().toLowerCase();
        }
    }

    // Postfix-specific headers
    if (entries['x-postfix-queue-id'] && entries['x-postfix-queue-id'].length) {
        result.queueId = entries['x-postfix-queue-id'][0].trim();
    }

    // Some MTAs include the original message ID in the delivery status
    if (entries['x-original-message-id'] && entries['x-original-message-id'].length) {
        result.messageId = entries['x-original-message-id'][0].trim();
    }

    return result;
}

/**
 * Parses text/rfc822-headers attachment to extract message headers
 *
 * @param {string|Buffer} content - The headers content
 * @returns {Object} Parsed header information
 * @returns {string} [returns.messageId] - The Message-ID header value
 */
function parseDeliveryHeaders(content) {
    content = (content || '').toString().trim();
    let entries = libmime.decodeHeaders(content);

    let result = {};

    // Extract Message-ID from the original message headers
    if (entries['message-id'] && entries['message-id'].length) {
        result.messageId = entries['message-id'][0].trim();
    }

    return result;
}

/**
 * Main bounce detection function that analyzes email messages for bounce information
 *
 * @async
 * @param {Stream|Object} sourceStream - Email stream or object with parsed email
 * @param {Object} [sourceStream.parsed] - Pre-parsed email object (avoids re-parsing)
 * @returns {Promise<Object>} Bounce detection results
 * @returns {string} [returns.recipient] - Failed recipient email address
 * @returns {string} [returns.action] - Bounce action (typically 'failed')
 * @returns {Object} [returns.response] - SMTP response details
 * @returns {string} [returns.response.message] - The error message from the remote server
 * @returns {string} [returns.response.status] - Enhanced status code (X.X.X format)
 * @returns {string} [returns.response.source] - Source of the diagnostic code
 * @returns {string} [returns.mta] - Mail server that reported the failure
 * @returns {string} [returns.queueId] - Queue ID from the sending MTA
 * @returns {string} [returns.messageId] - Original message ID that bounced
 * @returns {Object} [returns.messageHeaders] - Headers from the original message
 */
async function bounceDetect(sourceStream) {
    // Validate input parameter
    if (!sourceStream) {
        return {};
    }

    let parsed;

    // Use pre-parsed email if available to avoid parsing twice
    if (sourceStream.parsed) {
        parsed = sourceStream.parsed;
    } else {
        // Parse the email, keeping delivery status attachments intact
        parsed = await simpleParser(sourceStream, { keepDeliveryStatus: true });
    }

    let result = {};

    // Look for standard bounce attachments as defined in RFC 3464
    // Use case-insensitive comparison per RFC 2045 and handle missing attachments array
    const attachments = parsed.attachments || [];
    let deliveryStatus = attachments.find(attachment => attachment.contentType?.toLowerCase() === 'message/delivery-status');
    let messageHeaders = attachments.find(attachment => attachment.contentType?.toLowerCase() === 'text/rfc822-headers');
    let originalMessage = attachments.find(attachment => attachment.contentType?.toLowerCase() === 'message/rfc822');

    // Zoho Mail uses non-standard content type for original message
    let zohoOriginalMessage = attachments.find(attachment => attachment.contentType?.toLowerCase() === 'text/rfc822');

    let parsedMessageHeaders;

    // Handle Exchange/Outlook specific header for failed recipients
    if (parsed.headers && parsed.headers.has('x-failed-recipients')) {
        // Parse comma and space separated list of failed recipients
        let list = []
            .concat(parsed.headers.get('x-failed-recipients'))
            .map(addr => addr.split(/[,\s]/))
            .flat()
            .map(addr => addr.trim())
            .filter(addr => addr);

        if (list.length) {
            // Use the first failed recipient
            result.recipient = list[0];
        }
    }

    // Special handling for Amazon WorkMail bounces
    // WorkMail doesn't use standard delivery-status attachments
    if (parsed.headers && parsed.headers.has('x-mailer')) {
        let xMailer = []
            .concat(parsed.headers.get('x-mailer') || '')
            .shift()
            .trim();

        let threadTopic = []
            .concat(parsed.headers.get('thread-topic') || '')
            .shift()
            .trim();

        // Detect Amazon WorkMail bounce pattern
        if (xMailer === 'Amazon WorkMail' && threadTopic === 'Undelivered Mail Returned to Sender' && parsed.text) {
            // WorkMail includes bounce details in the plaintext body after "Technical report:"
            let splitMarker = 'Technical report:';
            let splitPos = parsed.text.indexOf(splitMarker);
            if (splitPos >= 0) {
                let bounceDetails = parsed.text.substr(splitPos + splitMarker.length).trim();
                // Parse the technical report section as if it were a delivery-status
                result = Object.assign(result, parseDeliveryStatus(bounceDetails) || {});
            }
        }
    }

    // Process standard delivery-status attachment
    if (deliveryStatus) {
        result = Object.assign(result, parseDeliveryStatus(deliveryStatus.content) || {});
    }

    // Process RFC822 headers attachment (contains headers of the original message)
    if (messageHeaders) {
        parsedMessageHeaders = libmime.decodeHeaders((messageHeaders.content || '').toString().trim());
        result = Object.assign(result, parseDeliveryHeaders(messageHeaders.content) || {});
    }

    // Process complete original message attachment
    if (originalMessage) {
        try {
            // Parse the original message to extract its headers
            let parsedOriginal = await simpleParser(originalMessage.content, { keepDeliveryStatus: true });
            if (parsedOriginal) {
                // Build headers object from headerLines for consistent access
                let headers = {};

                if (parsedOriginal.headerLines && Array.isArray(parsedOriginal.headerLines)) {
                    parsedOriginal.headerLines.forEach(entry => {
                        if (!headers[entry.key]) {
                            headers[entry.key] = [];
                        }
                        // Preserve the original header value (after the key and colon)
                        headers[entry.key].push(entry.line.substring(entry.key.length + 1).trim());
                    });
                }

                parsedMessageHeaders = headers;

                // Extract Message-ID if not already found
                if (!result.messageId && parsedOriginal.messageId) {
                    result.messageId = parsedOriginal.messageId;
                }

                // Some bounces include delivery-status within the original message attachment
                const originalAttachments = parsedOriginal.attachments || [];
                if (!deliveryStatus) {
                    deliveryStatus = originalAttachments.find(attachment => attachment.contentType?.toLowerCase() === 'message/delivery-status');
                    if (deliveryStatus) {
                        result = Object.assign(result, parseDeliveryStatus(deliveryStatus.content) || {});
                    }
                }

                // Similarly for headers attachment
                if (!messageHeaders) {
                    messageHeaders = originalAttachments.find(attachment => attachment.contentType?.toLowerCase() === 'text/rfc822-headers');
                    if (messageHeaders) {
                        result = Object.assign(result, parseDeliveryHeaders(messageHeaders.content) || {});
                    }
                }
            }
        } catch (E) {
            // Failed to parse original message attachment
            // Continue processing as this is not critical
            // TODO: Consider logging this error for debugging
        }
    }

    // Handle Zoho's non-standard bounce format
    // Zoho uses text/rfc822 content type (instead of standard message/rfc822)
    // and includes original message headers in a non-standard format
    if (zohoOriginalMessage) {
        // Verify this is actually a Zoho bounce to prevent false positives
        let isZohoBounce = false;

        // Check for Zoho-specific indicators in the bounce email headers
        if (parsed.headers) {
            // Check X-Mailer header
            const xMailer = parsed.headers.has('x-mailer')
                ? []
                      .concat(parsed.headers.get('x-mailer') || '')
                      .join(' ')
                      .toLowerCase()
                : '';
            // Check From header for Zoho domain
            const fromHeader = parsed.headers.has('from')
                ? []
                      .concat(parsed.headers.get('from') || '')
                      .map(f => (f.address || f.text || f || '').toLowerCase())
                      .join(' ')
                : '';
            // Check User-Agent header
            const userAgent = parsed.headers.has('user-agent')
                ? []
                      .concat(parsed.headers.get('user-agent') || '')
                      .join(' ')
                      .toLowerCase()
                : '';

            isZohoBounce = xMailer.includes('zoho') || fromHeader.includes('zoho') || userAgent.includes('zoho');
        }

        if (isZohoBounce) {
            try {
                let parsedOriginal = await simpleParser(zohoOriginalMessage.content, { keepDeliveryStatus: true });
                // Zoho sometimes includes headers in the text body with no actual header structure
                if (parsedOriginal && parsedOriginal.text && (!parsedOriginal.headerLines || !parsedOriginal.headerLines.filter(h => h.key).length)) {
                    // Remove leading spaces that indicate header continuation
                    let headerContent = (parsedOriginal.text || '').toString().replace(/^ (?=[^ ])/gm, '');

                    // Additional validation: content should look like email headers
                    // Check for common header patterns (Received:, Message-ID:, Date:, From:)
                    if (/^\s*(Received|Message-ID|Date|From):/im.test(headerContent)) {
                        let headers = libmime.decodeHeaders(headerContent);
                        if (headers && headers['message-id']) {
                            parsedMessageHeaders = headers;
                            result = Object.assign(result, parseDeliveryHeaders(headerContent) || {});
                        }
                    }
                }
            } catch (E) {
                // Failed to parse Zoho attachment
                // Continue processing as this is not critical
            }
        }
    }

    // Extract text content for pattern matching
    let text = (parsed.text || '').toString();

    // Some bounces put the content in an attachment with no content-type
    if (!text && !parsed.html && attachments.length) {
        let emptyContent = attachments.find(attachment => !attachment.contentType);
        if (emptyContent) {
            text = (emptyContent.content || '').toString();
        }
    }

    // Limit text size for pattern matching to prevent ReDoS attacks
    // Bounce information is typically in the first part of the message
    const MAX_TEXT_LENGTH = 50000;
    if (text.length > MAX_TEXT_LENGTH) {
        text = text.substring(0, MAX_TEXT_LENGTH);
    }

    // Pattern matching for non-standard bounce formats
    // Only proceed if we haven't found the recipient or response message yet

    if (!result.recipient || !result.response || !result.response.message) {
        /*
         * Match pattern like:
         * <user@example.com>: host mx.example.com[1.2.3.4] said:
         *     550 5.1.1 No such user (in reply to RCPT TO command)
         */
        let m = text.match(/<([^>@]+@[^>]+)>:\s*host\s+([a-z0-9._-]+)\s*(?:\[([^\]]+)\])?\s+said:/im);
        if (m) {
            // Find the end of the error message (double newline or end of string)
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                // Extract the error message, normalizing whitespace
                let message = text
                    .substr(m.index + m[0].length, end.index)
                    .replace(/\s+/g, ' ')
                    .trim();

                result.recipient = result.recipient || m[1].trim();
                result.action = result.action || 'failed';
                result.response = result.response || {};
                result.response.message = result.response.message || message;

                // Extract MTA hostname
                if (m[2]) {
                    result.mta = result.mta || m[2].trim();
                }

                // Try to extract enhanced status code from the message
                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+\.\d+\.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    if (!result.recipient) {
        /*
         * Match pattern like:
         * Delivery to the following recipient failed permanently:
         *     user@example.com
         */
        // Use bounded quantifier to prevent ReDoS with nested [\s\w]* patterns
        let m = text.match(/Delivery[^:]{0,100}failed[^:]{0,50}:/im);
        if (m) {
            // Look for email address on the next line
            let addrMatch = text.substring(m.index + m[0].length).match(/\s*\n*\s*([^\s\n]+)/);
            if (addrMatch && addrMatch[1].indexOf('@') >= 0) {
                result.recipient = addrMatch[1].trim();
            }
        }
    }

    if (!result.recipient) {
        /*
         * Match pattern like:
         * The following recipients were affected:
         *     user@example.com
         */
        let m = text.match(/The following recipients were affected:/im);
        if (m) {
            let addrMatch = text.substr(m.index + m[0].length).match(/\s*\n*\s*([^\s\n]+)/);
            if (addrMatch && addrMatch[1].indexOf('@') >= 0) {
                result.recipient = addrMatch[1].trim();
            }
        }
    }

    if (!result.response || !result.response.message) {
        /*
         * Match SMTP response at the beginning of a line
         * Technical details of permanent failure:
         *
         * 550-5.7.1 [1.2.3.4 11] Our system has detected that this message is not RFC 5322 compliant...
         */
        let m = text.match(/^\s*[45]\d{2}[\s-](\d+\.\d+\.\d+)[\s-]/im);
        if (m) {
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

                // Extract complete error message including the status code
                let message = text
                    .substr(m.index, m[0].length + end.index)
                    .replace(/\s+/g, ' ')
                    .trim();
                result.response = result.response || {};
                result.response.message = result.response.message || message;

                // Extract enhanced status code
                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+\.\d+\.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    // Another non-standard format
    if (!result.recipient || !result.response || !result.response.message) {
        /*
         * Match pattern like:
         * Sorry, we were unable to deliver your message to the following address.
         *
         * <user@example.com>:
         * 550: 5.1.1 <user@example.com>: Recipient address rejected: User unknown in relay recipient table
         */
        // Use bounded quantifier to prevent ReDoS
        let m = text.match(/\n<([^>@]+@[^>]+)>:[\s\r\n]{1,100}/);
        if (m) {
            result.recipient = result.recipient || m[1];

            let end = text.substring(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

                let message = text
                    .substring(m.index + m[0].length, m.index + m[0].length + end.index)
                    .replace(/\s+/g, ' ')
                    .trim();

                result.response = result.response || {};
                result.response.message = result.response.message || message;

                // Try X.X.X format
                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+\.\d+\.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }

                // Also try (#X.X.X) format
                if (!result.response.status) {
                    let statusMatch = message.match(/\(#(\d+\.\d+\.\d+)\)/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    if (!result.recipient) {
        /*
         * Match pattern like:
         * The following message to <user@example.com> was undeliverable
         */
        let m = text.match(/The following message to <([^>@]+@[^>]+)> was undeliverable/);
        if (m) {
            result.recipient = m[1];
        }
    }

    if (!result.response || !result.response.message) {
        /*
         * Match pattern like:
         * The reason for the problem:
         * 5.1.0 - Unknown address error 550-'user@example.com... No such user'
         */
        let m = text.match(/The reason for the problem:[ \t]*\r?\n(\d+\.\d+\.\d+)\s+/);
        if (m) {
            let status = m[1];
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

                // Include the status code in the message
                let message =
                    status +
                    ' ' +
                    text
                        .substr(m.index + m[0].length, end.index)
                        .replace(/\s+/g, ' ')
                        .trim();

                result.response = result.response || {};
                result.response.message = result.response.message || message;
                result.response.status = result.response.status || status;
            }
        }
    }

    if (!result.recipient && (!result.response || !result.response.message)) {
        /*
         * Match pattern like:
         * Your message could not be delivered to the following address: <user@example.com>
         * ...
         * Remote host said: response message
         */
        let m = text.match(/Your message could not be delivered to the following address:\s+<([^>@]+@[^>]+)>/);
        if (m) {
            result.recipient = result.recipient || m[1];

            // Look for "Remote host said:" pattern
            let resMatch = text.match(/Remote host said:\s*(.*)$/m);
            if (resMatch) {
                let message = resMatch[1].replace(/\s+/g, ' ').trim();
                result.response = result.response || {};
                result.response.message = result.response.message || message;
            }
        }
    }

    // Complex pattern for certain MTA formats
    if (result.recipient && result.response && !result.response.message && /A message that you sent could not be delivered/.test(text)) {
        /*
         * Match pattern like:
         * tfhgyuftghjyftghv@hot.ee
         *     SMTP error from remote mail server after RCPT TO:<tfhgyuftghjyftghv@hot.ee>:
         *     host mx1.hot.ee [194.126.101.119]: 550 5.1.1 <tfhgyuftghjyftghv@hot.ee>:
         *     Recipient address rejected: User unknown in relay recipient table
         */

        // Use iterative approach instead of complex regex to prevent ReDoS
        // Split by double newlines to find blocks, then look for the recipient's block
        const blocks = text.split(/\r?\n\r?\n/);
        for (const block of blocks) {
            // Check if this block starts with or contains our recipient email
            if (block.includes(result.recipient)) {
                // Look for "host ... :" pattern followed by error message
                const hostMatch = block.match(/\shost\s+[^\n:]+:\s*(.+)/s);
                if (hostMatch && hostMatch[1]) {
                    const message = hostMatch[1].replace(/\s+/g, ' ').trim();
                    if (message) {
                        result.response = result.response || {};
                        result.response.message = message;
                        break;
                    }
                }
            }
        }
    }

    // KDDI / Japanese carrier style bounce
    if (!result.recipient) {
        /*
         * Match pattern like:
         * Could not be delivered to: <kijitora@example.com>
         */
        let m = text.match(/Could not be delivered to:\s*<?([^\s<>\n]+@[^\s<>\n]+)>?/i);
        if (m) {
            result.recipient = m[1].trim();
            result.action = result.action || 'failed';
        }
    }

    // X6 / Generic MTA style with "permanent errors"
    if (!result.recipient) {
        /*
         * Match pattern like:
         * The following recipients returned permanent errors: kijitora@example.com
         */
        let m = text.match(/returned permanent errors?:\s*<?([^\s<>,\n]+@[^\s<>,\n]+)>?/i);
        if (m) {
            result.recipient = m[1].trim();
            result.action = result.action || 'failed';
        }
    }

    // Extract error message from Verizon MMS / mobile carrier style
    if (!result.response || !result.response.message) {
        /*
         * Match pattern like:
         * Message could not be delivered to mobile.
         * Error: No valid recipients for this MM
         */
        let m = text.match(/(?:Message could not be delivered|Error:[^\n]*(?:Invalid|No valid|not taken)[^\n]*)/i);
        if (m) {
            result.action = result.action || 'failed';
            result.response = result.response || {};
            result.response.message = result.response.message || m[0].replace(/\s+/g, ' ').trim();
        }
    }

    // Apache James / Verizon text style with RCPT TO
    if (!result.recipient) {
        /*
         * Match pattern like:
         * RCPT TO: 000000000000@example.com
         */
        let m = text.match(/RCPT TO:\s*<?([^\s<>\n]+@[^\s<>\n]+)>?/i);
        if (m) {
            result.recipient = m[1].trim();
        }
    }

    // Generic error code extraction (550, 551, 552, etc.)
    if (!result.response || !result.response.message) {
        /*
         * Match pattern like:
         * 550 - Requested action not taken: no such user here
         * 550 5.1.1 user unknown
         */
        let m = text.match(/\b(5[0-5]\d)\s*[-:]\s*([^\n]{10,100})/);
        if (m) {
            result.action = result.action || 'failed';
            result.response = result.response || {};
            result.response.message = result.response.message || m[1] + ' ' + m[2].trim();

            // Try to extract enhanced status code
            if (!result.response.status) {
                let statusMatch = m[2].match(/(\d+\.\d+\.\d+)/);
                if (statusMatch) {
                    result.response.status = statusMatch[1];
                }
            }
        }
    }

    // Try to find embedded message headers in the bounce body
    // Some MTAs include the original headers inline
    if (!result.messageId && text) {
        // Look for the start of email headers (Received or Return-Path)
        let m = text.match(/^(Received|Return-Path):/im);
        if (m) {
            // Extract headers until double newline
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                let headers = text.substr(m.index, m[0].length + end.index).trim();
                let entries = libmime.decodeHeaders(headers);
                if (entries['message-id'] && entries['message-id'].length) {
                    result.messageId = entries['message-id'][0].trim();
                    // Only use these headers if we haven't found headers elsewhere
                    if (!result.headers) {
                        parsedMessageHeaders = entries;
                    }
                }
            }
        }
    }

    // Include parsed message headers in the result
    result.messageHeaders = parsedMessageHeaders || null;

    return result;
}

// Export the main function
module.exports = { bounceDetect };
