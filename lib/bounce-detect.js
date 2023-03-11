/* eslint no-control-regex: 0 */
'use strict';

const libmime = require('libmime');
const simpleParser = require('mailparser').simpleParser;

function parseDeliveryStatus(content) {
    content = (content || '').toString().trim();
    let entries = libmime.decodeHeaders(content);

    let result = {};

    if (entries['final-recipient'] && entries['final-recipient'].length) {
        let rcpt = entries['final-recipient'][0];
        let splitPos = rcpt.indexOf(';');
        if (splitPos >= 0) {
            result.recipient = rcpt.substr(splitPos + 1).trim();
        } else {
            result.recipient = rcpt.trim();
        }
    }

    if (!result.recipient && entries['original-recipient'] && entries['original-recipient'].length) {
        let rcpt = entries['original-recipient'][0];
        let splitPos = rcpt.indexOf(';');
        if (splitPos >= 0) {
            result.recipient = rcpt.substr(splitPos + 1).trim();
        } else {
            result.recipient = rcpt.trim();
        }
    }

    if (entries.action && entries.action.length) {
        result.action = entries.action[0];
    }

    if (entries['diagnostic-code'] && entries['diagnostic-code'].length) {
        let code = entries['diagnostic-code'][0];
        let splitPos = code.indexOf(';');
        let respSource, respMessage;
        if (splitPos >= 0) {
            respSource = code.substr(0, splitPos).trim();
            respMessage = code.substr(splitPos + 1).trim();
        } else {
            respMessage = code.trim();
        }
        result.response = {};
        if (respSource) {
            result.response.source = respSource;
        }

        result.response.message = respMessage;
    }

    if (entries.status && entries.status.length) {
        if (!result.response) {
            result.response = {};
        }
        result.response.status = entries.status[0];
    }

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

    if (entries['x-postfix-queue-id'] && entries['x-postfix-queue-id'].length) {
        result.queueId = entries['x-postfix-queue-id'][0].trim();
    }

    if (entries['x-original-message-id'] && entries['x-original-message-id'].length) {
        result.messageId = entries['x-original-message-id'][0].trim();
    }

    return result;
}

function parseDeliveryHeaders(content) {
    content = (content || '').toString().trim();
    let entries = libmime.decodeHeaders(content);

    let result = {};

    if (entries['message-id'] && entries['message-id'].length) {
        result.messageId = entries['message-id'][0].trim();
    }

    return result;
}

async function bounceDetect(sourceStream) {
    let parsed;

    if (sourceStream.parsed) {
        parsed = sourceStream.parsed;
    } else {
        parsed = await simpleParser(sourceStream, { keepDeliveryStatus: true });
    }

    let result = {};

    let deliveryStatus = parsed.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
    let messageHeaders = parsed.attachments.find(attachment => attachment.contentType === 'text/rfc822-headers');
    let originalMessage = parsed.attachments.find(attachment => attachment.contentType === 'message/rfc822');
    let zohoOriginalMessage = parsed.attachments.find(attachment => attachment.contentType === 'text/rfc822');

    let parsedMessageHeaders;

    if (parsed.headers.has('x-failed-recipients')) {
        let list = []
            .concat(parsed.headers.get('x-failed-recipients'))
            .map(addr => addr.split(/[,\s]/))
            .flat()
            .map(addr => addr.trim())
            .filter(addr => addr);

        if (list.length) {
            result.recipient = list[0];
        }
    }

    if (parsed.headers.has('x-mailer')) {
        let xMailer = []
            .concat(parsed.headers.get('x-mailer') || '')
            .shift()
            .trim();

        let threadTopic = []
            .concat(parsed.headers.get('thread-topic') || '')
            .shift()
            .trim();

        if (xMailer === 'Amazon WorkMail' && threadTopic === 'Undelivered Mail Returned to Sender' && parsed.text) {
            // special case, look for the bounce details from the plaintext part
            let splitMarker = 'Technical report:';
            let splitPos = parsed.text.indexOf(splitMarker);
            if (splitPos >= 0) {
                let bounceDetails = parsed.text.substr(splitPos + splitMarker.length).trim();
                result = Object.assign(result, parseDeliveryStatus(bounceDetails) || {});
            }
        }
    }

    if (deliveryStatus) {
        result = Object.assign(result, parseDeliveryStatus(deliveryStatus.content) || {});
    }

    if (messageHeaders) {
        parsedMessageHeaders = libmime.decodeHeaders((messageHeaders.content || '').toString().trim());
        result = Object.assign(result, parseDeliveryHeaders(messageHeaders.content) || {});
    }

    if (originalMessage) {
        try {
            let parsedOriginal = await simpleParser(originalMessage.content, { keepDeliveryStatus: true });
            if (parsedOriginal) {
                let headers = {};

                parsedOriginal.headerLines.forEach(entry => {
                    if (!headers[entry.key]) {
                        headers[entry.key] = [];
                    }
                    headers[entry.key].push(entry.line.substring(entry.key.length + 1).trim());
                });

                parsedMessageHeaders = headers;

                if (!result.messageId && parsedOriginal.messageId) {
                    result.messageId = parsedOriginal.messageId;
                }

                if (!deliveryStatus) {
                    deliveryStatus = parsedOriginal.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
                    if (deliveryStatus) {
                        result = Object.assign(result, parseDeliveryStatus(deliveryStatus.content) || {});
                    }
                }

                if (!messageHeaders) {
                    messageHeaders = parsedOriginal.attachments.find(attachment => attachment.contentType === 'text/rfc822-headers');
                    if (messageHeaders) {
                        result = Object.assign(result, parseDeliveryHeaders(messageHeaders.content) || {});
                    }
                }
            }
        } catch (E) {
            // should we ignore it?
        }
    }

    if (zohoOriginalMessage) {
        try {
            let parsedOriginal = await simpleParser(zohoOriginalMessage.content, { keepDeliveryStatus: true });
            if (parsedOriginal && parsedOriginal.text && (!parsedOriginal.headerLines || !parsedOriginal.headerLines.filter(h => h.key).length)) {
                let headerContent = (parsedOriginal.text || '').toString().replace(/^ (?=[^ ])/gm, '');
                let headers = libmime.decodeHeaders(headerContent);
                if (headers && headers['message-id']) {
                    parsedMessageHeaders = headers;
                    result = Object.assign(result, parseDeliveryHeaders(headerContent) || {});
                }
            }
        } catch (E) {
            // should we ignore it?
        }
    }

    let text = (parsed.text || '').toString();
    if (!text && !parsed.html && parsed.attachments) {
        let emptyContent = parsed.attachments.find(attachment => !attachment.contentType);
        if (emptyContent) {
            text = (emptyContent.content || '').toString();
        }
    }

    if (!result.recipient || !result.response || !result.response.message) {
        /*
            <user@example.com>: host mx.example.com[1.2.3.4] said:
                550 5.1.1 No such user (in reply to RCPT TO command)
        */
        let m = text.match(/<([^>@]+@[^>]+)>:\s*host\s+([a-z0-9._-]+)\s*(?:\[([^\]]+)\])?\s+said:/im);
        if (m) {
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                let message = text
                    .substr(m.index + m[0].length, end.index)
                    .replace(/\s+/g, ' ')
                    .trim();

                result.recipient = result.recipient || m[1].trim();
                result.action = result.action || 'failed';
                result.response = result.response || {};
                result.response.message = result.response.message || message;

                if (m[2]) {
                    result.mta = result.mta || m[2].trim();
                }

                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+.\d+.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    if (!result.recipient) {
        /*        
            Delivery to the following recipient failed permanently:
                user@example.com
        */

        let m = text.match(/Delivery\s[\s\w]*failed[\s\w]*:/im);
        if (m) {
            let addrMatch = text.substr(m.index + m[0].length).match(/\s*\n*\s*([^\s\n]+)/);
            if (addrMatch && addrMatch[1].indexOf('@') >= 0) {
                result.recipient = addrMatch[1].trim();
            }
        }
    }

    if (!result.recipient) {
        /*        
            The following recipients were affected: 
                user@example.com
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
            Technical details of permanent failure:

                550-5.7.1 [1.2.3.4 11] Our system has detected that this message is not RFC 5322 compliant: 'From' header is missing. To reduce the amount of spam sent to Gmail, this message has been blocked. Please visit https://support.google.com/mail/?p=RfcMessageNonCompliant and review RFC 5322 specifications for more information. j7si18025416lfe.198 - gsmtp
        */
        let m = text.match(/^\s*[45]\d{2}[\s-](\d+.\d+.\d+)[\s-]/im);
        if (m) {
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

                let message = text
                    .substr(m.index, m[0].length + end.index)
                    .replace(/\s+/g, ' ')
                    .trim();
                result.response = result.response || {};
                result.response.message = result.response.message || message;

                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+.\d+.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    // still nothing
    if (!result.recipient || !result.response || !result.response.message) {
        /*
            Sorry, we were unable to deliver your message to the following address.

            <user@example.com>:
            550: 5.1.1 <user@example.com>: Recipient address rejected: User unknown in relay recipient table
        */
        let m = text.match(/\n<([^>@]+@[^>]+)>:[\s\r\n]+/);
        if (m) {
            result.recipient = result.recipient || m[1];

            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

                let message = text
                    .substr(m.index + m[0].length, end.index)
                    .replace(/\s+/g, ' ')
                    .trim();

                result.response = result.response || {};
                result.response.message = result.response.message || message;

                if (!result.response.status) {
                    let statusMatch = message.match(/[45]\d{2}[\s-](\d+.\d+.\d+)[\s-]/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }

                if (!result.response.status) {
                    let statusMatch = message.match(/\(#(\d+.\d+.\d+)\)/);
                    if (statusMatch && statusMatch[1]) {
                        result.response.status = statusMatch[1];
                    }
                }
            }
        }
    }

    if (!result.recipient) {
        /*
        The following message to <user@example.com> was undeliverable
         */
        let m = text.match(/The following message to <([^>@]+@[^>]+)> was undeliverable/);
        if (m) {
            result.recipient = m[1];
        }
    }

    if (!result.response || !result.response.message) {
        /*
            The reason for the problem:
            5.1.0 - Unknown address error 550-'user@example.com... No such user'
        */
        let m = text.match(/The reason for the problem:[ \t]*\r?\n(\d+\.\d+\.\d+)\s+/);
        if (m) {
            let status = m[1];
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                result.action = result.action || 'failed';

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
        // Your message could not be delivered to the following address: <user@example.com>
        let m = text.match(/Your message could not be delivered to the following address:\s+<([^>@]+@[^>]+)>/);
        if (m) {
            result.recipient = result.recipient || m[1];

            // Remote host said: response message
            let resMatch = text.match(/Remote host said:\s*(.*)$/m);
            if (resMatch) {
                let message = resMatch[1].replace(/\s+/g, ' ').trim();
                result.response = result.response || {};
                result.response.message = result.response.message || message;
            }
        }
    }

    if (result.recipient && result.response && !result.response.message && /A message that you sent could not be delivered/.test(text)) {
        /*
            tfhgyuftghjyftghv@hot.ee
                SMTP error from remote mail server after RCPT TO:<tfhgyuftghjyftghv@hot.ee>:
                host mx1.hot.ee [194.126.101.119]: 550 5.1.1 <tfhgyuftghjyftghv@hot.ee>:
                Recipient address rejected: User unknown in relay recipient table
         */
        text.replace(/\r?\n/g, '\x04').replace(/\x04\s*\x04\s*([^\s@]+@[^\s@\x04]+)\s*((?:\x04\s*[^\x04]+)+)/g, (...a) => {
            let addr = a[1];
            if (addr !== result.recipient || (result.response && result.response.message)) {
                return;
            }

            let m = (a[2] || '')
                .replace(/\x04/g, ' ')
                .replace(/\s+/g, ' ')
                .trim()
                .match(/\shost\s[^:]+:\s*(.*)$/);

            if (m && m[1]) {
                result.response = result.response || {};
                result.response.message = m[1];
            }
        });
    }

    if (!result.messageId && text) {
        // try to find embedded message headers
        let m = text.match(/^(Received|Return-Path):/im);
        if (m) {
            let end = text.substr(m.index + m[0].length).match(/\r?\n\r?\n|$/);
            if (end) {
                let headers = text.substr(m.index, m[0].length + end.index).trim();
                let entries = libmime.decodeHeaders(headers);
                if (entries['message-id'] && entries['message-id'].length) {
                    result.messageId = entries['message-id'][0].trim();
                    if (!result.headers) {
                        parsedMessageHeaders = entries;
                    }
                }
            }
        }
    }

    result.messageHeaders = parsedMessageHeaders || null;

    return result;
}

module.exports = { bounceDetect };
