'use strict';

const MailComposer = require('nodemailer/lib/mail-composer');
const { pipeline } = require('stream');
const { Splitter, Joiner } = require('@zone-eu/mailsplit');
const { HeadersRewriter } = require('./headers-rewriter');
const { markParseFailure } = require('./smtp-message-processor');
const mimeFuncs = require('nodemailer/lib/mime-funcs');
const MimeNode = require('nodemailer/lib/mime-node');
const { parseAddressHeader } = require('mailparser');
const { randomUUID: uuid } = require('crypto');
const os = require('os');
const { getBoolean, genBaseBoundary, download } = require('./tools');
const msgpack = require('./msgpack');
const crypto = require('crypto');
const { parseMessage } = require('./parse-message');

const { MIME_BOUNDARY_PREFIX, MAX_DELIVERY_ATTEMPTS } = require('./consts');

// Runs a message through the splitter and the headers rewriter and collects the result.
//
// pipeline() rather than pipe(): Readable.pipe() only listens for errors on the destination, so a
// failure in the splitter or the rewriter used to be an uncaught exception that took the whole
// IMAP worker (every account on it) down. pipeline() listens on every stage and tears the chain
// down on the first error, which download() then rejects with. The splitter's failures (its 1MB
// header block and MIME node caps, both EMAXLEN) recur on every attempt, so they are marked
// permanent before pipeline() hands them on; a headers-rewriter error can only come from our own
// callback, so it keeps the retryable default, like on the SMTP path.
function collectRewritten(splitter, headersRewriter, joiner, raw) {
    splitter.once('error', markParseFailure);
    pipeline(splitter, headersRewriter, joiner, () => {
        // every failure reaches the joiner, where download() rejects with it
    });
    splitter.end(raw);
    return download(joiner);
}

function getKeyHeader(licenseInfo) {
    if (!licenseInfo?.details?.key) {
        return 'UNLICENSED_COPY';
    }
    return msgpack.encode({ n: crypto.randomBytes(4), t: Date.now(), l: Buffer.from(licenseInfo.details.key, 'hex') }).toString('base64url');
}

/**
 * Reads and removes the X-EE-* control headers of a raw message, and takes the subject from the
 * message when the request gave none
 * @param {Object} headers - mailsplit headers of the root node
 * @param {Object} current - sendAt, deliveryAttempts, gateway, trackingEnabled and subject of the request
 * @returns {Object} The same fields, updated from the headers
 */
function extractControlHeaders(headers, current) {
    const result = Object.assign({}, current);

    let sendAtVal = headers.getFirst('x-ee-send-at');
    headers.remove('x-ee-send-at');

    let deliveryAttemptsVal = headers.getFirst('x-ee-delivery-attempts');
    headers.remove('x-ee-delivery-attempts');

    let gatewayVal = headers.getFirst('x-ee-gateway');
    headers.remove('x-ee-gateway');

    if (headers.hasHeader('x-ee-tracking-enabled')) {
        result.trackingEnabled = getBoolean(headers.getFirst('x-ee-tracking-enabled'));
        headers.remove('x-ee-tracking-enabled');
    }

    if (!result.subject && headers.hasHeader('subject')) {
        result.subject = headers.getFirst('subject');
    }

    if (sendAtVal) {
        if (!isNaN(sendAtVal)) {
            sendAtVal = Number(sendAtVal);
        }
        sendAtVal = new Date(sendAtVal);
        if (sendAtVal.toString() !== 'Invalid Date') {
            result.sendAt = sendAtVal;
        }
    }

    if (deliveryAttemptsVal && !isNaN(deliveryAttemptsVal)) {
        // within the bounds the API schema gives the same option; the header is what a stored
        // draft or an SMTP submission carries, and nothing else validates it
        result.deliveryAttempts = Math.min(Math.max(Math.round(Number(deliveryAttemptsVal)), 1), MAX_DELIVERY_ATTEMPTS);
    }

    if (gatewayVal) {
        result.gateway = gatewayVal;
    }

    return result;
}

/**
 * Replaces, adds or removes the From, To, Cc and Bcc headers the request names. A default sender
 * does not replace the one the message already has
 * @param {Object} headers - mailsplit headers of the root node
 * @param {Object} data - Request data
 */
function applyAddressHeaders(headers, data) {
    for (let addrKey of ['from', 'to', 'cc', 'bcc']) {
        if (!(addrKey in data)) {
            continue;
        }

        let addrValue = [].concat(data[addrKey] || []);
        if (!addrValue.length) {
            // remove existing
            headers.remove(addrKey);
            continue;
        }

        // update or add new
        let headerLine = MimeNode.encodeHeaderValue(addrKey, addrValue);
        if (headers.hasHeader(addrKey)) {
            let addressEntries = addrValue.filter(entry => !entry._default);
            if (!addressEntries.length) {
                // Do not replace existing value with a default value
                continue;
            }
            headers.update(
                addrKey.replace(/^./, c => c.toUpperCase()),
                headerLine
            );
        } else {
            // push to bottom
            headers.add(
                addrKey.replace(/^./, c => c.toUpperCase()),
                headerLine,
                Infinity
            );
        }
    }
}

/**
 * The SMTP envelope of a raw message: the one the request gave, else the addresses of the
 * (already rewritten) address headers
 * @param {Object} headers - mailsplit headers of the root node
 * @param {Object} data - Request data
 * @returns {Object} Envelope with a single `from` and a `to` list
 */
function buildEnvelope(headers, data) {
    // The addresses an envelope is built from: a punycode domain stays in the ASCII form every
    // server accepts, and an entry left without an address (an encoded word hiding one is
    // dropped by the parser) is no recipient. getDecoded() unfolds the value and drops the
    // header name, and leaves encoded words for the parser to judge
    const envelopeAddresses = key =>
        parseAddressHeader(
            headers.getDecoded(key).map(header => header.value),
            { flatten: true, decodePunycode: false }
        )
            .value.map(addr => addr.address)
            .filter(address => address);

    let envelope = data.envelope || {
        from: envelopeAddresses('from')[0] || '',
        to: Array.from(new Set([...envelopeAddresses('to'), ...envelopeAddresses('cc'), ...envelopeAddresses('bcc')]))
    };

    envelope.from = [].concat(envelope.from || []).shift() || '';
    envelope.to = [].concat(envelope.to || []);

    return envelope;
}

/**
 * Makes sure a raw message has a Message-ID (generated on the envelope sender domain, or the one
 * the request gave), a Date and a MIME-Version header
 * @param {Object} headers - mailsplit headers of the root node
 * @param {Object} data - Request data
 * @param {Object} envelope - SMTP envelope
 * @returns {string} The Message-ID of the message
 */
function ensureStandardHeaders(headers, data, envelope) {
    let messageId;

    // generate default message-id
    if (!data.messageId && !headers.hasHeader('message-id')) {
        let fromDomain = envelope.from ? envelope.from.split('@').pop().toLowerCase() : os.hostname();
        messageId = `<${uuid()}@${fromDomain}>`;
        headers.add('Message-ID', messageId, Infinity);
    }

    if (data.messageId) {
        messageId = (data.messageId || '').toString().trim().replace(/^<*/, '<').replace(/>*$/, '>');
        headers.update('Message-ID', messageId);
    }

    if (!messageId) {
        messageId = headers.getFirst('message-id');
    }

    // make sure that there is a Date header
    if (!headers.hasHeader('date')) {
        let dateVal = (data.date || new Date()).toUTCString().replace(/GMT/, '+0000');
        headers.add('Date', dateVal, Infinity);
    }

    // ... and MIME-Version
    if (!headers.hasHeader('mime-version')) {
        headers.add('MIME-Version', '1.0', Infinity);
    }

    return messageId;
}

/**
 * Adds the custom headers of the request. In-Reply-To and References replace the message's own
 * @param {Object} headers - mailsplit headers of the root node
 * @param {Object} [customHeaders] - Custom headers of the request
 */
function applyCustomHeaders(headers, customHeaders) {
    if (!customHeaders) {
        return;
    }

    for (let key of Object.keys(customHeaders)) {
        let casedKey = key.replace(/^.|-./g, c => c.toUpperCase());
        switch (key.toLowerCase()) {
            case 'in-reply-to':
            case 'references':
                headers.update(casedKey, customHeaders[key]);
                break;
            default:
                // Encoded like any other header: a non-ASCII value used to go out as raw 8-bit
                headers.add(casedKey, typeof customHeaders[key] === 'string' ? MimeNode.encodeHeaderValue(casedKey, customHeaders[key]) : customHeaders[key]);
                break;
        }
    }
}

async function processMessage(data, licenseInfo) {
    let raw = typeof data.raw === 'string' ? Buffer.from(data.raw, 'base64') : data.raw;
    let hasBcc = false;

    let messageId, envelope;

    // what the request gave, until the control headers of the message say otherwise
    let control = {
        sendAt: data.sendAt,
        deliveryAttempts: data.deliveryAttempts,
        subject: data.subject,
        trackingEnabled: data.trackingEnabled,
        gateway: data.gateway
    };

    const splitter = new Splitter();
    const joiner = new Joiner();

    // The steps depend on each other in this order: the envelope is built from the rewritten
    // address headers, and a generated Message-ID uses the envelope sender's domain
    const headersRewriter = new HeadersRewriter(async headers => {
        control = extractControlHeaders(headers, control);

        if (control.sendAt && control.sendAt > new Date()) {
            // update Date: header for delayed messages
            headers.update('Date', control.sendAt.toUTCString().replace(/GMT/, '+0000'));
        }

        if (licenseInfo) {
            headers.add('X-Ee-Sid', getKeyHeader(licenseInfo));
        }

        applyAddressHeaders(headers, data);

        hasBcc = headers.hasHeader('bcc');

        envelope = buildEnvelope(headers, data);

        messageId = ensureStandardHeaders(headers, data, envelope);

        if (data.subject) {
            headers.update('Subject', mimeFuncs.encodeWords(data.subject, 'Q', 64, true));
        }

        applyCustomHeaders(headers, data.headers);
    });

    let message = await collectRewritten(splitter, headersRewriter, joiner, raw);

    const { sendAt, deliveryAttempts, subject, trackingEnabled, gateway } = control;

    let trackClicks = typeof data.trackClicks === 'boolean' ? data.trackClicks : trackingEnabled;
    let trackOpens = typeof data.trackOpens === 'boolean' ? data.trackOpens : trackingEnabled;

    return {
        raw: message,
        hasBcc,
        messageId,
        envelope,
        subject,
        sendAt,
        deliveryAttempts,
        trackClicks,
        trackOpens,
        trackingEnabled,
        gateway
    };
}

async function removeBcc(raw) {
    const splitter = new Splitter();
    const joiner = new Joiner();
    const headersRewriter = new HeadersRewriter(async headers => {
        headers.remove('bcc');
    });

    return collectRewritten(splitter, headersRewriter, joiner, raw);
}

function addPreviev(html, previewText) {
    let formattedPreviewText = `<!--[if !gte mso 9]><!---->
<div style="
    display:none !important;
    max-height: 0px;
    max-width: 1px;
    font-size: 1px;
    line-height: 1px;
    opacity: 0.0;
    mso-hide: all;
    overflow: hidden !important;
    visibility: hidden !important;
">${previewText} ${'&#8199;&#65279;&#847; '.repeat(100)}</div>
<!--<![endif]-->`;

    let bodyStartMatch = html.match(/<body\b/i);
    if (!bodyStartMatch) {
        // no body tag found, so inject the preview to the beginning of the HTML
        return `${formattedPreviewText}
${html}`;
    }

    // Can't use a regex to detect tag end as regexes do not catch potential line breaks
    let insertPos = -1;
    let maxCheckLen = 1000;
    let startPos = bodyStartMatch.index + bodyStartMatch[0].length;
    let maxEndPos = Math.min(startPos + maxCheckLen, html.length);
    for (let i = startPos; i < maxEndPos; i++) {
        let c = html.charAt(i);
        if (c === '>') {
            // found tag ending
            insertPos = i;
            break;
        }
    }

    if (insertPos >= 0) {
        return html.substring(0, insertPos + 1) + '\n' + formattedPreviewText + html.substring(insertPos + 1);
    }

    // could not figure out where to add the preview text
    return html;
}

/**
 * Parses a raw message into the structured object a structured (API) send takes
 * @param {Buffer} raw - RFC822 message
 * @returns {Object} Message object
 */
async function parseRawToObject(raw) {
    // parse email into a structured object
    const parsed = await parseMessage(raw, {
        skipHtmlToText: true,
        skipImageLinks: true,
        skipTextToHtml: true,
        skipTextLinks: true,
        keepDeliveryStatus: true,
        keepCidLinks: true,
        ignoreEmbedded: true,
        defaultInlineEmbedded: false,
        maxHeadSize: 2 * 1024 * 1024
    });

    if (parsed.from) {
        parsed.from = parsed.from.value?.[0];
    }

    for (let key of ['to', 'cc', 'bcc', 'replyTo']) {
        if (parsed[key]) {
            parsed[key] = parsed[key].value;
        }
    }

    delete parsed.headers; // conflicts

    for (let attachment of parsed.attachments || []) {
        attachment.content = attachment.content.toString('base64');
        attachment.encoding = 'base64';
        if (attachment.contentId) {
            attachment.cid = attachment.contentId;
        }
        attachment.isInline = attachment.contentDisposition === 'inline';
    }

    return parsed;
}

/**
 * The MailComposer options of a structured message: the request with the preview text injected
 * into the html, the license header added and the EmailEngine-only options unset. Takes the
 * preview text out of `data`
 * @param {Object} data - Request data
 * @param {Object} licenseInfo - License information
 * @returns {Object} MailComposer options
 */
function buildComposerOptions(data, licenseInfo) {
    let html = data.html || null;
    if (data.previewText && html) {
        let previewText = data.previewText;
        delete data.previewText;
        html = addPreviev(html, previewText);
    }

    return Object.assign(
        {
            date: data.sendAt,
            disableUrlAccess: true,
            disableFileAccess: true,
            newline: '\r\n',
            boundaryPrefix: MIME_BOUNDARY_PREFIX,
            baseBoundary: genBaseBoundary()
        },
        data,
        {
            headers: Object.assign(
                {},
                data.headers || {},
                licenseInfo
                    ? {
                          'X-Ee-Sid': getKeyHeader(licenseInfo)
                      }
                    : {}
            ),
            html,
            // unset EE specific configuration elements
            sendAt: null,
            deliveryAttempts: null,
            gateway: null,
            trackingEnabled: null,
            trackClicks: null,
            trackOpens: null,
            previewText: null
        }
    );
}

/**
 * Builds the MIME message of a structured submission
 * @param {Object} mailComposerOptions - What buildComposerOptions() returned
 * @returns {Object} raw, messageId and envelope
 */
async function composeMime(mailComposerOptions) {
    for (let attachment of mailComposerOptions.attachments || []) {
        // Insert message/rfc822 attachments "as is" without any encoding. Handed over decoded,
        // nodemailer (10.2.0) labels the part 7bit when it is plain ASCII and 8bit otherwise,
        // which this used to work out itself by building the part's headers by hand
        if (/^message\/rfc822\b/i.test(attachment.contentType) && typeof attachment.content === 'string' && attachment.encoding) {
            attachment.content = Buffer.from(attachment.content, attachment.encoding);
            delete attachment.encoding;
            attachment.contentDisposition = attachment.contentDisposition || 'attachment';
        }
    }

    const mail = new MailComposer(mailComposerOptions);

    let compiled;
    try {
        compiled = mail.compile();
    } catch (err) {
        // an otp value the schema let through but the OTP-Token header can not carry
        if (err.code === 'EOTP') {
            err.statusCode = 400;
        }
        throw err;
    }
    // do not strip Bcc header from the message (will be removed later)
    compiled.keepBcc = true;

    const messageId = compiled.messageId();
    const raw = await compiled.build();
    const envelope = compiled.getEnvelope();

    return { raw, messageId, envelope };
}

/**
 * The SMTP envelope of a structured submission that is not built into MIME
 * @param {Object} data - Request data
 * @returns {Object} Envelope
 */
function envelopeFromData(data) {
    let envelopeTo = new Set();
    for (let key of ['to', 'cc', 'bcc']) {
        data[key]
            ?.map(entry => entry.address)
            .filter(address => address)
            .forEach(address => {
                envelopeTo.add(address);
            });
    }

    return {
        from: data.from?.address || null,
        to: Array.from(envelopeTo)
    };
}

async function getRawEmail(data, licenseInfo, options) {
    options = options || {};

    if (data.raw) {
        let response = await processMessage(data, licenseInfo);

        if (options.returnObject) {
            response.emailObject = await parseRawToObject(response.raw);
        }

        return response;
    }

    let sendAt = data.sendAt;
    let deliveryAttempts = data.deliveryAttempts;
    let gateway = data.gateway;
    let trackingEnabled = data.trackingEnabled;

    let trackClicks = typeof data.trackClicks === 'boolean' ? data.trackClicks : trackingEnabled;
    let trackOpens = typeof data.trackOpens === 'boolean' ? data.trackOpens : trackingEnabled;

    const mailComposerOptions = buildComposerOptions(data, licenseInfo);

    let emailBuffer;
    let emailObject;

    let messageId;
    let envelope;

    if (!options.returnObject) {
        ({ raw: emailBuffer, messageId, envelope } = await composeMime(mailComposerOptions));
    } else {
        emailObject = mailComposerOptions;
        messageId = data.messageId;
        envelope = envelopeFromData(data);
    }

    const bcc = [].concat(data.bcc || []);

    return {
        raw: emailBuffer,
        emailObject,
        hasBcc: !!bcc.length,
        messageId,
        envelope,
        subject: data.subject || null,
        sendAt,
        deliveryAttempts,
        trackingEnabled,
        trackClicks,
        trackOpens,
        gateway
    };
}

module.exports = {
    getRawEmail,
    removeBcc
};
