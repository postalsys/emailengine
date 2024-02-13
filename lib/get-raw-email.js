'use strict';

const MailComposer = require('nodemailer/lib/mail-composer');
const { Splitter, Joiner } = require('mailsplit');
const { HeadersRewriter } = require('./headers-rewriter');
const mimeFuncs = require('nodemailer/lib/mime-funcs');
const MimeNode = require('nodemailer/lib/mime-node');
const addressparser = require('nodemailer/lib/addressparser');
const uuid = require('uuid');
const os = require('os');
const libmime = require('libmime');
const { getBoolean } = require('./tools');
const msgpack = require('msgpack5')();
const crypto = require('crypto');

function getKeyHeader(licenseInfo) {
    if (!licenseInfo) {
        return 'UNLICENSED_COPY';
    }
    return msgpack.encode({ n: crypto.randomBytes(4), t: Date.now(), l: Buffer.from(licenseInfo.details.key, 'hex') }).toString('base64url');
}

async function processMessage(data, licenseInfo) {
    let raw = typeof data.raw === 'string' ? Buffer.from(data.raw, 'base64') : data.raw;
    let hasBcc = false;

    let messageId, envelope;
    let sendAt = data.sendAt;
    let deliveryAttempts = data.deliveryAttempts;
    let subject = data.subject;
    let trackingEnabled = data.trackingEnabled;
    let gateway = data.gateway;

    const splitter = new Splitter();
    const joiner = new Joiner();
    const headersRewriter = new HeadersRewriter(async headers => {
        let mn = new MimeNode();

        let sendAtVal = headers.getFirst('x-ee-send-at');
        headers.remove('x-ee-send-at');

        let deliveryAttemptsVal = headers.getFirst('x-ee-delivery-attempts');
        headers.remove('x-ee-delivery-attempts');

        let gatewayVal = headers.getFirst('x-ee-gateway');
        headers.remove('x-ee-gateway');

        if (headers.hasHeader('x-ee-tracking-enabled')) {
            trackingEnabled = getBoolean(headers.getFirst('x-ee-tracking-enabled'));
            headers.remove('x-ee-tracking-enabled');
        }

        if (!subject && headers.hasHeader('subject')) {
            subject = headers.getFirst('subject');
        }

        if (sendAtVal) {
            if (!isNaN(sendAtVal)) {
                sendAtVal = Number(sendAtVal);
            }
            sendAtVal = new Date(sendAtVal);
            if (sendAtVal.toString() !== 'Invalid Date') {
                sendAt = sendAtVal;
            }
        }

        if (deliveryAttemptsVal && !isNaN(deliveryAttemptsVal)) {
            deliveryAttempts = Number(deliveryAttemptsVal);
        }

        if (gatewayVal) {
            gateway = gatewayVal;
        }

        if (sendAt && sendAt > new Date()) {
            // update Date: header for delayed messages
            headers.update('Date', sendAt.toUTCString().replace(/GMT/, '+0000'));
        }

        if (licenseInfo) {
            headers.add('X-Ee-Sid', getKeyHeader(licenseInfo));
        }

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
            let headerLine = mn._encodeHeaderValue(addrKey, addrValue);
            if (headers.hasHeader(addrKey)) {
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

        hasBcc = headers.hasHeader('bcc');

        let addresses = {
            from: headers
                .get('from')
                .flatMap(line => addressparser(line, { flatten: true }))
                .filter(a => a)
                .map(addr => {
                    if (addr.name) {
                        try {
                            addr.name = libmime.decodeWords(addr.name);
                        } catch (err) {
                            // ignore
                        }
                    }
                    return addr;
                })
                .find(addr => addr && addr.address),
            to: headers
                .get('to')
                .flatMap(line => addressparser(line, { flatten: true }))
                .filter(a => a)
                .map(addr => {
                    if (addr.name) {
                        try {
                            addr.name = libmime.decodeWords(addr.name);
                        } catch (err) {
                            // ignore
                        }
                    }
                    return addr;
                }),
            cc: headers
                .get('cc')
                .flatMap(line => addressparser(line, { flatten: true }))
                .filter(a => a)
                .map(addr => {
                    if (addr.name) {
                        try {
                            addr.name = libmime.decodeWords(addr.name);
                        } catch (err) {
                            // ignore
                        }
                    }
                    return addr;
                }),
            bcc: headers
                .get('bcc')
                .flatMap(line => addressparser(line, { flatten: true }))
                .filter(a => a)
                .map(addr => {
                    if (addr.name) {
                        try {
                            addr.name = libmime.decodeWords(addr.name);
                        } catch (err) {
                            // ignore
                        }
                    }
                    return addr;
                })
        };

        envelope = data.envelope || {
            from: (addresses.from && addresses.from.address) || '',
            to: Array.from(
                new Set(
                    []
                        .concat(addresses.to)
                        .concat(addresses.cc)
                        .concat(addresses.bcc)
                        .map(addr => addr.address)
                )
            )
        };

        envelope.from = [].concat(envelope.from || []).shift() || '';
        envelope.to = [].concat(envelope.to || []);

        // generate default message-id
        if (!data.messageId && !headers.hasHeader('message-id')) {
            let fromDomain = envelope.from ? envelope.from.split('@').pop().toLowerCase() : os.hostname();
            messageId = `<${uuid.v4()}@${fromDomain}>`;
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

        if (data.subject) {
            headers.update('Subject', mimeFuncs.encodeWords(data.subject, 'Q', 64, true));
        }

        if (data.headers) {
            for (let key of Object.keys(headers)) {
                let casedKey = key.replace(/^.|-./g, c => c.toUpperCase());
                switch (key) {
                    case 'in-reply-to':
                    case 'references':
                        headers.update(casedKey, headers[key]);
                        break;
                    default:
                        headers.add(casedKey, headers[key]);
                        break;
                }
            }
        }
    });

    let message = await new Promise((resolve, reject) => {
        let chunks = [];
        let chunklen = 0;

        joiner.on('readable', () => {
            let chunk;
            while ((chunk = joiner.read()) !== null) {
                chunks.push(chunk);
                chunklen += chunk.length;
            }
        });

        joiner.once('end', () => {
            resolve(Buffer.concat(chunks, chunklen));
        });

        joiner.once('error', err => reject(err));
        splitter.pipe(headersRewriter).pipe(joiner);
        splitter.end(raw);
    });

    return { raw: message, hasBcc, messageId, envelope, subject, sendAt, deliveryAttempts, trackingEnabled, gateway };
}

async function removeBcc(raw) {
    const splitter = new Splitter();
    const joiner = new Joiner();
    const headersRewriter = new HeadersRewriter(async headers => {
        headers.remove('bcc');
    });

    return new Promise((resolve, reject) => {
        let chunks = [];
        let chunklen = 0;

        joiner.on('readable', () => {
            let chunk;
            while ((chunk = joiner.read()) !== null) {
                chunks.push(chunk);
                chunklen += chunk.length;
            }
        });

        joiner.once('end', () => {
            resolve(Buffer.concat(chunks, chunklen));
        });

        joiner.once('error', err => reject(err));
        splitter.pipe(headersRewriter).pipe(joiner);
        splitter.end(raw);
    });
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

async function getRawEmail(data, licenseInfo) {
    if (data.raw) {
        return await processMessage(data, licenseInfo);
    }

    let sendAt = data.sendAt;
    let deliveryAttempts = data.deliveryAttempts;
    let gateway = data.gateway;
    let trackingEnabled = data.trackingEnabled;

    let html = data.html || null;
    if (data.previewText && html) {
        let previewText = data.previewText;
        delete data.previewText;
        if (html) {
            html = addPreviev(html, previewText);
        }
    }

    const mail = new MailComposer(
        Object.assign(
            {
                date: sendAt,
                disableUrlAccess: true,
                disableFileAccess: true,
                newline: '\r\n'
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
                previewText: null
            }
        )
    );

    const compiled = mail.compile();
    // do not strip Bcc header from the message (will be removed later)
    compiled.keepBcc = true;

    const messageId = compiled.messageId();
    const email = await compiled.build();

    const bcc = [].concat(data.bcc || []);

    return {
        raw: email,
        hasBcc: !!bcc.length,
        messageId,
        envelope: compiled.getEnvelope(),
        subject: data.subject || null,
        sendAt,
        deliveryAttempts,
        trackingEnabled,
        gateway
    };
}

module.exports = {
    getRawEmail,
    removeBcc
};
