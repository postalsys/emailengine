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

async function processMessage(data) {
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
            let dateVal = new Date().toUTCString().replace(/GMT/, '+0000');
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

async function getRawEmail(data) {
    if (data.raw) {
        return await processMessage(data);
    }

    let sendAt = data.sendAt;
    delete data.sendAt;

    let deliveryAttempts = data.deliveryAttempts;
    delete data.deliveryAttempts;

    let trackingEnabled = data.trackingEnabled;
    delete data.trackingEnabled;

    data.disableUrlAccess = true;
    data.disableFileAccess = true;
    data.newline = '\r\n';

    const mail = new MailComposer(
        Object.assign(
            {
                date: sendAt
            },
            data
        )
    );

    const compiled = mail.compile();
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
        trackingEnabled
    };
}

module.exports = {
    getRawEmail,
    removeBcc
};
