'use strict';

const MailComposer = require('nodemailer/lib/mail-composer');
const { Splitter, Joiner } = require('mailsplit');
const Transform = require('stream').Transform;
const mimeFuncs = require('nodemailer/lib/mime-funcs');
const MimeNode = require('nodemailer/lib/mime-node');
const addressparser = require('nodemailer/lib/addressparser');
const uuid = require('uuid');
const os = require('os');
const libmime = require('libmime');

class HeadersRewriter extends Transform {
    constructor(headersCb) {
        let options = {
            readableObjectMode: true,
            writableObjectMode: true
        };
        super(options);
        this.headersCb = headersCb;
    }

    _transform(obj, encoding, callback) {
        if (obj.type !== 'node' || !obj.root || !typeof this.headersCb) {
            this.push(obj);
            return callback();
        }
        this.headersCb(obj.headers)
            .then(() => {
                this.push(obj);
                return callback();
            })
            .catch(err => callback(err));
    }

    _flush(callback) {
        return callback();
    }
}

async function processMessage(data) {
    let raw = typeof data.raw === 'string' ? Buffer.from(data.raw, 'base64') : data.raw;
    let hasBcc = false;

    let messageId, envelope;
    let sendAt = data.sendAt;

    const splitter = new Splitter();
    const joiner = new Joiner();
    const headersRewriter = new HeadersRewriter(async headers => {
        let mn = new MimeNode();

        let sendAtVal = headers.getFirst('x-ee-send-at');
        headers.remove('x-ee-send-at');
        if (sendAtVal) {
            if (!isNaN(sendAtVal)) {
                sendAtVal = Number(sendAtVal);
            }
            sendAtVal = new Date(sendAtVal);
            if (sendAtVal.toString() !== 'Invalid Date') {
                sendAt = sendAtVal;
            }
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
            headers.add('Message-ID', messageId);
        }

        if (data.messageId) {
            messageId = (data.messageId || '').toString().trim().replace(/^<*/, '<').replace(/>*$/, '>');
            headers.update('Message-ID', messageId);
        }

        if (!messageId) {
            messageId = headers.getFirst('message-id');
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

    return { raw: message, hasBcc, messageId, envelope, sendAt };
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

    const mail = new MailComposer(data);
    let compiled = mail.compile();
    compiled.keepBcc = true;

    let messageId = compiled.messageId();

    let email = await compiled.build();

    let bcc = [].concat(data.bcc || []);

    return { raw: email, hasBcc: !!bcc.length, messageId, envelope: compiled.getEnvelope(), sendAt };
}

module.exports = { getRawEmail, removeBcc };
