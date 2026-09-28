'use strict';

const Rewriter = require('@zone-eu/mailsplit/lib/node-rewriter');
const Splitter = require('@zone-eu/mailsplit/lib/message-splitter');
const Joiner = require('@zone-eu/mailsplit/lib/message-joiner');
const encodingJapanese = require('encoding-japanese');
const { Transform, pipeline } = require('stream');
const iconv = require('iconv-lite');
const LeWindows = require('nodemailer/lib/mime-node/le-windows');
const { markParseFailure } = require('./smtp-message-processor');
const logger = require('./logger').child({ component: 'rewrite-text-nodes' });

class JPDecoder extends Transform {
    constructor(charset) {
        super();

        this.charset = charset;
        this.chunks = [];
        this.chunklen = 0;
    }

    _transform(chunk, encoding, done) {
        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.chunks.push(chunk);
        this.chunklen += chunk.length;
        done();
    }

    _flush(done) {
        let input = Buffer.concat(this.chunks, this.chunklen);
        try {
            let output = encodingJapanese.convert(input, {
                to: 'UNICODE', // to_encoding
                from: this.charset, // from_encoding
                type: 'string'
            });
            if (typeof output === 'string') {
                output = Buffer.from(output);
            }
            this.push(output);
        } catch (err) {
            logger.debug({ msg: 'Failed to convert Japanese charset, keeping original content', charset: this.charset, err });
            // keep as is on errors
            this.push(input);
        }

        done();
    }
}

const createDecodeStream = charset => {
    charset = (charset || 'ascii').toString().trim().toLowerCase();
    if (/^jis|^iso-?2022-?jp|^EUCJP/i.test(charset)) {
        // special case not supported by iconv-lite
        return new JPDecoder(charset);
    }

    return iconv.decodeStream(charset);
};

/**
 * Rewrites text content in email messages
 * @param {String|Buffer|ReadableStream} source RFC822 formatted email message
 * @param {Function} [options.htmlRewriter] Async function that gets html string as input and must return a html string to replace it. Might be called multiple times, once for each HTML node
 * @param {Function} [options.textRewriter] Async function that gets text string as input and must return a text string to replace it. Might be called multiple times, once for each plaintext node
 * @returns {Buffer} RFC822 formatted email message
 */
function rewriteTextNodes(source, options) {
    options = options || {};
    return new Promise((resolve, reject) => {
        if (!source) {
            return reject(new Error('Missing input source'));
        }

        const splitter = new Splitter();
        const joiner = new Joiner();
        // The tail of the pipe chain. Every failure inside the chain is routed to its 'error'
        // handler below, which rejects the returned promise.
        const newlines = new LeWindows();

        // create a Rewriter for text/html
        let rewriter = new Rewriter(node => {
            if (
                ![]
                    .concat(options.htmlRewriter ? 'text/html' : [])
                    .concat(options.textRewriter ? 'text/plain' : [])
                    .includes(node.contentType) ||
                node.disposition === 'attachment'
            ) {
                return false;
            }

            let parentNode = node;
            while ((parentNode = parentNode.parentNode)) {
                if (['message/rfc822'].includes(parentNode.contentType)) {
                    // skip embedded
                    return false;
                }
            }

            return true;
        });

        rewriter.on('node', data => {
            let chunks = [];
            let chunklen = 0;

            let encoded = !!data.node.charset;
            let decoder = data.decoder;

            if (encoded && !['ascii', 'usascii', 'utf8'].includes(data.node.charset.toLowerCase().replace(/[^a-z0-9]+/g, ''))) {
                try {
                    let contentStream = decoder;
                    let decodeStream = createDecodeStream(data.node.charset);
                    contentStream.on('error', err => {
                        decodeStream.emit('error', err);
                    });
                    contentStream.pipe(decodeStream);
                    decoder = decodeStream;
                } catch (err) {
                    logger.debug({ msg: 'Failed to create charset decode stream, keeping original charset', charset: data.node.charset, err });
                    // do not decode charset
                }
            }

            // Nothing else listens for errors on the node decoder, so without this a decoder
            // failure would be an uncaughtException that takes the worker with it. None of the
            // decoders used here has a failure path today, so this is a guard against the next
            // dependency update giving one of them one, not a fix for a reachable case. Routed
            // to the tail so it rejects the same way any other pipeline failure does.
            decoder.on('error', err => {
                newlines.emit('error', err);
            });

            decoder.on('readable', () => {
                let chunk;
                while ((chunk = decoder.read()) !== null) {
                    if (typeof chunk === 'string') {
                        chunk = Buffer.from(chunk, 'utf-8');
                    }

                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });

            decoder.on('end', () => {
                const htmlBuf = Buffer.concat(chunks, chunklen);
                let html = htmlBuf.toString('utf-8');

                // enforce utf-8
                data.node.setCharset('utf-8');

                let handler;
                switch (data.node.contentType) {
                    case 'text/plain':
                        handler = options.textRewriter;
                        break;

                    case 'text/html':
                        handler = options.htmlRewriter;
                        break;
                }

                handler(html, data.node)
                    .then(formattedHtml => {
                        if (typeof formattedHtml !== 'string') {
                            // keep original value
                            data.encoder.end(htmlBuf);
                            return;
                        }

                        // return a Buffer
                        data.encoder.end(Buffer.from(formattedHtml, 'utf-8'));
                    })
                    .catch(err => {
                        logger.warn({ msg: 'Failed to rewrite text node, keeping original content', err });
                        // keep original value
                        data.encoder.end(htmlBuf);
                        return;
                    });
            });
        });

        const finalChunks = [];
        let finalChunkLen = 0;

        newlines.on('data', chunk => {
            if (typeof chunk === 'string') {
                chunk = Buffer.from(chunk, 'utf-8');
            }

            finalChunks.push(chunk);
            finalChunkLen += chunk.length;
        });

        newlines.on('end', () => {
            resolve(Buffer.concat(finalChunks, finalChunkLen));
        });

        // A splitter failure (EMAXLEN: a 1MB header block or too many MIME nodes) is a verdict on
        // the message and recurs on every attempt, so it is marked permanent the same way the
        // SMTP and raw-message paths mark it.
        splitter.once('error', markParseFailure);

        // pipeline() rather than pipe(): Readable.pipe() only listens for errors on the
        // destination, so a splitter limit used to be an uncaught exception that took the whole
        // worker down. pipeline() listens on every stage, source included, and tears the whole
        // chain down on the first failure. The node decoders are not stages of the chain; their
        // failures are emitted on the tail above, which pipeline() picks up like any other.
        const inline = typeof source === 'string' || Buffer.isBuffer(source);
        const stages = inline ? [splitter, rewriter, joiner, newlines] : [source, splitter, rewriter, joiner, newlines];
        pipeline(...stages, err => {
            if (err) {
                reject(err);
            }
        });

        if (inline) {
            splitter.end(Buffer.isBuffer(source) ? source : Buffer.from(source));
        }
    });
}

module.exports = { rewriteTextNodes };

/*
// example
let source = require('fs').createReadStream(process.argv[2]);
rewriteTextNodes(source, {
    htmlRewriter: async html => {
        // append ad link to the HTML code
        let adLink = '<p><a href="http://example.com/">Visit my Awesome homepage!!!!</a>🐭</p>';

        if (/<\/body\b/i.test(html)) {
            // add before <body> close
            html = html.replace(/<\/body\b/i, match => '\r\n' + adLink + '\r\n' + match);
        } else {
            // append to the body
            html += '\r\n' + adLink;
        }

        return html;
    },

    textRewriter: async text => {
        // append ad link to the HTML code
        let adLink = '[Visit my Awesome homepage!!!!](http://example.com/)';

        // append to the body
        text += '\r\n' + adLink;

        return text;
    }
})
    .then(html => {
        process.stdout.write(html);
        console.error('parser complete', Buffer.isBuffer(html), html.length);
    })
    .catch(err => {
        console.error('parsing failed', err);
    });
*/
