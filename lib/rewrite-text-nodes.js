'use strict';

const Rewriter = require('mailsplit/lib/node-rewriter');
const Splitter = require('mailsplit/lib/message-splitter');
const Joiner = require('mailsplit/lib/message-joiner');
const encodingJapanese = require('encoding-japanese');
const { Transform } = require('stream');
const iconv = require('iconv-lite');
const LeWindows = require('nodemailer/lib/mime-node/le-windows');

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
            console.error(err);
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
                    console.error(err);
                    // do not decode charset
                }
            }

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
                        console.error(err);
                        // keep original value
                        data.encoder.end(htmlBuf);
                        return;
                    });
            });
        });

        // set up pipe chain
        let newlines = new LeWindows();
        splitter.pipe(rewriter).pipe(joiner).pipe(newlines);

        joiner.on('error', err => {
            newlines.emit('error', err);
        });

        const finalChunks = [];
        let finalChunkLen = 0;

        newlines.on('readable', () => {
            let chunk;
            while ((chunk = newlines.read()) !== null) {
                if (typeof chunk === 'string') {
                    chunk = Buffer.from(chunk, 'utf-8');
                }

                finalChunks.push(chunk);
                finalChunkLen += chunk.length;
            }
        });

        newlines.on('error', err => {
            try {
                source.destroy();
            } catch (E) {
                // ignore
            }
            reject(err);
        });

        newlines.on('end', () => {
            resolve(Buffer.concat(finalChunks, finalChunkLen));
        });

        if (typeof source === 'string') {
            splitter.end(Buffer.from(source));
        } else if (Buffer.isBuffer(source)) {
            splitter.end(source);
        } else {
            source
                .once('error', err => {
                    try {
                        source.destroy();
                    } catch (E) {
                        // ignore
                    }
                    reject(err);
                })
                .pipe(splitter);
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
