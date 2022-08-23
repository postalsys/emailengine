'use strict';

const stream = require('stream');
const Writable = stream.Writable;
const PassThrough = stream.PassThrough;

/**
 * Incoming IMAP stream parser. Detects and emits command payloads.
 * If literal values are encountered the command payload is split into parts
 * and all parts are emitted separately. The client must send the +\r\n or
 * return a NO error for the literal
 *
 * @constructor
 * @param {Object} [options] Optional Stream options object
 */
class IMAPStream extends Writable {
    constructor(options) {
        // init Writable
        super();

        this.options = options || {};
        Writable.call(this, this.options);

        // unprocessed chars from the last parsing iteration
        this._remainder = '';
        this._literal = false;
        this._literalReady = false;

        // how many literal bytes to wait for
        this._expecting = 0;

        // once the input stream ends, flush all output without expecting the newline
        this.on('finish', this._flushData.bind(this));
    }

    /**
     * Placeholder command handler. Override this with your own.
     */
    oncommand(/* command, callback */) {
        throw new Error('Command handler is not set');
    }

    // PRIVATE METHODS

    /**
     * Writable._write method.
     */
    _write(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        let data = this._remainder + chunk.toString('binary');
        this._remainder = '';

        // start reading data
        // regex is passed as an argument because we need to keep count of the lastIndex property
        this._readValue(/\r?\n/g, data, 0, done);
    }

    /**
     * Reads next command from incoming stream
     *
     * @param {RegExp} regex Regular expression object. Needed to keep lastIndex value
     * @param {String} data Incoming data as binary string
     * @param {Number} pos Cursor position in current data chunk
     * @param {Function} done Function to call once data is processed
     */
    _readValue(regex, data, pos, done) {
        let match;
        let line;

        // Handle literal mode where we know how many bytes to expect before switching back to
        // normal line based mode. All the data we receive is pumped to a passthrough stream
        if (this._expecting > 0) {
            if (data.length - pos <= 0) {
                return done();
            }

            if (data.length - pos >= this._expecting) {
                // all bytes received
                this._literal.end(Buffer.from(data.substr(pos, this._expecting), 'binary'));
                pos += this._expecting;
                this._expecting = 0;
                this._literal = false;

                if (this._literalReady) {
                    // can continue
                    this._literalReady = false;
                } else {
                    this._literalReady = this._readValue.bind(this, /\r?\n/g, data.substr(pos), 0, done);
                    return;
                }
            } else {
                // data still pending
                this._literal.write(Buffer.from(data.substr(pos), 'binary'), done);
                this._expecting -= data.length - pos;
                return; // wait for the next chunk
            }
        }

        // search for the next newline
        // exec keeps count of the last match with lastIndex
        // so it knows from where to start with the next iteration
        if ((match = regex.exec(data))) {
            line = data.substr(pos, match.index - pos);
            pos += line.length + match[0].length;
        } else {
            this._remainder = pos < data.length ? data.substr(pos) : '';
            return done();
        }

        if ((match = /\{(\d+)\}$/.exec(line))) {
            this._expecting = Number(match[1]);
            if (!isNaN(match[1])) {
                this._literal = new PassThrough();

                this.oncommand(
                    {
                        value: line,
                        final: false,
                        expecting: this._expecting,
                        literal: this._literal,

                        // called once the stream has been processed
                        readyCallback: () => {
                            let next = this._literalReady;
                            if (typeof next === 'function') {
                                this._literalReady = false;
                                next();
                            } else {
                                this._literalReady = true;
                            }
                        }
                    },
                    err => {
                        if (err) {
                            this._expecting = 0;
                            this._literal = false;
                            this._literalReady = false;
                        }
                        setImmediate(this._readValue.bind(this, regex, data, pos, done));
                    }
                );
                return;
            }
        }

        this.oncommand(
            {
                value: line,
                final: true
            },
            this._readValue.bind(this, regex, data, pos, done)
        );
    }

    /**
     * Flushes remaining bytes
     */
    _flushData() {
        let line;
        if (this._remainder) {
            line = this._remainder;
            this._remainder = '';
            this.oncommand(Buffer.from(line, 'binary'));
        }
    }
}

// Expose to the world
module.exports.IMAPStream = IMAPStream;
