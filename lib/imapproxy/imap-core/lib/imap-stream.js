'use strict';

const stream = require('stream');
const Writable = stream.Writable;
const PassThrough = stream.PassThrough;

// Upper bound for a single command line (no CRLF yet). Generous - real IMAP command
// lines are short and bulk data is sent as size-bounded literals - but it prevents a
// client that never sends a newline from growing memory without limit (OOM).
const MAX_LINE_LENGTH = 1 * 1024 * 1024;

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

        // largest single command line we will buffer before giving up
        this._maxLineLength = Number(this.options.maxLineLength) || MAX_LINE_LENGTH;

        // unprocessed chars from the last parsing iteration
        this._remainder = '';
        // chunks of an unfinished line that arrived with no line break in them, kept apart until
        // one arrives so that a line trickled in small segments is not re-joined and re-scanned
        // from its start for every segment (that was quadratic in the line length)
        this._remainderParts = [];
        this._remainderLength = 0;
        this._literal = false;
        this._literalReady = false;

        // unparsed rest of the chunk the currently running command came in
        this._pending = null;

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

    /**
     * Discards any buffered or partial parser state. Used on TLS upgrade so that
     * plaintext pipelined before STARTTLS cannot be parsed as commands inside the
     * encrypted session (STARTTLS command injection).
     */
    reset() {
        this._clearRemainder();
        this._literal = false;
        this._literalReady = false;
        this._expecting = 0;
    }

    // PRIVATE METHODS

    /**
     * Writable._write method.
     */
    _write(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        let str = chunk.toString('binary');

        if (!this._expecting && !this._literalReady && str.indexOf('\n') < 0) {
            // No line ends in this chunk and no literal is being read, so nothing can be parsed
            // yet: keep the chunk and scan it once the line break arrives. The cap applies to
            // what is kept, so a line that never ends is refused the same as before
            if (this._remainder.length + this._remainderLength + str.length > this._maxLineLength) {
                this._clearRemainder();
                return done(new Error('Command line too long'));
            }
            this._remainderParts.push(str);
            this._remainderLength += str.length;
            return done();
        }

        let prefix = this._clearRemainder();
        let data = prefix + str;

        // start reading data
        // regex is passed as an argument because we need to keep count of the lastIndex property.
        // The prefix was already scanned for a line break and has none, so the search starts at
        // its end (one character back, in case a CR LF straddles the two)
        let regex = /\r?\n/g;
        regex.lastIndex = Math.max(0, prefix.length - 1);
        this._readValue(regex, data, 0, done);
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
            if (this._remainder.length > this._maxLineLength) {
                // Drop the buffered data and fail the stream - the connection layer
                // closes the socket on a parser error.
                this._remainder = '';
                return done(new Error('Command line too long'));
            }
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

        // Remember what is left of this chunk while the command runs. A LOGIN that switches the
        // connection to proxy mode never calls back, and whatever the client pipelined after it
        // has to be handed to the upstream server instead of being dropped (see takeRemainder).
        this._pending = { data, pos };
        let sync = true;
        this.oncommand(
            {
                value: line,
                final: true
            },
            () => {
                this._pending = null;
                // A command that completes synchronously (NOOP, CAPABILITY, ID) used to call back
                // into this method from inside it, so one chunk of a few thousand pipelined
                // commands grew the stack until it overflowed and the RangeError, thrown inside
                // the socket's data handler, took the whole worker down. Only that case is
                // deferred; a command that went through I/O calls back on a fresh stack
                if (sync) {
                    setImmediate(() => this._readValue(regex, data, pos, done));
                } else {
                    this._readValue(regex, data, pos, done);
                }
            }
        );
        sync = false;
    }

    /**
     * Takes the unfinished line out of the buffers
     * @returns {String} what was kept
     */
    _clearRemainder() {
        let line = this._remainder + this._remainderParts.join('');
        this._remainder = '';
        this._remainderParts = [];
        this._remainderLength = 0;
        return line;
    }

    /**
     * Returns every byte received but not yet parsed: the rest of the chunk the current command
     * came in, and any chunks written while that command was running. Used when the connection is
     * handed off to the proxy, after which this parser is never fed again.
     *
     * @returns {Buffer} Unparsed input, possibly empty
     */
    takeRemainder() {
        let chunks = [];

        if (this._pending && this._pending.pos < this._pending.data.length) {
            chunks.push(Buffer.from(this._pending.data.substr(this._pending.pos), 'binary'));
        }
        this._pending = null;

        let kept = this._clearRemainder();
        if (kept) {
            chunks.push(Buffer.from(kept, 'binary'));
        }

        let buffered = this.writableBuffer || (this._writableState && typeof this._writableState.getBuffer === 'function' && this._writableState.getBuffer()) || [];
        for (let entry of buffered) {
            if (entry && entry.chunk && entry.chunk.length) {
                chunks.push(Buffer.isBuffer(entry.chunk) ? entry.chunk : Buffer.from(entry.chunk, entry.encoding === 'buffer' ? undefined : entry.encoding));
            }
        }

        return Buffer.concat(chunks);
    }

    /**
     * Flushes remaining bytes
     */
    _flushData() {
        let line = this._clearRemainder();
        if (line) {
            this.oncommand(Buffer.from(line, 'binary'));
        }
    }
}

// Expose to the world
module.exports.IMAPStream = IMAPStream;
