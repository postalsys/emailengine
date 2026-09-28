'use strict';

const imapHandler = require('./handler/imap-handler');

const MAX_MESSAGE_SIZE = 1 * 1024 * 1024;
const MAX_BAD_COMMANDS = 50;

// Every literal is buffered in memory until the command line is complete, so a single command must
// not be able to announce literals without bound. Real commands carry a few at most (LOGIN has two).
const MAX_LITERALS_PER_COMMAND = 32;
// Literal bytes a single command may buffer on top of the largest literal it is allowed to send
// (the message of an APPEND); covers the small literals that can accompany it.
const LITERAL_BYTES_SLACK = 64 * 1024;

const commands = new Map([
     
    // require must normally be on top of the module
    ['NOOP', require('./commands/noop')],
    ['CAPABILITY', require('./commands/capability')],
    ['LOGOUT', require('./commands/logout')],
    ['ID', require('./commands/id')],
    ['STARTTLS', require('./commands/starttls')],
    ['LOGIN', require('./commands/login')],
    ['AUTHENTICATE PLAIN', require('./commands/authenticate-plain')],
    ['AUTHENTICATE PLAIN-CLIENTTOKEN', require('./commands/authenticate-plain')],
    ['NAMESPACE', require('./commands/namespace')],
    ['LIST', require('./commands/list')],
    ['XLIST', require('./commands/list')],
    ['LSUB', require('./commands/lsub')],
    ['SUBSCRIBE', require('./commands/subscribe')],
    ['UNSUBSCRIBE', require('./commands/unsubscribe')],
    ['CREATE', require('./commands/create')],
    ['DELETE', require('./commands/delete')],
    ['RENAME', require('./commands/rename')],
    ['SELECT', require('./commands/select')],
    ['EXAMINE', require('./commands/select')],
    ['IDLE', require('./commands/idle')],
    ['CHECK', require('./commands/check')],
    ['STATUS', require('./commands/status')],
    ['APPEND', require('./commands/append')],
    ['STORE', require('./commands/store')],
    ['UID STORE', require('./commands/uid-store')],
    ['EXPUNGE', require('./commands/expunge')],
    ['UID EXPUNGE', require('./commands/uid-expunge')],
    ['CLOSE', require('./commands/close')],
    ['UNSELECT', require('./commands/unselect')],
    ['COPY', require('./commands/copy')],
    ['UID COPY', require('./commands/copy')],
    ['MOVE', require('./commands/move')],
    ['UID MOVE', require('./commands/move')],
    ['FETCH', require('./commands/fetch')],
    ['UID FETCH', require('./commands/fetch')],
    ['SEARCH', require('./commands/search')],
    ['UID SEARCH', require('./commands/search')],
    ['ENABLE', require('./commands/enable')],
    ['GETQUOTAROOT', require('./commands/getquotaroot')],
    ['SETQUOTA', require('./commands/setquota')],
    ['GETQUOTA', require('./commands/getquota')],
    ['COMPRESS', require('./commands/compress')]
     
]);

class IMAPCommand {
    constructor(connection) {
        this.connection = connection;
        this.payload = '';
        this.literals = [];
        this.literalBytes = 0;
        // announced literals, counted when the continuation is sent: this.literals only fills
        // once a literal's data has arrived, and a payload announcing many literals in one
        // chunk got continuations past the cap before that count caught up
        this.literalCount = 0;
        this.first = true;
        this.connection._badCount = this.connection._badCount || 0;
    }

    // Drops everything buffered for a command whose literal was refused, so the next line the
    // client sends starts a new command instead of being appended to this one.
    abortCommand() {
        this.payload = '';
        this.literals = [];
        this.literalBytes = 0;
        this.literalCount = 0;
        this.first = true;
        if (this.connection._currentCommand === this) {
            this.connection._currentCommand = false;
        }
    }

    /**
     * Refuses a literal the command may not send: answers the client, drops what was buffered for
     * the command and hands the error to the caller. Not counted against the protocol-error
     * budget here, because append()'s caller counts every error it is handed; counting here as
     * well charged a refused literal twice
     * @param {string} status - NO or BAD
     * @param {string} message - Response text, also the error message
     * @param {string} code - Error code
     * @param {number} responseCode - HTTP-style code the error carries
     * @param {Function} callback
     */
    refuseLiteral(status, message, code, responseCode, callback) {
        this.connection.send(this.tag + ' ' + status + ' ' + message);
        this.abortCommand();
        let err = new Error(message);
        err.responseCode = responseCode;
        err.code = code;
        return callback(err);
    }

    append(command, callback) {
        let chunks = [];
        let chunklen = 0;

        this.payload += command.value;

        if (this.first) {
            // fetch tag and command name
            this.first = false;

            // only check payload if it is a regular command, not input for something else
            if (typeof this.connection._nextHandler !== 'function') {
                let match = /^([^\s]+)(?:\s+((?:AUTHENTICATE |UID )?[^\s]+)|$)/i.exec(command.value) || [];
                this.tag = match[1];
                this.command = (match[2] || '').trim().toUpperCase();

                if (!this.command || !this.tag) {
                    let err = new Error('Invalid tag');
                    err.responseCode = 400;
                    err.code = 'InvalidTag';
                    this.connection.send('* BAD Invalid tag');
                    return callback(err);
                }

                if (!commands.has(this.command)) {
                    let err = new Error('Unknown command');
                    err.responseCode = 400;
                    err.code = 'UnknownCommand';
                    this.connection.send(this.tag + ' BAD Unknown command: ' + this.command);
                    return callback(err);
                }
            }
        }

        if (command.literal) {
            // check if the literal size is in acceptable bounds
            if (isNaN(command.expecting) || command.expecting < 0 || command.expecting > Number.MAX_SAFE_INTEGER) {
                return this.refuseLiteral('BAD', 'Invalid literal size', 'InvalidLiteralSize', 400, callback);
            }

            // Run the state rule before accepting any literal data. It otherwise only runs once the
            // whole command has been buffered, which let an unauthenticated client stream literals
            // for commands it could never run (APPEND before login).
            let handler = typeof this.connection._nextHandler !== 'function' && commands.get(this.command);
            if (handler && handler.state && [].concat(handler.state).indexOf(this.connection.state) < 0) {
                return this.refuseLiteral('BAD', this.command + ' not allowed now', 'InvalidState', 500, callback);
            }

            let maxAllowed = Math.max(Number(this.connection._server.options.maxMessage) || 0, MAX_MESSAGE_SIZE);

            if (this.literalCount >= MAX_LITERALS_PER_COMMAND || this.literalBytes + command.expecting > maxAllowed + LITERAL_BYTES_SLACK) {
                return this.refuseLiteral('NO', 'Too much literal data', 'InvalidLiteralSize', 400, callback);
            }

            if (
                // Allow large literals for selected commands only
                (!['APPEND'].includes(this.command) && command.expecting > 1024) ||
                // Deny all literals bigger than maxMessage
                command.expecting > maxAllowed
            ) {
                this.connection.logger.debug(
                    {
                        tnx: 'client',
                        cid: this.connection.id,
                        src: 'C'
                    },
                    this.loggablePayload()
                );

                this.payload = ''; // reset payload
                this.literals = [];

                if (command.expecting > maxAllowed) {
                    // APPENDLIMIT response for too large messages
                    // TOOBIG: https://tools.ietf.org/html/rfc4469#section-4.2
                    this.connection.send(this.tag + ' NO [TOOBIG] Literal too large');
                } else {
                    this.connection.send(this.tag + ' NO Literal too large');
                }

                let err = new Error('Literal too large');
                err.responseCode = 400;
                err.code = 'InvalidLiteralSize';
                return callback(err);
            }

            // Accept literal input
            this.literalBytes += command.expecting;
            this.literalCount++;
            this.connection.send('+ Go ahead');

            // currently the stream is buffered into a large string and thats it.
            // in the future we might consider some kind of actual stream usage
            command.literal.on('data', chunk => {
                chunks.push(chunk);
                chunklen += chunk.length;
            });

            command.literal.on('end', () => {
                this.payload += '\r\n'; //  + Buffer.concat(chunks, chunklen).toString('binary');
                this.literals.push(Buffer.concat(chunks, chunklen));
                command.readyCallback(); // call this once stream is fully processed and ready to accept next data
            });
        }

        callback();
    }

    end(command, callback) {
        let callbackSent = false;
        let next = err => {
            if (!callbackSent) {
                callbackSent = true;
                return callback(err);
            }
        };

        this.append(command, err => {
            if (err) {
                this.connection.logger.debug(
                    {
                        err,
                        tnx: 'client',
                        cid: this.connection.id,
                        src: 'C'
                    },
                    this.loggablePayload()
                );
                if (!this.countBadResponses()) {
                    // stop processing
                    return;
                }
                return next(err);
            }

            // check if the payload needs to be directed to a preset handler
            if (typeof this.connection._nextHandler === 'function') {
                this.connection.logger.debug(
                    {
                        tnx: 'client',
                        cid: this.connection.id,
                        src: 'C'
                    },
                    this.loggablePayload()
                );
                return this.connection._nextHandler(this.payload, next);
            }

            try {
                this.parsed = imapHandler.parser(this.payload, { literals: this.literals });
            } catch (E) {
                this.connection.logger.debug(
                    {
                        err: E,
                        tnx: 'client',
                        cid: this.connection.id,
                        src: 'C'
                    },
                    this.loggablePayload()
                );
                this.connection.send(this.tag + ' BAD ' + E.message);
                if (!this.countBadResponses()) {
                    // stop processing
                    return;
                }
                return next();
            }

            let handler = commands.get(this.command);

            if (/^(AUTHENTICATE|LOGIN)/.test(this.command) && Array.isArray(this.parsed.attributes)) {
                this.parsed.attributes.forEach(attr => {
                    if (attr && typeof attr === 'object' && attr.value) {
                        attr.sensitive = true;
                    }
                });
            }

            if (!this.connection.session.commandCounters[this.command]) {
                this.connection.session.commandCounters[this.command] = 1;
            } else {
                this.connection.session.commandCounters[this.command]++;
            }

            this.connection.logger.debug(
                {
                    tnx: 'client',
                    cid: this.connection.id,
                    src: 'C'
                },
                this.compileForLog()
            );

            this.validateCommand(this.parsed, handler, err => {
                if (err) {
                    this.connection.send(this.tag + ' ' + (err.response || 'BAD') + ' ' + err.message);
                    if (!this.countBadResponses()) {
                        // stop processing
                        return;
                    }
                    return next(err);
                }

                if (typeof handler.handler === 'function') {
                    handler.handler.call(
                        this.connection,
                        this.parsed,
                        (err, response) => {
                            if (err) {
                                this.connection.send(this.tag + ' ' + (err.response || 'BAD') + ' ' + err.message);
                                if (!err.response || err.response === 'BAD') {
                                    if (!this.countBadResponses()) {
                                        // stop processing
                                        return;
                                    }
                                }
                                return next(err);
                            }

                            // send EXPUNGE, EXISTS etc queued notices
                            this.sendNotifications(handler, () => {
                                // send command ready response
                                this.connection.writeStream.write({
                                    tag: this.tag,
                                    command: response.response,
                                    attributes: []
                                        .concat(
                                            response.code
                                                ? {
                                                      type: 'SECTION',
                                                      section: [
                                                          {
                                                              type: 'TEXT',
                                                              value: response.code
                                                          }
                                                      ]
                                                  }
                                                : []
                                        )
                                        .concat({
                                            type: 'TEXT',
                                            value: response.message || this.command + ' completed'
                                        })
                                });

                                if (this.connection.state === 'Proxy') {
                                    // switch to proxy mode
                                    return this.connection.session.onProxy(this.connection.unbind());
                                }

                                next();
                            });
                        },
                        next
                    );
                } else {
                    this.connection.send(this.tag + ' NO Not implemented: ' + this.command);
                    return next();
                }
            });
        });
    }

    // LOGIN and AUTHENTICATE payloads carry credentials and must never be logged raw.
    // Also scans the payload itself for malformed lines (e.g. a missing tag) where the
    // credential-bearing command name was not parsed into this.command.
    loggablePayload() {
        // A continuation frame is not a command, so neither the parsed command name nor the payload
        // text identifies it - during AUTHENTICATE it is the bare base64 SASL blob. Nothing about
        // it is safe to render, so report the size only, the same way the accepted path does.
        if (typeof this.connection._nextHandler === 'function') {
            return `<${(this.payload && this.payload.length) || 0} bytes of data>`;
        }

        if (/^(AUTHENTICATE|LOGIN)/i.test(this.command || '') || /^\s*(?:\S+\s+)?(AUTHENTICATE|LOGIN)\b/i.test(this.payload || '')) {
            return [this.tag, this.command, '(* payload hidden *)'].filter(v => v).join(' ');
        }
        return this.payload || '';
    }

    // The compiler walks the parsed tree recursively and runs here outside the parser's try/catch,
    // from inside the socket's data handler, so a throw would be an uncaught exception. The parser
    // caps the nesting depth, this keeps any other compile failure a logging problem only.
    compileForLog() {
        try {
            return imapHandler.compiler(this.parsed, false, true);
        } catch (err) {
            return [this.tag, this.command, '(* payload not loggable *)'].filter(v => v).join(' ');
        }
    }

    sendNotifications(handler, callback) {
        if (this.connection.state !== 'Selected' || !!handler.disableNotifications) {
            // nothing to advertise if not in Selected state
            return callback();
        }

        this.connection.emitNotifications();

        return callback();
    }

    validateCommand(parsed, handler, callback) {
        let schema = handler.schema || [];
        let maxArgs = schema.length;
        let minArgs = schema.filter(item => !item.optional).length;

        // Check if the command can be run in current state
        if (handler.state && [].concat(handler.state || []).indexOf(this.connection.state) < 0) {
            let err = new Error(parsed.command.toUpperCase() + ' not allowed now');
            err.responseCode = 500;
            err.code = 'InvalidState';
            return callback(err);
        }

        if (handler.schema === false) {
            //schema check is disabled
            return callback();
        }

        // Deny commands with too many arguments
        if (parsed.attributes && parsed.attributes.length > maxArgs) {
            let err = new Error('Too many arguments provided');
            err.responseCode = 400;
            err.code = 'InvalidArguments';
            return callback(err);
        }

        // Deny commands with too little arguments
        if (((parsed.attributes && parsed.attributes.length) || 0) < minArgs) {
            let err = new Error('Not enough arguments provided');
            err.responseCode = 400;
            err.code = 'InvalidArguments';
            return callback(err);
        }

        callback();
    }

    countBadResponses() {
        this.connection._badCount++;
        if (this.connection._badCount > MAX_BAD_COMMANDS) {
            // Stop reading first so a command pipelined right after the offending input is not
            // dispatched during the graceful-close window.
            this.connection._stopReading();
            this.connection.clearNotificationListener();
            this.connection.send('* BYE Too many protocol errors');
            // Graceful close so the BYE is flushed to the client before teardown (close() ends
            // the socket and force-destroys via its own failsafe timer).
            setImmediate(() => this.connection.close());
            return false;
        }
        return true;
    }
}

module.exports.IMAPCommand = IMAPCommand;
