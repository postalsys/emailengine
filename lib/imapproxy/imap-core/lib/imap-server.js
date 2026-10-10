'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { IMAPConnection } = require('./imap-connection');
const tlsOptions = require('./tls-options');
const EventEmitter = require('events').EventEmitter;
const shared = require('nodemailer/lib/shared');
const punycode = require('punycode.js');
const { base32Encode } = require('../../../base32');

const CLOSE_TIMEOUT = 1 * 1000; // how much to wait until pending connections are terminated

// A PROXY protocol v1 header is at most ~107 bytes. Bound the buffer so a trusted
// proxy source that never sends a newline cannot grow memory without limit.
const MAX_PROXY_HEADER_SIZE = 256;

// A PROXY header is the first thing a load balancer sends, right after connecting. A socket that
// has not produced it by then is not a proxy we are waiting on, and it must not hold an fd forever.
const PROXY_HEADER_TIMEOUT = 10 * 1000;

// How long an implicit TLS client has to complete its handshake
const TLS_HANDSHAKE_TIMEOUT = 30 * 1000;

/**
 * Creates a IMAP server instance.
 *
 * @constructor
 * @param {Object} options Connection and IMAP options
 */
class IMAPServer extends EventEmitter {
    constructor(options) {
        super();

        this.options = options || {};

        this.updateSecureContext();

        this.logger = shared.getLogger(this.options, {
            component: this.options.component || 'imap-server'
        });

        /**
         * Timeout after close has been called until pending connections are forcibly closed
         */
        this._closeTimeout = false;

        /**
         * A set of all currently open connections
         */
        this.connections = new Set();

        // Accepted sockets that have not closed yet, counted from accept so connections still
        // waiting for a PROXY header or a TLS handshake are included. Checked against the
        // maxConnections option; every accepted socket is buffered in memory until its first
        // command completes, so the number of them has to be bounded.
        this._socketCount = 0;

        // setup server listener and connection handler
        //this.server = (this.options.secure ? tls : net).createServer(this.options, 1);

        // setup server listener and connection handler
        if (this.options.secure && !this.options.needsUpgrade) {
            this.server = net.createServer(this.options, socket => {
                if (!this._acceptSocket(socket)) {
                    return;
                }
                socket.setKeepAlive(true, 5 * 1000);
                this._handleProxy(socket, (err, socketOptions) => {
                    if (err) {
                        // ignore, should not happen
                    }
                    if (this.options.secured) {
                        return this.connect(socket, socketOptions);
                    }
                    this._upgrade(socket, (err, tlsSocket) => {
                        if (err) {
                            return this._onError(err);
                        }
                        this.connect(tlsSocket, socketOptions);
                    });
                });
            });
        } else {
            this.server = net.createServer(this.options, socket => {
                if (!this._acceptSocket(socket)) {
                    return;
                }
                this._handleProxy(socket, (err, socketOptions) => {
                    if (err) {
                        // ignore, should not happen
                    }
                    socket.setKeepAlive(true, 5 * 1000);
                    this.connect(socket, socketOptions);
                });
            });
        }

        this.skipFetchLog = options.skipFetchLog;

        this._setListeners();

        this.loggelf = () => false;
    }

    connect(socket, socketOptions) {
        let connection = new IMAPConnection(this, socket, socketOptions);
        connection.loggelf = message => this.loggelf(message);
        this.connections.add(connection);
        connection.on('error', this._onError.bind(this));
        connection.init();
    }

    /**
     * Start listening on selected port and interface
     */
    listen(...args) {
        this.server.listen(...args);
    }

    /**
     * Closes the server
     *
     * @param {Function} callback Callback to run once the server is fully closed
     */
    close(callback) {
        let connections = this.connections.size;
        let timeout = this.options.closeTimeout || CLOSE_TIMEOUT;

        // stop accepting new connections
        this.server.close(() => {
            clearTimeout(this._closeTimeout);
            callback();
        });

        // close active connections
        if (connections) {
            this.logger.info(
                {
                    tnx: 'close'
                },
                'Server closing with %s pending connection%s, waiting %s seconds before terminating',
                connections,
                connections !== 1 ? 's' : '',
                timeout / 1000
            );
        }

        this._closeTimeout = setTimeout(() => {
            connections = this.connections.size;
            if (connections) {
                this.logger.info(
                    {
                        tnx: 'close'
                    },
                    'Closing %s pending connection%s to close the server',
                    connections,
                    connections !== 1 ? 's' : ''
                );

                this.connections.forEach(connection => {
                    connection.send('* BYE System shutdown');
                    setImmediate(() => connection.close());
                });
            }
        }, timeout);
    }

    // PRIVATE METHODS

    /**
     * Setup server event handlers
     */
    _setListeners() {
        this.server.on('listening', this._onListening.bind(this));
        this.server.on('close', this._onClose.bind(this));
        this.server.on('error', this._onError.bind(this));
    }

    /**
     * Called when server started listening
     *
     * @event
     */
    _onListening() {
        let address = this.server.address();
        this.logger.info(
            //
            {
                tnx: 'listen',
                host: address.address,
                port: address.port,
                secure: !!this.options.secure,
                protocol: 'IMAP'
            },
            '%sIMAP Server listening on %s:%s',
            this.options.secure ? 'Secure ' : '',
            address.family === 'IPv4' ? address.address : '[' + address.address + ']',
            address.port
        );
    }

    /**
     * Called when server is closed
     *
     * @event
     */
    _onClose() {
        this.logger.info(
            {
                tnx: 'closed'
            },
            'IMAP Server closed'
        );
        this.emit('close');
    }

    /**
     * Called when an error occurs with the server
     *
     * @event
     */
    _onError(err) {
        this.emit('error', err);
    }

    /**
     * Counts an accepted socket and refuses it when the maxConnections option is exceeded.
     *
     * @param {net.Socket} socket Freshly accepted socket
     * @returns {Boolean} true if the socket may be served
     */
    _acceptSocket(socket) {
        let maxConnections = Number(this.options.maxConnections) || 0;
        if (maxConnections && this._socketCount >= maxConnections) {
            this.logger.info(
                {
                    tnx: 'connect',
                    remoteAddress: socket.remoteAddress
                },
                'Refusing connection from %s: too many connections (%s)',
                socket.remoteAddress,
                maxConnections
            );
            if (this.options.secure && !this.options.needsUpgrade) {
                // an implicit TLS client could not read a plaintext response
                socket.on('error', () => false);
                try {
                    socket.destroy();
                } catch (err) {
                    // ignore
                }
            } else {
                this._rejectSocket(socket, '* BYE Too many connections, try again later\r\n');
            }
            return false;
        }

        this._socketCount++;
        socket.once('close', () => {
            this._socketCount--;
        });

        // The non-PROXY path hands the socket over a tick later, with no error listener on it until
        // then; a reset in that window would be uncaught and take down the whole worker
        socket.on('error', err => {
            this.logger.debug(
                {
                    tnx: 'connect',
                    remoteAddress: socket.remoteAddress,
                    err
                },
                'Socket error on accepted connection: %s',
                err && err.message
            );
        });
        return true;
    }

    /**
     * Ends a socket refused before the protocol starts, with a one-line reason. end() only
     * half-closes, so a short timeout releases the fd even when the peer never closes its side
     * @param {net.Socket} socket
     * @param {string} line - The response line, CRLF included
     */
    _rejectSocket(socket, line) {
        socket.on('error', () => false);
        try {
            socket.end(line);
            socket.setTimeout(CLOSE_TIMEOUT, () => socket.destroy());
        } catch (err) {
            // ignore
        }
    }

    _handleProxy(socket, callback) {
        let socketOptions = {
            id: base32Encode(crypto.randomBytes(10)).toLowerCase()
        };

        if (
            !this.options.useProxy ||
            (Array.isArray(this.options.useProxy) && !this.options.useProxy.includes(socket.remoteAddress) && !this.options.useProxy.includes('*'))
        ) {
            socketOptions.ignore = this.options.ignoredHosts && this.options.ignoredHosts.includes(socket.remoteAddress);
            return setImmediate(() => callback(null, socketOptions));
        }

        let chunks = [];
        let chunklen = 0;

        // Nothing else listens on the raw socket until the header is read, so a reset from the
        // peer (a load balancer health check does exactly that) would be an uncaught 'error'.
        let onProxyTimeout = () => {
            stopWaiting();
            try {
                socket.destroy();
            } catch (E) {
                // ignore
            }
        };
        let onProxyError = err => {
            this.logger.debug(
                {
                    tnx: 'proxy',
                    cid: socketOptions.id,
                    err
                },
                'Socket error while waiting for PROXY header: %s',
                err && err.message
            );
            onProxyTimeout();
        };
        let stopWaiting = () => {
            socket.removeListener('readable', socketReader);
            socket.removeListener('error', onProxyError);
            socket.removeListener('timeout', onProxyTimeout);
            socket.setTimeout(0);
        };

        let socketReader = () => {
            let chunk;
            while ((chunk = socket.read()) !== null) {
                for (let i = 0, len = chunk.length; i < len; i++) {
                    let chr = chunk[i];
                    if (chr === 0x0a) {
                        stopWaiting();
                        chunks.push(chunk.slice(0, i + 1));
                        chunklen += i + 1;
                        let remainder = chunk.slice(i + 1);
                        if (remainder.length) {
                            socket.unshift(remainder);
                        }

                        let header = Buffer.concat(chunks, chunklen).toString().trim();

                        let params = (header || '').toString().split(' ');
                        let commandName = params.shift().toUpperCase();
                        if (commandName !== 'PROXY') {
                            this._rejectSocket(socket, '* BAD Invalid PROXY header\r\n');
                            return;
                        }

                        if (params[1]) {
                            socketOptions.remoteAddress = params[1].trim().toLowerCase();

                            socketOptions.ignore = this.options.ignoredHosts && this.options.ignoredHosts.includes(socketOptions.remoteAddress);

                            if (!socketOptions.ignore) {
                                this.logger.info(
                                    {
                                        tnx: 'proxy',
                                        cid: socketOptions.id,
                                        proxy: params[1].trim().toLowerCase()
                                    },
                                    'PROXY from %s through %s (%s)',
                                    params[1].trim().toLowerCase(),
                                    (params[2] || '').trim().toLowerCase(),
                                    JSON.stringify(params)
                                );
                            }

                            if (params[3]) {
                                socketOptions.remotePort = Number(params[3].trim()) || socketOptions.remotePort;
                            }
                        }

                        return callback(null, socketOptions);
                    }
                }
                chunks.push(chunk);
                chunklen += chunk.length;

                if (chunklen > MAX_PROXY_HEADER_SIZE) {
                    stopWaiting();
                    this._rejectSocket(socket, '* BAD Invalid PROXY header\r\n');
                    return;
                }
            }
        };
        socket.on('readable', socketReader);
        socket.on('error', onProxyError);
        socket.setTimeout(Number(this.options.proxyHeaderTimeout) || PROXY_HEADER_TIMEOUT);
        socket.on('timeout', onProxyTimeout);
    }

    _upgrade(socket, callback) {
        let socketOptions = {
            secureContext: this.secureContext.get('*'),
            isServer: true,
            server: this.server,
            SNICallback: (servername, cb) => {
                 
                this.options.SNICallback(this._normalizeHostname(servername), (err, context) => {
                    if (err) {
                        this.logger.error(
                            {
                                tnx: 'sni',
                                servername,
                                err
                            },
                            'Failed to fetch SNI context for servername %s',
                            servername
                        );
                    }
                    return cb(null, context || this.secureContext.get('*'));
                });
            }
        };

        let remoteAddress = socket.remoteAddress;

        // A client-side failure to establish the session, logged quietly
        let socketError = message => {
            let err = new Error(message);
            err.responseCode = 500;
            err.code = 'SocketError';
            err.report = false;
            err.meta = {
                protocol: 'imap',
                stage: 'connect',
                remoteAddress
            };
            return err;
        };

        let handshakeTimer = false;
        let returned = false;
        let onError = err => {
            clearTimeout(handshakeTimer);
            if (returned) {
                return;
            }
            returned = true;
            if (err && /SSL[23]*_GET_CLIENT_HELLO|ssl[23]*_read_bytes|ssl_bytes_to_cipher_list/i.test(err.message)) {
                let message = err.message;
                err.message = 'Failed to establish TLS session';
                err.responseCode = 500;
                err.code = err.code || 'TLSError';
                err.meta = {
                    protocol: 'imap',
                    stage: 'connect',
                    message,
                    remoteAddress
                };
            }
            if (!err || !err.message) {
                err = socketError('Socket closed while initiating TLS');
            }
            callback(err);
        };

        // remove all listeners from the original socket besides the error handler
        socket.once('error', onError);

        // upgrade connection
        let tlsSocket = new tls.TLSSocket(socket, socketOptions);

        let onCloseError = hadError => {
            if (hadError) {
                return onError();
            }
        };

        tlsSocket.once('close', onCloseError);
        tlsSocket.once('error', onError);
        tlsSocket.once('_tlsError', onError);
        tlsSocket.once('clientError', onError);
        tlsSocket.once('tlsClientError', onError);

        // Without this a client that never completes the handshake holds its socket and its
        // maxConnections slot for good: the PROXY header timeout is already cleared, and the
        // session's own socket timeout only starts after the handshake
        handshakeTimer = setTimeout(() => {
            onError(socketError('TLS handshake timed out'));
            tlsSocket.destroy();
            socket.destroy();
        }, Number(this.options.tlsHandshakeTimeout) || TLS_HANDSHAKE_TIMEOUT);

        tlsSocket.on('secure', () => {
            clearTimeout(handshakeTimer);
            socket.removeListener('error', onError);
            tlsSocket.removeListener('close', onCloseError);
            tlsSocket.removeListener('error', onError);
            tlsSocket.removeListener('_tlsError', onError);
            tlsSocket.removeListener('clientError', onError);
            tlsSocket.removeListener('tlsClientError', onError);
            if (returned) {
                try {
                    tlsSocket.end();
                } catch (E) {
                    //
                }
                return;
            }
            returned = true;
            return callback(null, tlsSocket);
        });
    }

    updateSecureContext(options) {
        Object.keys(options || {}).forEach(key => {
            this.options[key] = options[key];
        });

        let defaultTlsOptions = tlsOptions(this.options);

        this.secureContext = new Map();
        this.secureContext.set('*', tls.createSecureContext(defaultTlsOptions));

        let ctxMap = this.options.sniOptions || {};
        // sniOptions is either an object or a Map with domain names as keys and TLS option objects as values
        if (typeof ctxMap.get === 'function') {
            ctxMap.forEach((ctx, servername) => {
                this.secureContext.set(this._normalizeHostname(servername), tls.createSecureContext(tlsOptions(ctx)));
            });
        } else {
            Object.keys(ctxMap).forEach(servername => {
                this.secureContext.set(this._normalizeHostname(servername), tls.createSecureContext(tlsOptions(ctxMap[servername])));
            });
        }

        if (this.options.secure) {
            // apply changes

            Object.keys(defaultTlsOptions || {}).forEach(key => {
                if (!(key in this.options)) {
                    this.options[key] = defaultTlsOptions[key];
                }
            });

            // ensure SNICallback method
            if (typeof this.options.SNICallback !== 'function') {
                // create default SNI handler
                this.options.SNICallback = (servername, cb) => {
                    cb(null, this.secureContext.get(servername));
                };
            }
        }
    }

    _normalizeHostname(hostname) {
        return punycode.toUnicode((hostname || '').toString().trim()).toLowerCase();
    }
}

// Expose to the world
module.exports.IMAPServer = IMAPServer;
