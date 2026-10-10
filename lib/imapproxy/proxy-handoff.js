'use strict';

// The IMAP proxy's LOGIN handler and the byte pipe it sets up once the upstream session is ready.
// Kept out of lib/imapproxy/imap-server.js, which needs a worker-thread parentPort at require time,
// so the handoff can be tested with stub dependencies.

const { PassThrough } = require('stream');
const { imapHandler } = require('./imap-core/index.js');
const { isImapResponseError, toImapResponseError, faultResponseError } = require('./response-error');

class PassThroughLogger extends PassThrough {
    constructor(opts = {}) {
        super();
        this.logger = opts.logger;
        this.src = opts.src;
        this.cid = opts.cid;
        this.imapClient = opts.imapClient;
        this.logRaw = !!opts.logRaw;
    }
    _transform(chunk, encoding, next) {
        if (this.logRaw) {
            this.logger.trace({
                src: this.src,
                msg: 'write to socket',
                data: chunk.toString('base64'),
                compress: !!this.imapClient._deflate,
                secure: !!this.imapClient.secureConnection,
                cid: this.cid
            });
        }

        this.push(chunk);
        next();
    }

    _flush(next) {
        next();
    }
}

/**
 * Builds the imap-core `onAuth` callback of the proxy.
 *
 * @param {Object} deps
 * @param {Function} deps.onAuth Resolves with `{ accountData, imapConfig }` for a login
 * @param {Function} deps.createProxy Opens the authenticated upstream session
 * @param {Object} deps.logger Base logger (a child per proxied session is derived from it)
 * @param {Object} deps.serverLogger Logger for authentication failures
 * @param {Function} deps.metrics Metrics reporter
 * @param {Boolean} [deps.logRaw] Log every proxied chunk
 * @returns {Function} (login, session, callback) handler
 */
function createProxyAuthHandler({ onAuth, createProxy, logger, serverLogger, metrics, logRaw }) {
    // A refusal or a temporary failure the client is told to retry is a warning and reaches the
    // client as the IMAP response it carries; anything else is a proxy fault, logged here and
    // answered with a generic response so its text never reaches the client. Handing the fault
    // itself to imap-core sent that text as BAD, which also counted against the connection's
    // bad-command budget.
    const loginFailure = (err, fields, messages) => {
        if (isImapResponseError(err)) {
            serverLogger.warn(Object.assign({ msg: messages.response }, fields, { err }));
            return toImapResponseError(err);
        }
        serverLogger.error(Object.assign({ msg: messages.fault }, fields, { err }));
        return faultResponseError();
    };

    // Wires the two legs together once imap-core hands over the client socket
    const attachProxy = ({ session, account, downstream, upstream }) => {
        metrics(logger, 'events', 'inc', {
            event: 'imapProxyConnected'
        });

        const proxyLogger = logger.child({ property: 'proxy', account, cid: session.id });

        let upstreamLogger = new PassThroughLogger({
            src: 's',
            cid: session.id,
            imapClient: downstream.imapClient,
            logger: proxyLogger.child({ src: 'S' }),
            logRaw
        });

        let downstreamLogger = new PassThroughLogger({
            src: 'c',
            cid: session.id,
            imapClient: downstream.imapClient,
            logger: proxyLogger.child({ src: 'C' }),
            logRaw
        });

        // Idempotent teardown for both legs of the proxy. ImapFlow.close() is safe after
        // unbind(): it sends no LOGOUT, clears timers (including autoidle), removes the
        // deflate/writeSocket error forwarders and destroys the upstream socket. Without it the
        // upstream connection and its idle timer would leak (most visibly with COMPRESS enabled).
        let proxyClosed = false;
        const closeProxy = () => {
            if (proxyClosed) {
                return;
            }
            proxyClosed = true;

            try {
                downstream.imapClient.close();
            } catch (err) {
                proxyLogger.warn({ msg: 'Failed to close upstream connection', err });
            }

            try {
                if (upstream.socket && !upstream.socket.destroyed) {
                    upstream.socket.end();
                }
            } catch (err) {
                // ignore
            }
        };

        // Every terminal event from either leg funnels into the idempotent closeProxy(). The
        // helper keeps that wiring declarative; pass a message to log (level defaults to 'warn',
        // use 'info' for graceful closes).
        const teardownOn = (emitter, event, msg, level = 'warn') => {
            emitter.on(event, err => {
                if (msg) {
                    let entry = { msg };
                    if (err) {
                        entry.err = err;
                    }
                    proxyLogger[level](entry);
                }
                closeProxy();
            });
        };

        if (upstream.closed || upstream.socket.destroyed) {
            // The client disconnected while LOGIN was waiting for the upstream connection.
            // Nothing would ever close the upstream side, since the client socket's terminal
            // events have already fired.
            upstream.socket.on('error', () => false);
            proxyLogger.info({ msg: 'Client disconnected during login, closing upstream connection' });
            closeProxy();
            return;
        }

        downstream.readSocket.pipe(upstreamLogger).pipe(upstream.socket);

        if (upstream.head && upstream.head.length) {
            // Commands the client pipelined after LOGIN, read off the socket before the handoff.
            // Written ahead of the pipe so order is kept.
            downstreamLogger.write(upstream.head);
        }
        upstream.socket.pipe(downstreamLogger).pipe(downstream.writeSocket);

        teardownOn(upstreamLogger, 'error', 'Proxy stream error (to client)');
        teardownOn(downstreamLogger, 'error', 'Proxy stream error (to upstream)');
        teardownOn(upstream.socket, 'error', 'Client socket error');
        teardownOn(upstream.socket, 'end', 'Client connection closed', 'info');
        teardownOn(upstream.socket, 'close');
        teardownOn(downstream.readSocket, 'end', 'Upstream connection closed', 'info');

        downstream.readSocket.on('error', err => {
            proxyLogger.warn({ msg: 'Upstream read error', err });
            try {
                // best-effort notice to the client before tearing down
                upstream.socket.write('* BYE Upstream connection error\r\n');
            } catch (e) {
                // ignore
            }
            closeProxy();
        });

        // With COMPRESS enabled, readSocket/writeSocket are the inflate/deflate streams, not the
        // raw upstream socket, and unbind() removed ImapFlow's own listeners from that socket. An
        // upstream reset would then emit an 'error' with no listener and crash the worker - guard
        // it explicitly.
        if (downstream.imapClient.socket && downstream.imapClient.socket !== downstream.readSocket) {
            teardownOn(downstream.imapClient.socket, 'error', 'Upstream socket error');
            teardownOn(downstream.imapClient.socket, 'close');
        }

        proxyLogger.info({ msg: 'Proxy mode enabled' });
    };

    const handleLogin = async (login, session) => {
        let accountData;
        let imapConfig;
        try {
            ({ accountData, imapConfig } = await onAuth(login, session));
            if (!imapConfig) {
                throw new Error('IMAP not enabled for account');
            }
        } catch (err) {
            throw loginFailure(
                err,
                { username: login.username, cid: session.id, remoteAddress: session.remoteAddress },
                { response: 'Authentication check failed', fault: 'Authentication check failed' }
            );
        }

        // onAuth() resolves with { accountData, imapConfig }; the account id is read off the
        // stored account data (the login name is the same id, kept as a fallback).
        const account = (accountData && accountData.account) || login.username;

        let downstream;
        try {
            downstream = await createProxy({ imapConfig, id: session.id, logger: logger.child({ property: 'upstream', account }) });

            session.onProxy = upstream => attachProxy({ session, account, downstream, upstream });

            if (downstream.imapClient.rawCapabilities) {
                login.connection.send(
                    imapHandler.compiler({
                        tag: '*',
                        command: 'CAPABILITY',
                        attributes: downstream.imapClient.rawCapabilities
                    })
                );
            }
        } catch (err) {
            // The client is refused, so an upstream session already opened has no one to serve
            if (downstream && downstream.imapClient) {
                try {
                    downstream.imapClient.close();
                } catch (closeErr) {
                    logger.warn({ msg: 'Failed to close upstream connection', account, cid: session.id, err: closeErr });
                }
            }
            throw loginFailure(err, { account, cid: session.id }, { response: 'Upstream authentication failed', fault: 'Failed to create proxy' });
        }

        return {
            user: {
                id: 'id.' + login.username,
                username: login.username
            }
        };
    };

    return function (login, session, callback) {
        // imap-core ignores what the handler returns, so every outcome has to end in the callback
        handleLogin(login, session).then(
            response => callback(null, response),
            err => callback(err)
        );
    };
}

module.exports = { createProxyAuthHandler, PassThroughLogger };
