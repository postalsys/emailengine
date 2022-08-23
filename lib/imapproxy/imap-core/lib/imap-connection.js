'use strict';

const IMAPStream = require('./imap-stream').IMAPStream;
const IMAPCommand = require('./imap-command').IMAPCommand;
const IMAPComposer = require('./imap-composer').IMAPComposer;
const imapTools = require('./imap-tools');
const search = require('./search');
const dns = require('dns');
const crypto = require('crypto');
const os = require('os');
const base32 = require('base32.js');
const EventEmitter = require('events').EventEmitter;
const packageInfo = require('../../../../package');

const SOCKET_TIMEOUT = 5 * 60 * 1000;

/**
 * Creates a handler for new socket
 *
 * @constructor
 * @param {Object} server Server instance
 * @param {Object} socket Socket instance
 */
class IMAPConnection extends EventEmitter {
    constructor(server, socket, options) {
        super();

        options = options || {};
        // Random session ID, used for logging
        this.id = options.id || base32.encode(crypto.randomBytes(10)).toLowerCase();

        this.ignore = options.ignore;

        this.compression = false;
        this._deflate = false;
        this._inflate = false;

        this._server = server;
        this._socket = socket;

        this.writeStream = new IMAPComposer({
            connection: this,
            skipFetchLog: server.skipFetchLog
        });
        this.writeStream.pipe(this._socket);
        this.writeStream.on('error', this._onError.bind(this));

        // session data (envelope, user etc.)
        this.session = false;

        // If true then the connection is currently being upgraded to TLS
        this._upgrading = false;

        // Parser instance for the incoming stream
        this._parser = new IMAPStream();

        // Set handler for incoming commands
        this._parser.oncommand = this._onCommand.bind(this);

        // Manage multi part command
        this._currentCommand = false;

        // If set, then data payload is not executed as a command but as an argument for this function
        this._nextHandler = false;

        // If true, then the connection is using TLS
        this.secure = !!this._server.options.secure;

        // Store remote address for later usage
        this.remoteAddress = (options.remoteAddress || this._socket.remoteAddress || '').replace(/^::ffff:/, '');

        // Server hostname for the greegins
        this.name = (this._server.options.name || os.hostname()).toLowerCase();

        this.state = 'Not Authenticated';

        this._listenerData = false;

        // selected mailbox metadata
        this.selected = false;

        // ignore timeouts if true
        this.idling = false;

        // indicates if CONDSTORE is enabled for the session
        this.condstoreEnabled = false;

        // Resolved hostname for remote IP address
        this.clientHostname = false;

        // increment connection count
        this._closing = false;
        this._closed = false;

        this.logger = {};
        ['info', 'debug', 'error'].forEach(level => {
            this.logger[level] = (...args) => {
                if (!this.ignore) {
                    this._server.logger[level](...args);
                }
            };
        });

        this.loggelf = () => false;
    }

    /**
     * Initiates the connection. Checks connection limits and reverse resolves client hostname. The client
     * is not allowed to send anything before init has finished otherwise 'You talk too soon' error is returned
     */
    init() {
        // Setup event handlers for the socket
        this._setListeners();

        // make sure we have a session set up
        this._startSession();

        let now = Date.now();
        let greetingSent = false;
        let sendGreeting = () => {
            if (greetingSent) {
                return;
            }
            greetingSent = true;

            this.logger.info(
                {
                    tnx: 'connect',
                    cid: this.id,
                    servername: this._socket && this._socket.servername
                },
                '%s from %s to %s %s:%s',
                this.secure ? 'Secure connection' : 'Connection',
                this.session.clientHostname,
                (this._socket && this._socket.servername) || os.hostname(),
                this._socket && this._socket.localAddress,
                this._socket && this._socket.localPort
            );

            this.send(
                '* OK ' +
                    ((this._server.options.id && this._server.options.id.name) || packageInfo.name) +
                    ' ready for requests from ' +
                    this.remoteAddress +
                    ' ' +
                    this.id
            );
        };

        // do not wait with initial response too long
        let resolveTimer = setTimeout(() => {
            clearTimeout(resolveTimer);
            sendGreeting();
        }, 1000);

        let reverseCb = (err, hostnames) => {
            clearTimeout(resolveTimer);
            if (err) {
                //ignore, no big deal
            }

            let clientHostname = hostnames && hostnames.shift();
            this.session.clientHostname = this.clientHostname = clientHostname || '[' + this.remoteAddress + ']';

            if (greetingSent && clientHostname) {
                this.logger.info(
                    {
                        tnx: 'connect',
                        cid: this.id
                    },
                    'Resolved %s as %s in %ss',
                    this.remoteAddress,
                    clientHostname,
                    ((Date.now() - now) / 1000).toFixed(3)
                );
            }

            // eslint-disable-line handle-callback-err
            if (this._closing || this._closed) {
                return;
            }

            sendGreeting();
        };

        // Resolve hostname for the remote IP
        // we do not care for errors as we consider the ip as unresolved in this case, no big deal
        try {
            dns.reverse(this.remoteAddress, reverseCb);
        } catch (E) {
            // happens on invalid remote address
            reverseCb(E);
        }
    }

    unbind() {
        this.writeStream.unpipe(this._socket);
        this._socket.unpipe(this._parser);

        if (this._onCloseHandler) {
            this._socket.removeListener('close', this._onCloseHandler);
        }
        if (this._onEndHandler) {
            this._socket.removeListener('end', this._onEndHandler);
        }
        if (this._onErrorHandler) {
            this._socket.removeListener('error', this._onErrorHandler);
        }
        if (this._onTimeoutHandler) {
            this._socket.setTimeout(0, this._onTimeoutHandler);
        }

        return { socket: this._socket };
    }

    /**
     * Send data to socket
     *
     * @param {Number} code Response code
     * @param {String|Array} data If data is Array, send a multi-line response
     */
    send(payload, callback) {
        if (this._socket && !this._socket.destroyed && this._socket.readyState === 'open') {
            try {
                this[!this.compression ? '_socket' : '_deflate'].write(payload + '\r\n', 'binary', (...args) => {
                    if (args[0]) {
                        // write error
                        this.logger.error(
                            {
                                tnx: 'send',
                                cid: this.id,
                                err: args[0]
                            },
                            'Send error: %s',
                            args[0].message || args[0]
                        );
                        return this.close();
                    }
                    if (typeof callback === 'function') {
                        return callback(...args);
                    }
                });
            } catch (err) {
                // write error
                this.logger.error(
                    {
                        tnx: 'send',
                        cid: this.id,
                        err
                    },
                    'Send error: %s',
                    err.message || err
                );
                return this.close();
            }
            if (this.compression) {
                // make sure we transmit the message immediatelly
                this._deflate.flush();
            }
            this.logger.debug(
                {
                    tnx: 'send',
                    cid: this.id,
                    src: 'S'
                },
                payload
            );
        } else {
            // socket is not there anymore
            this.close();
        }
    }

    /**
     * Close socket
     */
    close(force) {
        if (this._closed || this._closing) {
            return;
        }

        if (!this._socket.destroyed && this._socket.writable) {
            this._socket[!force ? 'end' : 'destroy']();
        }

        this._server.connections.delete(this);

        if (!force) {
            // allow socket to close in 1500ms or force it to close
            this._closingTimeout = setTimeout(() => {
                if (this._closed) {
                    return;
                }

                try {
                    this._socket.destroy();
                } catch (err) {
                    // ignore
                }

                setImmediate(() => this._onClose());
            }, 1500);
        }

        this._closing = true;
        if (force) {
            setImmediate(() => this._onClose());
        }
    }

    // PRIVATE METHODS

    /**
     * Setup socket event handlers
     */
    _setListeners() {
        this._onCloseHandler = this._onClose.bind(this);
        this._onEndHandler = this._onEnd.bind(this);
        this._onErrorHandler = this._onError.bind(this);
        this._onTimeoutHandler = this._onTimeout.bind(this);

        this._socket.on('close', this._onCloseHandler);
        this._socket.on('end', this._onEndHandler);
        this._socket.on('error', this._onErrorHandler);
        this._socket.setTimeout(this._server.options.socketTimeout || SOCKET_TIMEOUT, this._onTimeoutHandler);

        this._socket.pipe(this._parser);
    }

    /**
     * Fired when the socket is closed
     * @event
     */
    _onEnd() {
        if (!this._closed) {
            this._onClose();
        }
    }

    /**
     * Fired when the socket is closed
     * @event
     */
    _onClose(/* hadError */) {
        clearTimeout(this._closingTimeout);

        if (this._closed) {
            return;
        }

        this._parser = false;

        this.state = 'Closed';

        if (this._dataStream) {
            this._dataStream.unpipe();
            this._dataStream = null;
        }

        if (this._deflate) {
            this._deflate = null;
        }

        if (this._inflate) {
            this._inflate = null;
        }

        this.clearNotificationListener();

        this._server.connections.delete(this);

        if (this.user && this._server.notifier) {
            if (typeof this._server.notifier.releaseConnection === 'function') {
                this._server.notifier.releaseConnection(
                    {
                        service: 'imap',
                        session: this.session,
                        user: this.user
                    },
                    () => false
                );
            }

            this.loggelf({
                short_message: '[CONNRELEASE] Connection released for ' + this.user.id,
                _connection: 'release',
                _service: 'imap',
                _sess: this.session && this.session.id,
                _user: this.user.id,
                _cid: this.id,
                _ip: this.remoteAddress
            });
        }

        this._closed = true;
        this._closing = false;

        this.logger.info(
            {
                tnx: 'close',
                cid: this.id
            },
            'Connection closed to %s',
            this.clientHostname
        );
    }

    /**
     * Fired when an error occurs with the socket
     *
     * @event
     * @param {Error} err Error object
     */
    _onError(err) {
        if (err.processed) {
            return;
        }

        if (['ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'EHOSTUNREACH'].includes(err.code)) {
            this.logger.info(
                {
                    tnx: 'connection',
                    cid: this.id
                },
                'Closing connection due to %s',
                err.code
            );
            this.close(); // mark connection as 'closing'
            return;
        }

        if (err && /SSL[23]*_GET_CLIENT_HELLO|ssl[23]*_read_bytes|ssl_bytes_to_cipher_list/i.test(err.message)) {
            let message = err.message;
            err.message = 'Failed to establish TLS session';
            err.responseCode = 500;
            err.code = err.code || 'TLSError';
            err.meta = {
                protocol: 'imap',
                stage: 'starttls',
                message,
                remoteAddress: this.remoteAddress
            };
        }

        if (!err || !err.message) {
            err = new Error('Socket closed unexpectedly');
            err.responseCode = 500;
            err.code = 'SocketError';
            err.meta = {
                remoteAddress: this.remoteAddress
            };
        }

        this.logger.error(
            {
                err,
                cid: this.id
            },
            err.message
        );
        this.emit('error', err);
    }

    /**
     * Fired when socket timeouts. Closes connection
     *
     * @event
     */
    _onTimeout() {
        this.logger.info(
            {
                tnx: 'connection',
                cid: this.id
            },
            'Connection TIMEOUT'
        );

        if (this.idling) {
            // see if the connection still works
            this.send('* OK Still here (' + Date.now() + ')');
            this._socket.setTimeout(this._server.options.socketTimeout || SOCKET_TIMEOUT, this._onTimeout.bind(this));
            return;
        }

        this.send('* BYE Idle timeout, closing connection');
        setImmediate(() => this.close(true));
    }

    /**
     * Checks if a selected command is available and ivokes it
     *
     * @param {Buffer} command Single line of data from the client
     * @param {Function} callback Callback to run once the command is processed
     */
    _onCommand(command, callback) {
        let currentCommand = this._currentCommand;

        callback = callback || (() => false);

        if (this._upgrading) {
            // ignore any commands before TLS upgrade is finished
            return callback();
        }

        if (!currentCommand) {
            this._currentCommand = currentCommand = new IMAPCommand(this);
        }

        if (!command.final) {
            currentCommand.append(command, callback);
        } else {
            this._currentCommand = false;
            currentCommand.end(command, callback);
        }
    }

    /**
     * Sets up a new session
     */
    _startSession() {
        this.session = {
            id: this.id,

            selected: this.selected,

            remoteAddress: this.remoteAddress,
            clientHostname: this.clientHostname || '[' + this.remoteAddress + ']',
            writeStream: this.writeStream,
            socket: this._socket,

            formatResponse: this.formatResponse.bind(this),
            getQueryResponse: imapTools.getQueryResponse,
            matchSearchQuery: search.matchSearchQuery,

            commandCounters: {},

            isUTF8Enabled: () => this.acceptUTF8Enabled
        };
    }

    /**
     * Sets up notification listener from upstream
     */
    setupNotificationListener() {
        let conn = this;

        if (this._closing || this._closed) {
            // nothing to do here
            return;
        }

        let isSelected = mailbox => mailbox && conn.selected && conn.selected.mailbox && conn.selected.mailbox.toString() === mailbox.toString();

        this._listenerData = {
            lock: false,
            cleared: false,
            callback(message) {
                let selectedMailbox = conn.selected && conn.selected.mailbox;
                if (this._closing || this._closed) {
                    conn.clearNotificationListener();
                    return;
                }

                if (message) {
                    // global triggers
                    switch (message.command) {
                        case 'LOGOUT':
                            conn.clearNotificationListener();
                            conn.send('* BYE ' + (message.reason || 'Logout requested'));
                            setImmediate(() => conn.close());
                            break;

                        case 'DROP':
                            if (isSelected(message.mailbox)) {
                                conn.clearNotificationListener();
                                conn.send('* BYE Selected mailbox was deleted, have to disconnect');
                                setImmediate(() => conn.close());
                                break;
                            }
                    }
                    return;
                }

                if (conn._listenerData.lock || !selectedMailbox) {
                    // race condition, do not allow fetching data before previous fetch is finished
                    return;
                }

                conn._listenerData.lock = true;
                conn._server.notifier.getUpdates(selectedMailbox, conn.selected.modifyIndex, (err, updates) => {
                    if (!conn._listenerData || conn._listenerData.cleared) {
                        // already logged out
                        return;
                    }
                    conn._listenerData.lock = false;

                    if (err) {
                        conn.logger.info(
                            {
                                err,
                                tnx: 'updates',
                                cid: conn.id
                            },
                            'Notification Error: %s',
                            err.message
                        );
                        return;
                    }

                    // check if the same mailbox is still selected
                    if (!isSelected(selectedMailbox) || !updates || !updates.length) {
                        return;
                    }

                    updates.sort((a, b) => a.modseq - b.modseq);

                    // store new incremental modify index
                    if (updates[updates.length - 1].modseq > conn.selected.modifyIndex) {
                        conn.selected.modifyIndex = updates[updates.length - 1].modseq;
                    }

                    // append received notifications to the list
                    conn.selected.notifications = conn.selected.notifications.concat(updates);
                    if (conn.idling) {
                        // when idling emit notifications immediatelly
                        conn.emitNotifications();
                    }
                });
            }
        };

        this._server.notifier.addListener(this.session, this._listenerData.callback);
    }

    clearNotificationListener() {
        if (!this._listenerData || this._listenerData.cleared) {
            return;
        }
        this._server.notifier.removeListener(this.session, this._listenerData.callback);
        this._listenerData.cleared = true;
        this._listenerData = false;
    }

    // send notifications to client
    emitNotifications() {
        if (this.state !== 'Selected' || !this.selected || !this.selected.notifications.length) {
            return;
        }

        let changed = false;
        let existsResponse;

        // show notifications
        this.logger.debug(
            {
                tnx: 'notifications',
                cid: this.id
            },
            'Pending notifications: %s',
            this.selected.notifications.length
        );

        // find UIDs that are both added and removed
        let added = new Set(); // added UIDs
        let removed = new Set(); // removed UIDs
        let skip = new Set(); // UIDs that are removed before ever seen

        for (let i = 0, len = this.selected.notifications.length; i < len; i++) {
            let update = this.selected.notifications[i];
            if (update.command === 'EXISTS') {
                added.add(update.uid);
            } else if (update.command === 'EXPUNGE') {
                removed.add(update.uid);
            }
        }

        removed.forEach(uid => {
            if (added.has(uid)) {
                skip.add(uid);
            }
        });

        // filter multiple FETCH calls, only keep latest, otherwise might mess up MODSEQ responses
        let fetches = new Set();
        for (let i = this.selected.notifications.length - 1; i >= 0; i--) {
            let update = this.selected.notifications[i];
            if (update.command === 'FETCH') {
                // skip multiple flag updates and updates for removed or newly added messages
                if (fetches.has(update.uid) || added.has(update.uid) || removed.has(update.uid)) {
                    this.selected.notifications.splice(i, 1);
                } else {
                    fetches.add(update.uid);
                }
            }
        }

        for (let i = 0, len = this.selected.notifications.length; i < len; i++) {
            let update = this.selected.notifications[i];

            // skip unnecessary entries that are already removed
            if (skip.has(update.uid)) {
                continue;
            }

            if (update.modseq > this.selected.modifyIndex) {
                this.selected.modifyIndex = update.modseq;
            }

            this.logger.debug(
                {
                    tnx: 'notifications',
                    cid: this.id
                },
                'Processing notification: %s',
                JSON.stringify(update)
            );

            if (update.ignore === this.id) {
                continue; // skip this
            }

            this.logger.debug(
                {
                    tnx: 'notifications',
                    cid: this.id
                },
                'UIDS: %s',
                this.selected.uidList.length
            );
            switch (update.command) {
                case 'EXISTS':
                    // Generate the response but do not send it yet (EXIST response generation is needed to modify the UID list)
                    // This way we can accumulate consecutive EXISTS responses into single one as
                    // only the last one actually matters to the client
                    existsResponse = this.formatResponse('EXISTS', update.uid);
                    changed = false;

                    break;

                case 'EXPUNGE': {
                    let seq = (this.selected.uidList || []).indexOf(update.uid);
                    this.logger.debug(
                        {
                            tnx: 'expunge',
                            cid: this.id
                        },
                        'EXPUNGE %s',
                        seq
                    );
                    if (seq >= 0) {
                        let output = this.formatResponse('EXPUNGE', update.uid);
                        this.writeStream.write(output);
                        changed = true; // if no more EXISTS after this, then generate an additional EXISTS
                    }

                    break;
                }
                case 'FETCH':
                    this.writeStream.write(
                        this.formatResponse('FETCH', update.uid, {
                            flags: update.flags,
                            modseq: (this.selected.condstoreEnabled && update.modseq) || false
                        })
                    );

                    break;
            }
        }

        if (existsResponse && !changed) {
            // send cached EXISTS response
            this.writeStream.write(existsResponse);
            existsResponse = false;
        }

        if (changed) {
            this.writeStream.write({
                tag: '*',
                command: String(this.selected.uidList.length),
                attributes: [
                    {
                        type: 'atom',
                        value: 'EXISTS'
                    }
                ]
            });
        }

        // clear queue
        this.selected.notifications = [];
    }

    formatResponse(command, uid, data) {
        command = command.toUpperCase();
        let seq;

        if (command === 'EXISTS') {
            this.selected.uidList.push(uid);
            seq = this.selected.uidList.length;
        } else {
            seq = (this.selected.uidList || []).indexOf(uid);
            if (seq < 0) {
                return false;
            }
            seq++;
        }

        if (command === 'EXPUNGE') {
            this.selected.uidList.splice(seq - 1, 1);
        }

        let response = {
            tag: '*',
            command: String(seq),
            attributes: [
                {
                    type: 'atom',
                    value: command
                }
            ]
        };

        if (data) {
            response.attributes.push([]);
            if ('query' in data) {
                // Response for FETCH command
                data.query.forEach((item, i) => {
                    response.attributes[1].push(item.original);
                    if (['flags', 'modseq'].indexOf(item.item) >= 0) {
                        response.attributes[1].push(
                            [].concat(data.values[i] || []).map(value => ({
                                type: 'ATOM',
                                value: (value || value === 0 ? value : '').toString()
                            }))
                        );
                    } else if (Object.prototype.toString.call(data.values[i]) === '[object Date]') {
                        response.attributes[1].push({
                            type: 'ATOM',
                            value: imapTools.formatInternalDate(data.values[i])
                        });
                    } else if (Array.isArray(data.values[i])) {
                        response.attributes[1].push(data.values[i]);
                    } else if (item.isLiteral) {
                        if (data.values[i] && data.values[i].type === 'stream') {
                            response.attributes[1].push({
                                type: 'LITERAL',
                                value: data.values[i].value,
                                expectedLength: data.values[i].expectedLength,
                                startFrom: data.values[i].startFrom,
                                maxLength: data.values[i].maxLength
                            });
                        } else {
                            response.attributes[1].push({
                                type: 'LITERAL',
                                value: data.values[i]
                            });
                        }
                    } else if (data.values[i] === '') {
                        response.attributes[1].push(data.values[i]);
                    } else {
                        response.attributes[1].push({
                            type: 'ATOM',
                            value: data.values[i].toString()
                        });
                    }
                });
            } else {
                // Notification response
                Object.keys(data).forEach(key => {
                    let value = data[key];
                    key = key.toUpperCase();
                    if (!value) {
                        return;
                    }

                    switch (key) {
                        case 'FLAGS':
                            value = [].concat(value || []).map(flag =>
                                flag && flag.value
                                    ? flag
                                    : {
                                          type: 'ATOM',
                                          value: flag
                                      }
                            );
                            break;

                        case 'UID':
                            value =
                                value && value.value
                                    ? value
                                    : {
                                          type: 'ATOM',
                                          value: (value || '0').toString()
                                      };
                            break;

                        case 'MODSEQ':
                            value = [].concat(
                                value && value.value
                                    ? value
                                    : {
                                          type: 'ATOM',
                                          value: (value || '0').toString()
                                      }
                            );
                            break;
                    }

                    response.attributes[1].push({
                        type: 'ATOM',
                        value: key
                    });

                    response.attributes[1].push(value);
                });
            }
        }

        return response;
    }

    setUser(user) {
        this.user = this.session.user = user;
    }
}

// Expose to the world
module.exports.IMAPConnection = IMAPConnection;
