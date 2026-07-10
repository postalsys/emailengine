'use strict';

const { ImapFlow } = require('imapflow');
const { backOff } = require('exponential-backoff');
const EventEmitter = require('events').EventEmitter;

const MAX_WAIT_DELAY = 450; //ms

class Subconnection extends EventEmitter {
    constructor(opts) {
        super();
        opts = opts || {};
        this.parent = opts.parent;

        this.mailbox = opts.mailbox || {};
        this.path = this.mailbox.path;
        this.logger = opts.logger;
        this.account = opts.account;

        this.imapClient = null;
        this.getImapConfig = opts.getImapConfig;

        this.isClosing = false;
        this.isClosed = false;
        this._connecting = false;

        this.state = 'connecting';
        this.disabledReason = false;

        this.emitTimer = false;

        // Reconnection tracking for capped exponential backoff
        this.reconnectAttempts = 0;
        this.reconnectBaseDelay = 2000;
        this.reconnectMaxDelay = 30000; // Cap at 30 seconds
        this.lastReconnectTime = 0;
    }

    isConnected() {
        return this.imapClient && this.imapClient.usable && !this.isClosing && !this.isClosed;
    }

    checkIMAPConnection() {
        if (!this.isConnected()) {
            let err = new Error('IMAP connection is currently not available for requested account');
            err.code = 'IMAPUnavailable';
            err.statusCode = 503;
            throw err;
        }
    }

    requestSync() {
        clearTimeout(this.emitTimer);
        this.emitTimer = setTimeout(() => {
            clearTimeout(this.emitTimer);

            this.emit('changes', this.path);
        }, MAX_WAIT_DELAY);
    }

    async init() {
        this.logger.info({ msg: 'Creating subconnection' });
        await this.reconnect();
    }

    async reconnect() {
        if (this._connecting || this.isClosing || this.isClosed) {
            return false;
        }

        // Block overlapping cycles right away. The 'error' and 'close' handlers
        // check this flag, so setting it before the backoff sleep prevents them
        // from starting a second reconnection cycle while this one is waiting
        this._connecting = true;

        try {
            // Calculate delay with cap (never stops trying)
            const delay = Math.min(this.reconnectMaxDelay, this.reconnectBaseDelay * Math.pow(1.5, Math.min(this.reconnectAttempts, 10)));

            // Add jitter to prevent thundering herd
            const jitter = Math.random() * 1000; // 0-1 second jitter
            const totalDelay = delay + jitter;

            this.reconnectAttempts++;

            this.logger.info({
                msg: 'Scheduling subconnection reconnect',
                attempt: this.reconnectAttempts,
                delay: totalDelay,
                path: this.path
            });

            // Wait before attempting reconnect
            await new Promise(resolve => setTimeout(resolve, totalDelay));

            if (this.isClosing || this.isClosed) {
                // close() was called during the delay. Do not revive a closed
                // subconnection - the parent has already discarded this instance,
                // so a new connection would be unreachable and leak
                return false;
            }

            await backOff(() => this.start(), {
                maxDelay: this.reconnectMaxDelay,
                numOfAttempts: Infinity,
                retry: () => !this.isClosing && !this.isClosed,
                startingDelay: 2000
            });
        } finally {
            // Cleared before the mailbox validation below on purpose: if the
            // server drops the connection while the monitored mailbox is being
            // opened, the 'close' handler must still be able to schedule the
            // single retry cycle
            this._connecting = false;
        }

        try {
            await this.checkIMAPConnection();
            await this.imapClient.mailboxOpen(this.mailbox.path);

            this.state = 'connected';
            this.disabledReason = false;

            // Reset the backoff counter only after the monitored mailbox is open.
            // Connect/login success alone does not validate the setup - resetting
            // already there would restart the close-triggered retry loop from the
            // base delay on every cycle when the mailbox itself can not be opened
            this.reconnectAttempts = 0;
        } catch (err) {
            if (err.responseStatus === 'NO' && this.imapClient?.usable) {
                // SELECT failed with NO - verify whether the mailbox exists at
                // all, mirroring the verification ImapFlow runs in
                // getMailboxLock(). mailboxOpen() itself does not set the
                // mailboxMissing marker
                try {
                    let folders = await this.imapClient.run('LIST', '', this.mailbox.path, { listOnly: true });
                    if (!folders || !folders.length) {
                        err.mailboxMissing = true;
                    }
                } catch (E) {
                    this.logger.debug({ msg: 'Failed to verify missing mailbox', path: this.mailbox.path, err: E });
                }
            }

            if (err.mailboxMissing) {
                // The monitored folder does not exist anymore, so retrying can
                // not succeed. Shut the subconnection down and mark it as
                // disabled - setupSubConnections() replaces it with a live
                // connection if the folder is re-created later
                this.logger.warn({ msg: 'Monitored mailbox is missing, disabling subconnection', path: this.mailbox.path, err });

                this.close();
                this.imapClient = null;

                // close() resets these, so set the disabled state afterwards
                this.disabled = true;
                this.state = 'disabled';
                this.disabledReason = 'Mailbox folder not found';

                // Process the folder deletion (stored listing, webhooks) right away
                this.parent.refreshAndProcessListing().catch(err => {
                    this.logger.error({ msg: 'Failed to refresh folder listing', err });
                });

                return;
            }

            // ended in an unconncted state
            this.logger.warn({ msg: 'Failed to set up subconnection', err });
        }
    }

    async start() {
        if (this.imapClient) {
            // close previous
            let prevImapClient = this.imapClient;
            prevImapClient.disabled = true;
            try {
                prevImapClient.removeAllListeners();
                prevImapClient.once('error', err => {
                    this.logger.warn({ msg: 'IMAP connection error', previous: true, account: this.account, err });
                });
                prevImapClient.close();
            } catch (err) {
                this.logger.warn({ msg: 'IMAP close error', err });
            } finally {
                if (prevImapClient === this.imapClient) {
                    this.imapClient = null;
                }

                // The close handler that maintains the connection count was removed
                // above, so update the tracking for the replaced client manually
                if (this.parent.connections.delete(prevImapClient)) {
                    try {
                        await this.parent.redis.hSetExists(this.parent.getAccountKey(), 'connections', this.parent.connections.size.toString());
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to update connection count in Redis', account: this.account, err });
                    }
                }
            }
        }

        let imapConfig = await this.getImapConfig(null, this);

        let imapClient = new ImapFlow(
            Object.assign({}, imapConfig, {
                logger: this.logger,
                expungeHandler: async payload => await this.expungeHandler(payload)
            })
        );
        this.parent.connections.add(imapClient);
        await this.parent.redis.hSetExists(this.parent.getAccountKey(), 'connections', this.parent.connections.size.toString());

        this.imapClient = imapClient;

        imapClient.subConnection = true;

        imapClient.on('error', err => {
            imapClient?.log.warn({ msg: 'IMAP connection error', account: this.account, err });
            if (imapClient !== this.imapClient || this._connecting) {
                return;
            }
            imapClient.close();
            this.reconnect().catch(err => {
                this.logger.warn({ msg: 'IMAP reconnection error', account: this.account, err });
            });
        });

        imapClient.on('close', async () => {
            try {
                this.parent.connections.delete(imapClient);
                await this.parent.redis.hSetExists(this.parent.getAccountKey(), 'connections', this.parent.connections.size.toString());
                imapClient.log.info({ msg: 'Connection closed', account: this.account });
            } catch (err) {
                this.logger.error({ msg: 'Error updating connection count on close', account: this.account, err });
            }

            try {
                if (!imapClient.disabled && imapClient === this.imapClient && !this._connecting) {
                    await this.reconnect();
                }
            } catch (err) {
                this.logger.error({ msg: 'Reconnection error', err });
            }

            imapClient = null;
        });

        try {
            await this.connect();
        } catch (err) {
            if (err.authenticationFailed) {
                this.logger.error({ msg: 'Failed to authenticate subconnection', account: this.account, err });
                this.state = 'authenticationError';
                this.disabledReason = 'Authentication failed';
            } else {
                this.logger.error({ msg: 'Failed to connect subconnection', account: this.account, err });
                this.state = 'connectError';
                this.disabledReason = 'Failed to connect';
            }
            throw err;
        }
    }

    async connect() {
        if (this.isClosing || this.isClosed) {
            return false;
        }

        let imapClient = this.imapClient;

        // throws if connection fails
        let response = await imapClient.connect();

        // Process untagged EXISTS responses
        imapClient.on('exists', event => {
            try {
                if (!event || !event.path) {
                    return; //?
                }

                this.logger.info({ msg: 'Exists notification', account: this.account, event });

                this.requestSync();
            } catch (err) {
                this.logger.error({ msg: 'Exists notification handling failed', account: this.account, err });
            }
        });

        imapClient.on('flags', event => {
            try {
                if (!event || !event.path) {
                    return; //?
                }

                this.logger.info({ msg: 'Flags notification', account: this.account, event });

                this.requestSync();
            } catch (err) {
                this.logger.error({ msg: 'Flags notification handling failed', account: this.account, err });
            }
        });

        return response;
    }

    async expungeHandler(payload) {
        this.logger.info({ msg: 'Expunge notification', account: this.account, payload });

        this.requestSync();
    }

    async notify() {
        // no op
    }

    close() {
        this.state = 'disconnected';
        this.disabledReason = false;

        if (this.isClosed || this.isClosing) {
            return;
        }
        this.isClosing = true;

        if (this.imapClient) {
            this.imapClient.close();
        }

        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        this.isClosing = false;
        this.isClosed = true;
    }
}

module.exports = { Subconnection };
