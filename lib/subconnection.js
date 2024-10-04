'use strict';

const { ImapFlow } = require('imapflow');
const { backOff } = require('exponential-backoff');
const EventEmitter = require('events').EventEmitter;

const { MAX_BACKOFF_DELAY } = require('./consts');

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

    async reconnect(force) {
        if (this._connecting || this.isClosing || (this.isClosed && !force)) {
            return false;
        }

        this._connecting = true;
        this.isClosed = false;

        try {
            await backOff(() => this.start(), {
                maxDelay: MAX_BACKOFF_DELAY,
                numOfAttempts: Infinity,
                retry: () => !this.isClosing && !this.isClosed,
                startingDelay: 2000
            });
        } finally {
            this._connecting = false;
        }

        try {
            await this.checkIMAPConnection();
            await this.imapClient.mailboxOpen(this.mailbox.path);

            this.state = 'connected';
            this.disabledReason = false;
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up subconnection', err });
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
                    this.logger.error({ msg: 'IMAP connection error', previous: true, account: this.account, err });
                });
                prevImapClient.close();
            } catch (err) {
                this.logger.error({ msg: 'IMAP close error', err });
            } finally {
                if (prevImapClient === this.imapClient) {
                    this.imapClient = null;
                }
                prevImapClient = null;
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
            imapClient?.log.error({ msg: 'IMAP connection error', account: this.account, err });
            if (imapClient !== this.imapClient || this._connecting) {
                return;
            }
            imapClient.close();
            this.reconnect().catch(err => {
                this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
            });
        });

        imapClient.on('close', async () => {
            this.parent.connections.delete(imapClient);
            await this.parent.redis.hSetExists(this.parent.getAccountKey(), 'connections', this.parent.connections.size.toString());
            imapClient.log.info({ msg: 'Connection closed', account: this.account });

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
        imapClient.on('exists', async event => {
            if (!event || !event.path) {
                return; //?
            }

            this.logger.info({ msg: 'Exists notification', account: this.account, event });

            this.requestSync();
        });

        imapClient.on('flags', async event => {
            if (!event || !event.path) {
                return; //?
            }

            this.logger.info({ msg: 'Flags notification', account: this.account, event });

            this.requestSync();
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
