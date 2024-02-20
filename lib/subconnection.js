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
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up subconnection', err });
        }
    }

    async start() {
        if (this.imapClient) {
            // close previous
            this.imapClient.disabled = true;
            try {
                this.imapClient.removeAllListeners();
                this.imapClient.on('error', err => {
                    this.logger.error({ msg: 'IMAP connection error', previous: true, account: this.account, err });
                });
                this.imapClient.close();
            } catch (err) {
                this.logger.error({ msg: 'IMAP close error', err });
            } finally {
                this.imapClient = null;
            }
        }

        let imapConfig = await this.getImapConfig(null, this);

        this.imapClient = new ImapFlow(
            Object.assign({}, imapConfig, {
                logger: this.logger,
                expungeHandler: async payload => await this.expungeHandler(payload)
            })
        );

        this.imapClient.subConnection = true;

        this.imapClient.on('error', err => {
            this.logger.error({ msg: 'IMAP connection error', account: this.account, err });
            this.reconnect().catch(err => {
                this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
            });
        });

        try {
            await this.connect();
        } catch (err) {
            if (err.authenticationFailed) {
                this.logger.error({ msg: 'Failed to authenticate subconnection', account: this.account, err });
                this.state = 'authenticationError';
            } else {
                this.logger.error({ msg: 'Failed to connect subconnection', account: this.account, err });
                this.state = 'connectError';
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

        imapClient.on('close', async () => {
            this.logger.info({ msg: 'Connection closed', account: this.account });

            try {
                if (!imapClient.disabled) {
                    await this.reconnect();
                }
            } catch (err) {
                this.logger.error({ msg: 'Connection close error', err });
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
