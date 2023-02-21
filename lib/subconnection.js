'use strict';

const { ImapFlow } = require('imapflow');
const { backOff } = require('exponential-backoff');

const { MAX_BACKOFF_DELAY } = require('./consts');

class Subconnection {
    constructor(opts) {
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

        let imapConfig = await this.getImapConfig();

        imapConfig.expungeHandler = async payload => await this.expungeHandler(payload);
        imapConfig.logger = this.logger;

        this.imapClient = new ImapFlow(imapConfig);

        this.imapClient.on('error', err => {
            this.logger.error({ msg: 'IMAP connection error', account: this.account, err });
            this.reconnect().catch(err => {
                this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
            });
        });

        await this.connect();
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
        });

        imapClient.on('flags', async event => {
            if (!event || !event.path) {
                return; //?
            }

            this.logger.info({ msg: 'Flags notification', account: this.account, event });
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
    }

    close() {
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
