'use strict';

const { BaseClient } = require('./base-client');
const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const { REDIS_PREFIX } = require('../consts');

/*

❌ listMessages
  ❌ paging - cursor based
❌ getText
❌ getMessage
❌ updateMessage
❌ updateMessages
❌ listMailboxes
❌ moveMessage
❌ moveMessages
❌ deleteMessage - no force option
❌ deleteMessages - no force option
❌ getRawMessage
❌ getQuota - not supported
❌ createMailbox
❌ renameMailbox
❌ deleteMailbox
❌ getAttachment
❌ submitMessage
❌ queueMessage
❌ uploadMessage
❌ subconnections - not supported

*/

class OutlookClient extends BaseClient {
    constructor(account, options) {
        super(account, options);

        this.cachedAccessToken = null;
        this.cachedAccessTokenRaw = null;

        // pseudo path for webhooks
        this.path = '\\All';
        this.listingEntry = { specialUse: '\\All' };
    }

    async request(...args) {
        let result, accessToken;
        try {
            accessToken = await this.getToken();
        } catch (err) {
            this.logger.error({ msg: 'Failed to load access token', account: this.account, err });
            throw err;
        }

        try {
            if (!this.oAuth2Client) {
                await this.getClient();
            }
            result = await this.oAuth2Client.request(accessToken, ...args);
        } catch (err) {
            this.logger.error({ msg: 'Failed to run API request', account: this.account, err });
            throw err;
        }

        return result;
    }

    // PUBLIC METHODS

    async init() {
        await this.getAccount();
        await this.getClient(true);
    }

    async close() {
        this.closed = true;
        return null;
    }

    async delete() {
        this.closed = true;
        return null;
    }

    async reconnect() {
        return await this.init();
    }

    async listMessages(/*query, options*/) {
        throw new Error('Future feature');
    }
    async getRawMessage(/*messageId*/) {
        throw new Error('Future feature');
    }
    async deleteMessage(/*messageId, force*/) {
        throw new Error('Future feature');
    }
    async deleteMessages(/*path, search*/) {
        throw new Error('Future feature');
    }
    async updateMessage(/*messageId, updates*/) {
        throw new Error('Future feature');
    }
    async updateMessages(/*path, search, updates*/) {
        throw new Error('Future feature');
    }
    async moveMessage(/*messageId, target*/) {
        throw new Error('Future feature');
    }
    async moveMessages(/*source, search, target*/) {
        throw new Error('Future feature');
    }
    async getAttachment(/*attachmentId*/) {
        throw new Error('Future feature');
    }
    async getMessage(/*messageId, options*/) {
        throw new Error('Future feature');
    }
    async getText(/*textId, options*/) {
        throw new Error('Future feature');
    }
    async uploadMessage(/*data*/) {
        throw new Error('Future feature');
    }
    async submitMessage(/*data*/) {
        throw new Error('Future feature');
    }
    async createMailbox(/*path*/) {
        throw new Error('Future feature');
    }
    async renameMailbox(/*path, newPath*/) {
        throw new Error('Future feature');
    }
    async deleteMailbox(/*path*/) {
        throw new Error('Future feature');
    }

    // PRIVATE METHODS

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    async getAccount() {
        if (this.accountObject) {
            return this.accountObject;
        }
        this.accountObject = new Account({ redis: this.redis, account: this.account, secret: await getSecret() });
        return this.accountObject;
    }

    async getToken() {
        const tokenData = await this.accountObject.getActiveAccessTokenData();
        return tokenData.accessToken;
    }

    async getClient(force) {
        if (this.oAuth2Client && !force) {
            return this.oAuth2Client;
        }
        let accountData = await this.accountObject.loadAccountData(this.account, false);
        this.oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, {
            logger: this.logger,
            logRaw: this.options.logRaw
        });
        return this.oAuth2Client;
    }

    async prepare() {
        await this.getAccount();
        await this.getClient();
    }
}

module.exports = { OutlookClient };
