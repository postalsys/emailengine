'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('msgpack5')();
const { normalizePath, formatAccountListingResponse, mergeObjects } = require('./tools');
const crypto = require('crypto');
const { MessageChannel } = require('worker_threads');
const { MessagePortReadable } = require('./message-port-stream');
const { deepStrictEqual, strictEqual } = require('assert');
const { encrypt, decrypt } = require('./encrypt');
const { getOAuth2Client } = require('./oauth');
const settings = require('./settings');
const redisScanDelete = require('./redis-scan-delete');
const { customAlphabet } = require('nanoid');
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 16);
const { REDIS_PREFIX, ACCOUNT_DELETED } = require('./consts');

class Account {
    constructor(options) {
        this.redis = options.redis;
        this.account = options.account || false;

        this.documentsQueue = options.documentsQueue || false;

        this.secret = options.secret;

        this.call = options.call; // async method to request data from parent

        this.logger = options.logger || logger;
    }

    async listAccounts(state, page, limit) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        let result = await this.redis.sListAccounts(`${REDIS_PREFIX}ia:accounts`, state || '*', skip, limit, `${REDIS_PREFIX}`);

        let list = {
            total: result[0],
            pages: Math.ceil(result[0] / limit),
            page,
            accounts: result[2]
                .map(formatAccountListingResponse)
                .map(this.unserializeAccountData.bind(this))
                .map(entry => ({
                    account: entry.account,
                    name: entry.name,
                    email: entry.email,
                    state: entry.state,
                    syncTime: entry.sync,
                    lastError: entry.state === 'connected' ? null : entry.lastErrorState
                }))
        };

        return list;
    }

    async getMailboxInfo(path) {
        let redisKey = BigInt('0x' + crypto.createHash('sha1').update(normalizePath(path)).digest('hex')).toString(36);

        let data = await this.redis.hgetall(`${REDIS_PREFIX}iam:${this.account}:h:${redisKey}`);
        if (!data || !Object.keys(data).length) {
            return {};
        }

        let encodedMailboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), path);
        if (!encodedMailboxData) {
            return {};
        }

        return {
            path: data.path || path,
            messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
            uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false
        };
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    unserializeAccountData(accountData) {
        let result = {};

        Object.keys(accountData).forEach(key => {
            switch (key) {
                case 'notifyFrom':
                    // Date object
                    if (accountData[key]) {
                        let date = new Date(accountData[key]);
                        if (date.toString() !== 'Invalid Date') {
                            result[key] = date;
                        }
                    }
                    break;

                // bolean values
                case 'copy':
                case 'logs':
                    result[key] = accountData[key] === 'true' ? true : false;
                    break;

                case 'imap':
                case 'smtp':
                case 'oauth2':
                case 'lastErrorState':
                case 'smtpStatus':
                case 'webhookErrorFlag':
                    try {
                        result[key] = JSON.parse(accountData[key]);
                        for (let subKey of ['created', 'expires']) {
                            if (result[key][subKey]) {
                                let dateVal = /^[0-9]+$/.test(result[key][subKey]) ? Number(result[key][subKey]) : result[key][subKey];
                                let date = new Date(dateVal);
                                if (date.toString() !== 'Invalid Date') {
                                    result[key][subKey] = date;
                                }
                            }
                        }
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to parse input from Redis', key, value: accountData[key], err });
                    }
                    break;

                default:
                    result[key] = accountData[key];
                    break;
            }
        });

        // decrypt secrets
        if (this.secret) {
            for (let type of ['imap', 'smtp', 'oauth2']) {
                if (result[type] && result[type].auth) {
                    for (let key of ['pass', 'accessToken', 'refreshToken']) {
                        if (key in result[type].auth) {
                            try {
                                result[type].auth[key] = decrypt(result[type].auth[key], this.secret);
                            } catch (err) {
                                // ignore??
                                this.logger.error({ msg: 'Failed to decrypt value', encrypted: result[type].auth[key], err });
                            }
                        } else if (key in result[type]) {
                            try {
                                result[type][key] = decrypt(result[type][key], this.secret);
                            } catch (err) {
                                // ignore??
                                this.logger.error({ msg: 'Failed to decrypt value', encrypted: result[type][key], err });
                            }
                        }
                    }
                }
            }
        }

        if (!result.path) {
            // by default listen changes on all folders
            result.path = '*';
        }

        if (typeof result.account === 'undefined') {
            result.account = null;
        }

        return result;
    }

    serializeAccountData(accountData) {
        let result = {};

        Object.keys(accountData).forEach(key => {
            switch (key) {
                case 'notifyFrom':
                    // Date object
                    if (accountData[key] === 'now') {
                        result[key] = new Date().toISOString();
                    } else if (accountData[key] && typeof accountData[key] === 'object' && accountData[key].toString() !== 'Invalid Date') {
                        result[key] = accountData[key].toISOString();
                    } else if (typeof accountData[key] === 'string') {
                        let date = new Date(accountData[key]);
                        if (date.toString() !== 'Invalid Date') {
                            result[key] = date.toISOString();
                        }
                    }
                    break;

                case 'imap':
                case 'smtp':
                case 'oauth2':
                    try {
                        // make a deep copy for manipulation
                        let connectData = JSON.parse(JSON.stringify(accountData[key]));

                        // if possible encrypt passwords
                        if (this.secret && connectData.auth) {
                            for (let key of ['pass', 'accessToken', 'refreshToken']) {
                                if (key in connectData.auth) {
                                    try {
                                        connectData.auth[key] = encrypt(connectData.auth[key], this.secret);
                                    } catch (err) {
                                        this.logger.error({ msg: 'Failed to encrypt value', err });
                                    }
                                } else if (key in connectData) {
                                    try {
                                        connectData[key] = encrypt(connectData[key], this.secret);
                                    } catch (err) {
                                        this.logger.error({ msg: 'Failed to encrypt value', err });
                                    }
                                }
                            }
                        }

                        if (
                            accountData[key].expires &&
                            typeof accountData[key].expires === 'object' &&
                            accountData[key].expires.toString() !== 'Invalid Date'
                        ) {
                            connectData.expires = accountData[key].expires.toISOString();
                        }

                        result[key] = JSON.stringify(connectData);
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to stringify input for Redis', key, err });
                    }
                    break;

                case 'webhooks':
                    if (typeof accountData[key] !== 'undefined' && accountData[key] !== null && typeof accountData[key].toString === 'function') {
                        result[key] = accountData[key].toString();
                        if (!result[key]) {
                            // clear potential error flag
                            result.webhookErrorFlag = '{}';
                        }
                    }
                    break;

                default:
                    if (typeof accountData[key] !== 'undefined' && accountData[key] !== null && typeof accountData[key].toString === 'function') {
                        result[key] = accountData[key].toString();
                    }
                    break;
            }
        });

        return result;
    }

    async loadAccountData(account, requireValid) {
        if (!this.account || (account && account !== this.account)) {
            let message = 'Invalid account ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let result = await this.redis.hgetall(this.getAccountKey());

        if (!result || !result.account) {
            let message = 'Account record was not found for requested ID';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            throw error;
        }

        let accountData = this.unserializeAccountData(result);
        if (requireValid && accountData.state !== 'connected') {
            let err;
            switch (accountData.state) {
                case 'init':
                    err = new Error('Requested account is not yet initialized');
                    break;
                case 'connecting':
                case 'syncing':
                    err = new Error('Requested account is not yet connected');
                    break;
                case 'authenticationError':
                    err = new Error('Requested account can not be authenticated');
                    break;
                case 'connectError':
                    err = new Error('Can not establish server connection for requested account');
                    break;
                default:
                    err = new Error('Requested account currently not available');
                    break;
            }

            let error = Boom.boomify(err, { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            throw error;
        }

        return accountData;
    }

    async update(accountData) {
        let oldAccountData = await this.loadAccountData(accountData.account);

        for (let subKey of ['imap', 'smtp', 'oauth2']) {
            if (!accountData[subKey] || typeof accountData[subKey] !== 'object') {
                continue;
            }
            let partial = accountData[subKey].partial;
            delete accountData[subKey].partial;
            if (!partial) {
                continue;
            }

            // merge old and new values
            if (!oldAccountData[subKey]) {
                // nothing to merge
                continue;
            }

            mergeObjects(accountData[subKey], oldAccountData[subKey]);
        }

        let result = await this.redis.hmset(this.getAccountKey(), this.serializeAccountData(accountData));
        if (!result || result !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        if ('imap' in accountData) {
            // if partial update, then skip check
            try {
                deepStrictEqual(oldAccountData.imap, accountData.imap);
                strictEqual(oldAccountData.path || '*', accountData.path || '*');
            } catch (err) {
                // changes detected!
                this.logger.info({ msg: 'IMAP configuration changed for account', account: this.account });
                await this.call({ cmd: 'update', account: this.account });
            }
        }

        return {
            account: this.account
        };
    }

    async genId() {
        let id;
        let retries = 0;
        while (retries++ < 20) {
            id = nanoid();
            let alreadyExists = await this.redis.exists(`${REDIS_PREFIX}iad:${id}`);
            if (alreadyExists) {
                id = false;
            } else {
                break;
            }
        }
        return id;
    }

    async create(accountData) {
        this.account = accountData.account;
        if (this.account === null) {
            // auogenerate ID
            this.account = accountData.account = await this.genId();
        }

        if (!this.account) {
            let message = 'Invalid account ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let result = await this.redis
            .multi()
            .hgetall(this.getAccountKey())
            .hmset(this.getAccountKey(), this.serializeAccountData(accountData))
            .hsetnx(this.getAccountKey(), 'state', 'init')
            .sadd(`${REDIS_PREFIX}ia:accounts`, this.account)
            .exec();

        if (!result || !result[1] || result[1][0] || result[1][1] !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        let state = false;
        if (result[0][1] && result[0][1].account) {
            // existing user
            state = 'existing';
            await this.call({ cmd: 'update', account: this.account });
        } else {
            state = 'new';
            await this.call({ cmd: 'new', account: this.account });
        }

        return { account: this.account, state };
    }

    async delete() {
        await this.loadAccountData(this.account);

        let result = await this.redis
            .multi()
            .del(this.getAccountKey())
            .srem(`${REDIS_PREFIX}ia:accounts`, this.account)
            .del(`${REDIS_PREFIX}ial:${this.account}`) // mailbox list
            .del(`${REDIS_PREFIX}iah:${this.account}`) // mailbox list for ID references
            .del(`${REDIS_PREFIX}iar:b:${this.account}`) // bounce list
            .del(`${REDIS_PREFIX}iar:s:${this.account}`) // seen messages list
            .del(`${REDIS_PREFIX}iaq:${this.account}`) // delayed message queue
            .del(`${REDIS_PREFIX}iat:${this.account}`) // access tokens
            .exec();

        // scan and delete keys
        // should we wait though? might take a lot of time
        await redisScanDelete(this.redis, this.logger, `${REDIS_PREFIX}iam:${this.account}:*`);

        if (!result || !result[0] || !result[0][1]) {
            return {
                account: this.account,
                deleted: false
            };
        }

        try {
            let queueKeep = (await settings.get('queueKeep')) || true;
            let serviceUrl = (await settings.get('serviceUrl')) || true;

            let payload = {
                serviceUrl,
                account: this.account,
                date: new Date().toISOString(),
                event: ACCOUNT_DELETED
            };

            await this.documentsQueue.add(ACCOUNT_DELETED, payload, {
                removeOnComplete: queueKeep,
                removeOnFail: queueKeep,
                attempts: 10,
                backoff: {
                    type: 'exponential',
                    delay: 5000
                }
            });
        } catch (err) {
            this.logger.error(err);
        }

        await this.call({ cmd: 'delete', account: this.account });

        return {
            account: this.account,
            deleted: true
        };
    }

    async getRawMessage(message) {
        await this.loadAccountData(this.account, true);

        const { port1, port2 } = new MessageChannel();
        const stream = new MessagePortReadable(port1);

        let streamCreated = await this.call({ cmd: 'getRawMessage', account: this.account, message, port: port2 }, [port2]);

        if (streamCreated && streamCreated.headers) {
            stream.headers = streamCreated.headers;
        }

        return stream;
    }

    async getAttachment(attachment) {
        await this.loadAccountData(this.account, true);

        const { port1, port2 } = new MessageChannel();
        const stream = new MessagePortReadable(port1);

        let streamCreated = await this.call({ cmd: 'getAttachment', account: this.account, attachment, port: port2 }, [port2]);

        if (streamCreated && streamCreated.headers) {
            stream.headers = streamCreated.headers;
        }

        return stream;
    }

    async getMailboxListing() {
        await this.loadAccountData(this.account, true);

        let mailboxes = [];
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());

        for (let path of Object.keys(storedListing || {})) {
            try {
                let decoded = msgpack.decode(storedListing[path]);

                if (decoded.delimiter && decoded.path.indexOf(decoded.delimiter) >= 0) {
                    decoded.parentPath = decoded.path.substr(0, decoded.path.lastIndexOf(decoded.delimiter));
                }

                mailboxes.push(Object.assign(decoded, await this.getMailboxInfo(path)));
            } catch (err) {
                // should not happen
                this.logger.error(err);
            }
        }

        mailboxes = mailboxes.sort((a, b) => {
            if (a.path === 'INBOX') {
                return -1;
            } else if (b.path === 'INBOX') {
                return 1;
            }

            if (a.specialUse && !b.specialUse) {
                return -1;
            } else if (!a.specialUse && b.specialUse) {
                return 1;
            }

            return a.path.toLowerCase().localeCompare(b.path.toLowerCase());
        });

        return mailboxes;
    }

    async updateMessage(message, updates) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'updateMessage', account: this.account, message, updates });
    }

    async moveMessage(message, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'moveMessage', account: this.account, message, target });
    }

    async deleteMessage(message, force) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'deleteMessage', account: this.account, message, force });
    }

    async createMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'createMailbox', account: this.account, path });
    }

    async deleteMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'deleteMailbox', account: this.account, path });
    }

    async getText(text, options) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'getText', account: this.account, text, options });
    }

    async getMessage(message, options) {
        await this.loadAccountData(this.account, !options.documentStore);

        if (options.documentStore) {
            // fetch from cache instead
        }

        let messageData = await this.call({ cmd: 'getMessage', account: this.account, message, options });
        if (!messageData) {
            let message = 'Requested message was not found';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            throw error;
        }
        return messageData;
    }

    async listMessages(query) {
        await this.loadAccountData(this.account, true);

        let path = normalizePath(query.path);
        let encodedMailboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), path);
        if (!encodedMailboxData) {
            let message = 'Mailbox record was not found';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            error.output.payload.path = query.path;
            throw error;
        }

        // mailbox seems to exist, so call parent to resolve open connection
        return await this.call(Object.assign({ cmd: 'listMessages', account: this.account }, query));
    }

    async buildContacts() {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'buildContacts', account: this.account, timeout: 5 * 60 * 1000 });
    }

    async uploadMessage(data) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call({ cmd: 'uploadMessage', account: this.account, data });
        return messageData;
    }

    async submitMessage(data) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call(
            {
                cmd: 'submitMessage',
                account: this.account,
                data
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );

        return messageData;
    }

    async queueMessage(data, meta) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call(
            {
                cmd: 'queueMessage',
                account: this.account,
                data,
                meta
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );
        return messageData;
    }

    async requestReconnect(data) {
        await this.loadAccountData(this.account, true);

        if (data.reconnect) {
            await this.call({ cmd: 'update', account: this.account });
            return true;
        }
        return false;
    }

    async requestSync(data) {
        await this.loadAccountData(this.account, true);

        if (data.sync) {
            await this.call({ cmd: 'sync', account: this.account });
            return true;
        }
        return false;
    }

    async renewAccessToken() {
        let accountData = await this.loadAccountData(this.account, false);

        const oAuth2Client = await getOAuth2Client(accountData.oauth2.provider);

        switch (accountData.oauth2.provider) {
            case 'gmail':
            case 'gmailService':
            case 'mailRu':
            case 'outlook': {
                let r = await oAuth2Client.refreshToken({
                    refreshToken: accountData.oauth2.refreshToken,
                    // user is needed if it's a service account
                    user: accountData.oauth2.auth.user
                });

                if (!r.access_token) {
                    throw new Error('Failed to renew token');
                }

                let updates = {
                    accessToken: r.access_token,
                    expires: new Date(Date.now() + r.expires_in * 1000).toISOString()
                };

                if (r.refresh_token) {
                    updates.refreshToken = r.refresh_token;
                }

                if (r.scope) {
                    updates.scope = r.scope.split(/\s+/);
                }

                accountData.oauth2 = Object.assign(accountData.oauth2 || {}, updates);
                break;
            }
            default:
                throw new Error('Unknown OAuth provider');
        }

        this.logger.info({ msg: 'Renewed the OAuth2 access token' });

        await this.update({ account: accountData.account, oauth2: accountData.oauth2 });

        return accountData;
    }

    async invalidateAccessToken() {
        let accountData = await this.loadAccountData(this.account, false);
        if (accountData.oauth2) {
            accountData.oauth2.expires = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
            await this.update({ account: accountData.account, oauth2: accountData.oauth2 });
            this.logger.info({ msg: 'Invalidated the OAuth2 access token', expires: accountData.oauth2.expires });
        }
        return accountData;
    }
}

module.exports = { Account };
