'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('msgpack5')();
const { normalizePath, formatAccountListingResponse } = require('./tools');
const crypto = require('crypto');
const { MessageChannel } = require('worker_threads');
const { MessagePortReadable } = require('./message-port-stream');
const { deepStrictEqual, strictEqual } = require('assert');
const { encrypt, decrypt } = require('./encrypt');

class Account {
    constructor(options) {
        this.redis = options.redis;
        this.account = options.account || false;

        this.secret = options.secret;

        this.call = options.call; // async method to request data from parent
    }

    async listAccounts(state, page, limit) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        let result = await this.redis.sListAccounts('ia:accounts', state || '*', skip, limit);

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
                    state: entry.state,
                    syncTime: entry.sync,
                    lastError: entry.state === 'connected' ? null : entry.lastErrorState
                }))
        };

        return list;
    }

    async getMailboxInfo(path) {
        let redisKey = BigInt('0x' + crypto.createHash('sha1').update(normalizePath(path)).digest('hex')).toString(36);

        let data = await this.redis.hgetall(`iam:${this.account}:h:${redisKey}`);
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
        return `iad:${this.account}`;
    }

    getMailboxListKey() {
        return `ial:${this.account}`;
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
                            result[key] = new Date(accountData[key]);
                        }
                    }
                    break;

                case 'copy':
                    result[key] = accountData[key] === 'true' ? true : false;
                    break;

                case 'imap':
                case 'smtp':
                case 'lastErrorState':
                    try {
                        result[key] = JSON.parse(accountData[key]);
                    } catch (err) {
                        logger.error({ msg: 'Failed to parse input from Redis', key, err });
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
                                logger.error({ msg: 'Failed to decrypt value', encrypted: result[type].auth[key], err });
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
                                        logger.error({ msg: 'Failed to encrypt value', err });
                                    }
                                }
                            }
                        }

                        result[key] = JSON.stringify(connectData);
                    } catch (err) {
                        logger.error({ msg: 'Failed to stringify input for Redis', key, err });
                    }
                    break;

                default:
                    if (accountData[key] !== undefined && typeof accountData[key].toString === 'function') {
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

        let result = await this.redis.hmset(this.getAccountKey(), this.serializeAccountData(accountData));
        if (!result || result !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        try {
            deepStrictEqual(oldAccountData.imap, accountData.imap);
            strictEqual(oldAccountData.path || '*', accountData.path || '*');
        } catch (err) {
            // changes detected!
            logger.info({ msg: 'IMAP configuration changed for account', account: this.account });
            await this.call({ cmd: 'update', account: this.account });
        }

        return {
            account: this.account
        };
    }

    async create(accountData) {
        this.account = accountData.account;

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
            .sadd('ia:accounts', this.account)
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
            .keys(`iam:${this.account}:*`)
            .srem('ia:accounts', this.account)
            .del(`ial:${this.account}`) // mailbox list
            // do not delete `iah:${this.account}` to keep ID references
            .exec();

        if (result && result[1] && result[1][1] && result[1][1].length) {
            // delete all mailbox specific keys
            let run = await this.redis.multi();
            for (let key of result[1][1]) {
                run = run.del(key);
            }
            await run.exec();
        }

        if (!result || !result[0] || !result[0][1]) {
            return {
                account: this.account,
                deleted: false
            };
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

        let result = [];
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());

        for (let path of Object.keys(storedListing || {})) {
            try {
                let decoded = msgpack.decode(storedListing[path]);
                if (decoded.delimiter && decoded.path.indexOf(decoded.delimiter) >= 0) {
                    decoded.parentPath = decoded.path.substr(0, decoded.path.lastIndexOf(decoded.delimiter));
                }
                delete decoded.delimiter;
                result.push(Object.assign(decoded, await this.getMailboxInfo(path)));
            } catch (err) {
                // should not happen
                logger.error(err);
            }
        }

        return result;
    }

    async updateMessage(message, updates) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'updateMessage', account: this.account, message, updates });
    }

    async moveMessage(message, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'moveMessage', account: this.account, message, target });
    }

    async deleteMessage(message) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'deleteMessage', account: this.account, message });
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
        await this.loadAccountData(this.account, true);

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

        let messageData = await this.call({ cmd: 'submitMessage', account: this.account, data });
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
}

module.exports = { Account };
