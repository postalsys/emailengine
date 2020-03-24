'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('msgpack5')();
const { normalizePath } = require('./tools');
const crypto = require('crypto');
const { MessageChannel } = require('worker_threads');
const { MessagePortReadable } = require('./message-port-stream');
const { deepStrictEqual } = require('assert');

class Account {
    constructor(options) {
        this.redis = options.redis;
        this.account = options.account || false;

        this.call = options.call; // async method to request data from parent
    }

    async getMailboxInfo(path) {
        let redisKey = BigInt(
            '0x' +
                crypto
                    .createHash('sha1')
                    .update(normalizePath(path))
                    .digest('hex')
        ).toString(36);

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
        return result;
    }

    serializeAccountData(accountData) {
        let result = {};
        Object.keys(accountData).forEach(key => {
            switch (key) {
                case 'imap':
                case 'smtp':
                    try {
                        result[key] = JSON.stringify(accountData[key]);
                    } catch (err) {
                        logger.error({ msg: 'Failed to stringify input for Redis', key, err });
                    }
                    break;

                default:
                    if (typeof accountData[key].toString === 'function') {
                        result[key] = accountData[key].toString();
                    }
                    break;
            }
        });
        return result;
    }

    async loadAccountData(account, requireValid) {
        if (!this.account || (account && account !== this.account)) {
            throw Boom.boomify(new Error('Invalid account ID'), { statusCode: 400 });
        }

        let result = await this.redis.hgetall(this.getAccountKey());

        if (!result || !result.account) {
            throw Boom.boomify(new Error('Account record was not found for requested ID'), { statusCode: 404 });
        }

        let accountData = this.unserializeAccountData(result);
        if (requireValid && accountData.state !== 'connected') {
            switch (accountData.state) {
                case 'init':
                    throw Boom.boomify(new Error('Requested account is not yet initialized'), { statusCode: 503 });
                case 'connecting':
                    throw Boom.boomify(new Error('Requested account is not yet connected'), { statusCode: 503 });
                case 'authenticationError':
                    throw Boom.boomify(new Error('Requested account can not be authenticated'), { statusCode: 503 });
                case 'connectError':
                    throw Boom.boomify(new Error('Can not establish server connection for requested account'), { statusCode: 503 });
                default:
                    throw Boom.boomify(new Error('Requested account currently not available'), { statusCode: 503 });
            }
        }

        return accountData;
    }

    async update(accountData) {
        let oldAccountData = await this.loadAccountData(accountData.account);

        let result = await this.redis.hmset(this.getAccountKey(), this.serializeAccountData(accountData));
        if (!result || result !== 'OK') {
            throw Boom.boomify(new Error('Something went wrong'), { statusCode: 500 });
        }

        try {
            deepStrictEqual(oldAccountData.imap, accountData.imap);
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
            throw Boom.boomify(new Error('Invalid account ID'), { statusCode: 400 });
        }

        let result = await this.redis
            .multi()
            .hgetall(this.getAccountKey())
            .hmset(this.getAccountKey(), this.serializeAccountData(accountData))
            .hsetnx(this.getAccountKey(), 'state', 'init')
            .sadd('ia:accounts', this.account)
            .exec();

        if (!result || !result[1] || result[1][0] || result[1][1] !== 'OK') {
            throw Boom.boomify(new Error('Something went wrong'), { statusCode: 500 });
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
            throw Boom.boomify(new Error('Requested message was not found'), { statusCode: 404 });
        }
        return messageData;
    }

    async listMessages(query) {
        await this.loadAccountData(this.account, true);

        let path = normalizePath(query.path);
        let encodedMailboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), path);
        if (!encodedMailboxData) {
            throw Boom.boomify(new Error('Mailbox record was not found'), { statusCode: 404 });
        }

        // mailbox seems to exist, so call parent to resolve open connection
        return await this.call(Object.assign({ cmd: 'listMessages', account: this.account }, query));
    }

    async buildContacts() {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'buildContacts', account: this.account, timeout: 5 * 60 * 1000 });
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
