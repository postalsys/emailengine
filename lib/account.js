'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('msgpack5')();
const { normalizePath, formatAccountListingResponse, unpackUIDRangeForSearch, mergeObjects } = require('./tools');
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

        this.esClient = options.esClient;

        this.call = options.call; // async method to request data from parent

        this.logger = options.logger || logger;
    }

    async listAccounts(state, query, page, limit) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        let result = await this.redis.sListAccounts(`${REDIS_PREFIX}ia:accounts`, state || '*', skip, limit, `${REDIS_PREFIX}`, query);

        let list = {
            total: result[0],
            pages: Math.ceil(result[0] / limit),
            page,
            query: query || false,
            state: state || '*',
            accounts: result[2]
                .map(formatAccountListingResponse)
                .map(this.unserializeAccountData.bind(this))
                .map(entry => ({
                    account: entry.account,
                    name: entry.name,
                    email: entry.email,
                    state: entry.state,
                    syncTime: entry.sync,
                    webhooks: entry.webhooks || undefined,
                    proxy: entry.proxy || undefined,
                    lastError: entry.state === 'connected' || !entry.lastErrorState || !Object.keys(entry.lastErrorState).length ? null : entry.lastErrorState
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
                case 'syncFrom':
                    // Date object
                    if (accountData[key]) {
                        if (accountData[key] === 'null') {
                            result[key] = null;
                        } else {
                            let date = new Date(accountData[key]);
                            if (date.toString() !== 'Invalid Date') {
                                result[key] = date;
                            }
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
                case 'imapServerInfo':
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
                case 'syncFrom':
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
                    } else if (accountData[key] === null) {
                        result[key] = 'null';
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
                case 'unset':
                    err = new Error('Syncing is disabled for the requested account');
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
            .hsetnx(this.getAccountKey(), `state:count:connected`, '0')
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

            .del(`${REDIS_PREFIX}tpl:${this.account}:i`) // stored templates index
            .del(`${REDIS_PREFIX}tpl:${this.account}:c`) // stored templates index

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
            this.logger.error({ msg: 'Failed to add entry to documents queue', err });
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

    async getMailboxListing(query) {
        let accountData = await this.loadAccountData(this.account, false);

        let mailboxListing;
        if (accountData.state === 'connected' || query.counters) {
            // run LIST
            mailboxListing = await this.listMailboxes(query);
        } else if (accountData.state === 'unset') {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Syncing is disabled for the requested account'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            throw error;
        } else if (accountData.state === 'init' || !(await this.redis.exists(this.getMailboxListKey()))) {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Requested account is not yet initialized'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            throw error;
        }

        let mailboxes = [];
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());

        for (let path of Object.keys(storedListing || {})) {
            try {
                let decoded = msgpack.decode(storedListing[path]);

                if (decoded.path && decoded.delimiter && decoded.path.indexOf(decoded.delimiter) >= 0) {
                    decoded.parentPath = decoded.path.substr(0, decoded.path.lastIndexOf(decoded.delimiter));
                }

                let listedMailboxInfo;
                if (mailboxListing) {
                    listedMailboxInfo = mailboxListing.find(entry => entry.path === path);
                    if (listedMailboxInfo && listedMailboxInfo.status) {
                        delete listedMailboxInfo.status.path;
                    }
                }

                mailboxes.push(
                    Object.assign(
                        decoded,
                        await this.getMailboxInfo(path),
                        listedMailboxInfo && listedMailboxInfo.status
                            ? {
                                  status: listedMailboxInfo.status
                              }
                            : {}
                    )
                );
            } catch (err) {
                // should not happen
                this.logger.error({ msg: 'Failed to process stored mailbox listing', path, err });
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

    async updateMessages(path, search, updates) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'updateMessages', account: this.account, path, search, updates });
    }

    async listMailboxes(query) {
        await this.loadAccountData(this.account, true);

        let options = {};
        if (query && query.counters) {
            options.statusQuery = {
                messages: true,
                unseen: true
            };
        }

        return await this.call({ cmd: 'listMailboxes', account: this.account, options });
    }

    async moveMessage(message, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'moveMessage', account: this.account, message, target });
    }

    async moveMessages(source, search, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({ cmd: 'moveMessages', account: this.account, source, search, target });
    }

    async deleteMessage(message, force) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'deleteMessage', account: this.account, message, force });
    }

    async deleteMessages(path, search, force) {
        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'deleteMessages', account: this.account, path, search, force });
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
        if (options.documentStore && (await settings.get('documentStoreEnabled'))) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            let buf = Buffer.from(text, 'base64url');
            let message = buf.subarray(0, 8).toString('base64url');

            let getResult = await client.get({
                index,
                id: `${this.account}:${message}`
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'get', index, id: `${this.account}:${message}` },
                results: getResult && getResult._source ? 1 : 0
            });

            if (!getResult || !getResult._source) {
                let message = 'Requested message was not found';
                let error = Boom.boomify(new Error(message), { statusCode: 404 });
                throw error;
            }

            let messageData = getResult._source;
            let response = {};

            response.hasMore = false;
            for (let textType of Object.keys(messageData.text || {})) {
                if (['plain', 'html'].includes(textType) && (options.textType === '*' || options.textType === textType)) {
                    if (options.maxBytes && messageData.text[textType].length > options.maxBytes) {
                        response[textType] = messageData.text[textType].substring(0, options.maxBytes);
                        response.hasMore = true;
                    } else {
                        response[textType] = messageData.text[textType];
                    }
                }
            }

            return response;
        }

        await this.loadAccountData(this.account, true);

        return await this.call({ cmd: 'getText', account: this.account, text, options });
    }

    async getMessage(message, options) {
        if (options.documentStore && (await settings.get('documentStoreEnabled'))) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            const reqOpts = {
                index,
                id: `${this.account}:${message}`,
                _source_excludes: 'preview,seemsLikeNew'
            };

            switch (options.textType) {
                case '*':
                    break;
                case 'html':
                    reqOpts._source_excludes = 'text.plain';
                    break;
                case 'plain':
                    reqOpts._source_excludes = 'text.html';
                    break;
                default:
                    reqOpts._source_excludes = 'text.plain,text.html';
            }

            let getResult = await client.get(reqOpts);

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'get', index, id: `${this.account}:${message}` },
                results: getResult && getResult._source ? 1 : 0
            });

            if (!getResult || !getResult._source) {
                let message = 'Requested message was not found';
                let error = Boom.boomify(new Error(message), { statusCode: 404 });
                throw error;
            }

            let messageData = getResult._source;

            // restore headers and text object as per the API response
            let headersObj = {};
            for (let { key, value } of messageData.headers) {
                headersObj[key] = value;
            }
            messageData.headers = headersObj;

            if (messageData.text && (messageData.text.html || messageData.text.plain)) {
                messageData.text.hasMore = false;

                for (let textType of Object.keys(messageData.text || {})) {
                    if (['plain', 'html'].includes(textType) && options.maxBytes && messageData.text[textType].length > options.maxBytes) {
                        messageData.text[textType] = messageData.text[textType].substring(0, options.maxBytes);
                        messageData.text.hasMore = true;
                    }
                }
            }

            for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                if (messageData[key] === false) {
                    delete messageData[key];
                }
            }

            for (let key of ['account', 'created', 'specialUse', 'seemsLikeNew']) {
                if (key in messageData) {
                    delete messageData[key];
                }
            }

            return messageData;
        }

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
        if (query.documentStore && (await settings.get('documentStoreEnabled'))) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            let inboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), 'INBOX');
            let delimiter;
            if (inboxData) {
                try {
                    inboxData = msgpack.decode(inboxData);
                    delimiter = inboxData.delimiter;
                } catch (err) {
                    delimiter = '/'; // hope for the best
                    inboxData = false;
                }
            }

            inboxData = inboxData || {
                path: 'INBOX',
                delimiter
            };

            inboxData.specialUse = inboxData.specialUse || '\\Inbox';

            let path = normalizePath(query.path, delimiter);
            let mailboxData = path === 'INBOX' ? inboxData : false;
            if (!mailboxData) {
                mailboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), path);
                if (mailboxData) {
                    try {
                        mailboxData = msgpack.decode(mailboxData);
                    } catch (err) {
                        mailboxData = false;
                    }
                }
            }

            let searchQuery = {
                bool: {
                    must: [
                        {
                            term: {
                                account: this.account
                            }
                        }
                    ]
                }
            };

            searchQuery.bool.must.push({
                bool: {
                    should: [
                        {
                            term: {
                                path
                            }
                        },
                        {
                            term: {
                                labels: mailboxData.specialUse || path
                            }
                        }
                    ],
                    minimum_should_match: 1
                }
            });

            let searchResult = await client.search({
                index,
                size: query.pageSize,
                from: query.pageSize * query.page,
                query: searchQuery,
                sort: { uid: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,seemsLikeNew'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'search', index, size: query.pageSize, from: query.pageSize * query.page, query: searchQuery, sort: { uid: 'desc' } },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page: query.page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / query.pageSize), 1),
                messages: searchResult.hits.hits.map(entry => {
                    let messageData = entry._source;

                    // normalize as per the API response

                    for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                        if (messageData[key] === false) {
                            messageData[key] = undefined;
                        }
                    }

                    for (let key of ['account', 'created', 'specialUse']) {
                        if (messageData[key]) {
                            messageData[key] = undefined;
                        }
                    }

                    return messageData;
                })
            };

            return response;
        }

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

    async searchMessages(query) {
        if (query.documentStore && (await settings.get('documentStoreEnabled'))) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            let searchQuery = {
                bool: {
                    must: [
                        {
                            term: {
                                account: this.account
                            }
                        }
                    ]
                }
            };

            if (query.path) {
                let inboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), 'INBOX');
                let delimiter;

                if (inboxData) {
                    try {
                        inboxData = msgpack.decode(inboxData);
                        delimiter = inboxData.delimiter;
                    } catch (err) {
                        delimiter = '/'; // hope for the best
                        inboxData = false;
                    }
                }

                inboxData = inboxData || {
                    path: 'INBOX',
                    delimiter
                };

                inboxData.specialUse = inboxData.specialUse || '\\Inbox';

                let path = normalizePath(query.path, delimiter);
                let mailboxData = path === 'INBOX' ? inboxData : false;
                if (!mailboxData) {
                    mailboxData = await this.redis.hgetBuffer(this.getMailboxListKey(), path);
                    if (mailboxData) {
                        try {
                            mailboxData = msgpack.decode(mailboxData);
                        } catch (err) {
                            mailboxData = false;
                        }
                    }
                }

                searchQuery.bool.must.push({
                    bool: {
                        should: [
                            {
                                term: {
                                    path
                                }
                            },
                            {
                                term: {
                                    labels: mailboxData.specialUse || path
                                }
                            }
                        ],
                        minimum_should_match: 1
                    }
                });
            }

            for (let key of ['answered', 'deleted', 'draft', 'unseen', 'flagged']) {
                if (typeof query.search[key] === 'boolean') {
                    searchQuery.bool.must.push({
                        term: {
                            [key]: query.search[key]
                        }
                    });
                }
            }

            if (typeof query.search.seen === 'boolean') {
                searchQuery.bool.must.push({
                    term: {
                        unseen: !query.search.seen
                    }
                });
            }

            for (let key of ['from', 'to', 'cc', 'bcc']) {
                if (query.search[key]) {
                    searchQuery.bool.must.push({
                        bool: {
                            should: [
                                {
                                    match: {
                                        [`${key}.name`]: {
                                            query: query.search[key],
                                            operator: 'and'
                                        }
                                    }
                                },
                                {
                                    term: {
                                        [`${key}.address`]: query.search[key]
                                    }
                                }
                            ],
                            minimum_should_match: 1
                        }
                    });
                }
            }

            if (query.search.uid) {
                let uidEntries = unpackUIDRangeForSearch(query.search.uid);
                if (uidEntries && uidEntries.length) {
                    let mustList = [];
                    for (let entry of uidEntries) {
                        if (typeof entry === 'number') {
                            mustList.push({
                                match: {
                                    uid: {
                                        query: entry,
                                        operator: 'and'
                                    }
                                }
                            });
                        } else if (typeof entry === 'object') {
                            mustList.push({
                                range: {
                                    uid: entry
                                }
                            });
                        }
                    }

                    if (mustList.length) {
                        searchQuery.bool.must.push({
                            bool: {
                                should: mustList,
                                minimum_should_match: 1
                            }
                        });
                    }
                }
            }

            for (let key of ['emailId', 'threadId']) {
                if (query.search[key]) {
                    searchQuery.bool.must.push({
                        term: {
                            key: query.search[key]
                        }
                    });
                }
            }

            if (query.search.subject) {
                searchQuery.bool.must.push({
                    match: {
                        subject: {
                            query: query.search.subject,
                            operator: 'and'
                        }
                    }
                });
            }

            if (query.search.body) {
                searchQuery.bool.must.push({
                    bool: {
                        should: [
                            {
                                match: {
                                    'text.plain': {
                                        query: query.search.body,
                                        operator: 'and'
                                    }
                                }
                            },
                            {
                                match: {
                                    'text.html': {
                                        query: query.search.body,
                                        operator: 'and'
                                    }
                                }
                            }
                        ],
                        minimum_should_match: 1
                    }
                });
            }

            let dateMatch = {};

            for (let key of ['before', 'sentBefore']) {
                if (query.search[key]) {
                    dateMatch.lte = query.search[key];
                }
            }

            for (let key of ['since', 'sentSince']) {
                if (query.search[key]) {
                    dateMatch.gte = query.search[key];
                }
            }

            if (Object.keys(dateMatch).length) {
                searchQuery.bool.must.push({
                    range: { date: dateMatch }
                });
            }

            let sizeMatch = {};

            if (query.search.larger) {
                dateMatch.gte = query.search.larger;
            }

            if (query.search.smaller) {
                dateMatch.lte = query.search.smaller;
            }

            if (Object.keys(sizeMatch).length) {
                searchQuery.bool.must.push({
                    range: { size: sizeMatch }
                });
            }

            // headers, nested query
            if (Object.keys(query.search.header || {}).length) {
                Object.keys(query.search.header).forEach(header => {
                    searchQuery.bool.must.push({
                        nested: {
                            path: 'headers',
                            query: {
                                bool: {
                                    must: [
                                        {
                                            term: {
                                                'headers.key': header.toLowerCase()
                                            }
                                        },
                                        {
                                            match: {
                                                'headers.value': {
                                                    query: (query.search.header[header] || '').toString(),
                                                    operator: 'and'
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    });
                });
            }

            if (query.documentQuery) {
                searchQuery.bool.must.push(query.documentQuery);
            }

            let searchResult = await client.search({
                index,
                size: query.pageSize,
                from: query.pageSize * query.page,
                query: searchQuery,
                sort: { uid: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,seemsLikeNew'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'search', index, size: query.pageSize, from: query.pageSize * query.page, query: searchQuery, sort: { uid: 'desc' } },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page: query.page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / query.pageSize), 1)
            };

            if (query.exposeQuery) {
                response.documentStoreQuery = query;
            }

            response.messages = searchResult.hits.hits.map(entry => {
                let messageData = entry._source;

                // normalize as per the API response

                for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                    if (messageData[key] === false) {
                        messageData[key] = undefined;
                    }
                }

                for (let key of ['account', 'created', 'specialUse']) {
                    if (messageData[key]) {
                        messageData[key] = undefined;
                    }
                }

                return messageData;
            });

            return response;
        }

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

    async uploadMessage(data) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call({ cmd: 'uploadMessage', account: this.account, data });
        return messageData;
    }

    async submitMessage(data) {
        await this.loadAccountData(this.account, false);

        let messageData = await this.call(
            {
                cmd: 'submitMessage',
                account: this.account,
                data,
                // extended wait period when sending emails
                timeout: 10 * 60 * 1000
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );

        return messageData;
    }

    async queueMessage(data, meta) {
        await this.loadAccountData(this.account, false);

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
