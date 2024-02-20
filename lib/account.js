'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('msgpack5')();
const { normalizePath, formatAccountListingResponse, unpackUIDRangeForSearch, mergeObjects, download } = require('./tools');
const crypto = require('crypto');
const { MessageChannel } = require('worker_threads');
const { MessagePortReadable } = require('./message-port-stream');
const { deepStrictEqual, strictEqual } = require('assert');
const { encrypt, decrypt } = require('./encrypt');
const { oauth2Apps, LEGACY_KEYS } = require('./oauth2-apps');
const settings = require('./settings');
const redisScanDelete = require('./redis-scan-delete');
const { customAlphabet } = require('nanoid');
const Lock = require('ioredfour');
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 16);
const { REDIS_PREFIX, ACCOUNT_DELETED } = require('./consts');
const { mimeHtml } = require('@postalsys/email-text-tools');

class Account {
    constructor(options) {
        this.redis = options.redis;
        this.account = options.account || false;

        this.documentsQueue = options.documentsQueue || false;

        this.secret = options.secret;

        this.timeout = options.timeout ? Number(options.timeout) : 0;

        this.esClient = options.esClient;

        this.call = options.call; // async method to request data from parent

        this.logger = options.logger || logger;
    }

    getLock() {
        if (!this.lock) {
            this.lock = new Lock({
                redis: this.redis,
                namespace: 'ee'
            });
        }
        return this.lock;
    }

    async listAccounts(state, query, page, limit) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        let result = await this.redis.sListAccounts(`${REDIS_PREFIX}ia:accounts`, state || '*', skip, limit, `${REDIS_PREFIX}`, query);

        let accounts = result[2].map(formatAccountListingResponse).map(this.unserializeAccountData.bind(this));
        let oauthApps = new Map();

        for (let accountData of accounts) {
            if (accountData.oauth2 && accountData.oauth2.provider) {
                let app;
                if (oauthApps.has(accountData.oauth2.provider)) {
                    app = oauthApps.get(accountData.oauth2.provider);
                } else {
                    app = await oauth2Apps.get(accountData.oauth2.provider);
                }
                oauthApps.set(accountData.oauth2.provider, app || null);
                if (app) {
                    accountData.type = app.provider;
                } else {
                    accountData.type = 'oauth2';
                }
            } else if (accountData.imap && !accountData.imap.disabled) {
                accountData.type = 'imap';
            } else {
                accountData.type = 'sending';
            }
        }

        let list = {
            total: result[0],
            pages: Math.ceil(result[0] / limit),
            page,
            query: query || false,
            state: state || '*',
            accounts: accounts.map(accountData => ({
                account: accountData.account,
                name: accountData.name,
                email: accountData.email,
                type: accountData.type,
                app:
                    accountData.oauth2 && accountData.oauth2.provider && accountData.oauth2.provider !== accountData.type
                        ? accountData.oauth2.provider
                        : undefined,
                state: accountData.state,

                webhooks: accountData.webhooks || undefined,
                proxy: accountData.proxy || undefined,
                smtpEhloName: accountData.smtpEhloName || undefined,

                counters: accountData.counters,

                syncTime: accountData.sync,
                lastError:
                    accountData.state === 'connected' || !accountData.lastErrorState || !Object.keys(accountData.lastErrorState).length
                        ? null
                        : accountData.lastErrorState
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
        const result = {};

        const counters = {};

        Object.keys(accountData).forEach(key => {
            let countMatch = key.match(/^stats:count:([^:]+):([^:]+)/);
            if (countMatch) {
                const [, type, counter] = countMatch;
                if (!counters[type]) {
                    counters[type] = {};
                }

                if (!counters[type][counter]) {
                    counters[type][counter] = 0;
                }

                counters[type][counter] = Number(accountData[key]);
                return;
            }

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

                // boolean values
                case 'copy':
                case 'logs':
                    if (accountData[key] && accountData[key] !== 'null') {
                        result[key] = accountData[key] === 'true' ? true : false;
                    }
                    break;

                case 'subconnections':
                    try {
                        let value = JSON.parse(accountData[key]);
                        if (value === null) {
                            break;
                        }
                        result[key] = value;
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to parse input from Redis', key, value: accountData[key], err });
                    }
                    break;

                case 'imap':
                case 'smtp':
                case 'imapServerInfo':
                case 'smtpServerEhlo':
                case 'oauth2':
                case 'lastErrorState':
                case 'smtpStatus':
                case 'webhookErrorFlag':
                    try {
                        let value = JSON.parse(accountData[key]);
                        if (value === null) {
                            break;
                        }
                        result[key] = value;
                        for (let subKey of ['created', 'expires']) {
                            if (result[key][subKey]) {
                                let dateVal = /^[0-9]+$/.test(result[key][subKey]) ? Number(result[key][subKey]) : result[key][subKey];
                                let date = new Date(dateVal);
                                if (date.toString() !== 'Invalid Date') {
                                    result[key][subKey] = date;
                                }
                            }
                        }
                        for (let subKey of Object.keys(result[key])) {
                            if (result[key][subKey] === null) {
                                delete result[key][subKey];
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

        result.counters = counters;

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

                case 'subconnections':
                    try {
                        result[key] = JSON.stringify(accountData[key]);
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to stringify input for Redis', key, err });
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

                case 'copy':
                case 'logs':
                    if (typeof accountData[key] === 'boolean') {
                        result[key] = accountData[key].toString();
                    } else if (accountData[key] === null) {
                        result[key] = '';
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
        if (requireValid && !['connected', 'connecting', 'syncing'].includes(accountData.state)) {
            let err;
            switch (accountData.state) {
                case 'init':
                    err = new Error('Requested account is not yet initialized');
                    err.code = 'NotYetConnected';
                    break;
                /*
                // Check disabled for the following states - allow commands to go through.
                // A secondary IMAP connection is opened if possible.
                */
                /*
                case 'connecting':
                case 'syncing':
                    err = new Error('Requested account is not yet connected');
                    err.code = 'NotYetConnected';
                    break;
                */
                case 'authenticationError':
                    err = new Error('Requested account can not be authenticated');
                    err.code = 'AuthenticationFails';
                    break;
                case 'connectError':
                    err = new Error('Can not establish server connection for requested account');
                    err.code = 'ConnectionError';
                    break;
                case 'unset':
                    err = new Error('Syncing is disabled for the requested account');
                    err.code = 'NotSyncing';
                    break;
                default:
                    err = new Error('Requested account currently not available');
                    err.code = 'NoAvailable';
                    break;
            }

            let error = Boom.boomify(err, { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            if (err.code) {
                error.output.payload.code = err.code;
            }
            throw error;
        }

        return accountData;
    }

    async update(accountData) {
        let oldAccountData = await this.loadAccountData(accountData.account);

        if (accountData.oauth2 && accountData.oauth2.provider) {
            // check if this OAuth2 provider exists
            let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                let message = 'Invalid or missing OAuth2 provider';
                let error = Boom.boomify(new Error(message), { statusCode: 400 });
                throw error;
            }
        }

        let removeProvider;
        let addProvider;

        if (accountData.oauth2 && accountData.oauth2.provider) {
            addProvider = accountData.oauth2.provider;
            if (oldAccountData.oauth2 && oldAccountData.oauth2.provider && oldAccountData.oauth2.provider !== accountData.oauth2.provider) {
                removeProvider = oldAccountData.oauth2.provider;
            }
        }

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

        let pipeline = this.redis.multi().hmset(this.getAccountKey(), this.serializeAccountData(accountData));

        if (addProvider && !LEGACY_KEYS.includes(addProvider)) {
            pipeline = pipeline.sadd(`${REDIS_PREFIX}oapp:a:${addProvider}`, this.account);
        }

        if (removeProvider) {
            pipeline = pipeline.srem(`${REDIS_PREFIX}oapp:a:${removeProvider}`, this.account);
        }

        let [[err, result]] = await pipeline.exec();
        if (err) {
            throw err;
        }

        if (!result || result !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        let reconnectRequested = false;

        if ('imap' in accountData && !reconnectRequested) {
            try {
                deepStrictEqual(oldAccountData.imap, accountData.imap);
            } catch (err) {
                // changes detected!
                reconnectRequested = true;
            }
        }

        if ('path' in accountData && !reconnectRequested) {
            try {
                strictEqual(oldAccountData.path || '*', accountData.path || '*');
            } catch (err) {
                // changes detected!
                reconnectRequested = true;
            }
        }

        if ('subconnections' in accountData && !reconnectRequested) {
            try {
                deepStrictEqual(oldAccountData.subconnections, accountData.subconnections);
            } catch (err) {
                // changes detected!
                reconnectRequested = true;
            }
        }

        if (reconnectRequested) {
            // changes detected!
            this.logger.info({ msg: 'IMAP configuration changed for account', account: this.account });
            await this.call({
                cmd: 'update',
                account: this.account,
                timeout: this.timeout
            });
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

        if (accountData.oauth2 && accountData.oauth2.provider) {
            // check if this OAuth2 provider exists
            let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                let message = 'Invalid or missing OAuth2 provider';
                let error = Boom.boomify(new Error(message), { statusCode: 400 });
                throw error;
            }
        }

        let pipeline = this.redis
            .multi()
            .hgetall(this.getAccountKey())
            .hmset(this.getAccountKey(), this.serializeAccountData(accountData))
            .hsetnx(this.getAccountKey(), 'state', 'init')
            .hsetnx(this.getAccountKey(), `state:count:connected`, '0')
            .sadd(`${REDIS_PREFIX}ia:accounts`, this.account);

        if (accountData.oauth2 && accountData.oauth2.provider) {
            pipeline = pipeline.sadd(`${REDIS_PREFIX}oapp:a:${accountData.oauth2.provider}`, this.account);
        }

        let result = await pipeline.exec();

        if (!result || !result[1] || result[1][0] || result[1][1] !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        let state = false;
        if (result[0][1] && result[0][1].account) {
            // existing user
            state = 'existing';
            await this.call({
                cmd: 'update',
                account: this.account,
                timeout: this.timeout
            });
        } else {
            state = 'new';
            await this.call({
                cmd: 'new',
                account: this.account,
                timeout: this.timeout
            });
        }

        return { account: this.account, state };
    }

    async delete() {
        let accountData = await this.loadAccountData(this.account);

        const dateKeyTdy = new Date().toISOString().substring(0, 10).replace(/-/g, '');
        const dateKeyYdy = new Date(Date.now() - 24 * 3600 * 1000).toISOString().substring(0, 10).replace(/-/g, '');

        const tombstoneTdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyTdy}`;
        const tombstoneYdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyYdy}`;

        let pipeline = this.redis
            .multi()
            .del(this.getAccountKey())
            .srem(`${REDIS_PREFIX}ia:accounts`, this.account)
            .del(`${REDIS_PREFIX}ial:${this.account}`) // mailbox list
            .del(`${REDIS_PREFIX}iah:${this.account}`) // mailbox list for ID references
            .del(`${REDIS_PREFIX}iar:b:${this.account}`) // bounce list
            .del(`${REDIS_PREFIX}iar:s:${this.account}`) // seen messages list
            .del(`${REDIS_PREFIX}iaq:${this.account}`) // delayed message queue
            .del(`${REDIS_PREFIX}iat:${this.account}`) // access tokens

            .del(tombstoneTdy)
            .del(tombstoneYdy)

            .del(`${REDIS_PREFIX}tpl:${this.account}:i`) // stored templates index
            .del(`${REDIS_PREFIX}tpl:${this.account}:c`); // stored templates index

        if (accountData.oauth2 && accountData.oauth2.provider) {
            pipeline = pipeline.srem(`${REDIS_PREFIX}oapp:a:${accountData.oauth2.provider}`, this.account);
        }

        let result = await pipeline.exec();

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

        await this.call({
            cmd: 'delete',
            account: this.account,
            timeout: this.timeout
        });

        return {
            account: this.account,
            deleted: true
        };
    }

    async getRawMessage(message) {
        await this.loadAccountData(this.account, true);

        const { port1, port2 } = new MessageChannel();
        const stream = new MessagePortReadable(port1);

        let streamCreated = await this.call(
            {
                cmd: 'getRawMessage',
                account: this.account,
                message,
                timeout: this.timeout,
                port: port2
            },
            [port2]
        );

        if (streamCreated && streamCreated.headers) {
            stream.headers = streamCreated.headers;
        }

        return stream;
    }

    async getAttachment(attachment) {
        await this.loadAccountData(this.account, true);

        const { port1, port2 } = new MessageChannel();
        const stream = new MessagePortReadable(port1);

        let streamCreated = await this.call(
            {
                cmd: 'getAttachment',
                account: this.account,
                attachment,
                timeout: this.timeout,
                port: port2
            },
            [port2]
        );

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
            if (mailboxListing && mailboxListing.error) {
                let error = Boom.boomify(new Error(mailboxListing.error), { statusCode: mailboxListing.statusCode || 500 });
                if (mailboxListing.code) {
                    error.output.payload.code = mailboxListing.code;
                }
                throw error;
            }
        } else if (accountData.state === 'unset') {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Syncing is disabled for the requested account'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            error.output.payload.code = 'NotSyncing';
            throw error;
        } else if (accountData.state === 'init' || !(await this.redis.exists(this.getMailboxListKey()))) {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Requested account is not yet initialized'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            error.output.payload.code = 'NotYetConnected';
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
                if (logger.notifyError) {
                    logger.notifyError(err, event => {
                        if (this.account) {
                            event.setUser(this.account);
                        }

                        event.addMetadata('ee', {
                            path,
                            mailboxListing: typeof mailboxListing
                        });
                    });
                }

                let message = 'Failed to process stored mailbox listing';
                this.logger.error({ msg: message, path, mailboxListing: typeof mailboxListing, account: this.account, err });
                let error = Boom.boomify(new Error(message), { statusCode: 503 });
                error.output.payload.code = err.code;
                throw error;
            }
        }

        return mailboxes;
    }

    async updateMessage(message, updates) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'updateMessage',
            account: this.account,
            message,
            updates,
            timeout: this.timeout
        });
    }

    async updateMessages(path, search, updates) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'updateMessages',
            account: this.account,
            path,
            search,
            updates,
            timeout: this.timeout
        });
    }

    async listMailboxes(query) {
        let options = {};
        if (query && query.counters) {
            options.statusQuery = {
                messages: true,
                unseen: true
            };
        }

        return await this.call({
            cmd: 'listMailboxes',
            account: this.account,
            options,
            timeout: this.timeout
        });
    }

    async moveMessage(message, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({
            cmd: 'moveMessage',
            account: this.account,
            message,
            target,
            timeout: this.timeout
        });
    }

    async moveMessages(source, search, target) {
        await this.loadAccountData(this.account, true);
        return await this.call({
            cmd: 'moveMessages',
            account: this.account,
            source,
            search,
            target,
            timeout: this.timeout
        });
    }

    async deleteMessage(message, force) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'deleteMessage',
            account: this.account,
            message,
            force,
            timeout: this.timeout
        });
    }

    async deleteMessages(path, search, force) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'deleteMessages',
            account: this.account,
            path,
            search,
            force,
            timeout: this.timeout
        });
    }

    async getQuota() {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'getQuota',
            account: this.account,
            timeout: this.timeout
        });
    }

    async createMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'createMailbox',
            account: this.account,
            path,
            timeout: this.timeout
        });
    }

    async renameMailbox(path, newPath) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'renameMailbox',
            account: this.account,
            path,
            newPath,
            timeout: this.timeout
        });
    }

    async deleteMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'deleteMailbox',
            account: this.account,
            path,
            timeout: this.timeout
        });
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

        return await this.call({
            cmd: 'getText',
            account: this.account,
            text,
            options,
            timeout: this.timeout
        });
    }

    async getMessage(message, options) {
        if (options.webSafeHtml) {
            options.textType = '*';
            options.embedAttachedImages = true;
            options.preProcessHtml = true;
        }

        if (options.documentStore && (await settings.get('documentStoreEnabled'))) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            const reqOpts = {
                index,
                id: `${this.account}:${message}`,
                _source_excludes: 'preview,seemsLikeNew,account,created,updateTime'
            };

            switch (options.textType) {
                case '*':
                    break;
                case 'html':
                    reqOpts._source_excludes += ',text.plain';
                    break;
                case 'plain':
                    reqOpts._source_excludes += ',text.html,text._generatedHtml';
                    break;
                default:
                    reqOpts._source_excludes += ',text.plain,text.html,text._generatedHtml';
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

            if (options.embedAttachedImages && messageData.text && messageData.text.html && messageData.attachments && messageData.attachments.length) {
                let attachmentsToDownload = [];

                // first pass, find attachments to inline
                messageData.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                    let attachment = messageData.attachments.find(attachment => [`<${cidMatch}>`, cidMatch].includes(attachment.contentId));
                    if (attachment && !attachment.content) {
                        attachmentsToDownload.push(attachment);
                    }
                });

                // download large inline attachments not stored in ES
                for (let attachment of attachmentsToDownload) {
                    try {
                        let downloadStream = await this.getAttachment(attachment.id);
                        if (downloadStream) {
                            let content = await download(downloadStream);
                            this.logger.trace({ msg: 'Fetched attachment content', account: this.account, attachment, size: content.length });
                            attachment.content = content.toString('base64');
                        }
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to fetch attachment content', account: this.account, attachment, err });
                    }
                }

                // second pass, replace placeholders with inline attachments
                messageData.text.html = messageData.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                    let attachment = messageData.attachments.find(attachment => [`<${cidMatch}>`, cidMatch].includes(attachment.contentId));
                    if (attachment && attachment.content) {
                        return `data:${attachment.contentType || 'application/octet-stream'};base64,${attachment.content}`;
                    }
                    return fullMatch;
                });
            }

            if (options.preProcessHtml && messageData.text && (messageData.text.html || messageData.text.plain)) {
                // If available, use the cached version
                messageData.text.html =
                    messageData.text._generatedHtml ||
                    mimeHtml({
                        html: messageData.text.html,
                        text: messageData.text.plain
                    });
                messageData.text.webSafe = true;
                messageData.text._cachedWebSafe = !!messageData.text._generatedHtml;
            }

            if (messageData.text && messageData.text._generatedHtml) {
                // remove cached pre-processed HTML from output
                delete messageData.text._generatedHtml;
            }

            // Add event file content if the attachment exists
            if (messageData.calendarEvents) {
                for (let calendarEvent of messageData.calendarEvents) {
                    if (!calendarEvent.content && calendarEvent.attachment) {
                        let attachment = messageData.attachments && messageData.attachments.find(attachment => attachment.id === calendarEvent.attachment);
                        if (attachment && attachment.content) {
                            calendarEvent.encoding = 'base64';
                            calendarEvent.content = attachment.content;
                        }
                    }
                }
            }

            if (messageData.attachments) {
                for (let attachment of messageData.attachments) {
                    delete attachment.content;
                }
            }

            if (options.markAsSeen && (!messageData.flags || !messageData.flags.includes('\\Seen'))) {
                // mark message as seen
                messageData.flags.push('\\Seen');
                // do not wait until the update is completed, return immediatelly
                this.updateMessage(message, { flags: { add: ['\\Seen'] } }).catch(err => {
                    this.logger.error({ msg: 'Failed to mark message as Seen', message, err });
                });
            }

            if (messageData.specialUse && !messageData.messageSpecialUse) {
                for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
                    if (messageData.specialUse === specialUseTag || (messageData.labels && messageData.labels.includes(specialUseTag))) {
                        messageData.messageSpecialUse = specialUseTag;
                        break;
                    }
                }
            }

            return messageData;
        }

        await this.loadAccountData(this.account, true);

        let messageData = await this.call({
            cmd: 'getMessage',
            account: this.account,
            message,
            options,
            timeout: this.timeout
        });
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
                                labels: (mailboxData && mailboxData.specialUse) || path
                            }
                        }
                    ],
                    minimum_should_match: 1
                }
            });

            let page = Number(query.page) || 0;
            let pageSize = Math.abs(Number(query.pageSize) || 20);

            if (page < 0) {
                page = 0;
            }

            let searchResult = await client.search({
                index,
                size: pageSize,
                from: pageSize * page,
                query: searchQuery,
                sort: { uid: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,text._generatedHtml,seemsLikeNew,attachments.content,summary,riskAssessment,updateTime'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'search', index, size: pageSize, from: pageSize * page, query: searchQuery, sort: { uid: 'desc' } },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / pageSize), 1),
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
        return await this.call(
            Object.assign(
                {
                    cmd: 'listMessages',
                    account: this.account
                },
                query,
                { timeout: this.timeout }
            )
        );
    }

    async searchMessages(query, searchOpts) {
        searchOpts = searchOpts || {};
        if (query.documentStore && (await settings.get('documentStoreEnabled'))) {
            if (!searchOpts.unified) {
                await this.loadAccountData(this.account, false);
            }

            const { index, client } = this.esClient;

            let searchQuery = {
                bool: {
                    must: []
                }
            };

            if (this.account) {
                searchQuery.bool.must.push({
                    term: {
                        account: this.account
                    }
                });
            }

            if (searchOpts.unified && query.accounts && query.accounts.length) {
                searchQuery.bool.must.push({
                    bool: {
                        should: query.accounts.map(account => ({
                            term: {
                                account
                            }
                        })),
                        minimum_should_match: 1
                    }
                });
            }

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
                                    labels: (mailboxData && mailboxData.specialUse) || path
                                }
                            }
                        ],
                        minimum_should_match: 1
                    }
                });
            }

            if (searchOpts.unified && query.paths && query.paths.length) {
                searchQuery.bool.must.push({
                    bool: {
                        should: query.paths.flatMap(path => {
                            let res = [
                                {
                                    term: {
                                        path
                                    }
                                },
                                {
                                    term: {
                                        labels: path
                                    }
                                },
                                {
                                    term: {
                                        messageSpecialUse: path
                                    }
                                }
                            ];

                            if (/^inbox$/i.test(path)) {
                                res.push({
                                    term: {
                                        messageSpecialUse: '\\Inbox'
                                    }
                                });
                            }

                            return res;
                        }),
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
                            [key]: query.search[key]
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

            let page = Number(query.page) || 0;
            let pageSize = Math.abs(Number(query.pageSize) || 20);

            if (page < 0) {
                page = 0;
            }

            let searchResult = await client.search({
                index,
                size: pageSize,
                from: pageSize * page,
                query: searchQuery,
                sort: { [!searchOpts.unified ? 'uid' : 'date']: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,text._generatedHtml,seemsLikeNew,attachments.content,summary,riskAssessment,updateTime'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'search', index, size: pageSize, from: pageSize * page, query: searchQuery, sort: { uid: 'desc' } },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / pageSize), 1)
            };

            if (query.exposeQuery) {
                response.documentStoreQuery = query;
            }

            if (query.accounts) {
                response.accounts = query.accounts;
            }

            if (query.paths) {
                response.paths = query.paths;
            }

            response.messages = searchResult.hits.hits.map(entry => {
                let messageData = entry._source;

                // normalize as per the API response

                for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                    if (messageData[key] === false) {
                        messageData[key] = undefined;
                    }
                }

                for (let key of ['created', 'specialUse'].concat(!searchOpts.unified ? 'account' : [])) {
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
        return await this.call(
            Object.assign(
                {
                    cmd: 'listMessages',
                    account: this.account
                },
                query,
                { timeout: this.timeout }
            )
        );
    }

    async uploadMessage(data) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call({
            cmd: 'uploadMessage',
            account: this.account,
            data,
            timeout: this.timeout
        });
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
                timeout: Math.max(this.timeout, 10 * 60 * 1000)
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
                meta,
                timeout: this.timeout
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );
        return messageData;
    }

    async requestReconnect(data) {
        await this.loadAccountData(this.account, true);

        if (data.reconnect) {
            await this.call({
                cmd: 'update',
                account: this.account,
                timeout: this.timeout
            });
            return true;
        }
        return false;
    }

    async requestSync(data) {
        await this.loadAccountData(this.account, true);

        if (data.sync) {
            await this.call({
                cmd: 'sync',
                account: this.account,
                timeout: this.timeout
            });
            return true;
        }
        return false;
    }

    async flush(data) {
        await this.loadAccountData(this.account, true);

        if (!data.flush) {
            return false;
        }

        // use a global lock to decrease Redis scanning operations
        let lockKey = ['flush' /*, this.account*/].join(':');

        let lock = this.getLock();
        let flushLock;

        try {
            flushLock = await lock.acquireLock(lockKey, 30 * 60 * 1000);
            if (!flushLock.success) {
                this.logger.error({ msg: 'Failed to get lock', lockKey });

                let error = Boom.boomify(new Error('One flush operation at a time allowed, try again later'), { statusCode: 429 });
                error.output.payload.code = 'LockFail';
                throw error;
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to get lock', lockKey, err });
            if (Boom.isBoom) {
                throw err;
            }
            let error = Boom.boomify(new Error('Failed to get flush lock, try again later'), { statusCode: 500 });
            if (err.code) {
                error.output.payload.code = err.code || 'LockFail';
            }
            throw error;
        }

        try {
            await this.call({
                cmd: 'pause',
                account: this.account,
                timeout: this.timeout
            });

            let notifyFrom = data.notifyFrom && data.notifyFrom !== 'now' ? data.notifyFrom : new Date();

            const dateKeyTdy = new Date().toISOString().substring(0, 10).replace(/-/g, '');
            const dateKeyYdy = new Date(Date.now() - 24 * 3600 * 1000).toISOString().substring(0, 10).replace(/-/g, '');

            const tombstoneTdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyTdy}`;
            const tombstoneYdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyYdy}`;

            try {
                let pipeline = this.redis
                    .multi()
                    // start syncing new messages from current time
                    .hset(this.getAccountKey(), 'notifyFrom', notifyFrom.toISOString())
                    // mark connection count to 0 to trigger `accountInitialized` event
                    .hset(this.getAccountKey(), `state:count:connected`, '0')
                    .del(`${REDIS_PREFIX}ial:${this.account}`) // mailbox list
                    .del(`${REDIS_PREFIX}iah:${this.account}`) // mailbox list for ID references
                    .del(`${REDIS_PREFIX}iar:b:${this.account}`) // bounce list
                    .del(`${REDIS_PREFIX}iar:s:${this.account}`) // seen messages list
                    .del(tombstoneTdy)
                    .del(tombstoneYdy);

                if (data.syncFrom || data.syncFrom === null) {
                    pipeline = pipeline.hset(this.getAccountKey(), 'syncFrom', data.syncFrom ? data.syncFrom.toISOString() : 'null');
                }

                await pipeline.exec();

                // scan and delete keys
                await redisScanDelete(this.redis, this.logger, `${REDIS_PREFIX}iam:${this.account}:*`);

                if (await settings.get('documentStoreEnabled')) {
                    // Flush ElasticSearch index for this account
                    const { index, client } = this.esClient;
                    if (!client) {
                        return;
                    }

                    let deleteResult = {};
                    let deletedCount = 0;

                    let filterQuery = {
                        match: {
                            account: this.account
                        }
                    };

                    for (let indexName of [index, `${index}.threads`, `${index}.embeddings`]) {
                        try {
                            deleteResult[indexName] = await client.deleteByQuery({
                                index: indexName,
                                query: filterQuery
                            });
                            deletedCount += deleteResult[indexName].deleted || 0;
                        } catch (err) {
                            logger.error({
                                msg: 'Failed to delete account emails from index',
                                action: 'flush',
                                code: 'document_delete_account_error',
                                index: indexName,
                                request: filterQuery,
                                err
                            });
                            if (indexName === index) {
                                throw err;
                            }
                        }
                    }

                    logger.trace({
                        msg: 'Deleted account emails from index',
                        action: 'flush',
                        code: 'document_delete_account',
                        deletedCount,
                        deleteResult
                    });
                }

                return true;
            } finally {
                let finalize = async () => {
                    // Wait a bit before resuming. Just to be sure all pending processes have been completed.
                    await new Promise(r => setTimeout(r, 5 * 1000));
                    await this.call({
                        cmd: 'resume',
                        account: this.account,
                        timeout: this.timeout
                    });
                };
                finalize().catch(err => {
                    this.logger.error({ msg: 'Failed to finish flushing', account: this.account, err });
                });
            }
        } finally {
            await lock.releaseLock(flushLock);
        }
    }

    async renewAccessToken(oauth2Opts) {
        let lockKey = ['oauth', this.account].join(':');

        let lock = this.getLock();
        let renewLock;

        try {
            renewLock = await lock.waitAcquireLock(lockKey, 5 * 60 * 1000, 1 * 60 * 1000);
            if (!renewLock.success) {
                this.logger.error({ msg: 'Failed to get lock', lockKey });
                throw new Error('Failed to get renewal lock');
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to get lock', lockKey, err });
            let error = Boom.boomify(new Error('Failed to get renewal lock'), { statusCode: 500 });
            if (err.code) {
                error.output.payload.code = err.code || 'LockFail';
            }
            throw error;
        }

        try {
            let accountData = await this.loadAccountData(this.account, false);

            // check if the token was already renewed
            if (
                accountData.oauth2 &&
                accountData.oauth2.accessToken &&
                accountData.oauth2.expires &&
                accountData.oauth2.expires > new Date(Date.now() + 30 * 1000)
            ) {
                this.logger.info({
                    msg: 'OAuth2 access token renewed while locked',
                    action: 'ensureAccessToken',
                    error: null,
                    user: accountData.oauth2.auth.user,
                    expires: accountData.oauth2.expires,
                    scopes: accountData.oauth2.scope,
                    oauth2App: accountData.oauth2.provider
                });
                return accountData;
            }

            const oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, oauth2Opts);

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

            this.logger.info({
                msg: 'Renewed OAuth2 access token',
                action: 'ensureAccessToken',
                error: null,
                user: accountData.oauth2.auth.user,
                expires: updates.expires,
                scopes: updates.scope,
                oauth2App: accountData.oauth2.provider
            });

            await this.update({ account: accountData.account, oauth2: accountData.oauth2 });

            return accountData;
        } catch (err) {
            this.logger.info({
                msg: 'Failed to renew OAuth2 access token',
                action: 'ensureAccessToken',
                error: err,
                response: err.tokenRequest && err.tokenRequest.response,
                flag: err.tokenRequest && err.tokenRequest.flag
            });
            throw err;
        } finally {
            await lock.releaseLock(renewLock);
        }
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

    async getActiveAccessTokenData() {
        // throws if account does not exist
        let accountData = await this.loadAccountData(this.account);
        if (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.user || !accountData.oauth2.provider) {
            let error = Boom.boomify(new Error('Not an OAuth2 account'), { statusCode: 403 });
            error.output.payload.code = 'AccountNotOAuth2';
            throw error;
        }

        let now = Date.now();
        let accessToken;
        let cached = false;
        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
            // renew access token
            try {
                accountData = await this.renewAccessToken();
                accessToken = accountData.oauth2.accessToken;
            } catch (err) {
                let error = Boom.boomify(err, { statusCode: 403 });
                error.output.payload.code = 'OauthRenewError';
                error.output.payload.authenticationFailed = true;
                if (err.tokenRequest) {
                    error.output.payload.tokenRequest = err.tokenRequest;
                }
                throw error;
            }
        } else {
            accessToken = accountData.oauth2.accessToken;
            cached = true;
        }

        return {
            account: accountData.account,
            user: accountData.oauth2.auth.user,
            accessToken,
            provider: accountData.oauth2.auth.provider,
            registeredScopes: accountData.oauth2.scope,
            expires:
                accountData.oauth2.expires && typeof accountData.oauth2.expires.toISOString === 'function'
                    ? accountData.oauth2.expires.toISOString()
                    : accountData.oauth2.expires,
            cached
        };
    }
}

module.exports = { Account };
