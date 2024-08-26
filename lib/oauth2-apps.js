'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const { encrypt, decrypt } = require('./encrypt');
const Boom = require('@hapi/boom');
const settings = require('./settings');
const Lock = require('ioredfour');

const { OutlookOauth, outlookScopes } = require('./oauth/outlook');
const { GmailOauth, GMAIL_SCOPES } = require('./oauth/gmail');
const { MailRuOauth, MAIL_RU_SCOPES } = require('./oauth/mail-ru');

const LEGACY_KEYS = ['gmail', 'gmailService', 'outlook', 'mailRu'];
const LEGACY_KEYS_REV = JSON.parse(JSON.stringify(LEGACY_KEYS)).reverse();

const OAUTH_PROVIDERS = {
    gmail: 'Gmail',
    gmailService: 'Gmail Service Accounts',
    outlook: 'Outlook',
    mailRu: 'Mail.ru'
};

const lock = new Lock({
    redis,
    namespace: 'ee'
});

function oauth2ProviderData(provider) {
    let caseName = provider.replace(/^./, c => c.toUpperCase());

    let providerData = {
        name: 'OAuth2',
        provider,
        caseName,
        comment: OAUTH_PROVIDERS[provider] || caseName
    };

    switch (provider) {
        case 'gmail':
            providerData.icon = 'fab fa-google';
            providerData.tutorialUrl = 'https://emailengine.app/gmail-over-imap';
            providerData.linkImage = '/static/providers/google_dark_edited.png';
            providerData.imap = {
                host: 'imap.gmail.com',
                port: 993,
                secure: true
            };
            providerData.smtp = {
                host: 'smtp.gmail.com',
                port: 465,
                secure: true
            };
            break;

        case 'gmailService':
            providerData.icon = 'fab fa-google';
            providerData.tutorialUrl = 'https://emailengine.app/google-service-accounts';
            providerData.imap = {
                host: 'imap.gmail.com',
                port: 993,
                secure: true
            };
            providerData.smtp = {
                host: 'smtp.gmail.com',
                port: 465,
                secure: true
            };
            break;

        case 'outlook':
            providerData.icon = 'fab fa-microsoft';
            providerData.tutorialUrl = 'https://emailengine.app/outlook-and-ms-365';
            providerData.linkImage = '/static/providers/ms_light.svg';
            providerData.imap = {
                host: 'outlook.office365.com',
                port: 993,
                secure: true
            };
            providerData.smtp = {
                host: 'smtp.office365.com',
                port: 587,
                secure: false
            };
            break;

        case 'mailRu':
            providerData.icon = 'fa fa-envelope';
            providerData.imap = {
                host: 'imap.mail.ru',
                port: 993,
                secure: true
            };
            providerData.smtp = {
                host: 'smtp.mail.ru',
                port: 465,
                secure: true
            };
            break;

        default:
            providerData.icon = 'fa fa-envelope';
    }

    return providerData;
}

function formatExtraScopes(extraScopes, baseScopes, defaultScopesList, skipScopes, scopePrefix) {
    let defaultScopes;

    skipScopes = [].concat(skipScopes || []);

    if (Array.isArray(defaultScopesList)) {
        defaultScopes = defaultScopesList;
    } else {
        defaultScopes = (baseScopes && defaultScopesList[baseScopes]) || defaultScopesList.imap;
    }

    let extras = [];
    if (!extraScopes && !skipScopes.length) {
        return defaultScopes;
    }

    for (let extraScope of extraScopes) {
        if (defaultScopes.includes(extraScope) || (scopePrefix && defaultScopes.includes(`${scopePrefix}/${extraScope}`))) {
            // skip existing
            continue;
        }
        extras.push(extraScope);
    }

    let result = extras.length ? extras.concat(defaultScopes) : defaultScopes;

    if (skipScopes.length) {
        result = result.filter(scope => {
            for (let skipScope of skipScopes) {
                if (scope === skipScope || scope === `https://outlook.office.com/${skipScope}` || scope === `https://graph.microsoft.com/${skipScope}`) {
                    return false;
                }
            }
            return true;
        });
    }

    return result;
}

class OAuth2AppsHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;
    }

    getIndexKey() {
        return `${REDIS_PREFIX}oapp:i`;
    }

    getDataKey() {
        return `${REDIS_PREFIX}oapp:c`;
    }

    getSubscribersKey() {
        return `${REDIS_PREFIX}oapp:sub`;
    }

    getPubsubAppKey(pubsubApp) {
        return `${REDIS_PREFIX}oapp:pub:${pubsubApp}`;
    }

    getSettingsKey() {
        return `${REDIS_PREFIX}settings`;
    }

    async list(page, pageSize, opts) {
        opts = opts || {};
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let keyFunc;
        if (opts.pubsub) {
            keyFunc = 'getSubscribersKey';
        } else {
            keyFunc = 'getIndexKey';
        }

        let idList = await this.redis.smembers(this[keyFunc]());
        idList = [].concat(idList || []).sort((a, b) => -a.localeCompare(b));

        if (!opts.pubsub) {
            for (let legacyKey of LEGACY_KEYS_REV) {
                if (await settings.get(`${legacyKey}Enabled`)) {
                    idList.unshift(legacyKey);
                } else if (await settings.get(`${legacyKey}Client`)) {
                    idList.unshift(legacyKey);
                } else if (await settings.get(`${legacyKey}ClientId`)) {
                    idList.unshift(legacyKey);
                }
            }
        }

        let response = {
            total: idList.length,
            pages: Math.ceil(idList.length / pageSize),
            page,
            apps: []
        };

        if (idList.length <= startPos) {
            return response;
        }

        let keys = idList.slice(startPos, startPos + pageSize);

        let legacyKeys = keys.filter(key => LEGACY_KEYS.includes(key));
        keys = keys.filter(key => !LEGACY_KEYS.includes(key));

        for (let legacyKey of legacyKeys) {
            try {
                let data = await this.get(legacyKey);
                response.apps.push(data);
            } catch (err) {
                logger.error({ msg: 'Failed to process legacy app', legacyKey });
                continue;
            }
        }

        if (keys.length) {
            let bufKeys = keys.flatMap(id => [`${id}:data`, `${id}:meta`]);
            let list = await this.redis.hmgetBuffer(this.getDataKey(), bufKeys);
            for (let i = 0; i < list.length; i++) {
                let entry = list[i];
                try {
                    if (i % 2 === 0) {
                        let data = msgpack.decode(entry);
                        response.apps.push(data);
                    } else if (entry) {
                        response.apps[response.apps.length - 1].meta = msgpack.decode(entry);
                    }
                } catch (err) {
                    logger.error({ msg: 'Failed to process app', entry: entry.toString('base64') });
                    continue;
                }
            }
        }

        response.apps.forEach(app => {
            app.includeInListing = !!app.enabled;
            if (['gmailService'].includes(app.provider)) {
                // service accounts are always enabled
                app.enabled = true;
                app.includeInListing = false;
            }
        });

        return response;
    }

    async generateId() {
        let idNum = await this.redis.hincrby(this.getSettingsKey(), 'idcount', 1);

        let idBuf = Buffer.alloc(8 + 4);
        idBuf.writeBigUInt64BE(BigInt(Date.now()), 0);
        idBuf.writeUInt32BE(idNum, 8);

        const id = idBuf.toString('base64url');

        return id;
    }

    async getLegacyApp(id) {
        let extraScopes = await settings.get(`${id}ExtraScopes`);
        if (!Array.isArray(extraScopes)) {
            extraScopes = (extraScopes || '').toString().split(/[\s,]+/);
        }
        extraScopes = extraScopes.filter(entry => entry);

        let skipScopes = await settings.get(`${id}SkipScopes`);
        if (!Array.isArray(skipScopes)) {
            skipScopes = (skipScopes || '').toString().split(/[\s,]+/);
        }
        skipScopes = skipScopes.filter(entry => entry);

        switch (id) {
            case 'gmail': {
                let appData = {
                    id: 'gmail',
                    provider: 'gmail',
                    legacy: true,
                    enabled: await settings.get(`${id}Enabled`),
                    clientId: await settings.get(`${id}ClientId`),
                    clientSecret: await settings.get(`${id}ClientSecret`),
                    redirectUrl: await settings.get(`${id}RedirectUrl`),
                    extraScopes,
                    skipScopes,

                    name: 'Gmail',
                    description: 'Legacy OAuth2 app',

                    meta: {
                        authFlag: await settings.get(`${id}AuthFlag`)
                    }
                };
                return appData;
            }

            case 'gmailService': {
                let appData = {
                    id: 'gmailService',
                    provider: 'gmailService',
                    legacy: true,
                    serviceClient: await settings.get(`${id}Client`),
                    serviceKey: await settings.get(`${id}Key`),
                    extraScopes,
                    skipScopes,

                    name: 'Gmail service',
                    description: 'Legacy OAuth2 app',

                    meta: {
                        authFlag: await settings.get(`${id}AuthFlag`)
                    },

                    enabled: true
                };
                return appData;
            }

            case 'outlook': {
                let appData = {
                    id: 'outlook',
                    provider: 'outlook',
                    legacy: true,
                    enabled: await settings.get(`${id}Enabled`),
                    authority: await settings.get(`${id}Authority`),
                    clientId: await settings.get(`${id}ClientId`),
                    clientSecret: await settings.get(`${id}ClientSecret`),
                    redirectUrl: await settings.get(`${id}RedirectUrl`),
                    extraScopes,
                    skipScopes,

                    name: 'Outlook',
                    description: 'Legacy OAuth2 app',

                    meta: {
                        authFlag: await settings.get(`${id}AuthFlag`)
                    }
                };
                return appData;
            }

            case 'mailRu': {
                let appData = {
                    id: 'mailRu',
                    provider: 'mailRu',
                    legacy: true,
                    enabled: await settings.get(`${id}Enabled`),
                    clientId: await settings.get(`${id}ClientId`),
                    clientSecret: await settings.get(`${id}ClientSecret`),
                    redirectUrl: await settings.get(`${id}RedirectUrl`),
                    extraScopes,
                    skipScopes,

                    name: 'Mail.ru',
                    description: 'Legacy OAuth2 app',

                    meta: {
                        authFlag: await settings.get(`${id}AuthFlag`)
                    }
                };
                return appData;
            }

            default:
                return false;
        }
    }

    async updateLegacyApp(id, updates) {
        updates = updates || {};

        let data = {};

        switch (id) {
            case 'gmail':
                for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'extraScopes', 'skipScopes']) {
                    if (typeof updates[key] !== 'undefined') {
                        data[`${id}${key.replace(/^./, c => c.toUpperCase())}`] = updates[key];
                    }
                }
                break;

            case 'gmailService':
                for (let key of ['serviceClient', 'serviceKey', 'extraScopes', 'skipScopes']) {
                    if (typeof updates[key] !== 'undefined') {
                        let dataKey;
                        switch (key) {
                            case 'extraScopes':
                                dataKey = 'gmailServiceExtraScopes';
                                break;
                            case 'skipScopes':
                                dataKey = 'gmailServiceSkipScopes';
                                break;
                            default:
                                dataKey = `gmail${key.replace(/^./, c => c.toUpperCase())}`;
                        }
                        data[dataKey] = updates[key];
                    }
                }
                break;

            case 'outlook':
                for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'authority', 'extraScopes', 'skipScopes']) {
                    if (typeof updates[key] !== 'undefined') {
                        data[`${id}${key.replace(/^./, c => c.toUpperCase())}`] = updates[key];
                    }
                }

                break;

            case 'mailRu':
                for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'extraScopes', 'skipScopes']) {
                    if (typeof updates[key] !== 'undefined') {
                        data[`${id}${key.replace(/^./, c => c.toUpperCase())}`] = updates[key];
                    }
                }

                break;
        }

        for (let key of Object.keys(data)) {
            await settings.set(key, data[key]);
        }

        // clear alert flag if set
        await settings.clear(`${id}AuthFlag`);

        return {
            id,
            updated: true,
            legacy: true
        };
    }

    async delLegacyApp(id) {
        let pipeline = redis.multi();
        for (let key of ['Enabled', 'RedirectUrl', 'Client', 'ClientId', 'ClientSecret', 'Authority', 'ExtraScopes', 'SkipScopes', 'Key', 'AuthFlag']) {
            pipeline = pipeline.hdel(`${REDIS_PREFIX}settings`, `${id}${key}`);
        }
        await pipeline.exec();

        return {
            id,
            deleted: true,
            legacy: true
        };
    }

    async get(id) {
        if (LEGACY_KEYS.includes(id)) {
            // legacy
            let data = await this.getLegacyApp(id);
            data.includeInListing = !!data.enabled;
            if (['gmailService'].includes(data.provider)) {
                // service account are always enabled
                data.enabled = true;
                data.includeInListing = false;
            }
            return data;
        }

        let [getDataBuf, getMetaBuf] = await this.redis.hmgetBuffer(this.getDataKey(), [`${id}:data`, `${id}:meta`]);
        if (!getDataBuf) {
            return false;
        }

        let data;
        try {
            data = msgpack.decode(getDataBuf);
        } catch (err) {
            logger.error({ msg: 'Failed to process app', app: id, entry: getDataBuf.toString('base64') });
            throw err;
        }

        if (getMetaBuf) {
            try {
                data = Object.assign(data, { meta: msgpack.decode(getMetaBuf) });
            } catch (err) {
                logger.error({ msg: 'Failed to process app', app: id, entry: getMetaBuf.toString('base64') });
            }
        }

        data.includeInListing = !!data.enabled;
        if (['gmailService'].includes(data.provider)) {
            // service account are always enabled
            data.enabled = true;
            data.includeInListing = false;
        }

        data.accounts = await this.redis.scard(`${REDIS_PREFIX}oapp:a:${id}`);

        return data;
    }

    async create(data) {
        const id = await this.generateId();

        let encryptedValues = {};
        for (let key of ['clientSecret', 'serviceKey', 'accessToken']) {
            if (data[key]) {
                encryptedValues[key] = await encrypt(data[key]);
            }
        }

        let entry = Object.assign({ id: null }, data || {}, encryptedValues, {
            id,
            created: new Date().toISOString()
        });

        let insertResultReq = this.redis
            .multi()
            .sadd(this.getIndexKey(), id)
            .hmset(this.getDataKey(), {
                [`${id}:data`]: msgpack.encode(entry)
            });

        if (data.pubSubSubscription) {
            insertResultReq = insertResultReq.sadd(this.getSubscribersKey(), id);
        }

        if (data.pubSubApp) {
            insertResultReq = insertResultReq.sadd(this.getPubsubAppKey(data.pubSubApp), id);
        }

        let insertResult = await insertResultReq.exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        const result = {
            id,
            created: true
        };

        try {
            let appData = await this.get(id);
            if (appData.baseScopes === 'pubsub') {
                let pubsubUpdates = await this.ensurePubsub(appData);
                if (Object.keys(pubsubUpdates || {})) {
                    result.pubsubUpdates = pubsubUpdates;
                }
            }
        } catch (err) {
            logger.error({ msg: 'Failed to set up pubsub', app: id, err });
        }

        return result;
    }

    async update(id, data, opts) {
        opts = opts || {};
        if (LEGACY_KEYS.includes(id)) {
            // legacy
            return await this.updateLegacyApp(id, data);
        }

        let existingDataBuf = await this.redis.hgetBuffer(this.getDataKey(), `${id}:data`);
        if (!existingDataBuf) {
            let err = new Error('Document was not found');
            err.code = 'NotFound';
            err.statusCode = 404;
            throw err;
        }

        let existingData = msgpack.decode(existingDataBuf);

        let encryptedValues = {};
        for (let key of ['clientSecret', 'serviceKey', 'accessToken']) {
            if (data[key]) {
                encryptedValues[key] = await encrypt(data[key]);
            }
        }

        let entry = Object.assign(existingData, data || {}, encryptedValues, {
            id: existingData.id,
            created: existingData.created,
            updated: new Date().toISOString()
        });

        let updates = {
            [`${id}:data`]: msgpack.encode(entry)
        };

        let insertResultReq = this.redis.multi().sadd(this.getIndexKey(), id).hmset(this.getDataKey(), updates);

        if (data.pubSubSubscription) {
            insertResultReq = insertResultReq.sadd(this.getSubscribersKey(), id);
        }

        if (data.pubSubApp) {
            if (existingData.pubSubApp && existingData.pubSubApp !== data.pubSubApp) {
                insertResultReq = insertResultReq.srem(this.getPubsubAppKey(existingData.pubSubApp), id);
            }
            insertResultReq = insertResultReq.sadd(this.getPubsubAppKey(data.pubSubApp), id);
        }

        let insertResult = await insertResultReq.exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        if (opts.partial) {
            return {
                id,
                updated: true
            };
        }

        // clear auth flag
        await this.setMeta(id, { authFlag: null });

        const result = {
            id,
            updated: true
        };

        try {
            let appData = await this.get(id);
            if (appData.baseScopes === 'pubsub') {
                let pubsubUpdates = await this.ensurePubsub(appData);
                if (Object.keys(pubsubUpdates || {})) {
                    result.pubsubUpdates = pubsubUpdates;
                }
            }
        } catch (err) {
            logger.error({ msg: 'Failed to set up pubsub', app: id, err });
        }

        return result;
    }

    async del(id) {
        if (LEGACY_KEYS.includes(id)) {
            // legacy
            return await this.delLegacyApp(id);
        }

        let appData = await this.get(id);

        if (appData.pubSubTopic) {
            // try to delete topic
            try {
                await this.deleteTopic(appData);
            } catch (err) {
                logger.error({ msg: 'Failed to delete existing pubsub topic', app: appData.id, topic: appData.pubSubTopic, err });
            }
        }

        let pipeline = this.redis
            .multi()
            .srem(this.getIndexKey(), id)
            .hdel(this.getDataKey(), [`${id}:data`, `${id}:meta`])
            .scard(`${REDIS_PREFIX}oapp:a:${id}`)
            .del(`${REDIS_PREFIX}oapp:a:${id}`)
            .del(`${REDIS_PREFIX}oapp:h:${id}`)
            .srem(this.getSubscribersKey(), id);

        if (appData.pubsubApp) {
            pipeline = pipeline.srem(this.getPubsubAppKey(appData.pubSubApp), id);
        }

        let deleteResult = await pipeline.exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        let deletedDocs = ((deleteResult[0] && deleteResult[0][1]) || 0) + ((deleteResult[1] && deleteResult[1][1]) || 0);

        return {
            id,
            deleted: deletedDocs >= 2,
            accounts: Number(deleteResult[2] && deleteResult[2][1]) || 0
        };
    }

    async setMeta(id, meta) {
        let existingMeta;
        let existingMetaBuf = await this.redis.hgetBuffer(this.getDataKey(), `${id}:meta`);
        if (!existingMetaBuf) {
            existingMeta = {};
        } else {
            existingMeta = msgpack.decode(existingMetaBuf);
        }

        let entry = Object.assign(existingMeta, meta || {});

        let updates = {
            [`${id}:meta`]: msgpack.encode(entry)
        };

        await this.redis.hmset(this.getDataKey(), updates);

        return {
            id,
            updated: true
        };
    }

    async deleteTopic(appData) {
        let topicName = appData.pubSubTopic;
        let topicUrl = `https://pubsub.googleapis.com/v1/${topicName}`;

        let subscriptionName = appData.pubSubSubscription;
        let subscriptionUrl = `https://pubsub.googleapis.com/v1/${subscriptionName}`;

        let client = await this.getClient(appData.id);

        // Step 1. Get access token for service client
        let accessToken = await this.getServiceAccessToken(appData, client);
        if (!accessToken) {
            throw new Error('Failed to get access token');
        }

        try {
            if (topicName) {
                // fails if topic does not exist
                await client.request(accessToken, topicUrl, 'DELETE', Buffer.alloc(0), { returnText: true });
                /*
                {}
            */
            }
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403:
                    // no permissions
                    logger.error({
                        msg: 'Service client does not have permissions to delete Pub/Sub topics. Make sure the role for the service user is "Pub/Sub Admin".',
                        app: appData.id,
                        topic: topicName
                    });
                    throw err;
                case 404: {
                    // does not exist
                    logger.info({ msg: 'Topic does not exist', app: appData.id, topic: topicName });
                    break;
                }
                default:
                    throw err;
            }
        }

        try {
            if (subscriptionName) {
                // fails if subscription does not exist
                await client.request(accessToken, subscriptionUrl, 'DELETE', Buffer.alloc(0), { returnText: true });
                /*
                {}
            */
            }
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403:
                    // no permissions
                    logger.error({
                        msg: 'Service client does not have permissions to delete Pub/Sub subscriptions. Make sure the role for the service user is "Pub/Sub Admin".',
                        app: appData.id,
                        topic: topicName
                    });
                    throw err;
                case 404: {
                    // does not exist
                    logger.info({ msg: 'Subscription does not exist', app: appData.id, topic: topicName });
                    break;
                }
                default:
                    throw err;
            }
        }
    }

    async ensurePubsub(appData) {
        let project = appData.googleProjectId;
        let topic = `ee-pub-${appData.id}`;

        let subscription = `ee-sub-${appData.id}`;

        let results = {};

        if (!project || !topic) {
            return results;
        }

        let topicName = `projects/${project}/topics/${topic}`;
        let subscriptionName = `projects/${project}/subscriptions/${subscription}`;

        let topicUrl = `https://pubsub.googleapis.com/v1/${topicName}`;
        let subscriptionUrl = `https://pubsub.googleapis.com/v1/${subscriptionName}`;

        const member = 'serviceAccount:gmail-api-push@system.gserviceaccount.com';
        const role = 'roles/pubsub.publisher';

        let client = await this.getClient(appData.id);

        // Step 1. Get access token for service client
        let accessToken = await this.getServiceAccessToken(appData, client);
        if (!accessToken) {
            throw new Error('Failed to get access token');
        }

        // Step 2. Ensure topic
        try {
            // fails if topic does not exist
            await client.request(accessToken, topicUrl, 'GET');
            logger.debug({ msg: 'Topic already exists', app: appData.id, topic: topicName });
            /*
                {name: 'projects/...'}
            */
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403:
                    // no permissions
                    this.setMeta(appData.id, {
                        authFlag: {
                            message:
                                'Service client does not have permissions to view Pub/Sub topics. Make sure the role for the service user is "Pub/Sub Admin".'
                        }
                    });
                    throw err;
                case 404: {
                    // does not exist
                    logger.info({ msg: 'Topic does not exist', app: appData.id, topic: topicName });
                    try {
                        let topicCreateRes = await client.request(accessToken, topicUrl, 'PUT', Buffer.alloc(0));
                        /*
                            {name: 'projects/...'}
                        */
                        if (!topicCreateRes?.name) {
                            throw new Error('Topic was not created');
                        }

                        await this.update(
                            appData.id,
                            {
                                pubSubTopic: topicName
                            },
                            { partial: true }
                        );

                        results.pubSubTopic = topicName;
                    } catch (err) {
                        switch (err?.oauthRequest?.response?.error?.code) {
                            case 403:
                                // no permissions
                                this.setMeta(appData.id, {
                                    authFlag: {
                                        message:
                                            'Service client does not have permissions to modify Pub/Sub topics. Make sure the role for the service user is "Pub/Sub Admin".'
                                    }
                                });
                                throw err;
                            case 409:
                                // already exists
                                logger.info({ msg: 'Topic already exists', app: appData.id, topic: topicName });
                                break;
                            default:
                                throw err;
                        }
                    }
                    break;
                }
                default:
                    throw err;
            }
        }

        // Step 3. Set up subscriber

        try {
            // fails if topic does not exist
            await client.request(accessToken, subscriptionUrl, 'GET');
            logger.debug({ msg: 'Subscription already exists', app: appData.id, subscription: subscriptionName });
            /*
                {name: 'projects/...'}
            */
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403:
                    // no permissions
                    this.setMeta(appData.id, {
                        authFlag: {
                            message:
                                'Service client does not have permissions to view Pub/Sub subscriptions. Make sure the role for the service user is "Pub/Sub Admin".'
                        }
                    });
                    throw err;
                case 404: {
                    // does not exist
                    logger.info({ msg: 'Subscription does not exist', app: appData.id, subscription: subscriptionName });
                    try {
                        let subscriptionCreateRes = await client.request(accessToken, subscriptionUrl, 'PUT', {
                            topic: topicName,
                            ackDeadlineSeconds: 30
                        });
                        console.log('TOPIC RES', subscriptionCreateRes);
                        /*
                            {
                            name: 'projects/webhooks-425411/subscriptions/ee-sub-AAABkE9_uNMAAAAH',
                            topic: 'projects/webhooks-425411/topics/ee-pub-AAABkE9_uNMAAAAH',
                            pushConfig: {},
                            ackDeadlineSeconds: 10,
                            messageRetentionDuration: '604800s',
                            expirationPolicy: { ttl: '2678400s' },
                            state: 'ACTIVE'
                            }
                        */

                        if (!subscriptionCreateRes?.name) {
                            throw new Error('Topic was not created');
                        }

                        await this.update(
                            appData.id,
                            {
                                pubSubSubscription: subscriptionName
                            },
                            { partial: true }
                        );

                        results.pubSubSubscription = subscriptionName;
                    } catch (err) {
                        switch (err?.oauthRequest?.response?.error?.code) {
                            case 403:
                                // no permissions
                                this.setMeta(appData.id, {
                                    authFlag: {
                                        message:
                                            'Service client does not have permissions to modify Pub/Sub subscriptions. Make sure the role for the service user is "Pub/Sub Admin".'
                                    }
                                });
                                throw err;
                            case 409:
                                // already exists
                                logger.info({ msg: 'Subscription already exists', app: appData.id, subscription: subscriptionName });
                                break;
                            default:
                                throw err;
                        }
                    }
                    break;
                }
                default:
                    throw err;
            }
        }

        // Step 4. Grant access to Gmail publisher

        let existingPolicy;
        try {
            // Check for an existing policy grant
            let getIamPolycyRes = await client.request(accessToken, `${topicUrl}:getIamPolicy`, 'GET');
            existingPolicy = getIamPolycyRes?.bindings?.find(binding => binding?.role === role && binding?.members?.includes(member));
            /*
                {
                version: 1,
                etag: 'BwYbtWmb5c0=',
                bindings: [
                    {
                    role: 'roles/pubsub.publisher',
                    members: [ 'serviceAccount:gmail-api-push@system.gserviceaccount.com' ]
                    }
                ]
                }
            */
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403:
                    // no permissions
                    this.setMeta(appData.id, {
                        authFlag: {
                            message:
                                'Service client does not have permissions to modify Pub/Sub policies. Make sure the role for the service user is "Pub/Sub Admin".'
                        }
                    });
                    throw err;
                default:
                    throw err;
            }
        }

        if (existingPolicy) {
            logger.debug({ msg: 'Gmail publisher policy already exists', app: appData.id, topic: topicName });
        } else {
            logger.debug({ msg: 'Granting access to Gmail publisher', app: appData.id, topic: topicName });
            const policyPayload = {
                policy: {
                    bindings: [
                        {
                            members: [member],
                            role
                        }
                    ]
                }
            };
            try {
                await client.request(accessToken, `${topicUrl}:setIamPolicy`, 'POST', policyPayload);
                results.iamPolicy = {
                    members: [member],
                    role
                };

                await this.update(
                    appData.id,
                    {
                        pubSubIamPolicy: results.iamPolicy
                    },
                    { partial: true }
                );
            } catch (err) {
                switch (err?.oauthRequest?.response?.error?.code) {
                    case 403:
                        // no permissions
                        this.setMeta(appData.id, {
                            authFlag: {
                                message:
                                    'Service client does not have permissions to modify Pub/Sub policies. Make sure the role for the service user is "Pub/Sub Admin".'
                            }
                        });
                        throw err;
                    default:
                        throw err;
                }
            }
        }

        // clear auth flag if everything worked
        await this.setMeta(appData.id, { authFlag: null });

        return results;
    }

    async getClient(id, extraOpts) {
        extraOpts = extraOpts || {};

        let appData = await this.get(id);
        if (!appData) {
            let error = Boom.boomify(new Error('Missing or disabled OAuth2 app'), { statusCode: 404 });
            throw error;
        }

        switch (appData.provider) {
            case 'gmail': {
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;
                let scopes = formatExtraScopes(appData.extraScopes, appData.baseScopes, GMAIL_SCOPES, appData.skipScopes);

                if (!clientId || !clientSecret || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                    throw error;
                }

                return new GmailOauth(
                    Object.assign(
                        {
                            clientId,
                            clientSecret,
                            redirectUrl,
                            scopes,
                            setFlag: async flag => {
                                try {
                                    if (appData.legacy) {
                                        await settings.set('gmailAuthFlag', flag);
                                    } else {
                                        await this.setMeta(id, { authFlag: flag });
                                    }
                                } catch (err) {
                                    // ignore
                                }
                            }
                        },
                        extraOpts
                    )
                );
            }

            case 'gmailService': {
                let serviceClient = appData.serviceClient;
                let googleProjectId = appData.projectIdv;
                let serviceClientEmail = appData.serviceClientEmail;
                let serviceKey = appData.serviceKey ? await decrypt(appData.serviceKey) : null;

                let scopes = formatExtraScopes(appData.extraScopes, appData.baseScopes, GMAIL_SCOPES, appData.skipScopes);

                if (!serviceClient || !serviceKey) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                    throw error;
                }

                return new GmailOauth(
                    Object.assign(
                        {
                            serviceClient,
                            serviceKey,
                            googleProjectId,
                            serviceClientEmail,
                            scopes,
                            setFlag: async flag => {
                                try {
                                    if (appData.legacy) {
                                        await settings.set('gmailServiceAuthFlag', flag);
                                    } else {
                                        await this.setMeta(id, { authFlag: flag });
                                    }
                                } catch (err) {
                                    // ignore
                                }
                            }
                        },
                        extraOpts
                    )
                );
            }

            case 'outlook': {
                let authority = await appData.authority;
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;

                let cloud = appData.cloud || 'global';

                let scopes = formatExtraScopes(appData.extraScopes, appData.baseScopes, outlookScopes(cloud), appData.skipScopes);

                if (!clientId || !clientSecret || !authority || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Outlook'), { statusCode: 400 });
                    throw error;
                }

                return new OutlookOauth(
                    Object.assign(
                        {
                            authority,
                            clientId,
                            clientSecret,
                            redirectUrl,
                            scopes,
                            cloud,
                            setFlag: async flag => {
                                try {
                                    if (appData.legacy) {
                                        await settings.set('outlookAuthFlag', flag);
                                    } else {
                                        await this.setMeta(id, { authFlag: flag });
                                    }
                                } catch (err) {
                                    // ignore
                                }
                            }
                        },
                        extraOpts
                    )
                );
            }

            case 'mailRu': {
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;
                let scopes = formatExtraScopes(appData.extraScopes, appData.baseScopes, MAIL_RU_SCOPES, appData.skipScopes);

                if (!clientId || !clientSecret || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Mail.ru'), { statusCode: 400 });
                    throw error;
                }

                return new MailRuOauth(
                    Object.assign(
                        {
                            clientId,
                            clientSecret,
                            redirectUrl,
                            scopes,
                            setFlag: async flag => {
                                try {
                                    if (appData.legacy) {
                                        await settings.set('mailRuAuthFlag', flag);
                                    } else {
                                        await this.setMeta(id, { authFlag: flag });
                                    }
                                } catch (err) {
                                    // ignore
                                }
                            }
                        },
                        extraOpts
                    )
                );
            }

            default: {
                let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
                throw error;
            }
        }
    }

    async getServiceAccessToken(appData, client) {
        let accessToken = appData.accessToken ? await decrypt(appData.accessToken) : null;
        let accessTokenExpires = appData.accessTokenExpires ? new Date(appData.accessTokenExpires) : null;
        let now = Date.now();

        if (accessToken && accessTokenExpires && accessTokenExpires > new Date(now + 30 * 1000)) {
            // return cached value
            return accessToken;
        }

        let lockKey = ['oauth', 'service', appData.id].join(':');

        let renewLock;

        try {
            renewLock = await lock.waitAcquireLock(lockKey, 5 * 60 * 1000, 1 * 60 * 1000);
            if (!renewLock.success) {
                logger.error({ msg: 'Failed to get lock', lockKey });
                throw new Error('Failed to get renewal lock');
            }
        } catch (err) {
            logger.error({ msg: 'Failed to get lock', lockKey, err });
            let error = Boom.boomify(new Error('Failed to get renewal lock'), { statusCode: 500 });
            if (err.code) {
                error.output.payload.code = err.code || 'LockFail';
            }
            throw error;
        }

        try {
            // check if already renewed
            appData = await this.get(appData.id);

            accessToken = appData.accessToken ? await decrypt(appData.accessToken) : null;
            accessTokenExpires = appData.accessTokenExpires ? new Date(appData.accessTokenExpires) : null;
            now = Date.now();

            if (accessToken && accessTokenExpires && accessTokenExpires > new Date(now + 30 * 1000)) {
                // return cached value
                return accessToken;
            } else {
                // create new
                let isPrincipal = true;
                let { access_token: accessToken, expires_in: expiresIn } = await client.refreshToken({ isPrincipal });
                let expires = new Date(now + expiresIn * 1000);
                if (!accessToken) {
                    return null;
                }

                logger.debug({ msg: 'Renewed access token for service account', app: appData.id, isPrincipal });

                await this.update(
                    appData.id,
                    {
                        accessToken,
                        accessTokenExpires: expires.toISOString()
                    },
                    { partial: true }
                );

                return accessToken;
            }
        } catch (err) {
            logger.info({
                msg: 'Failed to renew OAuth2 access token',
                action: 'getServiceAccessToken',
                error: err,
                response: err.tokenRequest && err.tokenRequest.response,
                flag: err.tokenRequest && err.tokenRequest.flag
            });
            throw err;
        } finally {
            await lock.releaseLock(renewLock);
        }
    }
}

module.exports = {
    oauth2Apps: new OAuth2AppsHandler({ redis }),
    OAUTH_PROVIDERS,
    LEGACY_KEYS,
    oauth2ProviderData
};
