'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const { encrypt, decrypt } = require('./encrypt');
const Boom = require('@hapi/boom');
const settings = require('./settings');

const { OutlookOauth, OUTLOOK_SCOPES } = require('./oauth/outlook');
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
            providerData.tutorialUrl = 'https://docs.emailengine.app/setting-up-gmail-oauth2-for-imap-api/';
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
            providerData.tutorialUrl = 'https://docs.emailengine.app/gmail-oauth-service-accounts/';
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
            providerData.tutorialUrl = 'https://docs.emailengine.app/setting-up-oauth2-with-outlook/';
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

function formatExtraScopes(extraScopes, baseScopes, defaultScopesList, skipScopes) {
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
        if (defaultScopes.includes(extraScope) || defaultScopes.includes(`https://outlook.office.com/${extraScope}`)) {
            // skip existing
            continue;
        }
        extras.push(extraScope);
    }

    let result = [];

    if (extras.length) {
        result = extras.concat(defaultScopes);
    }

    result = defaultScopes;

    if (skipScopes.length) {
        result = result.filter(scope => {
            for (let skipScope of skipScopes) {
                if (scope === skipScope || scope === `https://outlook.office.com/${skipScope}`) {
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

    getSettingsKey() {
        return `${REDIS_PREFIX}settings`;
    }

    async list(page, pageSize) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let idList = await this.redis.smembers(this.getIndexKey());
        idList = [].concat(idList || []).sort((a, b) => -a.localeCompare(b));

        for (let legacyKey of LEGACY_KEYS_REV) {
            if (await settings.get(`${legacyKey}Enabled`)) {
                idList.unshift(legacyKey);
            } else if (await settings.get(`${legacyKey}Client`)) {
                idList.unshift(legacyKey);
            } else if (await settings.get(`${legacyKey}ClientId`)) {
                idList.unshift(legacyKey);
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
            logger.error({ msg: 'Failed to process app', entry: getDataBuf.toString('base64') });
            throw err;
        }

        if (getMetaBuf) {
            try {
                data = Object.assign(data, { meta: msgpack.decode(getMetaBuf) });
            } catch (err) {
                logger.error({ msg: 'Failed to process app', entry: getMetaBuf.toString('base64') });
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
        for (let key of ['clientSecret', 'serviceKey']) {
            if (data[key]) {
                encryptedValues[key] = await encrypt(data[key]);
            }
        }

        let entry = Object.assign({ id: null }, data || {}, encryptedValues, {
            id,
            created: new Date().toISOString()
        });

        let insertResult = await this.redis
            .multi()
            .sadd(this.getIndexKey(), id)
            .hmset(this.getDataKey(), {
                [`${id}:data`]: msgpack.encode(entry)
            })
            .exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        return {
            id,
            created: true
        };
    }

    async update(id, data) {
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
        for (let key of ['clientSecret', 'serviceKey']) {
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

        let insertResult = await this.redis.multi().sadd(this.getIndexKey(), id).hmset(this.getDataKey(), updates).exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        // clear auth flag
        await this.setMeta(id, { authFlag: null });

        return {
            id,
            updated: true
        };
    }

    async del(id) {
        if (LEGACY_KEYS.includes(id)) {
            // legacy
            return await this.delLegacyApp(id);
        }

        let deleteResult = await this.redis
            .multi()
            .srem(this.getIndexKey(), id)
            .hdel(this.getDataKey(), [`${id}:data`, `${id}:meta`])
            .scard(`${REDIS_PREFIX}oapp:a:${id}`)
            .del(`${REDIS_PREFIX}oapp:a:${id}`)
            .exec();

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
                let scopes = formatExtraScopes(appData.extraScopes, appData.baseScopes, OUTLOOK_SCOPES, appData.skipScopes);

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
}

module.exports = {
    oauth2Apps: new OAuth2AppsHandler({ redis }),
    OAUTH_PROVIDERS,
    LEGACY_KEYS,
    oauth2ProviderData
};
