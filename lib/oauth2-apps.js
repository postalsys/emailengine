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

function formatExtraScopes(extraScopes, defaultScopes) {
    let extras = [];
    if (!extraScopes) {
        return defaultScopes;
    }

    for (let extraScope of extraScopes) {
        if (defaultScopes.includes(extraScope) || defaultScopes.includes(`https://outlook.office.com/${extraScope}`)) {
            // skip existing
            continue;
        }
        extras.push(extraScope);
    }
    if (extras.length) {
        return extras.concat(defaultScopes);
    }

    return defaultScopes;
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

    async list(page, pageSize) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let idList = await this.redis.smembers(this.getIndexKey());
        idList = [].concat(idList || []).sort((a, b) => -a.localeCompare(b));

        let response = {
            total: idList.length,
            pages: Math.ceil(idList.length / pageSize),
            page,
            apps: []
        };

        if (idList.length <= startPos) {
            return response;
        }

        let keys = idList.slice(startPos, startPos + pageSize).flatMap(id => [`${id}:data`]);
        let list = await this.redis.hmgetBuffer(this.getDataKey(), keys);
        for (let entry of list) {
            try {
                let data = msgpack.decode(entry);
                response.apps.push(data);
            } catch (err) {
                logger.error({ msg: 'Failed to process app', entry: entry.toString('base64') });
                continue;
            }
        }

        return response;
    }

    async generateId() {
        let idNum = await this.redis.hincrby(this.getDataKey(), 'id', 1);

        let idBuf = Buffer.alloc(8 + 4);
        idBuf.writeBigUInt64BE(BigInt(Date.now()), 0);
        idBuf.writeUInt32BE(idNum, 8);

        const id = idBuf.toString('base64url');

        return id;
    }

    unpackId(id) {
        let idBuf = Buffer.from(id, 'base64');
        return {
            counter: idBuf.readUInt32BE(8),
            created: new Date(Number(idBuf.readBigUInt64BE(0))).toISOString()
        };
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
            created: true,
            id
        };
    }

    async update(id, data) {
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

        return {
            updated: true,
            id
        };
    }

    async getLegacyApp(id) {
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
                    scopes: await settings.get(`${id}ExtraScopes`)
                };
                appData.active = appData.clientId && appData.clientSecret && appData.redirectUrl && true;
                return appData;
            }

            case 'gmailService': {
                let appData = {
                    id: 'gmailService',
                    provider: 'gmailService',
                    legacy: true,
                    serviceClient: await settings.get(`${id}Client`),
                    serviceKey: await settings.get(`${id}Key`),
                    scopes: await settings.get(`${id}ExtraScopes`)
                };
                appData.active = appData.serviceClient && appData.serviceKey && true;
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
                    scopes: await settings.get(`${id}ExtraScopes`)
                };
                appData.active = appData.clientId && appData.clientSecret && appData.redirectUrl && appData.authority && true;
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
                    scopes: await settings.get(`${id}ExtraScopes`)
                };
                appData.active = appData.clientId && appData.clientSecret && appData.redirectUrl && true;
                return appData;
            }

            default:
                return false;
        }
    }

    async get(id) {
        if (['gmail', 'gmailService', 'outlook', 'mailRu'].includes(id)) {
            // legacy
            return await this.getLegacyApp(id);
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

        return data;
    }

    async del(id) {
        let deleteResult = await this.redis
            .multi()
            .srem(this.getIndexKey(), id)
            .hdel(this.getDataKey(), [`${id}:data`, `${id}:meta`])
            .exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        let deletedDocs = ((deleteResult[0] && deleteResult[0][1]) || 0) + ((deleteResult[1] && deleteResult[1][1]) || 0);

        return {
            deleted: deletedDocs >= 2,
            id
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

        let insertResult = await this.redis.hmset(this.getDataKey(), updates);
        console.log(insertResult);
        return {
            updated: true,
            id
        };
    }

    async getClient(id) {
        let appData = await this.get(id);
        if (!appData || !appData.active) {
            let error = Boom.boomify(new Error('Missing or disabled OAuth2 app'), { statusCode: 404 });
            throw error;
        }

        switch (appData.provider) {
            case 'gmail': {
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;
                let scopes = formatExtraScopes(appData.scopes, GMAIL_SCOPES);

                if (!clientId || !clientSecret || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                    throw error;
                }

                return new GmailOauth({
                    clientId,
                    clientSecret,
                    redirectUrl,
                    scopes,
                    async setFlag(flag) {
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
                });
            }

            case 'gmailService': {
                let serviceClient = appData.serviceClient;
                let serviceKey = appData.serviceKey ? await decrypt(appData.serviceKey) : null;
                let scopes = formatExtraScopes(appData.scopes, GMAIL_SCOPES);

                if (!serviceClient || !serviceKey) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Gmail'), { statusCode: 400 });
                    throw error;
                }

                return new GmailOauth({
                    serviceClient,
                    serviceKey,
                    scopes,
                    async setFlag(flag) {
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
                });
            }

            case 'outlook': {
                let authority = await appData.authority;
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;
                let scopes = formatExtraScopes(appData.scopes, OUTLOOK_SCOPES);

                if (!clientId || !clientSecret || !authority || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Outlook'), { statusCode: 400 });
                    throw error;
                }

                return new OutlookOauth({
                    authority,
                    clientId,
                    clientSecret,
                    redirectUrl,
                    scopes,
                    async setFlag(flag) {
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
                });
            }

            case 'mailRu': {
                let clientId = appData.clientId;
                let clientSecret = appData.clientSecret ? await decrypt(appData.clientSecret) : null;
                let redirectUrl = appData.redirectUrl;
                let scopes = formatExtraScopes(appData.scopes, MAIL_RU_SCOPES);

                if (!clientId || !clientSecret || !redirectUrl) {
                    let error = Boom.boomify(new Error('OAuth2 credentials not set up for Mail.ru'), { statusCode: 400 });
                    throw error;
                }

                return new MailRuOauth({
                    clientId,
                    clientSecret,
                    redirectUrl,
                    scopes,
                    async setFlag(flag) {
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
                });
            }

            default: {
                let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
                throw error;
            }
        }
    }
}

module.exports.oauth2Apps = new OAuth2AppsHandler({ redis });
