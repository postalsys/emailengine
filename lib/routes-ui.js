'use strict';

const Boom = require('@hapi/boom');
const consts = require('./consts');
const settings = require('./settings');
const tokens = require('./tokens');
const Joi = require('joi');
const logger = require('./logger');
const fetch = require('node-fetch');
const { failAction, verifyAccountInfo } = require('./tools');
const packageData = require('../package.json');
const he = require('he');
const crypto = require('crypto');
const pbkdf2 = require('@phc/pbkdf2');
const { Account } = require('./account');
const { redis } = require('./db');
const psl = require('psl');
const { getOAuth2Client } = require('./oauth');
const { autodetectImapSettings } = require('./autodetect-imap-settings');
const getSecret = require('./get-secret');

const { DEFAULT_MAX_LOG_LINES, PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST, LOGIN_PERIOD_TTL, DEFAULT_PAGE_SIZE } = require('./consts');

const notificationTypes = Object.keys(consts)
    .map(key => {
        if (/_NOTIFY$/.test(key)) {
            return key.replace(/_NOTIFY$/, '');
        }
        return false;
    })
    .filter(key => key)
    .map(key => ({
        key,
        name: consts[`${key}_NOTIFY`],
        description: consts[`${key}_DESCRIPTION`]
    }));

const configWebhooksSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable Webhooks'),
    webhooks: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/imap/webhooks')
        .description('Webhook URL'),
    notifyAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    headersAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyHeaders: Joi.string().empty('').trim(),
    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyTextSize: Joi.number().empty('')
};

for (let type of notificationTypes) {
    configWebhooksSchema[`notify_${type.name}`] = Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false);
}

const configLoggingSchema = {
    all: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable logs for all accounts'),
    resetLoggedAccounts: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Reconnect logged accounts'),
    accounts: Joi.string()
        .trim()
        .empty('')
        .max(10 * 1024)
        .example('account-id-1\naccount-id-2')
        .description('Enable logs for listed accounts')
        .label('LoggedAccounts'),
    maxLogLines: Joi.number().empty('').min(0).max(10000000).default(DEFAULT_MAX_LOG_LINES)
};

const configOauthSchema = {
    provider: Joi.string().valid('gmail', 'outlook').required().description('OAuth2 provider'),

    clientId: Joi.string().trim().allow('').max(256).description('Gmail OAuth2 Client ID'),
    clientSecret: Joi.string().trim().empty('').max(256).description('Gmail OAuth2 Client Secret'),

    authority: Joi.any()
        .when('provider', {
            switch: [
                {
                    is: 'gmail',
                    then: Joi.string().empty('').forbidden()
                },

                {
                    is: 'outlook',
                    then: Joi.string().empty('').valid('consumers', 'organizations', 'common').default('consumers')
                }
            ]
        })
        .label('SupportedAccountTypes'),

    redirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('OAuth2 Callback URL')
};

function applyRoutes(server, call) {
    server.route({
        method: 'GET',
        path: '/admin',
        async handler(request, h) {
            const values = {};

            return h.view(
                'dashboard',
                {
                    menuDashboard: true,
                    values
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/swagger',
        async handler(request, h) {
            return h.view(
                'swagger/index',
                {
                    menuSwagger: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/webhooks',
        async handler(request, h) {
            const notifyHeaders = (await settings.get('notifyHeaders')) || [];
            const webhookEvents = (await settings.get('webhookEvents')) || [];
            const notifyText = (await settings.get('notifyText')) || false;
            const notifyTextSize = Number(await settings.get('notifyTextSize')) || 0;

            let webhooksDisabled = await settings.get('webhooksDisabled');
            let values = {
                webhooksEnabled: webhooksDisabled !== null ? !webhooksDisabled : false,
                webhooks: (await settings.get('webhooks')) || '',

                notifyAll: webhookEvents.includes('*'),

                headersAll: notifyHeaders.includes('*'),
                notifyHeaders: notifyHeaders
                    .filter(entry => entry !== '*')
                    .map(entry => entry.replace(/^mime|^dkim|-id$|^.|-./gi, c => c.toUpperCase()))
                    .join('\n'),
                notifyText,
                notifyTextSize: notifyTextSize ? notifyTextSize : ''
            };

            return h.view(
                'config/webhooks',
                {
                    menuConfig: true,
                    menuConfigWebhooks: true,

                    notificationTypes: notificationTypes.map(type => Object.assign({}, type, { checked: webhookEvents.includes(type.name) })),

                    values
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/webhooks',
        async handler(request, h) {
            try {
                const data = {
                    webhooksDisabled: !request.payload.webhooksEnabled,
                    webhooks: request.payload.webhooks,
                    notifyText: request.payload.notifyText,
                    notifyTextSize: request.payload.notifyTextSize || 0,

                    webhookEvents: notificationTypes.filter(type => !!request.payload[`notify_${type.name}`]).map(type => type.name),
                    notifyHeaders: (request.payload.notifyHeaders || '')
                        .split(/\r?\n/)
                        .map(line => line.toLowerCase().trim())
                        .filter(line => line)
                };

                if (!data.webhooks) {
                    data.webhooksDisabled = true;
                }

                if (request.payload.notifyAll) {
                    data.webhookEvents.push('*');
                }
                if (request.payload.headersAll) {
                    data.notifyHeaders.push('*');
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/webhooks');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/webhooks',
                    {
                        menuConfig: true,
                        menuConfigWebhooks: true,

                        notificationTypes: notificationTypes.map(type => Object.assign({}, type, { checked: !!request.payload[`notify_${type.name}`] }))
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update configuration` });
                    logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/webhooks',
                            {
                                menuConfig: true,
                                menuConfigWebhooks: true,

                                notificationTypes: notificationTypes.map(type =>
                                    Object.assign({}, type, { checked: !!request.payload[`notify_${type.name}`], error: errors[`notify_${type.name}`] })
                                ),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configWebhooksSchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/service',
        async handler(request, h) {
            const values = {
                serviceUrl: (await settings.get('serviceUrl')) || null,
                serviceSecret: (await settings.get('serviceSecret')) || null
            };

            return h.view(
                'config/service',
                {
                    menuConfig: true,
                    menuConfigService: true,

                    values
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/service',
        async handler(request, h) {
            try {
                let data = {
                    serviceSecret: request.payload.serviceSecret
                };

                if (request.payload.serviceUrl) {
                    let url = new URL(request.payload.serviceUrl);
                    data.serviceUrl = url.origin;
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/service');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/service',
                    {
                        menuConfig: true,
                        menuConfigService: true
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update configuration` });
                    logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/service',
                            {
                                menuConfig: true,
                                menuConfigService: true,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    serviceUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://emailengine.example.com')
                        .description('Base URL of EmailEngine')
                        .label('ServiceURL'),
                    serviceSecret: Joi.string().allow('').example('verysecr8t').description('HMAC secret for signing public requests').label('ServiceSecret')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/logging',
        async handler(request, h) {
            let values = (await settings.get('logs')) || {};

            if (typeof values.maxLogLines === 'undefined') {
                values.maxLogLines = DEFAULT_MAX_LOG_LINES;
            }

            values.accounts = [].concat(values.accounts || []).join('\n');

            return h.view(
                'config/logging',
                {
                    menuConfig: true,
                    menuConfigLogging: true,

                    values
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/logging',
        async handler(request, h) {
            try {
                const data = {
                    logs: {
                        all: !!request.payload.all,
                        accounts: (request.payload.accounts || '')
                            .split(/\r?\n/)
                            .map(line => line.trim())
                            .filter(line => line),
                        maxLogLines: request.payload.maxLogLines || 0
                    }
                };

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (request.payload.resetLoggedAccounts && data.logs.accounts && data.logs.accounts.length) {
                    for (let account of data.logs.accounts) {
                        logger.info({ msg: 'Request reconnect for logging', account });
                        try {
                            await call({ cmd: 'update', account });
                        } catch (err) {
                            logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                        }
                    }
                }

                return h.redirect('/admin/config/logging');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/logging',
                    {
                        menuConfig: true,
                        menuConfigWebhooks: true
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update configuration` });
                    logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/logging',
                            {
                                menuConfig: true,
                                menuConfigWebhooks: true,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configLoggingSchema)
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/logging/reconnect',
        async handler(request) {
            try {
                let requested = 0;
                for (let account of request.payload.accounts) {
                    logger.info({ msg: 'Request reconnect for logging', account });
                    try {
                        await call({ cmd: 'update', account });
                        requested++;
                    } catch (err) {
                        logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                    }
                }

                return {
                    success: true,
                    accounts: requested
                };
            } catch (err) {
                logger.error({ msg: 'Failed to request reconnect', err, accounts: request.payload.accounts });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    accounts: Joi.array()
                        .items(Joi.string().max(256))
                        .default([])
                        .example(['account-id-1', 'account-id-2'])
                        .description('Request reconnect for listed accounts')
                        .label('LoggedAccounts')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/webhooks/test',
        async handler(request) {
            let headers = {
                'Content-Type': 'application/json',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            };

            const webhooks = request.payload.webhooks;

            let parsed = new URL(webhooks);
            let username, password;

            if (parsed.username) {
                username = he.decode(parsed.username);
                parsed.username = '';
            }

            if (parsed.password) {
                password = he.decode(parsed.password);
                parsed.password = '';
            }

            if (username || password) {
                headers.Authorization = `Basic ${Buffer.from(he.encode(username || '') + ':' + he.encode(password || '')).toString('base64')}`;
            }

            let start = Date.now();
            let duration;
            try {
                let res;

                try {
                    res = await fetch(parsed.toString(), {
                        method: 'post',
                        body: JSON.stringify({
                            account: null,
                            date: new Date().toISOString(),
                            event: 'test',
                            data: {
                                nonce: crypto.randomBytes(12).toString('hex')
                            }
                        }),
                        headers
                    });
                    duration = Date.now() - start;
                } catch (err) {
                    duration = Date.now() - start;
                    throw err;
                }

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.status = res.status;
                    throw err;
                }

                return {
                    success: true,
                    target: webhooks,
                    duration
                };
            } catch (err) {
                logger.error({ msg: 'Failed posting webhook', webhooks, event: 'test', err });
                return {
                    success: false,
                    target: webhooks,
                    duration,
                    error: err.message
                };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook URL')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/{provider?}',
        async handler(request, h) {
            let values = {
                provider: request.params.provider
            };

            let hasClientSecret;

            switch (values.provider) {
                case 'gmail':
                    values.clientId = await settings.get('gmailClientId');
                    hasClientSecret = !!(await settings.get('gmailClientSecret'));
                    values.redirectUrl = await settings.get('gmailRedirectUrl');
                    break;
                case 'outlook':
                    values.clientId = await settings.get('outlookClientId');
                    hasClientSecret = !!(await settings.get('outlookClientSecret'));
                    values.redirectUrl = await settings.get('outlookRedirectUrl');
                    values.authority = (await settings.get('outlookAuthority')) || 'consumers';
                    break;
                default: {
                    await request.flash({ type: 'danger', message: `Unknown OAuth2 provider requested` });
                    return h.redirect('/admin');
                }
            }

            let serviceUrl = await settings.get('serviceUrl');
            let defaultRedirectUrl = `${serviceUrl}/oauth`;
            if (values.provider === 'outlook') {
                defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
            }

            return h.view(
                'config/oauth',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    activeGmail: values.provider === 'gmail',
                    activeOutlook: values.provider === 'outlook',

                    hasClientSecret,
                    defaultRedirectUrl,

                    values
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    logger.error({ msg: 'Failed to validate provider argument', err });
                    return h.redirect('/admin').takeover();
                },

                params: Joi.object({
                    provider: Joi.string().empty('').valid('gmail', 'outlook').default('gmail').label('Provider')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth',
        async handler(request, h) {
            try {
                const provider = request.payload.provider;
                const data = {};

                switch (provider) {
                    case 'gmail':
                        for (let key of ['clientId', 'clientSecret', 'redirectUrl']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                data[`${provider}${key.replace(/^./, c => c.toUpperCase())}`] = request.payload[key];
                            }
                        }

                        if (request.payload.clientId === '') {
                            // clear secret as well
                            data[`${provider}ClientSecret`] = '';
                        }
                        break;

                    case 'outlook':
                        for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'authority']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                data[`${provider}${key.replace(/^./, c => c.toUpperCase())}`] = request.payload[key];
                            }
                        }

                        if (request.payload.clientId === '') {
                            // clear secret as well
                            data[`${provider}ClientSecret`] = '';
                        }
                        break;
                    default:
                        await request.flash({ type: 'danger', message: `Unknown OAuth2 provider requested` });
                        return h.redirect('/admin');
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (request.payload.resetLoggedAccounts && data.logs.accounts && data.logs.accounts.length) {
                    for (let account of data.logs.accounts) {
                        logger.info({ msg: 'Request reconnect for logging', account });
                        try {
                            await call({ cmd: 'update', account });
                        } catch (err) {
                            logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                        }
                    }
                }

                return h.redirect(`/admin/config/oauth/${request.payload.provider}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

                let serviceUrl = await settings.get('serviceUrl');
                let defaultRedirectUrl = `${serviceUrl}/oauth`;
                if (request.payload.provider === 'outlook') {
                    defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                }

                return h.view(
                    'config/oauth',
                    {
                        menuConfig: true,
                        menuConfigOauth: true,

                        activeGmail: request.payload.provider === 'gmail',
                        activeOutlook: request.payload.provider === 'outlook',

                        defaultRedirectUrl,

                        hasClientSecret: !!(await settings.get(`${request.payload.provider}ClientSecret`))
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update configuration` });
                    logger.error({ msg: 'Failed to update configuration', err });

                    let serviceUrl = await settings.get('serviceUrl');
                    let defaultRedirectUrl = `${serviceUrl}/oauth`;
                    if (request.payload.provider === 'outlook') {
                        defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                    }

                    return h
                        .view(
                            'config/oauth',
                            {
                                menuConfig: true,
                                menuConfigOauth: true,

                                activeGmail: request.payload.provider === 'gmail',
                                activeOutlook: request.payload.provider === 'outlook',
                                hasClientSecret: !!(await settings.get(`${request.payload.provider}ClientSecret`)),

                                defaultRedirectUrl,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configOauthSchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/tokens',
        async handler(request, h) {
            const tokenList = await tokens.list();
            return h.view(
                'tokens/index',
                {
                    menuTokens: true,
                    tokenList: tokenList.map(entry => {
                        entry.access = entry.access || {};
                        entry.access.timeStr =
                            entry.access && entry.access.time && typeof entry.access.time.toISOString === 'function' ? entry.access.time.toISOString() : null;
                        entry.scopes = entry.scopes
                            ? entry.scopes.map((scope, i) => ({
                                  name: scope === '*' ? 'all scopes' : scope,
                                  first: !i
                              }))
                            : false;
                        return entry;
                    })
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/tokens/new',
        async handler(request, h) {
            return h.view(
                'tokens/new',
                {
                    menuTokens: true,
                    values: {
                        scopesAll: true
                    }
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/tokens/new',

        async handler(request) {
            try {
                let data = {
                    ip: request.app.ip,
                    remoteAddress: request.app.ip,
                    description: request.payload.description,
                    scopes: request.payload.scopes
                };

                let token = await tokens.provision(data);

                return {
                    success: true,
                    token
                };
            } catch (err) {
                logger.error({ msg: 'Failed to generate token', err, remoteAddress: request.app.ip, description: request.payload.description });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                    scopes: Joi.array().items(Joi.string().valid('*', 'api', 'metrics')).required().label('Scopes')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/tokens/delete',
        async handler(request, h) {
            try {
                let deleted = await tokens.delete(request.payload.token, { remoteAddress: request.app.ip });
                if (deleted) {
                    await request.flash({ type: 'info', message: `Access token was deleted` });
                }

                return h.redirect('/admin/tokens');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete access token` });
                logger.error({ msg: 'Failed to delete access token', err, token: request.payload.token, remoteAddress: request.app.ip });
                return h.redirect('/admin/tokens');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Failed to delete access token` });
                    logger.error({ msg: 'Failed to delete access token', err });

                    return h.redirect('/admin/tokens').takeover();
                },

                payload: Joi.object({ token: Joi.string().length(64).hex().required().example('123456').description('Access token') })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/license',
        async handler(request, h) {
            return h.view(
                'config/license',
                {
                    menuLicense: true,
                    hideLicenseWarning: true,
                    menuConfig: true,
                    menuConfigLicense: true,

                    showLicenseText: !request.app.licenseInfo || !request.app.licenseInfo.active
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license',
        async handler(request, h) {
            try {
                // update license
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `License key was successfully registered` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to register license key` });
                logger.error({ msg: 'Failed to register license key', err });

                return h.view(
                    'config/license',
                    {
                        menuConfig: true,
                        menuConfigWebhooks: true,

                        errors: err.details,
                        showLicenseText: (err.details && !!err.details.license) || !request.app.licenseInfo || !request.app.licenseInfo.active
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to register license key` });
                    logger.error({ msg: 'Failed to register license key', err });

                    return h
                        .view(
                            'config/license',
                            {
                                menuConfig: true,
                                menuConfigWebhooks: true,

                                errors,

                                showLicenseText: (errors && !!errors.license) || !request.app.licenseInfo || !request.app.licenseInfo.active
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    license: Joi.string()
                        .max(10 * 1024)
                        .required()
                        .example('-----BEGIN LICENSE-----\r\n...')
                        .description('License file')
                }).label('RegisterLicense')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license/delete',
        async handler(request, h) {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense' });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                } else {
                    await request.flash({ type: 'info', message: `License key was unregistered` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to unregister license key` });
                logger.error({ msg: 'Failed to unregister license key', err, token: request.payload.token, remoteAddress: request.app.ip });
                return h.redirect('/admin/config/license');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Failed to unregister license key` });
                    logger.error({ msg: 'Failed to unregister license key', err });

                    return h.redirect('/admin/config/license').takeover();
                },

                payload: Joi.object({})
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/login',
        async handler(request, h) {
            return h.view(
                'account/login',
                {
                    menuLogin: true,
                    values: {
                        username: 'admin',
                        next: request.query.next
                    }
                },
                {
                    layout: 'login'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    logger.error({ msg: 'Failed to validate login arguments', err });
                    return h.redirect('/admin/login').takeover();
                },

                query: Joi.object({
                    next: Joi.string().uri({ relativeOnly: true }).label('NextUrl')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/logout',
        async handler(request, h) {
            if (request.cookieAuth) {
                request.cookieAuth.clear();
            }
            return h.redirect('/');
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/login',
        async handler(request, h) {
            try {
                let authData = await settings.get('authData');
                if (authData && authData.password) {
                    try {
                        let valid = await pbkdf2.verify(authData.password, request.payload.password);
                        if (!valid) {
                            throw new Error('Invalid password');
                        }
                    } catch (E) {
                        logger.error({ msg: 'Failed to verify password hash', err: E, hash: authData.password });
                        let err = new Error('Failed to authenticate');
                        err.details = { password: err.message };
                        throw err;
                    }

                    request.cookieAuth.set({ user: authData.user });
                    if (request.payload.remember) {
                        request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                    }
                }

                await request.flash({ type: 'info', message: `Authentication successful` });

                if (request.payload.next) {
                    return h.redirect(request.payload.next);
                } else {
                    return h.redirect('/admin');
                }
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to authenticate` });
                logger.error({ msg: 'Failed to authenticate', err });

                let errors = err.details;

                return h.view(
                    'account/login',
                    {
                        menuLogin: true,
                        errors
                    },
                    {
                        layout: 'login'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update account password` });
                    logger.error({ msg: 'Failed to update account password', err });

                    return h
                        .view(
                            'account/login',
                            {
                                menuLogin: true,
                                errors
                            },
                            {
                                layout: 'login'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    username: Joi.string().max(256).example('user').label('Username').description('Your account username'),
                    password: Joi.string().max(256).min(8).required().example('secret').label('Password').description('Your account password'),
                    remember: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Remember me'),
                    next: Joi.string().uri({ relativeOnly: true }).label('NextUrl')
                })
            },

            auth: {
                strategy: 'session',
                mode: 'try'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/account/password',
        async handler(request, h) {
            return h.view(
                'account/password',
                {
                    menuPassword: true,
                    disableAuthWarning: true,

                    username: 'admin' //fixed value
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/password',
        async handler(request, h) {
            try {
                let authData = await settings.get('authData');
                if (authData && authData.password) {
                    try {
                        let valid = await pbkdf2.verify(authData.password, request.payload.password0);
                        if (!valid) {
                            throw new Error('Invalid current password');
                        }
                    } catch (E) {
                        logger.error({ msg: 'Failed to verify password hash', err: E, hash: authData.password });
                        let err = new Error('Failed to verify current password');
                        err.details = { password0: err.message };
                        throw err;
                    }
                }

                const passwordHash = await pbkdf2.hash(request.payload.password, {
                    iterations: PDKDF2_ITERATIONS,
                    saltSize: PDKDF2_SALT_SIZE,
                    digest: PDKDF2_DIGEST
                });

                authData = authData || {};
                authData.user = authData.user || 'admin';
                authData.password = passwordHash;

                await settings.set('authData', authData);

                if (!server.auth.settings.default) {
                    server.auth.default('session');
                    request.cookieAuth.set({ user: authData.user });
                }

                await request.flash({ type: 'info', message: `Authentication password updated` });

                return h.redirect('/admin/account/password');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update password` });
                logger.error({ msg: 'Failed to update password', err });

                return h.view(
                    'account/password',
                    {
                        menuPassword: true,
                        disableAuthWarning: true,
                        errors: err.details,

                        username: 'admin' //fixed value
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to update account password` });
                    logger.error({ msg: 'Failed to update account password', err });

                    return h
                        .view(
                            'account/password',
                            {
                                menuPassword: true,
                                disableAuthWarning: true,
                                errors,

                                username: 'admin' //fixed value
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    password0: Joi.string().max(256).min(8).example('secret').label('Currrent password').description('Current password'),
                    password: Joi.string().max(256).min(8).required().example('secret').label('New password').description('New password'),
                    password2: Joi.string()
                        .max(256)
                        .required()
                        .example('secret')
                        .label('Repeat password')
                        .description('Repeat password')
                        .valid(Joi.ref('password'))
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts',
        async handler(request, h) {
            let accountObject = new Account({ redis });

            const accounts = await accountObject.listAccounts(request.query.state, request.query.page - 1, request.query.pageSize);

            console.log(accounts);
            if (accounts.pages < request.query.page) {
                request.query.page = accounts.pages;
            }

            for (let account of accounts.accounts) {
                let accountObject = new Account({ redis, account: account.account });
                account.data = await accountObject.loadAccountData();
            }

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/accounts`, 'http://localhost');
                url.searchParams.append('page', page);
                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }
                return url.pathname + url.search;
            };

            if (accounts.pages > accounts.page + 1) {
                nextPage = getPagingUrl(accounts.page + 2);
            }

            if (accounts.page > 0) {
                prevPage = getPagingUrl(accounts.page);
            }

            console.log(accounts.accounts.map(account => account.data || accounts));

            console.log(request.url);

            return h.view(
                'accounts/index',
                {
                    menuAccounts: true,

                    showPaging: accounts.pages > 1,
                    nextPage,
                    prevPage,
                    pageLinks: new Array(accounts.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === accounts.page
                    })),

                    accounts: accounts.accounts.map(account => {
                        account = account.data || account;

                        account.type = {};
                        if (account.oauth2 && account.oauth2.provider) {
                            account.type.name = 'OAuth2';

                            switch (account.oauth2.provider) {
                                case 'gmail':
                                    account.type.comment = 'Gmail';
                                    account.type.icon = 'fab fa-google';
                                    break;
                                case 'outlook':
                                    account.type.comment = 'Outlook';
                                    account.type.icon = 'fab fa-microsoft';
                                    break;
                                default:
                                    account.type.comment = account.oauth2.provider.replace(/^./, c => c.toUpperCase());
                            }
                        } else if (account.imap) {
                            account.type.icon = 'fa fa-envelope-square';
                            account.type.name = 'IMAP';
                            account.type.comment = psl.get(account.imap.host) || account.imap.host;
                        } else {
                            account.type.name = 'N/A';
                        }

                        switch (account.state) {
                            case 'init':
                                account.stateLabel = {
                                    type: 'info',
                                    name: 'Initializing'
                                };
                                break;
                            case 'connecting':
                                account.stateLabel = {
                                    type: 'info',
                                    name: 'Connecting'
                                };
                                break;
                            case 'syncing':
                                account.stateLabel = {
                                    type: 'info',
                                    name: 'Syncing',
                                    spinner: true
                                };
                                break;
                            case 'connected':
                                account.stateLabel = {
                                    type: 'success',
                                    name: 'Connected'
                                };
                                break;
                            case ('authenticationError', 'connectError'):
                                account.stateLabel = {
                                    type: 'danger',
                                    name: 'Failed',
                                    error: account.lastErrorState ? account.lastErrorState.response : false
                                };
                                break;
                            case 'unset':
                            case 'disconnected':
                                account.stateLabel = {
                                    type: 'warning',
                                    name: 'Disconnected'
                                };
                                break;
                            default:
                                account.stateLabel = {
                                    type: 'secondary',
                                    name: 'N/A'
                                };
                                break;
                        }
                        console.log(account);

                        return account;
                    }),

                    curpage: encodeURIComponent(request.url.pathname + request.url.search)
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/accounts').takeover();
                },

                query: Joi.object({
                    page: Joi.number().min(1).max(1000000).default(1),
                    pageSize: Joi.number().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/new',

        async handler(request, h) {
            let data = Buffer.from(
                JSON.stringify({
                    account: request.payload.account,
                    name: request.payload.name,
                    redirectUrl: `/admin/accounts`
                })
            );

            let signature;
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                signature = hmac.digest('base64url');
            }

            let url = new URL(`accounts/new`, 'http://localhost');

            url.searchParams.append('data', data.toString('base64url'));
            if (signature) {
                url.searchParams.append('sig', signature);
            }

            return h.redirect(url.pathname + url.search);
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to set up account${errors.account ? `: ${errors.account}` : ''}` });
                    logger.error({ msg: 'Failed to update configuration', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                payload: Joi.object({
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID'),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/accounts/new',
        async handler(request, h) {
            let data = Buffer.from(request.query.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.query.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            return h.view(
                'accounts/register/index',
                {
                    values: {
                        data: request.query.data,
                        sig: request.query.sig
                    }
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error('Failed to validate request arguments'), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true })
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new',

        async handler(request, h) {
            let data = Buffer.from(request.payload.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.payload.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);

            let accountData = {
                account: data.account
            };

            if (data.name) {
                accountData.name = data.name;
            }

            if (data.email) {
                accountData.email = data.email;
            }

            if (data.redirectUrl) {
                accountData._meta = {
                    redirectUrl: data.redirectUrl
                };
            }

            accountData.notifyFrom = new Date().toISOString();

            if (['gmail', 'outlook'].includes(request.payload.type)) {
                const oAuth2Client = await getOAuth2Client(request.payload.type);
                let nonce = crypto.randomBytes(12).toString('hex');

                accountData.copy = false;
                accountData.oauth2 = {
                    provider: request.payload.type
                };

                // store account data
                await redis
                    .multi()
                    .set(`account:add:${nonce}`, JSON.stringify(accountData))
                    .expire(`account:add:${nonce}`, 1 * 24 * 3600)
                    .exec();

                // Generate the url that will be used for the consent dialog.
                let authorizeUrl;
                switch (request.payload.type) {
                    case 'gmail':
                        authorizeUrl = oAuth2Client.generateAuthUrl({
                            access_type: 'offline',
                            scope: ['https://mail.google.com/'],
                            state: `account:add:${nonce}`,
                            prompt: 'consent'
                        });

                        break;
                    case 'outlook':
                        authorizeUrl = oAuth2Client.generateAuthUrl({
                            state: `account:add:${nonce}`
                        });
                        break;
                    default: {
                        let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
                        throw error;
                    }
                }

                return h.redirect(authorizeUrl);
            }

            return h.view(
                'accounts/register/imap',
                {
                    values: {
                        data: request.payload.data,
                        sig: request.payload.sig,
                        email: data.email
                    }
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error('Failed to validate request arguments'), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: Joi.string().valid('imap', 'gmail', 'outlook').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap',

        async handler(request, h) {
            let data = Buffer.from(request.payload.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.payload.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);

            let serverSettings;
            try {
                serverSettings = await autodetectImapSettings(request.payload.email);
            } catch (err) {
                logger.error({ msg: 'Failed to resolve email server settings', email: request.payload.email, err });
            }

            let flatten = obj => {
                let result = {};
                let seen = new WeakSet();
                let walk = (prefix, c) => {
                    if (!c || typeof c !== 'object') {
                        return;
                    }
                    for (let key of Object.keys(c)) {
                        if (typeof c[key] === 'object') {
                            if (seen.has(c[key])) {
                                // recursive
                                continue;
                            }
                            seen.add(c[key]);
                            walk([].concat(prefix || []).concat(key), c[key]);
                        } else {
                            let printKey = []
                                .concat(prefix || [])
                                .concat(key)
                                .join('_');
                            result[printKey] = c[key];
                        }
                    }
                };
                walk(false, obj);
                return result;
            };

            let values = Object.assign(
                {
                    email: request.payload.email,
                    password: request.payload.password,
                    data: request.payload.data,
                    sig: request.payload.sig
                },
                flatten(serverSettings)
            );

            values.imap_auth_user = values.imap_auth_user || request.payload.email;
            values.smtp_auth_user = values.smtp_auth_user || request.payload.email;

            values.imap_auth_pass = request.payload.password;
            values.smtp_auth_pass = request.payload.password;

            return h.view(
                'accounts/register/imap-server',
                {
                    values
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to process account` });
                    logger.error({ msg: 'Failed to process account', err });

                    return h
                        .view(
                            'accounts/register/imap',
                            {
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
                    password: Joi.string().max(1024).min(1).required().example('secret').label('Password').description('Your account password')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap/test',
        async handler(request) {
            try {
                let verifyResult = await verifyAccountInfo({
                    imap: {
                        host: request.payload.imap_host,
                        port: request.payload.imap_port,
                        secure: request.payload.imap_secure,
                        auth: {
                            user: request.payload.imap_auth_user,
                            pass: request.payload.imap_auth_pass
                        }
                    },
                    smtp: {
                        host: request.payload.smtp_host,
                        port: request.payload.smtp_port,
                        secure: request.payload.smtp_secure,
                        auth: {
                            user: request.payload.smtp_auth_user,
                            pass: request.payload.smtp_auth_pass
                        }
                    }
                });

                if (verifyResult) {
                    console.error(verifyResult);

                    if (verifyResult.imap && verifyResult.imap.error && verifyResult.imap.code) {
                        switch (verifyResult.imap.code) {
                            case 'ENOTFOUND':
                                verifyResult.imap.error = 'Server hostname was not found';
                                break;
                            case 'AUTHENTICATIONFAILED':
                                verifyResult.imap.error = 'Invalid username or password';
                                break;
                        }
                    }

                    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
                        switch (verifyResult.smtp.code) {
                            case 'EDNS':
                                verifyResult.smtp.error = 'Server hostname was not found';
                                break;

                            case 'EAUTH':
                                verifyResult.smtp.error = 'Invalid username or password';
                                break;

                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = 'TLS protocol error';
                                }
                                break;
                        }
                    }
                }

                return verifyResult;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    imap_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    imap_auth_pass: Joi.string().empty('').max(1024).required(),
                    imap_host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(993)
                        .description('Service port number'),
                    imap_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(465)
                        .description('Service port number'),
                    smtp_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap/server',

        async handler(request, h) {
            let data = Buffer.from(request.payload.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.payload.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);

            let accountData = {
                account: data.account,
                name: data.name,
                email: request.payload.email,

                imap: {
                    host: request.payload.imap_host,
                    port: request.payload.imap_port,
                    secure: request.payload.imap_secure,
                    auth: {
                        user: request.payload.imap_auth_user,
                        pass: request.payload.imap_auth_pass
                    }
                },
                smtp: {
                    host: request.payload.smtp_host,
                    port: request.payload.smtp_port,
                    secure: request.payload.smtp_secure,
                    auth: {
                        user: request.payload.smtp_auth_user,
                        pass: request.payload.smtp_auth_pass
                    }
                }
            };

            let accountObject = new Account({ redis, call, secret: await getSecret() });
            let result = await accountObject.create(accountData);

            return h.view(
                'redirect',
                { httpRedirectUrl: data.redirectUrl ? data.redirectUrl : `/#account:created=${result.account}` },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to process account` });
                    logger.error({ msg: 'Failed to process account', err });

                    return h
                        .view(
                            'accounts/register/imap-server',
                            {
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
                    imap_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    imap_auth_pass: Joi.string().empty('').max(1024).required(),
                    imap_host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(993)
                        .description('Service port number'),
                    imap_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(465)
                        .description('Service port number'),
                    smtp_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}',
        async handler(request, h) {
            let values = {
                account: request.params.account,
                next: request.params.next || '/admin/accounts'
            };

            return h.view(
                'accounts/account',
                {
                    menuAccounts: true,
                    disableAuthWarning: true,

                    values
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    console.log(err);
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID'),
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
                })
            }
        }
    });
}

module.exports = (...args) => {
    applyRoutes(...args);
};
