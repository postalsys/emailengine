'use strict';

const consts = require('./consts');
const settings = require('./settings');
const tokens = require('./tokens');
const Joi = require('joi');
const logger = require('./logger');
const fetch = require('node-fetch');
const { failAction } = require('./tools');
const packageData = require('../package.json');
const he = require('he');
const crypto = require('crypto');
const pbkdf2 = require('@phc/pbkdf2');

const { DEFAULT_MAX_LOG_LINES, PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST, LOGIN_PERIOD_TTL } = require('./consts');
const { query } = require('express');

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

function applyRoutes(server, call) {
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
        path: '/admin/config/oauth',
        async handler(request, h) {
            let values = {
                provider: 'gmail'
            };

            return h.view(
                'config/oauth',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    activeGmail: values.provider === 'gmail',
                    activeOutlook: values.provider === 'outlook',

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
                    menuTokens: true
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
                    description: request.payload.description
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
                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description')
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

                payload: Joi.object({ token: Joi.string().length(64).hex().required().example('123456').description('Access Token') })
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
}

module.exports = (...args) => {
    applyRoutes(...args);
};
