'use strict';

const { parentPort } = require('worker_threads');
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const BasicAuth = require('@hapi/basic');
const Joi = require('joi');
const logger = require('../lib/logger');
const hapiPino = require('hapi-pino');
const { ImapFlow } = require('imapflow');
const nodemailer = require('nodemailer');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const packageData = require('../package.json');
const pathlib = require('path');
const config = require('wild-config');
const crypto = require('crypto');
const { PassThrough } = require('stream');
const msgpack = require('msgpack5')();
const { OAuth2Client } = require('google-auth-library');
const consts = require('../lib/consts');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const settings = require('../lib/settings');
const { getByteSize, getDuration, getCounterValues, getAuthSettings } = require('../lib/tools');

const {
    settingsSchema,
    addressSchema,
    settingsQuerySchema,
    imapSchema,
    smtpSchema,
    oauth2Schema,
    messageDetailsSchema,
    messageListSchema,
    mailboxesSchema,
    shortMailboxesSchema
} = require('../lib/schemas');

const DEFAULT_COMMAND_TIMEOUT = 10 * 1000;
const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024;

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1'
};

config.service = config.service || {};

const COMMAND_TIMEOUT = getDuration(process.env.COMMAND_TIMEOUT || config.service.commandTimeout) || DEFAULT_COMMAND_TIMEOUT;
const MAX_ATTACHMENT_SIZE = getByteSize(process.env.API_MAX_SIZE || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;
const ENCRYPT_PASSWORD = process.env.IMAPAPI_SECRET || config.service.secret;
const IMAPAPI_AUTH = getAuthSettings(process.env.IMAPAPI_AUTH || config.api.auth);

const failAction = async (request, h, err) => {
    let details = (err.details || []).map(detail => ({ message: detail.message, key: detail.context.key }));

    logger.error({
        msg: 'Request failed',
        method: request.method,
        route: request.route.path,
        statusCode: request.response && request.response.statusCode,
        err
    });

    let message = 'Invalid input';
    let error = Boom.boomify(new Error(message), { statusCode: 400 });
    error.output.payload.fields = details;
    throw error;
};

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response');
            err.statusCode = 504;
            err.code = 'Timeout';
            reject(err);
        }, message.timeout || COMMAND_TIMEOUT);

        callQueue.set(mid, { resolve, reject, timer });

        parentPort.postMessage(
            {
                cmd: 'call',
                mid,
                message
            },
            transferList
        );
    });
}

async function metrics(logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

async function notify(cmd, data) {
    parentPort.postMessage({
        cmd,
        data
    });
}

async function onCommand(command) {
    logger.debug({ msg: 'Unhandled command', command });
}

parentPort.on('message', message => {
    if (message && message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
        let { resolve, reject, timer } = callQueue.get(message.mid);
        clearTimeout(timer);
        callQueue.delete(message.mid);
        if (message.error) {
            let err = new Error(message.error);
            if (message.code) {
                err.code = message.code;
            }
            if (message.statusCode) {
                err.statusCode = message.statusCode;
            }
            return reject(err);
        } else {
            return resolve(message.response);
        }
    }

    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

const getOAuth2Client = async () => {
    let keys = {
        clientId: await settings.get('gmailClientId'),
        clientSecret: await settings.get('gmailClientSecret'),
        redirectUrl: await settings.get('gmailRedirectUrl')
    };

    if (!keys.clientId || !keys.clientSecret || !keys.redirectUrl) {
        let error = Boom.boomify(new Error('Oauth2 credentials not set up'), { statusCode: 400 });
        throw error;
    }

    return new OAuth2Client(keys.clientId, keys.clientSecret, keys.redirectUrl);
};

const init = async () => {
    const server = Hapi.server({
        port: (process.env.API_PORT && Number(process.env.API_PORT)) || config.api.port,
        host: process.env.API_HOST || config.api.host
    });

    const swaggerOptions = {
        swaggerUI: true,
        swaggerUIPath: '/swagger/',
        documentationPage: true,
        documentationPath: '/docs',

        grouping: 'tags',

        info: {
            title: 'IMAP API',
            version: packageData.version,
            contact: {
                name: 'Andris Reinman',
                email: 'andris@imapapi.com'
            }
        }
    };

    const validateBasicAuth = async (request, username, password /*, h*/) => {
        if (!IMAPAPI_AUTH.enabled) {
            return { credentials: null, isValid: true };
        }

        if (username.trim() !== IMAPAPI_AUTH.user || password !== IMAPAPI_AUTH.pass) {
            return { credentials: null, isValid: false };
        }

        return { isValid: true, credentials: { id: username } };
    };

    if (IMAPAPI_AUTH.enabled) {
        // setup basic auth
        await server.register(BasicAuth);

        server.auth.strategy('simple', 'basic', { validate: validateBasicAuth });
        server.auth.default('simple');
    }

    await server.register({
        plugin: hapiPino,
        options: {
            instance: logger.child({ component: 'api' }),
            // Redact Authorization headers, see https://getpino.io/#/docs/redaction
            redact: ['req.headers.authorization']
        }
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: swaggerOptions
        }
    ]);

    server.events.on('response', request => {
        if (!/^\/v1\//.test(request.route.path)) {
            // only log API calls
            return;
        }
        metrics(logger, 'apiCall', 'inc', {
            method: request.method,
            route: request.route.path,
            statusCode: request.response && request.response.statusCode
        });
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: {
            file: pathlib.join(__dirname, '..', 'static', 'index.html')
        }
    });

    server.route({
        method: 'GET',
        path: '/favicon.ico',
        handler: {
            file: pathlib.join(__dirname, '..', 'static', 'favicon.ico')
        }
    });

    server.route({
        method: 'GET',
        path: '/static/{file*}',
        handler: {
            directory: {
                path: pathlib.join(__dirname, '..', 'static')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/oauth',
        async handler(request, h) {
            const oAuth2Client = await getOAuth2Client();

            if (request.query.error) {
                let error = Boom.boomify(new Error(`Oauth failed: ${request.query.error}`), { statusCode: 400 });
                throw error;
            }

            if (!request.query.code) {
                // throw
                let error = Boom.boomify(new Error(`Oauth failed: node code received`), { statusCode: 400 });
                throw error;
            }

            if (!/^account:add:/.test(request.query.state)) {
                let error = Boom.boomify(new Error(`Oauth failed: invalid state received`), { statusCode: 400 });
                throw error;
            }

            let [[, accountData]] = await redis.multi().get(request.query.state).del(request.query.state).exec();
            if (!accountData) {
                let error = Boom.boomify(new Error(`Oauth failed: session expired`), { statusCode: 400 });
                throw error;
            }

            try {
                accountData = JSON.parse(accountData);
            } catch (E) {
                let error = Boom.boomify(new Error(`Oauth failed: invalid session`), { statusCode: 400 });
                throw error;
            }

            const r = await oAuth2Client.getToken(request.query.code);
            if (!r || !r.tokens) {
                let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                throw error;
            }

            accountData.oauth2 = Object.assign(accountData.oauth2 || {}, {
                provider: 'gmail',
                accessToken: r.tokens.access_token,
                refreshToken: r.tokens.refresh_token,
                expires: r.tokens.expiry_date,
                scope: r.tokens.scope,
                tokenType: r.tokens.token_type
            });

            let accountObject = new Account({ redis, call, secret: ENCRYPT_PASSWORD });
            let result = await accountObject.create(accountData);

            return h.redirect(`/#account:created=${result.account}`);
        },
        options: {
            description: 'Oauth2 response endpoint',

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    state: Joi.string().max(1024).example('account:add:12345').description('Oauth2 state info'),
                    code: Joi.string().max(1024).example('67890...').description('Oauth2 setup code'),
                    scope: Joi.string().max(1024).example('https://mail.google.com/').description('Oauth2 scopes'),
                    error: Joi.string().max(1024).example('access_denied').description('Oauth2 scopes')
                }).label('CreateAccount')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account',

        async handler(request) {
            let accountObject = new Account({ redis, call, secret: ENCRYPT_PASSWORD });

            try {
                if (request.payload.oauth2) {
                    // redirect to Oauth2 consent screen

                    const oAuth2Client = await getOAuth2Client();

                    let nonce = crypto.randomBytes(12).toString('hex');

                    // store account data
                    await redis
                        .multi()
                        .set(`account:add:${nonce}`, JSON.stringify(request.payload))
                        .expire(`account:add:${nonce}`, 1 * 24 * 3600)
                        .exec();

                    // Generate the url that will be used for the consent dialog.
                    const authorizeUrl = oAuth2Client.generateAuthUrl({
                        access_type: 'offline',
                        scope: ['https://mail.google.com/', 'https://www.googleapis.com/auth/userinfo.profile'],
                        state: `account:add:${nonce}`,
                        login_hint: request.payload.oauth2.auth.user,
                        prompt: 'consent',
                        include_granted_scopes: true
                    });

                    return {
                        redirect: authorizeUrl
                    };
                }

                let result = await accountObject.create(request.payload);
                return result;
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
            description: 'Register new account',
            notes: 'Registers new IMAP account to be synced',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),

                    path: Joi.string().empty('').max(1024).default('*').example('INBOX').description('Check changes only on selected path'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder').default(true),
                    notifyFrom: Joi.date().example('2021-07-08T07:06:34.336Z').description('Notify messages from date').default('now').iso(),

                    imap: Joi.object(imapSchema).allow(false).xor('useAuthServer', 'auth').description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP'),

                    oauth2: Joi.object(oauth2Schema).allow(false).description('Oauth2 configuration').label('Oauth2')
                }).label('CreateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    state: Joi.string().required().valid('existing', 'new').example('new').description('Is the account new or updated existing')
                }).label('CreateAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.update(request.payload);
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
            description: 'Update account info',
            notes: 'Updates account information',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),

                    path: Joi.string().empty('').max(1024).default('*').example('INBOX').description('Check changes only on selected path'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder').default(true),
                    notifyFrom: Joi.date().example('2021-07-08T07:06:34.336Z').description('Notify messages from date').default('now').iso(),

                    imap: Joi.object(imapSchema).xor('useAuthServer', 'auth').description('IMAP configuration').label('IMAP'),
                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP')
                }).label('UpdateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('UpdateAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/reconnect',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return { reconnect: await accountObject.requestReconnect(request.payload) };
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
            description: 'Request reconnect',
            notes: 'Requests connection to be reconnected',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnect')
            },

            response: {
                schema: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnectReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.delete();
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
            description: 'Remove synced account',
            notes: 'Stop syncing IMAP account and delete cached values',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('DeleteRequest')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteRequestReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/accounts',

        async handler(request) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

                return await accountObject.listAccounts(request.query.state, request.query.page, request.query.pageSize);
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
            description: 'List accounts',
            notes: 'Lists registered accounts',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    state: Joi.string()
                        .valid('init', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState')
                }).label('AccountsFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),

                    accounts: Joi.array()
                        .items(
                            Joi.object({
                                account: Joi.string().max(256).required().example('example').description('Account ID'),
                                name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                                state: Joi.string()
                                    .required()
                                    .valid('init', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                                    .example('connected')
                                    .description('Account state'),
                                syncTime: Joi.date().example('2021-02-17T13:43:18.860Z').description('Last sync time').iso(),
                                lastError: Joi.object({
                                    response: Joi.string().example('Request to authentication server failed'),
                                    serverResponseCode: Joi.string().example('HTTPRequestError')
                                })
                                    .allow(null)
                                    .label('AccountErrorEntry')
                            }).label('AccountResponseItem')
                        )
                        .label('AccountEntries')
                }).label('AccountsFilterReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });
            try {
                let accountData = await accountObject.loadAccountData();

                // remove secrets
                for (let type of ['imap', 'smtp', 'oauth2']) {
                    if (accountData[type] && accountData[type].auth) {
                        for (let key of ['pass', 'accessToken']) {
                            if (key in accountData[type].auth) {
                                accountData[type].auth[key] = '******';
                            }
                        }
                    }
                }

                let result = {};

                for (let key of ['account', 'name', 'copy', 'notifyFrom', 'imap', 'smtp', 'oauth2']) {
                    if (key in accountData) {
                        result[key] = accountData[key];
                    }
                }

                return result;
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
            description: 'Get account info',
            notes: 'Returns stored information about the account. Passwords are not included.',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder').default(true),
                    notifyFrom: Joi.date().example('2021-07-08T07:06:34.336Z').description('Notify messages from date').default('now').iso(),

                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).description('SMTP configuration').label('SMTP')
                }).label('AccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/mailboxes',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return { mailboxes: await accountObject.getMailboxListing() };
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
            description: 'List mailboxes',
            notes: 'Lists all available mailboxes',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    mailboxes: mailboxesSchema
                }).label('MailboxesFilterReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.createMailbox(request.payload.path);
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
            description: 'Create mailbox',
            notes: 'Create new mailbox folder',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).example('example').required().description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.array()
                        .items(Joi.string().max(256))
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array. If account is namespaced then namespace prefix is added by default.')
                        .label('MailboxPath')
                }).label('CreateMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    mailboxId: Joi.string().example('1439876283476').description('Mailbox ID (if server has support)').label('MailboxId'),
                    created: Joi.boolean().example(true).description('Was the mailbox created')
                }).label('CreateMailboxReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.deleteMailbox(request.query.path);
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
            description: 'Delete mailbox',
            notes: 'Delete existing mailbox folder',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('My Outdated Mail').description('Mailbox folder path to delete').label('MailboxPath')
                }).label('DeleteMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    deleted: Joi.boolean().example(true).description('Was the mailbox deleted')
                }).label('DeleteMailboxReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}/source',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.getRawMessage(request.params.message);
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
            description: 'Download raw message',
            notes: 'Fetches raw message as a stream',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).example('AAAAAQAACnA').required().description('Message ID')
                }).label('RawMessageRequest')
            } /*,

            response: {
                schema: Joi.binary().example('MIME-Version: 1.0...').description('RFC822 formatted email').label('RawMessageResponse'),
                failAction: 'log'
            }
            */
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/attachment/{attachment}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.getAttachment(request.params.attachment);
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
            description: 'Download attachment',
            notes: 'Fetches attachment file as a binary stream',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    attachment: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcde')
                        .description('Attachment ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.getMessage(request.params.message, request.query);
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
            description: 'Get message information',
            notes: 'Returns details of a specific message. By default text content is not included, use textType value to force retrieving text',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(5 * 1025 * 1024)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default text content is not returned.')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).required().example('AAAAAQAACnA').description('Message ID')
                })
            },

            response: {
                schema: messageDetailsSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/message',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.uploadMessage(request.payload);
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
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Upload message',
            notes: 'Upload a message structure, compile it into an EML file and store it into selected mailbox.',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    flags: Joi.array().items(Joi.string().max(128)).example(['\\Seen', '\\Draft']).default([]).description('Message flags').label('Flags'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is IMAP API specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    from: addressSchema.required().example({ name: 'From Me', address: 'sender@example.com' }),

                    to: Joi.array()
                        .items(addressSchema)
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(74).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers')
                }).label('MessageUpload')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string()
                        .example('AAAAAgAACrI')
                        .description('Message ID. NB! This and other fields might not be present if server did not provide enough information')
                        .label('MessageAppendId'),
                    path: Joi.string().example('INBOX').description('Folder this message was uploaded to').label('MessageAppendPath'),
                    uid: Joi.number().example(12345).description('UID of uploaded message'),
                    seq: Joi.number().example(12345).description('Sequence number of uploaded message')
                }).label('MessageUploadResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.updateMessage(request.params.message, request.payload);
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
            description: 'Update message',
            notes: 'Update message information. Mainly this means changing message flag values',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    flags: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new flags').example(['\\Seen']).label('AddFlags'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific flags').example(['\\Flagged']).label('DeleteFlags'),
                        set: Joi.array().items(Joi.string().max(128)).description('Override all flags').example(['\\Seen', '\\Flagged']).label('SetFlags')
                    })
                        .description('Flag updates')
                        .label('FlagUpdate'),

                    labels: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new labels').example(['Some label']).label('AddLabels'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific labels').example(['Some label']).label('DeleteLabels'),
                        set: Joi.array()
                            .items(Joi.string().max(128))
                            .description('Override all labels')
                            .example(['First label', 'Second label'])
                            .label('SetLabels')
                    })
                        .description('Label updates')
                        .label('LabelUpdate')
                }).label('MessageUpdate')
            },
            response: {
                schema: Joi.object({
                    flags: Joi.object({
                        add: Joi.boolean().example(true),
                        delete: Joi.boolean().example(false),
                        set: Joi.boolean().example(false)
                    }).label('FlagResponse'),
                    labels: Joi.object({
                        add: Joi.boolean().example(true),
                        delete: Joi.boolean().example(false),
                        set: Joi.boolean().example(false)
                    }).label('FlagResponse')
                }).label('MessageUpdateReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}/move',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.moveMessage(request.params.message, request.payload);
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
            description: 'Move message',
            notes: 'Move message to another folder',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path')
                }).label('MessageMove')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),
                    id: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID'),
                    uid: Joi.number().example(12345).description('UID of moved message')
                }).label('MessageMoveResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.deleteMessage(request.params.message);
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
            description: 'Delete message',
            notes: 'Move message to Trash or delete it if already in Trash',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }).label('MessageDelete')
            },
            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(true).description('Present if message was actualy deleted'),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),
                        messageId: Joi.string().required().example('AAAAAwAAAWg').description('Message ID in Trash').label('TrashMessageId')
                    }).description('Present if message was moved to Trash')
                }).label('MessageDeleteReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/text/{text}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.getText(request.params.text, request.query);
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
            description: 'Retrieve message text',
            notes: 'Retrieves message text',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(MAX_ATTACHMENT_SIZE)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .default('*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default all contents are returned.')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    text: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcdfaaN')
                        .description('Message text ID')
                }).label('Text')
            },

            response: {
                schema: Joi.object({
                    plain: Joi.string().example('Hello world').description('Plaintext content'),
                    html: Joi.string().example('<p>Hello world</p>').description('HTML content'),
                    hasMore: Joi.boolean().example(false).description('Is the current text output capped or not')
                }).label('TextResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/messages',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });
            try {
                return await accountObject.listMessages(request.query);
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
            description: 'List messages in a folder',
            notes: 'Lists messages in a mailbox folder',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID').label('AccountId')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Mailbox folder path').label('Path'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('MessageQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/search',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });
            try {
                return await accountObject.listMessages(Object.assign(request.query, request.payload));
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
            description: 'Search for messages',
            notes: 'Filter messages from a mailbox folder by search options. Search is performed against a specific foldera and not for the entire account.',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Mailbox folder path'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page')
                }),

                payload: Joi.object({
                    search: Joi.object({
                        seq: Joi.string().max(256).description('Sequence number range'),

                        answered: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is answered or not')
                            .label('AnsweredFlag'),
                        deleted: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked for being deleted or not')
                            .label('DeletedFlag'),
                        draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is a draft').label('DraftFlag'),
                        unseen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as unseen or not')
                            .label('UnseenFlag'),
                        flagged: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is flagged or not')
                            .label('Flagged'),
                        seen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as seen or not')
                            .label('SeenFlag'),

                        from: Joi.string().max(256).description('Match From: header').label('From'),
                        to: Joi.string().max(256).description('Match To: header').label('To'),
                        cc: Joi.string().max(256).description('Match Cc: header').label('Cc'),
                        bcc: Joi.string().max(256).description('Match Bcc: header').label('Bcc'),

                        body: Joi.string().max(256).description('Match text body').label('MessageBody'),
                        subject: Joi.string().max(256).description('Match message subject').label('Subject'),

                        larger: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages larger than value')
                            .label('MessageLarger'),

                        smaller: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages smaller than value')
                            .label('MessageSmaller'),

                        uid: Joi.string().max(256).description('UID range').label('UIDRange'),

                        modseq: Joi.number().min(0).description('Matches messages with modseq higher than value').label('ModseqLarger'),

                        before: Joi.date().description('Matches messages received before date').label('EnvelopeBefore'),
                        since: Joi.date().description('Matches messages received after date').label('EnvelopeSince'),

                        sentBefore: Joi.date().description('Matches messages sent before date').label('HeaderBefore'),
                        sentSince: Joi.date().description('Matches messages sent after date').label('HeaderSince'),

                        emailId: Joi.string().max(256).description('Match specific Gmail unique email UD'),
                        threadId: Joi.string().max(256).description('Match specific Gmail unique thread UD'),

                        header: Joi.object().unknown(true).description('Headers to match against').label('Headers')
                    })
                        .required()
                        .description('Search query to filter messages')
                        .label('SearchQuery')
                }).label('SearchQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/contacts',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });
            try {
                return await accountObject.buildContacts();
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
            description: 'Builds a contact listing',
            notes: 'Builds a contact listings from email addresses. For larger mailboxes this could take a lot of time.',
            tags: [/*'api', */ 'experimental'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/submit',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: ENCRYPT_PASSWORD });

            try {
                return await accountObject.submitMessage(request.payload);
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
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Submit message for delivery',
            notes: 'Submit message for delivery. If reference message ID is provided then IMAP API adds all headers and flags required for a reply/forward automatically.',
            tags: ['api', 'submit'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is IMAP API specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    from: addressSchema.required().example({ name: 'From Me', address: 'sender@example.com' }),

                    to: Joi.array()
                        .items(addressSchema)
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('ToAddressList'),

                    cc: Joi.array().items(addressSchema).description('List of addresses').label('CcAddressList'),

                    bcc: Joi.array().items(addressSchema).description('List of addresses').label('BccAddressList'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(74).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers')
                }).label('SubmitMessage')
            },

            response: {
                schema: Joi.object({
                    response: Joi.string().example('250 2.0.0 OK  1618577221 l6sm992285lfp.13 - gsmtp').description('Response from SMTP server'),
                    messageId: Joi.string().example('<a2184d08-a470-fec6-a493-fa211a3756e9@example.com>').description('Message-ID header value')
                }).label('SubmitMessageResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/settings',

        async handler(request) {
            let values = {};
            for (let key of Object.keys(request.query)) {
                if (request.query[key]) {
                    if (key === 'eventTypes') {
                        values[key] = Object.keys(consts)
                            .map(key => {
                                if (/_NOTIFY?/.test(key)) {
                                    return consts[key];
                                }
                                return false;
                            })
                            .map(key => key);
                        continue;
                    }

                    let value = await settings.get(key);

                    if (settings.encryptedKeys.includes(key)) {
                        // do not reveal secret values
                        // instead show boolean value true if value is set, or false if it's not
                        value = value ? true : false;
                    }

                    values[key] = value;
                }
            }
            return values;
        },
        options: {
            description: 'List specific settings',
            notes: 'List setting values for specific keys',
            tags: ['api', 'settings'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object(settingsQuerySchema).label('SettingsQuery')
            },

            response: {
                schema: Joi.object(settingsSchema).label('SettingsQueryResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/settings',

        async handler(request) {
            let updated = [];
            for (let key of Object.keys(request.payload)) {
                switch (key) {
                    case 'logs': {
                        let logs = request.payload.logs;
                        let resetLoggedAccounts = logs.resetLoggedAccounts;
                        delete logs.resetLoggedAccounts;
                        if (resetLoggedAccounts && logs.accounts && logs.accounts.length) {
                            for (let account of logs.accounts) {
                                logger.info({ msg: 'Request reconnect for logging', account });
                                try {
                                    await call({ cmd: 'update', account });
                                } catch (err) {
                                    logger.error({ action: 'request_reconnect', account, err });
                                }
                            }
                        }
                    }
                }

                await settings.set(key, request.payload[key]);
                updated.push(key);
            }

            notify('settings', request.payload);
            return { updated };
        },
        options: {
            description: 'Set setting values',
            notes: 'Set setting values for specific keys',
            tags: ['api', 'settings'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object(settingsSchema).label('Settings')
            },

            response: {
                schema: Joi.object({ updated: Joi.array().items(Joi.string().example('notifyHeaders')).description('List of updated setting keys') }).label(
                    'SettingsResponse'
                ),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/logs/{account}',

        async handler(request) {
            return getLogs(request.params.account);
        },
        options: {
            description: 'Return IMAP logs for an account',
            notes: 'Output is a downloadable text file',
            tags: ['api', 'logs'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/stats',

        async handler(request) {
            return await getStats(request.query.seconds);
        },
        options: {
            description: 'Return server stats',
            tags: ['api', 'stats'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    seconds: Joi.number()
                        .empty('')
                        .min(0)
                        .max(consts.MAX_DAYS_STATS * 24 * 3600)
                        .default(3600)
                        .example(3600)
                        .description('Duration for counters')
                        .label('CounterSeconds')
                }).label('ServerStats')
            },

            response: {
                schema: Joi.object({
                    version: Joi.string().example(packageData.version).description('IMAP API version number'),
                    license: Joi.string().example(packageData.license).description('IMAP API license'),
                    accounts: Joi.number().example(26).description('Number of registered accounts'),
                    connections: Joi.object({
                        init: Joi.number().example(2).description('Accounts not yet initialized'),
                        connected: Joi.number().example(8).description('Successfully connected accounts'),
                        connecting: Joi.number().example(7).description('Connection is being established'),
                        authenticationError: Joi.number().example(3).description('Authentication failed'),
                        connectError: Joi.number().example(5).description('Connection failed due to technical error'),
                        unset: Joi.number().example(0).description('Accounts without valid IMAP settings'),
                        disconnected: Joi.number().example(1).description('IMAP connection was closed')
                    })
                        .description('Counts of accounts in different connection states')
                        .label('ConnectionsStats'),
                    counters: Joi.object().label('CounterStats')
                }).label('SettingsResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/verifyAccount',

        async handler(request) {
            try {
                return await verifyAccountInfo(request.payload);
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
            description: 'Verify IMAP and SMTP settings',
            notes: 'Checks if can connect and authenticate using provided account info',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    mailboxes: Joi.boolean().example(false).description('Include mailbox listing in response').default(false),
                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAP'),
                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SMTP')
                }).label('VerifyAccount')
            },
            response: {
                schema: Joi.object({
                    imap: Joi.object({
                        success: Joi.boolean().example(true).description('Was IMAP account verified').label('VerifyImapSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for IMAP verification. Only present if success=false')
                            .label('VerifyImapError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifyImapCode')
                    }),
                    smtp: Joi.object({
                        success: Joi.boolean().example(true).description('Was SMTP account verified').label('VerifySmtpSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for SMTP verification. Only present if success=false')
                            .label('VerifySmtpError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifySmtpCode')
                    }),
                    mailboxes: shortMailboxesSchema
                }).label('VerifyAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/metrics',
        async handler(request, h) {
            const renderedMetrics = await call({ cmd: 'metrics' });
            const response = h.response('success');
            response.type('text/plain');
            return renderedMetrics;
        }
    });

    server.route({
        method: '*',
        path: '/{any*}',
        async handler() {
            throw Boom.notFound('Requested page not found'); // 404
        }
    });

    await server.start();
};

function getLogs(account) {
    let logKey = `iam:${account}:g`;
    let passThrough = new PassThrough();

    redis
        .lrangeBuffer(logKey, 0, -1)
        .then(rows => {
            if (!rows || !Array.isArray(rows) || !rows.length) {
                return passThrough.end(`No logs found for ${account}\n`);
            }
            let processNext = () => {
                if (!rows.length) {
                    return passThrough.end();
                }

                let row = rows.shift();
                let entry;
                try {
                    entry = msgpack.decode(row);
                } catch (err) {
                    entry = { error: err.stack };
                }

                if (entry) {
                    if (!passThrough.write(JSON.stringify(entry) + '\n')) {
                        return passThrough.once('drain', processNext);
                    }
                }

                setImmediate(processNext);
            };

            processNext();
        })
        .catch(err => {
            passThrough.end(`\nFailed to process logs\n${err.stack}\n`);
        });

    return passThrough;
}

async function verifyAccountInfo(accountData) {
    let response = {};

    if (accountData.imap) {
        try {
            let imapClient = new ImapFlow(
                Object.assign(
                    {
                        verifyOnly: true,
                        includeMailboxes: accountData.mailboxes
                    },
                    accountData.imap
                )
            );

            let mailboxes = await new Promise((resolve, reject) => {
                imapClient.on('error', err => {
                    reject(err);
                });
                imapClient
                    .connect()
                    .then(() => resolve(imapClient._mailboxList))
                    .catch(reject);
            });

            response.imap = {
                success: !!imapClient.authenticated
            };

            if (accountData.mailboxes && mailboxes && mailboxes.length) {
                // format mailbox listing
                let mailboxList = [];
                for (let entry of mailboxes) {
                    let mailbox = {};
                    Object.keys(entry).forEach(key => {
                        if (['path', 'specialUse', 'name', 'listed', 'subscribed', 'delimiter'].includes(key)) {
                            mailbox[key] = entry[key];
                        }
                    });
                    if (mailbox.delimiter && mailbox.path.indexOf(mailbox.delimiter) >= 0) {
                        mailbox.parentPath = mailbox.path.substr(0, mailbox.path.lastIndexOf(mailbox.delimiter));
                    }
                    mailboxList.push(mailbox);
                }
                response.mailboxes = mailboxList;
            }
        } catch (err) {
            response.imap = {
                success: false,
                error: err.message,
                code: err.code,
                statusCode: err.statusCode
            };
        }
    }

    if (accountData.smtp) {
        try {
            let smtpClient = nodemailer.createTransport(Object.assign({}, accountData.smtp));
            response.smtp = {
                success: await smtpClient.verify()
            };
        } catch (err) {
            response.smtp = {
                success: false,
                error: err.message,
                code: err.code,
                statusCode: err.statusCode
            };
        }
    }

    return response;
}

async function getStats(seconds) {
    const structuredMetrics = await call({ cmd: 'structuredMetrics' });

    let counters = await getCounterValues(redis, seconds);

    let stats = Object.assign(
        {
            version: packageData.version,
            license: packageData.license,
            accounts: await redis.scard('ia:accounts'),
            counters
        },
        structuredMetrics
    );

    return stats;
}

init()
    .then(() => {
        logger.debug({
            msg: 'API server started',
            port: (process.env.API_PORT && Number(process.env.API_PORT)) || config.api.port,
            host: process.env.API_HOST || config.api.host,
            maxSize: MAX_ATTACHMENT_SIZE
        });
    })
    .catch(err => {
        logger.error(err);
        setImmediate(() => process.exit(3));
    });
