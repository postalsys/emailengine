'use strict';

const crypto = require('crypto');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { oauth2Apps, SERVICE_ACCOUNT_PROVIDERS } = require('../oauth2-apps');
const settings = require('../settings');
const { autodetectImapSettings } = require('../autodetect-imap-settings');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction, getSignedFormData, getLogs, verifyAccountInfo } = require('../tools');
const { handleError } = require('./route-helpers');

const {
    settingsSchema,
    accountSchemas,
    accountIdSchema,
    accountCountersSchema,
    accountPathSchema,
    lastErrorSchema,
    imapSchema,
    imapUpdateSchema,
    smtpSchema,
    smtpUpdateSchema,
    oauth2Schema,
    oauth2UpdateSchema,
    defaultAccountTypeSchema,
    shortMailboxesSchema
} = require('../schemas');

const { REDIS_PREFIX, MAX_FORM_TTL, NONCE_BYTES } = require('../consts');

/**
 * Validates that delegation fields are only used with OAuth2 accounts.
 */
function validateDelegationFields(payload) {
    const auth = payload.oauth2?.auth;
    const hasDelegation = auth?.delegatedUser || auth?.delegatedAccount;
    if (hasDelegation && !payload.oauth2?.provider) {
        throw Boom.badRequest('Delegation fields (delegatedUser, delegatedAccount) require oauth2.provider to be set');
    }
}

async function init(args) {
    const {
        server,
        call,
        documentsQueue,
        oauth2Schema: oauth2SchemaArg,
        imapSchema: imapSchemaArg,
        smtpSchema: smtpSchemaArg,
        CORS_CONFIG,
        AccountTypeSchema,
        OAuth2ProviderSchema,
        metrics
    } = args;

    // POST /v1/account - Create account
    server.route({
        method: 'POST',
        path: '/v1/account',

        async handler(request) {
            let accountObject = new Account({
                redis,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                if (request.payload.oauth2 && request.payload.oauth2.authorize) {
                    // redirect to OAuth2 consent screen

                    const oAuth2Client = await oauth2Apps.getClient(request.payload.oauth2.provider);

                    // Service providers use client_credentials - no interactive authorization
                    if (SERVICE_ACCOUNT_PROVIDERS.has(oAuth2Client.provider)) {
                        throw Boom.badRequest('Application-only OAuth providers do not support interactive authorization');
                    }

                    const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64url');

                    const accountData = request.payload;

                    if (accountData.oauth2.redirectUrl) {
                        accountData._meta = {
                            redirectUrl: accountData.oauth2.redirectUrl
                        };
                        delete accountData.oauth2.redirectUrl;
                    }

                    delete accountData.oauth2.authorize; // do not store this property
                    // store account data
                    await redis
                        .multi()
                        .set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData))
                        .expire(`${REDIS_PREFIX}account:add:${nonce}`, Math.floor(MAX_FORM_TTL / 1000))
                        .exec();

                    // Generate the url that will be used for the consent dialog.
                    let authorizeUrl;
                    switch (oAuth2Client.provider) {
                        case 'gmail': {
                            let requestData = {
                                state: `account:add:${nonce}`
                            };

                            if (accountData.email) {
                                requestData.email = accountData.email;
                            }

                            authorizeUrl = oAuth2Client.generateAuthUrl(requestData);

                            break;
                        }

                        case 'outlook':
                        case 'mailRu':
                            authorizeUrl = oAuth2Client.generateAuthUrl({
                                state: `account:add:${nonce}`
                            });
                            break;

                        default: {
                            let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
                            throw error;
                        }
                    }

                    return {
                        redirect: authorizeUrl
                    };
                }

                // Validate delegation fields are only used with OAuth2 provider
                validateDelegationFields(request.payload);

                let result = await accountObject.create(request.payload);
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Register new account',
            notes: 'Registers new IMAP account to be synced',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string()
                        .empty('')
                        .trim()
                        .max(256)
                        .allow(null)
                        .example('example')
                        .description(
                            'Account ID. If set to `null`, a unique ID will be generated automatically. If you provide an existing account ID, the settings for that account will be updated instead'
                        )
                        .required(),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description('Copy submitted messages to Sent folder. Set to `null` to unset and use provider specific default.'),

                    logs: Joi.boolean().example(false).description('Store recent logs').default(false),

                    notifyFrom: accountSchemas.notifyFrom.default('now'),
                    syncFrom: accountSchemas.syncFrom.default(null),

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imapIndexer: accountSchemas.imapIndexer,

                    imap: Joi.object(imapSchemaArg).allow(false).description('IMAP configuration').label('ImapConfiguration'),

                    smtp: Joi.object(smtpSchemaArg).allow(false).description('SMTP configuration').label('SmtpConfiguration'),

                    oauth2: Joi.object(oauth2SchemaArg).allow(false).description('OAuth2 configuration').label('OAuth2'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
                })
                    .label('CreateAccount')
                    .example({
                        account: 'example',
                        name: 'Nyan Cat',
                        email: 'nyan.cat@example.com',
                        imap: {
                            auth: {
                                user: 'nyan.cat',
                                pass: 'sercretpass'
                            },
                            host: 'mail.example.com',
                            port: 993,
                            secure: true
                        },
                        smtp: {
                            auth: {
                                user: 'nyan.cat',
                                pass: 'secretpass'
                            },
                            host: 'mail.example.com',
                            port: 465,
                            secure: true
                        }
                    })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    state: Joi.string()
                        .required()
                        .valid('existing', 'new')
                        .example('new')
                        .description('Is the account new or updated existing')
                        .label('CreateAccountState')
                }).label('CreateAccountResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account} - Update account
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // Validate delegation fields are only used with OAuth2 provider
                validateDelegationFields(request.payload);

                return await accountObject.update(request.payload);
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Update account info',
            notes: 'Updates account information',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description('Copy submitted messages to Sent folder. Set to `null` to unset and use provider specific default.'),

                    logs: Joi.boolean().example(false).description('Store recent logs'),

                    notifyFrom: accountSchemas.notifyFrom,
                    syncFrom: accountSchemas.syncFrom,

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.object(imapUpdateSchema).allow(false).description('IMAP configuration').label('IMAPUpdate'),
                    smtp: Joi.object(smtpUpdateSchema).allow(false).description('SMTP configuration').label('SMTPUpdate'),
                    oauth2: Joi.object(oauth2UpdateSchema).allow(false).description('OAuth2 configuration').label('OAuth2Update'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
                })
                    .label('UpdateAccount')
                    .example({
                        name: 'Nyan Cat',
                        email: 'nyan.cat@example.com',
                        imap: {
                            partial: true,
                            disabled: true
                        },
                        smtp: {
                            partial: true,
                            host: 'mail.example.com'
                        }
                    })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required()
                }).label('UpdateAccountResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/reconnect - Request reconnect
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/reconnect',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return { reconnect: await accountObject.requestReconnect(request.payload) };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Request reconnect',
            notes: 'Requests connection to be reconnected',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnect')
            },

            response: {
                schema: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Reconnection status')
                }).label('RequestReconnectResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/sync - Request syncing
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/sync',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return { sync: await accountObject.requestSync(request.payload) };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Request syncing',
            notes: 'Immediately trigger account syncing for IMAP accounts',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    sync: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only sync if true')
                }).label('RequestSync')
            },

            response: {
                schema: Joi.object({
                    sync: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Sync status')
                }).label('RequestSyncResponse'),
                failAction: 'log'
            }
        }
    });

    // DELETE /v1/account/{account} - Remove account
    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                documentsQueue,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.delete({ revoke: request.query.revoke });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove account',
            notes: "Stop processing and clear the account's cache. Pass revoke=true to also attempt revocation of the upstream OAuth2 grant at the provider before the account is removed.",

            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    revoke: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'If true, EmailEngine attempts to revoke the upstream OAuth2 grant at the provider before deleting the account. Currently supported for individual Gmail OAuth grants. For Gmail Workspace service-account integrations (gmailService), Outlook, and non-OAuth2 accounts the flag is a no-op. Revoke failures are logged and do not block deletion.'
                        )
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteAccountResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/flush - Request account flush
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/flush',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return { flush: await accountObject.flush(request.payload) };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Request account flush',
            notes: 'Deletes all email indexes from Redis and ElasticSearch and re-creates the index for that account. You can only run a single flush operation at a time, so you must wait until the previous flush has finished before initiating a new one.',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    flush: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only flush the account if true'),
                    notifyFrom: accountSchemas.notifyFrom.default('now'),
                    imapIndexer: accountSchemas.imapIndexer,
                    syncFrom: accountSchemas.syncFrom
                }).label('RequestFlush')
            },

            response: {
                schema: Joi.object({
                    flush: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Flush status')
                }).label('RequestFlushResponse'),
                failAction: 'log'
            }
        }
    });

    // GET /v1/accounts - List accounts
    server.route({
        method: 'GET',
        path: '/v1/accounts',

        async handler(request) {
            try {
                let accountObject = new Account({
                    redis,
                    account: request.params.account,
                    call,
                    secret: await getSecret(),
                    timeout: request.headers['x-ee-timeout']
                });

                return await accountObject.listAccounts(request.query.state, request.query.query, request.query.page, request.query.pageSize);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List accounts',
            notes: 'Lists registered accounts',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    state: Joi.string()
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState'),
                    query: Joi.string().example('user@example.com').description('Filter accounts by string match').label('AccountQuery')
                }).label('AccountsFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    accounts: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
                                name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                                email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),
                                type: AccountTypeSchema,
                                app: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                                state: Joi.string()
                                    .required()
                                    .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                                    .example('connected')
                                    .description('Account state')
                                    .label('AccountListState'),
                                webhooks: Joi.string()
                                    .uri({
                                        scheme: ['http', 'https'],
                                        allowRelative: false
                                    })
                                    .example('https://myservice.com/imap/webhooks')
                                    .description('Account-specific webhook URL'),
                                proxy: settingsSchema.proxyUrl,
                                smtpEhloName: settingsSchema.smtpEhloName,

                                counters: accountCountersSchema,

                                syncTime: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last sync time'),
                                lastError: lastErrorSchema.allow(null)
                            }).label('AccountResponseItem')
                        )
                        .label('AccountEntries')
                }).label('AccountsFilterResponse'),
                failAction: 'log'
            }
        }
    });

    // GET /v1/account/{account} - Get account info
    server.route({
        method: 'GET',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });
            try {
                let accountData = await accountObject.loadAccountData();

                // remove secrets
                for (let type of ['imap', 'smtp', 'oauth2']) {
                    if (accountData[type] && accountData[type].auth) {
                        for (let key of ['pass', 'accessToken', 'refreshToken']) {
                            if (key in accountData[type].auth) {
                                accountData[type].auth[key] = '******';
                            }
                        }
                    }

                    if (accountData[type]) {
                        for (let key of ['accessToken', 'refreshToken']) {
                            if (key in accountData[type]) {
                                accountData[type][key] = '******';
                            }
                        }
                    }
                }

                let result = {};

                for (let key of [
                    'account',
                    'name',
                    'email',
                    'copy',
                    'logs',
                    'notifyFrom',
                    'syncFrom',
                    'path',
                    'subconnections',
                    'webhooks',
                    'proxy',
                    'smtpEhloName',
                    'imapIndexer',
                    'imap',
                    'smtp',
                    'oauth2',
                    'state',
                    'smtpStatus',
                    'syncError',
                    'connections',
                    'webhooksCustomHeaders',
                    'locale',
                    'tz',
                    'outlookSubscription'
                ]) {
                    if (key in accountData) {
                        result[key] = accountData[key];
                    }
                }

                if (result.outlookSubscription) {
                    try {
                        let parsed = typeof result.outlookSubscription === 'string' ? JSON.parse(result.outlookSubscription) : result.outlookSubscription;
                        delete parsed.clientState;
                        result.outlookSubscription = parsed;
                    } catch (err) {
                        result.outlookSubscription = {};
                    }
                }

                // default false
                for (let key of ['logs']) {
                    result[key] = !!result[key];
                }

                // default null
                for (let key of ['notifyFrom', 'syncFrom', 'lastError', 'smtpStatus']) {
                    result[key] = result[key] || null;
                }

                let oauth2App;
                if (accountData.oauth2 && accountData.oauth2.provider) {
                    oauth2App = await oauth2Apps.get(accountData.oauth2.provider);

                    if (oauth2App) {
                        // Check if account is already marked as send-only
                        if (accountData.sendOnly) {
                            result.sendOnly = true;
                        } else {
                            result.type = oauth2App.provider;
                        }
                        if (oauth2App.id !== oauth2App.provider) {
                            result.app = oauth2App.id;
                        }
                        result.baseScopes = oauth2App.baseScope || 'imap';
                    } else {
                        result.type = 'oauth2';
                    }
                } else if (accountData.oauth2 && accountData.oauth2.auth && accountData.oauth2.auth.delegatedAccount) {
                    result.type = 'delegated';
                } else if (accountData.imap && !accountData.imap.disabled) {
                    result.type = 'imap';
                } else {
                    result.type = 'sending';
                    result.sendOnly = true;
                }

                if ((accountData.imap || (oauth2App && (!oauth2App.baseScopes || oauth2App.baseScopes === 'imap'))) && !result.imapIndexer) {
                    result.imapIndexer = 'full';
                }

                if (accountData.sync) {
                    result.syncTime = accountData.sync;
                }

                if (accountData.state) {
                    result.lastError = accountData.state === 'connected' ? null : accountData.lastErrorState;
                }

                if (accountData.counters) {
                    result.counters = accountData.counters;
                }

                if (request.query.quota && !result.sendOnly) {
                    result.quota = await accountObject.getQuota();
                }

                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Get account info',
            notes: 'Returns stored information about the account. Passwords are not included.',
            tags: ['api', 'Account'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    quota: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then include quota information in the response')
                        .label('AccountQuota')
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),

                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder'),
                    logs: Joi.boolean().example(false).description('Store recent logs'),

                    notifyFrom: accountSchemas.notifyFrom,
                    syncFrom: accountSchemas.syncFrom,

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    imapIndexer: accountSchemas.imapIndexer,

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),
                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAPResponse'),

                    smtp: Joi.object(smtpSchema).description('SMTP configuration').label('SMTPResponse'),

                    oauth2: Joi.object(oauth2Schema).description('OAuth2 configuration').label('Oauth2Response'),

                    state: Joi.string()
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Informational account state')
                        .label('AccountInfoState'),

                    smtpStatus: Joi.object({
                        created: Joi.date()
                            .iso()
                            .allow(null)
                            .example('2021-07-08T07:06:34.336Z')
                            .description('When was the status for SMTP connection last updated'),
                        status: Joi.string().valid('ok', 'error').description('Was the last SMTP attempt successful or not').label('SMTPStatusStatus'),
                        response: Joi.string().example('250 OK').description('SMTP response message for delivery attempt'),
                        description: Joi.string().example('Authentication failed').description('Error information'),
                        responseCode: Joi.number().integer().example(500).description('Error status code'),
                        code: Joi.string().example('EAUTH').description('Error type identifier'),
                        command: Joi.string().example('AUTH PLAIN').description('SMTP command that failed')
                    })
                        .description('Information about the last SMTP connection attempt')
                        .label('SMTPInfoStatus'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone'),

                    type: AccountTypeSchema,
                    app: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    baseScopes: Joi.string()
                        .empty('')
                        .trim()
                        .valid(...['imap', 'api', 'pubsub'])
                        .example('imap')
                        .description('OAuth2 Base Scopes')
                        .label('AccountBaseScopes'),

                    counters: accountCountersSchema,

                    quota: Joi.object({
                        usage: Joi.number().integer().example(8547884032).description('How many bytes has the account stored in emails'),
                        limit: Joi.number().integer().example(16106127360).description('How many bytes can the account store emails'),
                        status: Joi.string().example('53%').description('Textual information about the usage')
                    })
                        .label('AccountQuota')
                        .allow(false)
                        .description(
                            'Account quota information if query argument quota=true. This value will be false if the server does not provide quota information.'
                        ),

                    syncTime: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last sync time'),

                    outlookSubscription: Joi.object({
                        id: Joi.string().description('Microsoft Graph subscription ID'),
                        expirationDateTime: Joi.date().iso().description('When the subscription expires'),
                        state: Joi.object({
                            state: Joi.string().valid('creating', 'created', 'error').description('Subscription state'),
                            time: Joi.number().description('Timestamp of last state change'),
                            error: Joi.string().description('Error message if state is error')
                        }).description('Current subscription state')
                    }).description('Microsoft Graph subscription details (Outlook accounts only)'),

                    lastError: lastErrorSchema.allow(null)
                }).label('AccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/oauth-token',

        async handler(request) {
            let enableOAuthTokensApi = await settings.get('enableOAuthTokensApi');
            if (!enableOAuthTokensApi) {
                let error = Boom.boomify(new Error('Disabled API endpoint'), { statusCode: 403 });
                error.output.payload.code = 'ApiEndpointDisabled';
                throw error;
            }

            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                const tokenData = await accountObject.getActiveAccessTokenData();

                // Record metric if token was actually refreshed (not cached)
                if (!tokenData.cached) {
                    const provider = tokenData.provider || 'unknown';
                    metrics(request.logger, 'oauth2TokenRefresh', 'inc', { status: 'success', provider, statusCode: '200' });
                }

                return tokenData;
            } catch (err) {
                // Record failed token refresh
                const statusCode = String(err.statusCode || 0);
                metrics(request.logger, 'oauth2TokenRefresh', 'inc', { status: 'failure', provider: 'unknown', statusCode });

                handleError(request, err);
            }
        },

        options: {
            description: 'Get OAuth2 access token',
            notes: 'Get the active OAuth2 access token for an account. NB! This endpoint is disabled by default and needs activation on the Service configuration page.',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,
                params: Joi.object({
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    user: Joi.string().max(256).required().example('user@example.com').description('Username'),
                    accessToken: Joi.string().max(256).required().example('aGVsbG8gd29ybGQ=').description('Access Token').label('OAuthAccessToken'),
                    provider: OAuth2ProviderSchema
                }).label('AccountTokenResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/server-signatures',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });
            try {
                return await accountObject.listSignatures(request.query);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List Account Signatures',
            notes: 'Returns signatures associated with the account. Currently only Gmail is supported, and only "new message" signatures from the "sendAs" list are returned.',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,
                params: Joi.object({
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    signatures: Joi.array()
                        .items(
                            Joi.object({
                                address: Joi.string().email().example('user@example.com').description('Email address associated with the signature').required(),
                                signature: Joi.string().example('<div>Best regards,</div>').description('Signature HTML code').required()
                            }).label('SignatureResponseItem')
                        )
                        .label('SignatureEntries')
                }).label('AccountSignaturesResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/authentication/form',

        async handler(request) {
            try {
                let { data, signature } = await getSignedFormData({
                    account: request.payload.account,
                    name: request.payload.name,
                    email: request.payload.email,
                    syncFrom: request.payload.syncFrom,
                    notifyFrom: request.payload.notifyFrom,
                    subconnections: request.payload.subconnections,
                    redirectUrl: request.payload.redirectUrl,
                    delegated: request.payload.delegated,
                    path: request.payload.path && !request.payload.path.includes('*') ? request.payload.path : null,
                    // identify request
                    n: crypto.randomBytes(NONCE_BYTES).toString('base64url'),
                    t: Date.now()
                });

                let serviceUrl = await settings.get('serviceUrl');
                if (!serviceUrl) {
                    let err = new Error('Service URL not set up');
                    err.code = 'MissingServiceURLSetup';
                    throw err;
                }

                let url = new URL(`accounts/new`, serviceUrl);

                url.searchParams.append('data', data);
                if (signature) {
                    url.searchParams.append('sig', signature);
                }

                let type = request.payload.type;

                if (type && type !== 'imap') {
                    let oauth2app = await oauth2Apps.get(type);
                    if (!oauth2app || !oauth2app.enabled) {
                        type = false;
                    }
                }

                if (!type) {
                    let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);
                    if (!oauth2apps.length) {
                        type = 'imap';
                    }
                }

                if (type) {
                    url.searchParams.append('type', type);
                }

                return {
                    url: url.href
                };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Generate authentication link',
            notes: 'Generates a redirect link to the hosted authentication form',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string()
                        .empty('')
                        .trim()
                        .max(256)
                        .allow(null)
                        .example('example')
                        .default(null)
                        .description(
                            'Account ID. If set to `null`, a unique ID will be generated automatically. If you provide an existing account ID, the settings for that account will be updated instead'
                        ),

                    name: Joi.string().empty('').max(256).example('My Email Account').description('Display name for the account'),

                    email: Joi.string()
                        .empty('')
                        .email()
                        .example('user@example.com')
                        .description('Specifies the default email address for this account. Users can change it if needed.'),

                    delegated: Joi.boolean()
                        .empty('')
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, configures this account as a shared mailbox. Currently supported by MS365 OAuth2 accounts'),

                    syncFrom: accountSchemas.syncFrom,
                    notifyFrom: accountSchemas.notifyFrom,

                    subconnections: accountSchemas.subconnections,

                    path: accountPathSchema.example(['*']).label('AccountFormPath'),
                    redirectUrl: Joi.string()
                        .empty('')
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .required()
                        .example('https://myapp/account/settings.php')
                        .description('After the authentication process is completed, the user is redirected to this URL'),

                    type: defaultAccountTypeSchema
                }).label('RequestAuthForm')
            },

            response: {
                schema: Joi.object({
                    url: Joi.string()
                        .empty('')
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .required()
                        .example('https://ee.example.com/accounts/new?data=eyJhY2NvdW50IjoiZXhh...L0W_BkFH5HW6Krwmr7c&type=imap')
                        .description('Generated URL to the hosted authentication form')
                }).label('RequestAuthFormResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/logs/{account}',

        async handler(request) {
            return getLogs(redis, request.params.account);
        },
        options: {
            description: 'Return IMAP logs for an account',
            notes: 'Output is a downloadable text file',
            tags: ['api', 'Logs'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            plugins: {
                'hapi-swagger': {
                    produces: ['text/plain']
                }
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/verifyAccount',

        async handler(request) {
            try {
                return await verifyAccountInfo(redis, request.payload, request.logger.child({ action: 'verify-account' }));
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Verify IMAP and SMTP settings',
            notes: 'Checks if can connect and authenticate using provided account info',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    mailboxes: Joi.boolean().example(false).description('Include mailbox listing in response').default(false).label('IncludeMailboxes'),
                    imap: Joi.object(imapSchema).allow(false).description('IMAP configuration').label('ImapConfiguration'),
                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SmtpConfiguration'),
                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName
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
                    }).label('VerifyImapResult'),
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
                    }).label('VerifySmtpResult'),
                    mailboxes: shortMailboxesSchema
                }).label('VerifyAccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/autoconfig',

        async handler(request) {
            try {
                let serverSettings = await autodetectImapSettings(request.query.email, request.app.gt);
                return serverSettings;
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                return { imap: false, smtp: false, _source: 'unknown' };
            }
        },

        options: {
            description: 'Discover Email settings',
            notes: 'Try to discover IMAP and SMTP settings for an email account',
            tags: ['api', 'Settings'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    email: Joi.string()
                        .email()
                        .required()
                        .example('sender@example.com')
                        .description('Email address to discover email settings for')
                        .label('EmailAddress')
                }).label('AutodiscoverQuery')
            },

            response: {
                schema: Joi.object({
                    imap: Joi.object({
                        auth: Joi.object({
                            user: Joi.string().max(256).example('myuser@gmail.com').description('Account username')
                        }).label('DetectedAuthenticationInfo'),

                        host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                        port: Joi.number()
                            .integer()
                            .min(1)
                            .max(64 * 1024)
                            .required()
                            .example(993)
                            .description('Service port number'),
                        secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993')
                    }).label('ResolvedServerSettings'),
                    smtp: Joi.object({
                        auth: Joi.object({
                            user: Joi.string().max(256).example('myuser@gmail.com').description('Account username')
                        }).label('DetectedAuthenticationInfo'),

                        host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                        port: Joi.number()
                            .integer()
                            .min(1)
                            .max(64 * 1024)
                            .required()
                            .example(993)
                            .description('Service port number'),
                        secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993')
                    }).label('DiscoveredServerSettings'),
                    _source: Joi.string().example('srv').description('Source for the detected info')
                }).label('DiscoveredEmailSettings'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
