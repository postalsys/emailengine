'use strict';

const config = require('wild-config');
const Boom = require('@hapi/boom');
const consts = require('./consts');
const settings = require('./settings');
const tokens = require('./tokens');
const Joi = require('joi');
const {
    failAction,
    verifyAccountInfo,
    getLogs,
    flattenObjectKeys,
    getStats,
    getBoolean,
    getSignedFormData,
    readEnvValue,
    getServiceHostname,
    getByteSize,
    parseSignedFormData
} = require('./tools');
const packageData = require('../package.json');
const he = require('he');
const crypto = require('crypto');
const pbkdf2 = require('@phc/pbkdf2');
const { Account } = require('./account');
const { Gateway } = require('./gateway');
const { redis, submitQueue, notifyQueue, documentsQueue } = require('./db');
const psl = require('psl');
const { oauth2Apps, LEGACY_KEYS, OAUTH_PROVIDERS, oauth2ProviderData } = require('./oauth2-apps');
const { autodetectImapSettings } = require('./autodetect-imap-settings');
const getSecret = require('./get-secret');
const humanize = require('humanize');
const { resolvePublicInterfaces } = require('pubface');
const os = require('os');
const { ADDRESS_STRATEGIES, settingsSchema, templateSchemas, oauthCreateSchema, accountIdSchema } = require('./schemas');
const fs = require('fs');
const pathlib = require('path');
const timezonesList = require('timezones-list').default;
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
const { templates } = require('./templates');
const { webhooks } = require('./webhooks');
const { llmPreProcess } = require('./llm-pre-process');
const wellKnownServices = require('nodemailer/lib/well-known/services.json');
const { locales, gt } = require('./translations');
const capa = require('./capa');
const exampleWebhookPayloads = require('./payload-examples-webhooks.json');
const exampleDocumentsPayloads = require('./payload-examples-documents.json');
const { defaultMappings } = require('./es');
const { getESClient } = require('../lib/document-store');
const assert = require('assert');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');
const base32 = require('base32.js');
const { simpleParser } = require('mailparser');
const libmime = require('libmime');
const featureFlags = require('./feature-flags');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

const {
    DEFAULT_MAX_LOG_LINES,
    PDKDF2_ITERATIONS,
    PDKDF2_SALT_SIZE,
    PDKDF2_DIGEST,
    LOGIN_PERIOD_TTL,
    DEFAULT_PAGE_SIZE,
    REDIS_PREFIX,
    TOTP_WINDOW_SIZE,
    FETCH_TIMEOUT,
    DEFAULT_DELIVERY_ATTEMPTS,
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_MAX_PAYLOAD_TIMEOUT,
    MAX_FORM_TTL,
    NONCE_BYTES,
    ALLOWED_REDIS_LATENCY
} = consts;

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1',
    proxy: false
};

const MAX_BODY_SIZE = getByteSize(readEnvValue('EENGINE_MAX_BODY_SIZE') || config.api.maxBodySize) || DEFAULT_MAX_BODY_SIZE;
const MAX_PAYLOAD_TIMEOUT = getByteSize(readEnvValue('EENGINE_MAX_PAYLOAD_TIMEOUT') || config.api.maxPayloadTimeout) || DEFAULT_MAX_PAYLOAD_TIMEOUT;

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const LICENSE_HOST = 'https://postalsys.com';
const SMTP_TEST_HOST = 'https://api.nodemailer.com';

const OPEN_AI_MODELS = [
    {
        name: 'GPT-3 (instruct)',
        id: 'gpt-3.5-turbo-instruct'
    },

    {
        name: 'GPT-3 (chat)',
        id: 'gpt-3.5-turbo'
    },

    {
        name: 'GPT-4',
        id: 'gpt-4'
    }
];

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

const cachedTemplates = {
    addressList: fs.readFileSync(pathlib.join(__dirname, '..', 'views', 'partials', 'address_list.hbs'), 'utf-8'),
    testSend: fs.readFileSync(pathlib.join(__dirname, '..', 'views', 'partials', 'test_send.hbs'), 'utf-8')
};

const getOpenAiModels = async (models, selectedModel) => {
    let modelList = (await settings.get('openAiModels')) || pfStructuredClone(models);

    if (selectedModel && !modelList.find(model => model.id === selectedModel)) {
        modelList.unshift({
            name: selectedModel,
            id: selectedModel
        });
    }

    return modelList.map(model => {
        model.selected = model.id === selectedModel;
        return model;
    });
};

const FIELD_TYPES = [
    {
        type: 'keyword',
        name: 'Keyword – for exact matches'
    },
    {
        type: 'text',
        name: 'Text – for fulltext search'
    },
    {
        type: 'html',
        name: 'HTML – a text field with HTML analyzer (does not index HTML tags)'
    },
    {
        type: 'filename',
        name: 'File name – a text field with filename analyzer (ngram)'
    },
    {
        type: 'boolean',
        name: 'Boolean'
    },
    {
        type: 'date',
        name: 'Date – date and date-time values'
    },
    {
        type: 'long',
        name: 'Number, long – from -2^63 to 2^63-1'
    },
    {
        type: 'integer',
        name: 'Number, integer – from -2^31 to 2^31-1'
    },
    {
        type: 'short',
        name: 'Number, short – from -32,768 to 32,767'
    },
    {
        type: 'byte',
        name: 'Number, short – from -128 to 127'
    },
    {
        type: 'double',
        name: 'Number, double – a double-precision 64-bit IEEE 754 floating point number'
    }
];

const defaultMappingsList = Object.keys(defaultMappings)
    .map(key => {
        let type = defaultMappings[key].type || (defaultMappings[key].properties ? 'object' : 'text');
        if (defaultMappings[key].analyzer === 'htmlStripAnalyzer') {
            type += ' (HTML)';
        }
        if (defaultMappings[key].analyzer === 'filenameIndex') {
            type += ' (filename)';
        }
        return {
            key,
            type,
            indexed: defaultMappings[key].index !== false
        };
    })
    .sort((a, b) => a.key.toLowerCase().localeCompare(b.key.toLowerCase()));

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
    notifyWebSafeHtml: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyTextSize: Joi.number().integer().empty(''),
    notifyCalendarEvents: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    inboxNewOnly: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

    customHeaders: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .description('Custom request headers')
};

for (let type of notificationTypes) {
    configWebhooksSchema[`notify_${type.name}`] = Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false);
}

const configSmtpSchema = {
    smtpServerEnabled: settingsSchema.smtpServerEnabled.default(false),
    smtpServerPassword: settingsSchema.smtpServerPassword.default(null),
    smtpServerAuthEnabled: settingsSchema.smtpServerAuthEnabled.default(false),
    smtpServerPort: settingsSchema.smtpServerPort,
    smtpServerHost: settingsSchema.smtpServerHost.default('0.0.0.0'),
    smtpServerProxy: settingsSchema.smtpServerProxy.default(false),
    smtpServerTLSEnabled: settingsSchema.smtpServerTLSEnabled.default(false)
};

const configImapProxySchema = {
    imapProxyServerEnabled: settingsSchema.imapProxyServerEnabled.default(false),
    imapProxyServerPassword: settingsSchema.imapProxyServerPassword.default(null),
    imapProxyServerPort: settingsSchema.imapProxyServerPort,
    imapProxyServerHost: settingsSchema.imapProxyServerHost.default('0.0.0.0'),
    imapProxyServerProxy: settingsSchema.imapProxyServerProxy.default(false),
    imapProxyServerTLSEnabled: settingsSchema.imapProxyServerTLSEnabled.default(false)
};

const configDocumentStoreSchema = {
    documentStoreEnabled: settingsSchema.documentStoreEnabled.default(false),
    documentStoreUrl: settingsSchema.documentStoreUrl.default(''),
    documentStoreIndex: settingsSchema.documentStoreIndex.default('emailengine'),
    documentStoreAuthEnabled: settingsSchema.documentStoreAuthEnabled.default(false),
    documentStoreUsername: settingsSchema.documentStoreUsername.default(''),
    documentStorePassword: settingsSchema.documentStorePassword
};

const configLoggingSchema = {
    all: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable logs for all accounts'),
    maxLogLines: Joi.number().integer().empty('').min(0).max(10000000).default(DEFAULT_MAX_LOG_LINES)
};

const OKTA_OAUTH2_ISSUER = readEnvValue('OKTA_OAUTH2_ISSUER');
const OKTA_OAUTH2_CLIENT_ID = readEnvValue('OKTA_OAUTH2_CLIENT_ID');
const OKTA_OAUTH2_CLIENT_SECRET = readEnvValue('OKTA_OAUTH2_CLIENT_SECRET');
const USE_OKTA_AUTH = !!(OKTA_OAUTH2_ISSUER && OKTA_OAUTH2_CLIENT_ID && OKTA_OAUTH2_CLIENT_SECRET);

const CODE_FORMATS = [
    {
        format: 'html',
        name: 'HTML'
    },
    {
        format: 'mjml',
        name: 'MJML'
    },
    {
        format: 'markdown',
        name: 'Markdown'
    }
];

const oauthUpdateSchema = {
    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required(),

    provider: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .valid(...Object.keys(OAUTH_PROVIDERS))
        .example('gmail')
        .required()
        .description('OAuth2 provider'),

    name: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .example('My Gmail App')
        .description('Application name')
        .when('app', {
            not: Joi.string().valid(...LEGACY_KEYS),
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        }),
    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Application description'),

    title: Joi.string().allow('').trim().max(256).example('App title').description('Title for the application button'),

    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable this app'),

    clientId: Joi.string()
        .trim()
        .allow('')
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Client ID'),

    clientSecret: Joi.string()
        .trim()
        .empty('', false, null)
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description('OAuth2 Client Secret'),

    baseScopes: Joi.string()
        .empty('')
        .trim()
        .valid(...['imap'].concat(featureFlags.enabled('gmail api') ? 'api' : []))
        .example('imap')
        .description('OAuth2 Base Scopes'),

    extraScopes: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .description('OAuth2 Extra Scopes'),

    skipScopes: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .description('OAuth2 scopes to skip from the base set'),

    serviceClient: Joi.string()
        .trim()
        .allow('')
        .max(256)
        .when('provider', {
            is: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Service Client ID'),

    serviceKey: Joi.string()
        .trim()
        .empty('', false, null)
        .max(100 * 1024)
        .when('provider', {
            is: 'gmailService',
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description('OAuth2 Secret Service Key'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .when('provider', {
            is: 'outlook',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example(false)
        .label('SupportedAccountTypes'),

    redirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Callback URL')
};

function formatAccountData(account) {
    account.type = {};

    if (account.oauth2 && account.oauth2.app) {
        account.type = oauth2ProviderData(account.oauth2.app.provider);
    } else if (account.oauth2 && account.oauth2.provider) {
        account.type = oauth2ProviderData(account.oauth2.provider);
    } else if (account.imap && !account.imap.disabled) {
        account.type.icon = 'fa fa-envelope-square';
        account.type.name = 'IMAP';
        account.type.comment = psl.get(account.imap.host) || account.imap.host;
    } else if (account.smtp) {
        account.type.icon = 'fa fa-paper-plane';
        account.type.name = 'SMTP';
        account.type.comment = psl.get(account.smtp.host) || account.smtp.host;
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

        case 'authenticationError':
        case 'connectError': {
            let errorMessage = account.lastErrorState ? account.lastErrorState.response : false;
            if (account.lastErrorState) {
                switch (account.lastErrorState.serverResponseCode) {
                    case 'ETIMEDOUT':
                        errorMessage = 'Connection timed out. This usually happens when you are firewalled, for example are connecting to a wrong port.';
                        break;
                    case 'ClosedAfterConnectTLS':
                        errorMessage = 'Server unexpectedly closed the connection.';
                        break;
                    case 'ClosedAfterConnectText':
                        errorMessage =
                            'The server unexpectedly closed the connection. This usually happens when you try to connect to a TLS port without having TLS enabled.';
                        break;
                    case 'ECONNREFUSED':
                        errorMessage =
                            'The server refused the connection. This usually happens when the server is not running, is overloaded, or you are connecting to a wrong host or port.';
                        break;
                }
            }

            account.stateLabel = {
                type: 'danger',
                name: 'Failed',
                error: errorMessage
            };
            break;
        }
        case 'unset':
            account.stateLabel = {
                type: 'light',
                name: 'Not syncing'
            };
            break;
        case 'disconnected':
            account.stateLabel = {
                type: 'warning',
                name: 'Disconnected'
            };
            break;
        case 'paused':
            account.stateLabel = {
                type: 'secondary',
                name: 'Paused'
            };
            break;
        default:
            account.stateLabel = {
                type: 'secondary',
                name: 'N/A'
            };
            break;
    }

    if (account.oauth2) {
        account.oauth2.scopes = []
            .concat(account.oauth2.scope || [])
            .concat(account.oauth2.scopes || [])
            .flatMap(entry => entry.split(/\s+/))
            .map(entry => entry.trim())
            .filter(entry => entry);

        account.oauth2.expiresStr = account.oauth2.expires ? account.oauth2.expires.toISOString() : false;
    }

    return account;
}

function formatServerState(state, payload) {
    switch (state) {
        case 'suspended':
        case 'exited':
        case 'disabled':
            return {
                type: 'warning',
                name: state
            };

        case 'spawning':
        case 'initializing':
            return {
                type: 'info',
                name: state,
                spinner: true
            };

        case 'listening':
            return {
                type: 'success',
                name: state
            };

        case 'failed':
            return {
                type: 'danger',
                name: state,
                error: (payload && payload.error && payload.error.message) || null
            };

        default:
            return {
                type: 'secondary',
                name: 'N/A'
            };
    }
}

async function updatePublicInterfaces() {
    let interfaces = await resolvePublicInterfaces();

    for (let iface of interfaces) {
        if (!iface.localAddress) {
            continue;
        }

        if (iface.defaultInterface) {
            await redis.hset(`${REDIS_PREFIX}interfaces`, `default:${iface.family}`, iface.localAddress);
        }

        let existingEntry = await redis.hget(`${REDIS_PREFIX}interfaces`, iface.localAddress);
        if (existingEntry) {
            try {
                existingEntry = JSON.parse(existingEntry);

                iface.name = iface.name || existingEntry.name;

                if (!iface.localAddress || !iface.ip || !iface.name) {
                    // not much point in updating
                    continue;
                }
            } catch (err) {
                // ignore?
            }
        }

        delete iface.defaultInterface;
        await redis.hset(`${REDIS_PREFIX}interfaces`, iface.localAddress, JSON.stringify(iface));
    }
}

async function getOpenAiError() {
    let openAiError = await redis.get(`${REDIS_PREFIX}:openai:error`);
    if (openAiError) {
        try {
            openAiError = JSON.parse(openAiError);
            switch (openAiError.code) {
                case 'invalid_api_key':
                    openAiError.message = gt.gettext('Invalid API key for OpenAI');
                    break;
            }
        } catch (err) {
            openAiError = null;
        }
    }
    return openAiError;
}

async function getExampleWebhookPayloads() {
    let serviceUrl = await settings.get('serviceUrl');
    let date = new Date().toISOString();

    let examplePayloads = pfStructuredClone(exampleWebhookPayloads);

    examplePayloads.forEach(payload => {
        if (payload && payload.content) {
            if (typeof payload.content.serviceUrl === 'string') {
                payload.content.serviceUrl = serviceUrl;
            }

            if (typeof payload.content.date === 'string') {
                payload.content.date = date;
            }

            if (payload.content.data && typeof payload.content.data.date === 'string') {
                payload.content.data.date = date;
            }

            if (payload.content.data && typeof payload.content.data.created === 'string') {
                payload.content.data.created = date;
            }
        }
    });
    return examplePayloads;
}

async function getExampleDocumentsPayloads() {
    let date = new Date().toISOString();

    let examplePayloads = pfStructuredClone(exampleDocumentsPayloads);

    examplePayloads.forEach(payload => {
        if (payload && payload.content) {
            if (typeof payload.content.date === 'string') {
                payload.content.date = date;
            }

            if (typeof payload.content.created === 'string') {
                payload.content.created = date;
            }
        }
    });
    return examplePayloads;
}

async function getMailboxListing(accountObject) {
    let mailboxes = [
        {
            path: 'INBOX',
            listed: true,
            specialUse: '\\Inbox',
            name: 'INBOX',
            subscribed: true
        }
    ];

    try {
        mailboxes = await accountObject.getMailboxListing();
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
    } catch (err) {
        // failed to get mailbox list
    }

    return mailboxes;
}

async function listPublicInterfaces(selectedAddresses) {
    let existingAddresses = Object.values(os.networkInterfaces())
        .flatMap(entry => entry)
        .map(entry => entry.address);

    let entries = await redis.hgetall(`${REDIS_PREFIX}interfaces`);

    let defaultInterfaces = {};

    let addresses = Object.keys(entries)
        .map(key => {
            if (/^default:/.test(key)) {
                let family = key.split(':').pop();
                defaultInterfaces[family] = entries[key];
                return false;
            }

            let entry = entries[key];
            try {
                return JSON.parse(entry);
            } catch (err) {
                return false;
            }
        })
        .filter(entry => entry && entry.family === 'IPv4')
        .map(entry => entry);

    addresses.forEach(address => {
        if (address.localAddress === defaultInterfaces[address.family]) {
            address.defaultInterface = true;
        }

        if (selectedAddresses && selectedAddresses.includes(address.localAddress)) {
            address.checked = true;
        }

        if (!existingAddresses.includes(address.localAddress)) {
            address.notice = 'This address was not found from the current interface listing';
        }
    });

    return addresses.sort((a, b) => {
        if (a.family !== b.family) {
            return a.family.localeCompare(b.family);
        }
        if (a.defaultInterface) {
            return -1;
        }
        if (b.defaultInterface) {
            return 1;
        }
        return (a.name || a.ip).localeCompare(b.name || b.ip);
    });
}

async function getServerStatus(type) {
    let serverStatus = await redis.hgetall(`${REDIS_PREFIX}${type}`);
    let state = (serverStatus && serverStatus.state) || 'disabled';
    let payload;
    try {
        payload = (serverStatus && typeof serverStatus.payload === 'string' && JSON.parse(serverStatus.payload)) || {};
    } catch (err) {
        // ignore
    }

    return { state, payload, label: formatServerState(state, payload) };
}

function applyRoutes(server, call) {
    const getDefaultPrompt = async () =>
        await call({
            cmd: 'openAiDefaultPrompt'
        });

    server.route({
        method: 'GET',
        path: '/admin',
        async handler(request, h) {
            let stats = await getStats(redis, call, request.query.seconds || 24 * 3600);

            let counterList = [
                {
                    key: 'events:messageNew',
                    title: 'New emails',
                    color: 'primary',
                    icon: 'envelope',
                    comment: 'Detected new emails in IMAP mailboxes.'
                },
                {
                    key: 'webhooks:success',
                    title: 'Webhooks sent',
                    color: 'primary',
                    icon: 'network-wired',
                    comment: 'Count of successfully delivered webhooks.'
                },
                {
                    key: 'webhooks:fail',
                    title: 'Webhooks failed',
                    color: 'danger',
                    icon: 'network-wired',
                    comment: 'Count of webhooks that failed to deliver.'
                },
                {
                    key: 'submit:success',
                    title: 'Emails sent',
                    color: 'primary',
                    icon: 'mail-bulk',
                    comment: 'Count of emails sent to MTA servers.'
                },
                {
                    key: 'submit:fail',
                    title: 'Emails rejected',
                    color: 'danger',
                    icon: 'mail-bulk',
                    comment: 'Count of emails rejected by MTA servers.'
                },
                {
                    key: 'apiCall:success',
                    title: 'Successful API calls',
                    color: 'primary',
                    icon: 'file-code',
                    comment: 'Successful API calls with positive responses.'
                },
                {
                    key: 'apiCall:fail',
                    title: 'Failed API calls',
                    color: 'danger',
                    icon: 'file-code',
                    comment: 'API calls that returned error responses.'
                }
            ];

            for (let counter of counterList) {
                counter.value = humanize.numberFormat(stats.counters[counter.key] || 0, 0, '.', ' ');
            }

            let hasAccounts = !!stats.accounts;
            stats.accounts = humanize.numberFormat(stats.accounts || 0, 0, '.', ' ');
            stats.connectedAccounts = humanize.numberFormat((stats.connections.connected || 0) + (stats.connections.syncing || 0), 0, '.', ' ');

            return h.view(
                'dashboard',
                {
                    menuDashboard: true,
                    stats,
                    counterList,
                    hasAccounts,

                    isElastiCache: ['elasticache'].includes(stats.redisSoftware),
                    isRedisCluster: stats.redisCluster,

                    redisPing: {
                        key: 'redisPing',
                        title: 'Redis Latency',
                        color: typeof stats.redisPing !== 'number' ? 'warning' : stats.redisPing < ALLOWED_REDIS_LATENCY ? 'success' : 'danger',
                        icon: 'clock',
                        comment: 'How many milliseconds does it take to run a Redis command',
                        value: typeof stats.redisPing !== 'number' ? '\u2013' : humanize.numberFormat(stats.redisPing / 1000000, 3, '.', ' ')
                    }
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
                    menuSwagger: true,
                    iframePage: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/arena',
        async handler(request, h) {
            return h.view(
                'arena/index',
                {
                    menuTools: true,
                    menuToolsArena: true,
                    iframePage: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/arena/queue/{queue}',
        async handler(request, h) {
            return h.view(
                'arena/index',
                {
                    menuTools: true,
                    menuToolsArena: true,
                    iframePage: true,

                    queue: request.params.queue
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
                    request.logger.error({ msg: 'Failed to validate queue argument', err });
                    return h.redirect('/admin').takeover();
                },

                params: Joi.object({
                    queue: Joi.string().empty('').valid('submit', 'notify', 'documents').label('Queue').required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/legal',
        async handler(request, h) {
            return h.view(
                'legal',
                {
                    menuLegal: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/upgrade',
        async handler(request, h) {
            const isDO = getBoolean(readEnvValue('EENGINE_DOCEAN'));
            const isScriptInstalled = getBoolean(readEnvValue('EENGINE_INSTALL_SCRIPT'));
            const isRender = typeof readEnvValue('RENDER_SERVICE_SLUG') === 'string' && readEnvValue('RENDER_SERVICE_SLUG');
            const isGeneral = !isDO && !isRender && !isScriptInstalled;

            return h.view(
                'upgrade',
                {
                    isDO,
                    isRender,
                    isScriptInstalled,
                    isGeneral
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
            const notifyWebSafeHtml = (await settings.get('notifyWebSafeHtml')) || false;
            const notifyTextSize = Number(await settings.get('notifyTextSize')) || 0;
            const notifyCalendarEvents = (await settings.get('notifyCalendarEvents')) || false;
            const inboxNewOnly = (await settings.get('inboxNewOnly')) || false;
            const customHeaders = (await settings.get('webhooksCustomHeaders')) || [];

            let webhooksEnabled = await settings.get('webhooksEnabled');
            let values = {
                webhooksEnabled: webhooksEnabled !== null ? !!webhooksEnabled : false,
                webhooks: (await settings.get('webhooks')) || '',

                notifyAll: webhookEvents.includes('*'),
                inboxNewOnly,

                headersAll: notifyHeaders.includes('*'),
                notifyHeaders: notifyHeaders
                    .filter(entry => entry !== '*')
                    .map(entry => entry.replace(/^mime|^dkim|-id$|^.|-./gi, c => c.toUpperCase()))
                    .join('\n'),
                notifyText,
                notifyWebSafeHtml,
                notifyTextSize: notifyTextSize ? notifyTextSize : '',
                notifyCalendarEvents,

                customHeaders: []
                    .concat(customHeaders || [])
                    .map(entry => `${entry.key}: ${entry.value}`.trim())
                    .join('\n')
            };

            return h.view(
                'config/webhooks',
                {
                    menuConfig: true,
                    menuConfigWebhooks: true,

                    notificationTypes: notificationTypes.map(type =>
                        Object.assign({}, type, { checked: webhookEvents.includes(type.name), isMessageNew: type.name === 'messageNew' })
                    ),

                    values,

                    webhookErrorFlag: await settings.get('webhookErrorFlag'),
                    documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
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
                let customHeaders = request.payload.customHeaders
                    .split(/[\r\n]+/)
                    .map(header => header.trim())
                    .filter(header => header)
                    .map(line => {
                        let sep = line.indexOf(':');
                        if (sep >= 0) {
                            return {
                                key: line.substring(0, sep).trim(),
                                value: line.substring(sep + 1).trim()
                            };
                        }
                        return {
                            key: line,
                            value: ''
                        };
                    });

                const data = {
                    webhooksEnabled: request.payload.webhooksEnabled,
                    webhooks: request.payload.webhooks,
                    notifyText: request.payload.notifyText,
                    notifyWebSafeHtml: request.payload.notifyWebSafeHtml,
                    notifyTextSize: request.payload.notifyTextSize || 0,
                    notifyCalendarEvents: request.payload.notifyCalendarEvents,
                    inboxNewOnly: request.payload.inboxNewOnly,

                    webhookEvents: notificationTypes.filter(type => !!request.payload[`notify_${type.name}`]).map(type => type.name),
                    notifyHeaders: (request.payload.notifyHeaders || '')
                        .split(/\r?\n/)
                        .map(line => line.toLowerCase().trim())
                        .filter(line => line),

                    webhooksCustomHeaders: customHeaders
                };

                if (request.payload.notifyAll) {
                    data.webhookEvents.push('*');
                }

                if (request.payload.headersAll) {
                    data.notifyHeaders.push('*');
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                if (!data.webhooksEnabled) {
                    // clear error message (if exists)
                    await settings.clear('webhookErrorFlag');
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/webhooks');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/webhooks',
                    {
                        menuConfig: true,
                        menuConfigWebhooks: true,

                        notificationTypes: notificationTypes.map(type =>
                            Object.assign({}, type, { checked: !!request.payload[`notify_${type.name}`], isMessageNew: type.name === 'messageNew' })
                        ),

                        webhookErrorFlag: await settings.get('webhookErrorFlag'),
                        documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/webhooks',
                            {
                                menuConfig: true,
                                menuConfigWebhooks: true,

                                notificationTypes: notificationTypes.map(type =>
                                    Object.assign({}, type, {
                                        checked: !!request.payload[`notify_${type.name}`],
                                        isMessageNew: type.name === 'messageNew',
                                        error: errors[`notify_${type.name}`]
                                    })
                                ),

                                errors,

                                webhookErrorFlag: await settings.get('webhookErrorFlag'),
                                documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
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
                serviceSecret: (await settings.get('serviceSecret')) || null,
                queueKeep: (await settings.get('queueKeep')) || 0,
                deliveryAttempts: await settings.get('deliveryAttempts'),
                templateHeader: (await settings.get('templateHeader')) || '',
                scriptEnv: (await settings.get('scriptEnv')) || '',
                enableTokens: !(await settings.get('disableTokens')),
                enableApiProxy: (await settings.get('enableApiProxy')) || false,
                trackSentMessages: (await settings.get('trackSentMessages')) || false,
                resolveGmailCategories: (await settings.get('resolveGmailCategories')) || false,
                enableOAuthTokensApi: (await settings.get('enableOAuthTokensApi')) || false,

                ignoreMailCertErrors: (await settings.get('ignoreMailCertErrors')) || false,

                locale: (await settings.get('locale')) || false,
                timezone: (await settings.get('timezone')) || false
            };

            if (typeof values.deliveryAttempts !== 'number') {
                values.deliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
            }

            return h.view(
                'config/service',
                {
                    menuConfig: true,
                    menuConfigService: true,
                    encryption: await getSecret(),
                    locales: locales.map(locale => Object.assign({ selected: locale.locale === values.locale }, locale)),

                    timezones: timezonesList.map(entry => ({
                        name: entry.label,
                        timezone: entry.tzCode,
                        selected: entry.tzCode === values.timezone
                    })),

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
                    serviceSecret: request.payload.serviceSecret,
                    queueKeep: request.payload.queueKeep,
                    templateHeader: request.payload.templateHeader,
                    scriptEnv: request.payload.scriptEnv,
                    disableTokens: !request.payload.enableTokens,
                    enableApiProxy: request.payload.enableApiProxy,
                    trackSentMessages: request.payload.trackSentMessages,
                    resolveGmailCategories: request.payload.resolveGmailCategories,
                    enableOAuthTokensApi: request.payload.enableOAuthTokensApi,
                    ignoreMailCertErrors: request.payload.ignoreMailCertErrors,
                    locale: request.payload.locale,
                    timezone: request.payload.timezone,
                    deliveryAttempts: request.payload.deliveryAttempts
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
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/service',
                    {
                        menuConfig: true,
                        menuConfigService: true,
                        locales: locales.map(locale => Object.assign({ selected: locale.locale === request.payload.locale }, locale)),
                        encryption: await getSecret(),

                        timezones: timezonesList.map(entry => ({
                            name: entry.label,
                            timezone: entry.tzCode,
                            selected: entry.tzCode === request.payload.timezone
                        }))
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/service',
                            {
                                menuConfig: true,
                                menuConfigService: true,
                                locales: locales.map(locale => Object.assign({ selected: locale.locale === request.payload.locale }, locale)),
                                encryption: await getSecret(),

                                timezones: timezonesList.map(entry => ({
                                    name: entry.label,
                                    timezone: entry.tzCode,
                                    selected: entry.tzCode === request.payload.timezone
                                })),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    serviceUrl: settingsSchema.serviceUrl,
                    serviceSecret: settingsSchema.serviceSecret,
                    queueKeep: settingsSchema.queueKeep.default(0),
                    deliveryAttempts: settingsSchema.deliveryAttempts.default(DEFAULT_DELIVERY_ATTEMPTS),
                    templateHeader: settingsSchema.templateHeader.default(''),
                    scriptEnv: settingsSchema.scriptEnv.default(''),
                    enableApiProxy: settingsSchema.enableApiProxy.default(false),
                    trackSentMessages: settingsSchema.trackSentMessages.default(false),
                    resolveGmailCategories: settingsSchema.resolveGmailCategories.default(false),
                    ignoreMailCertErrors: settingsSchema.ignoreMailCertErrors.default(false),

                    // Following options can only be changed via the UI
                    enableOAuthTokensApi: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .description('If true, then allow using using the OAuth tokens API endpoint')
                        .default(false),
                    enableTokens: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    locale: settingsSchema.locale
                        .empty('')
                        .valid(...locales.map(locale => locale.locale))
                        .default('en'),

                    timezone: settingsSchema.timezone.empty('')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/ai',
        async handler(request, h) {
            const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
                if (entry.error && typeof entry.error === 'string') {
                    entry.error = entry.error
                        .replace(/\r?\n/g, '\n')
                        .replace(/^\s+at\s+.*$/gm, '')
                        .replace(/\n+/g, '\n')
                        .trim()
                        .replace(/(evalmachine.<anonymous>:)(\d+)/, (o, p, n) => p + (Number(n) - 1));
                }
                return entry;
            });

            const values = {
                generateEmailSummary: (await settings.get('generateEmailSummary')) || false,
                openAiPrompt: ((await settings.get('openAiPrompt')) || '').toString(),
                contentFnJson: JSON.stringify(
                    ((await settings.get(`openAiPreProcessingFn`)) || '').toString() ||
                        `// Pass all emails
return true;`
                ),

                openAiAPIUrl: ((await settings.get('openAiAPIUrl')) || '').toString(),

                openAiTemperature: ((await settings.get('openAiTemperature')) || '').toString(),
                openAiTopP: ((await settings.get('openAiTopP')) || '').toString()
            };

            if (!values.openAiPrompt.trim()) {
                values.openAiPrompt = await getDefaultPrompt();
            }

            let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
            let openAiModel = await settings.get('openAiModel');
            let openAiError = await getOpenAiError();

            return h.view(
                'config/ai',
                {
                    menuConfig: true,
                    menuConfigAi: true,

                    errorLog,
                    defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),

                    values,

                    hasOpenAiAPIKey,
                    openAiError,
                    openAiModels: await getOpenAiModels(OPEN_AI_MODELS, openAiModel),

                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                    examplePayloadsJson: JSON.stringify(
                        (await getExampleDocumentsPayloads()).map(entry =>
                            Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                        )
                    )
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/ai',
        async handler(request, h) {
            try {
                let contentFn;
                try {
                    if (request.payload.contentFnJson === '') {
                        contentFn = null;
                    } else {
                        contentFn = JSON.parse(request.payload.contentFnJson);
                        if (typeof contentFn !== 'string') {
                            throw new Error('Invalid Format');
                        }
                    }
                } catch (err) {
                    err.details = {
                        contentFnJson: 'Invalid JSON'
                    };
                    throw err;
                }

                let data = {
                    generateEmailSummary: request.payload.generateEmailSummary,
                    openAiModel: request.payload.openAiModel,
                    openAiAPIUrl: request.payload.openAiAPIUrl,
                    openAiPrompt: (request.payload.openAiPrompt || '').toString(),
                    openAiPreProcessingFn: contentFn,
                    openAiTemperature: request.payload.openAiTemperature,
                    openAiTopP: request.payload.openAiTopP
                };

                let defaultUserPrompt = await getDefaultPrompt();

                if (!data.openAiPrompt.trim() || data.openAiPrompt.trim() === defaultUserPrompt.trim()) {
                    data.openAiPrompt = '';
                }

                if (typeof request.payload.openAiAPIKey === 'string') {
                    data.openAiAPIKey = request.payload.openAiAPIKey;
                }

                if (typeof request.payload.openAiAPIUrl === 'string') {
                    data.openAiAPIUrl = request.payload.openAiAPIUrl;
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/ai');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
                let openAiError = await getOpenAiError();

                const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
                    if (entry.error && typeof entry.error === 'string') {
                        entry.error = entry.error
                            .replace(/\r?\n/g, '\n')
                            .replace(/^\s+at\s+.*$/gm, '')
                            .replace(/\n+/g, '\n')
                            .trim()
                            .replace(/(evalmachine.<anonymous>:)(\d+)/, (o, p, n) => p + (Number(n) - 1));
                    }
                    return entry;
                });

                return h.view(
                    'config/ai',
                    {
                        menuConfig: true,
                        menuConfigAi: true,

                        errorLog,
                        defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),

                        hasOpenAiAPIKey,
                        openAiError,
                        openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.openAiModel),

                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                        examplePayloadsJson: JSON.stringify(
                            (await getExampleDocumentsPayloads()).map(entry =>
                                Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                            )
                        )
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
                    let openAiError = await getOpenAiError();

                    const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
                        if (entry.error && typeof entry.error === 'string') {
                            entry.error = entry.error
                                .replace(/\r?\n/g, '\n')
                                .replace(/^\s+at\s+.*$/gm, '')
                                .replace(/\n+/g, '\n')
                                .trim()
                                .replace(/(evalmachine.<anonymous>:)(\d+)/, (o, p, n) => p + (Number(n) - 1));
                        }
                        return entry;
                    });

                    return h
                        .view(
                            'config/ai',
                            {
                                menuConfig: true,
                                menuConfigAi: true,

                                errorLog,
                                defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),

                                hasOpenAiAPIKey,
                                openAiError,
                                openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.openAiModel),

                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                                examplePayloadsJson: JSON.stringify(
                                    (await getExampleDocumentsPayloads()).map(entry =>
                                        Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                                    )
                                ),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    generateEmailSummary: settingsSchema.generateEmailSummary.default(false),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiModel: settingsSchema.openAiModel.empty(''),

                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default(''),

                    openAiPrompt: settingsSchema.openAiPrompt.default(''),

                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),

                    openAiTemperature: settingsSchema.openAiTemperature.default(''),
                    openAiTopP: settingsSchema.openAiTopP.default('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/ai/test-prompt',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Prompt test' });

                const parsed = await simpleParser(Buffer.from(request.payload.emailFile, 'base64'));

                const response = {};
                response.summary = await call({
                    cmd: 'generateSummary',
                    data: {
                        message: {
                            headers: parsed.headerLines.map(header => libmime.decodeHeader(header.line)),
                            attachments: parsed.attachments,
                            html: parsed.html,
                            text: parsed.text
                        },
                        openAiAPIKey: request.payload.openAiAPIKey,
                        openAiModel: request.payload.openAiModel,
                        openAiAPIUrl: request.payload.openAiAPIUrl,
                        openAiPrompt: request.payload.openAiPrompt,
                        openAiTemperature: request.payload.openAiTemperature,
                        openAiTopP: request.payload.openAiTopP
                    },
                    timeout: 2 * 60 * 1000
                });

                // crux from olden times
                for (let key of Object.keys(response.summary)) {
                    // remove meta keys from output
                    if (key.charAt(0) === '_' || response.summary[key] === '') {
                        delete response.summary[key];
                    }
                    if (key === 'riskAssessment') {
                        response.riskAssessment = response.summary.riskAssessment;
                        delete response.summary.riskAssessment;
                    }
                }

                return { success: true, response };
            } catch (err) {
                request.logger.error({ msg: 'Failed to test prompt', err });
                return { success: false, error: err.message };
            }
        },
        options: {
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    emailFile: Joi.string().base64({ paddingRequired: false }).required(),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiModel: settingsSchema.openAiModel.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default(''),
                    openAiPrompt: settingsSchema.openAiPrompt.default(''),
                    openAiTemperature: settingsSchema.openAiTemperature.empty(''),
                    openAiTopP: settingsSchema.openAiTopP.empty('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/ai/reload-models',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Reload models' });

                const { models } = await call({
                    cmd: 'openAiListModels',
                    data: {
                        openAiAPIKey: request.payload.openAiAPIKey,
                        openAiAPIUrl: request.payload.openAiAPIUrl
                    },
                    timeout: 2 * 60 * 1000
                });

                if (models && models.length) {
                    await settings.set('openAiModels', models);
                }

                return { success: true, models };
            } catch (err) {
                request.logger.error({ msg: 'Failed reloading OpenAI models', err });
                return {
                    success: false,
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
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/service/preview',
        async handler(request, h) {
            return h.view(
                'config/service-preview',
                {
                    embeddedTemplateHeader: request.payload.templateHeader
                },
                {
                    layout: 'public'
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
                    request.logger.error({ msg: 'Failed to process preview', err });
                    return h.redirect('/admin').takeover();
                },

                payload: Joi.object({
                    templateHeader: settingsSchema.templateHeader.default('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/clear-error',
        async handler(request) {
            switch (request.payload.alert) {
                case 'open-ai':
                    await redis.del(`${REDIS_PREFIX}:openai:error`);
                    break;

                case 'webhook-default':
                    await settings.clear('webhookErrorFlag');
                    break;

                case 'webhook-route':
                    if (request.payload.entry) {
                        await redis.hdel(`${REDIS_PREFIX}wh:c`, `${request.payload.entry}:webhookErrorFlag`);
                    }
                    break;
            }

            return { success: true };
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
                    alert: Joi.string().required().max(1024),
                    entry: Joi.string().empty('').max(1024).trim()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/service/clean',
        async handler(request) {
            let errors = [];

            for (let queue of [submitQueue, notifyQueue, documentsQueue]) {
                for (let type of ['failed', 'completed']) {
                    try {
                        await queue.clean(1000, 100000, type);
                        request.logger.trace({ msg: 'Queue cleaned', queue: queue.name, type });
                    } catch (err) {
                        request.logger.error({ msg: 'Failed to clean queue', queue: queue.name, type, err });
                        errors.push(err.message);
                    }
                }
            }

            if (errors.length) {
                return { success: false, error: 'Cleaning failed for some queues' };
            }

            return { success: true };
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                }
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
                        maxLogLines: request.payload.maxLogLines || 0
                    }
                };

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/logging');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

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
                    request.logger.error({ msg: 'Failed to update configuration', err });

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
                    request.logger.info({ msg: 'Request reconnect for logging', account });
                    try {
                        await call({ cmd: 'update', account });
                        requested++;
                    } catch (err) {
                        request.logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                    }
                }

                return {
                    success: true,
                    accounts: requested
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request reconnect', err, accounts: request.payload.accounts });
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
            if (!webhooks) {
                return {
                    success: false,
                    target: webhooks,
                    error: 'Webhook URL is not set'
                };
            }

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

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return {
                            key: line.substring(0, sep).trim(),
                            value: line.substring(sep + 1).trim()
                        };
                    }
                    return {
                        key: line,
                        value: ''
                    };
                });

            customHeaders.forEach(header => {
                headers[header.key] = header.value;
            });

            let start = Date.now();
            let duration;
            try {
                let res;

                let serviceUrl = await settings.get('serviceUrl');

                try {
                    res = await fetchCmd(parsed.toString(), {
                        method: 'post',
                        body:
                            request.payload.payload ||
                            JSON.stringify({
                                serviceUrl,
                                account: null,
                                date: new Date().toISOString(),
                                event: 'test',
                                data: {
                                    nonce: crypto.randomBytes(NONCE_BYTES).toString('base64url')
                                }
                            }),
                        headers,
                        dispatcher: fetchAgent
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
                request.logger.error({ msg: 'Failed posting webhook', webhooks, event: 'test', err });
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
                        .description('Webhook URL'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .default('')
                        .description('Custom request headers'),
                    payload: Joi.string()
                        .max(1024 * 1024)
                        .empty('')
                        .trim()
                        .description('Example JSON payload')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth',
        async handler(request, h) {
            let data = await oauth2Apps.list(request.query.page - 1, request.query.pageSize);

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/webhooks`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            data.apps.forEach(app => {
                app.providerData = oauth2ProviderData(app.provider);
            });

            let newLink = new URL('/admin/config/oauth/new', 'http://localhost');

            return h.view(
                'config/oauth/index',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    newLink: newLink.pathname + newLink.search,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === data.page
                    })),

                    apps: data.apps
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/app/{app}',
        async handler(request, h) {
            let app = await oauth2Apps.get(request.params.app);
            if (!app) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            let providerData = oauth2ProviderData(app.provider);

            let disabledScopes = {};
            if (
                (app.skipScopes && app.skipScopes.includes('SMTP.Send')) ||
                (app.skipScopes && app.skipScopes.includes('https://outlook.office.com/SMTP.Send'))
            ) {
                disabledScopes.SMTP_Send = true;
            }

            return h.view(
                'config/oauth/app',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    [`active${providerData.caseName}`]: true,

                    app,

                    disabledScopes,

                    providerData
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/delete',
        async handler(request, h) {
            try {
                await oauth2Apps.del(request.payload.app);

                await request.flash({ type: 'info', message: `OAuth2 application was deleted` });

                return h.redirect('/admin/config/oauth');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete the OAuth2 application` });
                request.logger.error({ msg: 'Failed to delete OAuth2 application', err, app: request.payload.app, remoteAddress: request.app.ip });
                return h.redirect(`/admin/config/oauth/app/${request.payload.app}`);
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
                    await request.flash({ type: 'danger', message: `Failed to delete the OAuth2 application` });
                    request.logger.error({ msg: 'Failed to delete delete the OAuth2 application', err });

                    return h.redirect('/admin/config/oauth').takeover();
                },

                payload: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/new',
        async handler(request, h) {
            let { provider } = request.query;
            let providerData = oauth2ProviderData(provider);

            let serviceUrl = await settings.get('serviceUrl');
            let defaultRedirectUrl = `${serviceUrl}/oauth`;
            if (provider === 'outlook') {
                defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
            }

            return h.view(
                'config/oauth/new',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    [`active${providerData.caseName}`]: true,
                    providerData,
                    defaultRedirectUrl,

                    baseScopesApi: false,
                    baseScopesImap: true,

                    values: {
                        provider,
                        authority: 'common',
                        redirectUrl: defaultRedirectUrl
                    }
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                query: Joi.object({
                    provider: Joi.string()
                        .empty('')
                        .valid(...Object.keys(OAUTH_PROVIDERS))
                        .label('Provider')
                        .required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/new',
        async handler(request, h) {
            try {
                let appData = Object.assign({}, request.payload);
                appData.extraScopes = appData.extraScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                appData.skipScopes = appData.skipScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                let oauth2App = await oauth2Apps.create(appData);
                if (!oauth2App || !oauth2App.id) {
                    throw new Error('Unexpected result');
                }

                await request.flash({ type: 'success', message: `OAuth2 application was registered` });
                return h.redirect(`/admin/config/oauth/app/${oauth2App.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to register OAuth2 app` });
                request.logger.error({ msg: 'Failed to register OAuth2 app', err });

                let { provider, baseScopes } = request.payload;
                if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                    return h.redirect('/admin');
                }

                let providerData = oauth2ProviderData(provider);

                let serviceUrl = await settings.get('serviceUrl');
                let defaultRedirectUrl = `${serviceUrl}/oauth`;
                if (provider === 'outlook') {
                    defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                }

                return h.view(
                    'config/oauth/new',
                    {
                        menuConfig: true,
                        menuConfigOauth: true,

                        [`active${providerData.caseName}`]: true,
                        providerData,
                        defaultRedirectUrl,

                        baseScopesApi: baseScopes === 'api',
                        baseScopesImap: baseScopes === 'imap' || !baseScopes
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

                    await request.flash({ type: 'danger', message: `Failed to register OAuth2 app` });
                    request.logger.error({ msg: 'Failed to register OAuth2 app', err });

                    let { provider, baseScopes } = request.payload;
                    if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                        return h.redirect('/admin').takeover();
                    }

                    let providerData = oauth2ProviderData(provider);

                    let serviceUrl = await settings.get('serviceUrl');
                    let defaultRedirectUrl = `${serviceUrl}/oauth`;
                    if (provider === 'outlook') {
                        defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                    }

                    return h
                        .view(
                            'config/oauth/new',
                            {
                                menuConfig: true,
                                menuConfigOauth: true,

                                [`active${providerData.caseName}`]: true,
                                providerData,
                                defaultRedirectUrl,

                                baseScopesApi: baseScopes === 'api',
                                baseScopesImap: baseScopes === 'imap' || !baseScopes,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(oauthCreateSchema).tailor('web')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/edit/{app}',
        async handler(request, h) {
            let appData = await oauth2Apps.get(request.params.app);
            if (!appData) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            let providerData = oauth2ProviderData(appData.provider);
            let serviceUrl = await settings.get('serviceUrl');
            let defaultRedirectUrl = `${serviceUrl}/oauth`;
            if (providerData.provider === 'outlook') {
                defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
            }

            let values = Object.assign({}, appData, {
                clientSecret: '',
                serviceKey: '',
                extraScopes: [].concat(appData.extraScopes || []).join('\n'),
                skipScopes: [].concat(appData.skipScopes || []).join('\n')
            });

            return h.view(
                'config/oauth/edit',
                {
                    menuConfig: true,
                    menuConfigOauth: true,

                    [`active${providerData.caseName}`]: true,
                    providerData,
                    defaultRedirectUrl,

                    appData,

                    hasClientSecret: !!appData.clientSecret,
                    hasServiceKey: !!appData.serviceKey,

                    values,

                    baseScopesApi: values.baseScopes === 'api',
                    baseScopesImap: values.baseScopes === 'imap' || !values.baseScopes
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/edit',
        async handler(request, h) {
            let appData = await oauth2Apps.get(request.payload.app);
            if (!appData) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            try {
                let updates = Object.assign({}, request.payload);
                updates.extraScopes = updates.extraScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                updates.skipScopes = updates.skipScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                let oauth2App = await oauth2Apps.update(appData.id, updates);
                if (!oauth2App || !oauth2App.id) {
                    throw new Error('Unexpected result');
                }

                await request.flash({ type: 'success', message: `OAuth2 application was updated` });
                return h.redirect(`/admin/config/oauth/app/${oauth2App.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update OAuth2 app` });
                request.logger.error({ msg: 'Failed to update OAuth2 app', app: request.payload.app, err });

                let providerData = oauth2ProviderData(appData.provider);

                let serviceUrl = await settings.get('serviceUrl');
                let defaultRedirectUrl = `${serviceUrl}/oauth`;
                if (appData.provider === 'outlook') {
                    defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                }

                return h.view(
                    'config/oauth/edit',
                    {
                        menuConfig: true,
                        menuConfigOauth: true,

                        [`active${providerData.caseName}`]: true,
                        providerData,
                        defaultRedirectUrl,
                        appData,

                        hasClientSecret: !!appData.clientSecret,
                        hasServiceKey: !!appData.serviceKey,

                        baseScopesApi: request.payload.baseScopes === 'api',
                        baseScopesImap: request.payload.baseScopes === 'imap' || !request.payload.baseScopes
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

                    let appData = await oauth2Apps.get(request.payload.app);
                    if (!appData) {
                        await request.flash({ type: 'danger', message: `Application was not found.` });
                        request.logger.error({ msg: 'Application was not found.', app: request.payload.app });
                        return h.redirect('/admin').takeover();
                    }

                    await request.flash({ type: 'danger', message: `Failed to update OAuth2 app` });
                    request.logger.error({ msg: 'Failed to update OAuth2 app', err });

                    let { provider } = request.payload;
                    if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                        return h.redirect('/admin').takeover();
                    }

                    let providerData = oauth2ProviderData(provider);

                    let serviceUrl = await settings.get('serviceUrl');
                    let defaultRedirectUrl = `${serviceUrl}/oauth`;
                    if (provider === 'outlook') {
                        defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                    }

                    return h
                        .view(
                            'config/oauth/edit',
                            {
                                menuConfig: true,
                                menuConfigOauth: true,

                                [`active${providerData.caseName}`]: true,
                                providerData,
                                defaultRedirectUrl,

                                appData,

                                hasClientSecret: !!appData.clientSecret,
                                hasServiceKey: !!appData.serviceKey,

                                baseScopesApi: request.payload.baseScopes === 'api',
                                baseScopesImap: request.payload.baseScopes === 'imap' || !request.payload.baseScopes,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(oauthUpdateSchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks',
        async handler(request, h) {
            let data = await webhooks.list(request.query.page - 1, request.query.pageSize);

            let nextPage = false;
            let prevPage = false;

            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                data.account = await accountObject.loadAccountData();
            }

            let getPagingUrl = page => {
                let url = new URL(`admin/webhooks`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/webhooks/new', 'http://localhost');

            return h.view(
                'webhooks/index',
                {
                    menuWebhooks: true,

                    newLink: newLink.pathname + newLink.search,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === data.page
                    })),

                    webhooksEnabled: await settings.get('webhooksEnabled'),

                    webhooks: data.webhooks
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
                    return h.redirect('/admin/webhooks').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/new',
        async handler(request, h) {
            const values = {
                name: '',
                description: '',

                contentFnJson: JSON.stringify(`/*
// The following example passes webhooks for new emails that appear in the Inbox of the user "testaccount".
// NB! Gmail webhooks are always emitted from the "All Mail" folder, not the Inbox, so we need to check both the path and label values.

const isInbox = payload.path === 'INBOX' || payload.data?.labels?.includes('\\\\Inbox');
if (payload.event === 'messageNew' && payload.account === 'testaccount' && isInbox) {
    return true;
}
*/`),
                contentMapJson: JSON.stringify(`// By default the output payload is returned unmodified.

return payload;`)
            };

            return h.view(
                'webhooks/new',
                {
                    menuWebhooks: true,
                    values,

                    examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                    notificationTypesJson: JSON.stringify(notificationTypes),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
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
                    return h.redirect('/admin/webhooks').takeover();
                },

                query: Joi.object({})
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/new',
        async handler(request, h) {
            let contentFn, contentMap;
            try {
                if (request.payload.contentFnJson === '') {
                    contentFn = null;
                } else {
                    contentFn = JSON.parse(request.payload.contentFnJson);
                    if (typeof contentFn !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                if (request.payload.contentMapJson === '') {
                    contentMap = null;
                } else {
                    contentMap = JSON.parse(request.payload.contentMapJson);
                    if (typeof contentMap !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentMapJson: 'Invalid JSON'
                };
                throw err;
            }

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return {
                            key: line.substring(0, sep).trim(),
                            value: line.substring(sep + 1).trim()
                        };
                    }
                    return {
                        key: line,
                        value: ''
                    };
                });

            try {
                let createRequest = await webhooks.create(
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled,

                        customHeaders
                    },
                    {
                        fn: contentFn,
                        map: contentMap
                    }
                );

                await request.flash({ type: 'info', message: `Webhook routing was created` });
                return h.redirect(`/admin/webhooks/webhook/${createRequest.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to create webhook routing` });
                request.logger.error({ msg: 'Failed to create webhook routing', err });

                return h.view(
                    'webhooks/new',
                    {
                        menuTemplates: true,
                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                        notificationTypesJson: JSON.stringify(notificationTypes),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
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

                    await request.flash({ type: 'danger', message: `Failed to create webhook routing` });
                    request.logger.error({ msg: 'Failed to create webhook routing', err });

                    return h
                        .view(
                            'templates/new',
                            {
                                menuTemplates: true,
                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                                notificationTypesJson: JSON.stringify(notificationTypes)
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the routing').label('RoutingName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the routing')
                        .description('Optional description of the webhook routing')
                        .label('RoutingDescription'),
                    targetUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook target URL'),
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the routing enabled'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .description('Custom request headers'),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),
                    contentMapJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Map function')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/webhook/{webhook}',
        async handler(request, h) {
            let webhook = await webhooks.get(request.params.webhook);
            if (!webhook) {
                let error = Boom.boomify(new Error('Webhook Route was not found.'), { statusCode: 404 });
                throw error;
            }

            webhook.targetUrlShort = webhook.targetUrl ? new URL(webhook.targetUrl).hostname : false;

            const errorLog = ((await webhooks.getErrorLog(webhook.id)) || []).map(entry => {
                if (entry.error && typeof entry.error === 'string') {
                    entry.error = entry.error
                        .replace(/\r?\n/g, '\n')
                        .replace(/^\s+at\s+.*$/gm, '')
                        .replace(/\n+/g, '\n')
                        .trim()
                        .replace(/(evalmachine.<anonymous>:)(\d+)/, (o, p, n) => p + (Number(n) - 1));
                }
                return entry;
            });

            return h.view(
                'webhooks/webhook',
                {
                    menuWebhooks: true,
                    webhook,

                    errorLog
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
                    return h.redirect('/admin/webhooks').takeover();
                },

                params: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/webhook/{webhook}/edit',
        async handler(request, h) {
            let webhook = await webhooks.get(request.params.webhook);
            if (!webhook) {
                let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                throw error;
            }

            const values = {
                webhook: webhook.id,
                name: webhook.name,
                description: webhook.description,
                targetUrl: webhook.targetUrl,
                enabled: webhook.enabled,
                contentFnJson: JSON.stringify(webhook.content.fn || ''),
                contentMapJson: JSON.stringify(webhook.content.map || ''),

                customHeaders: []
                    .concat(webhook.customHeaders || [])
                    .map(entry => `${entry.key}: ${entry.value}`.trim())
                    .join('\n')
            };

            return h.view(
                'webhooks/edit',
                {
                    menuWebhooks: true,

                    webhook,

                    values,

                    examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                    notificationTypesJson: JSON.stringify(notificationTypes),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
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
                    return h.redirect('/admin/webhooks').takeover();
                },

                params: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/edit',
        async handler(request, h) {
            let contentFn, contentMap;
            try {
                if (request.payload.contentFnJson === '') {
                    contentFn = null;
                } else {
                    contentFn = JSON.parse(request.payload.contentFnJson);
                    if (typeof contentFn !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                if (request.payload.contentMapJson === '') {
                    contentMap = null;
                } else {
                    contentMap = JSON.parse(request.payload.contentMapJson);
                    if (typeof contentMap !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentMapJson: 'Invalid JSON'
                };
                throw err;
            }

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return {
                            key: line.substring(0, sep).trim(),
                            value: line.substring(sep + 1).trim()
                        };
                    }
                    return {
                        key: line,
                        value: ''
                    };
                });

            try {
                await webhooks.update(
                    request.payload.webhook,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled,

                        customHeaders
                    },
                    {
                        fn: contentFn,
                        map: contentMap
                    }
                );

                await request.flash({ type: 'info', message: `Webhook Route settings were updated` });
                return h.redirect(`/admin/webhooks/webhook/${request.payload.webhook}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update Webhook Route` });
                request.logger.error({ msg: 'Failed to update Webhook Route', err });

                let webhook = await webhooks.get(request.payload.webhook);
                if (!webhook) {
                    let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                    throw error;
                }

                return h.view(
                    'webhooks/edit',
                    {
                        menuWebhooks: true,

                        webhook,

                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                        notificationTypesJson: JSON.stringify(notificationTypes),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
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

                    await request.flash({ type: 'danger', message: `Failed to update Webhook Route` });
                    request.logger.error({ msg: 'Failed to update Webhook Route', err });

                    let webhook = await webhooks.get(request.payload.webhook);
                    if (!webhook) {
                        let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                        throw error;
                    }

                    return h
                        .view(
                            'webhooks/edit',
                            {
                                menuWebhooks: true,

                                webhook,

                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                                notificationTypesJson: JSON.stringify(notificationTypes),
                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID'),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the routing').label('RoutingName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the routing')
                        .description('Optional description of the webhook routing')
                        .label('RoutingDescription'),
                    targetUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook target URL'),
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the routing enabled'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .description('Custom request headers'),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),
                    contentMapJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Map function')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/delete',
        async handler(request, h) {
            try {
                await webhooks.del(request.payload.webhook);

                await request.flash({ type: 'info', message: `Webhook Route was deleted` });

                let accountWebhooksLink = new URL('/admin/webhooks', 'http://localhost');

                return h.redirect(accountWebhooksLink.pathname + accountWebhooksLink.search);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete the Webhook Route` });
                request.logger.error({ msg: 'Failed to delete Webhook Route', err, webhook: request.payload.webhook, remoteAddress: request.app.ip });
                return h.redirect(`/admin/webhooks/webhook/${request.payload.webhook}`);
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
                    await request.flash({ type: 'danger', message: `Failed to delete Webhook Route` });
                    request.logger.error({ msg: 'Failed to delete delete Webhook Route', err });

                    return h.redirect('/admin/webhooks').takeover();
                },

                payload: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates',
        async handler(request, h) {
            let data = await templates.list(request.query.account, request.query.page - 1, request.query.pageSize);

            let nextPage = false;
            let prevPage = false;

            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                data.account = await accountObject.loadAccountData();
            }

            let getPagingUrl = page => {
                let url = new URL(`admin/templates`, 'http://localhost');
                url.searchParams.append('page', page);

                if (request.query.account) {
                    url.searchParams.append('account', request.query.account);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/templates/new', 'http://localhost');
            if (request.query.account) {
                newLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'templates/index',
                {
                    menuTemplates: true,

                    account: data.account,
                    newLink: newLink.pathname + newLink.search,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === data.page
                    })),

                    templates: data.templates
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
                    return h.redirect('/admin/templates').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null),
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/template/{template}',
        async handler(request, h) {
            let template = await templates.get(request.params.template);
            if (!template) {
                let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                throw error;
            }

            let account;
            if (template.account) {
                let accountObject = new Account({ redis, account: template.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            return h.view(
                'templates/template',
                {
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    format: CODE_FORMATS.find(entry => entry.format === template.format),

                    template
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
                    return h.redirect('/admin/templates').takeover();
                },

                params: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/template/{template}/edit',
        async handler(request, h) {
            let template = await templates.get(request.params.template);
            if (!template) {
                let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                throw error;
            }

            let account;
            if (template.account) {
                let accountObject = new Account({ redis, account: template.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            const values = {
                template: template.id,
                name: template.name,
                description: template.description,
                subject: template.content.subject,
                format: template.format,
                previewText: template.content.previewText
            };

            return h.view(
                'templates/edit',
                {
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    template,

                    formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === values.format }, format)),

                    values,

                    contentHtmlJson: JSON.stringify(template.content.html || ''),
                    contentTextJson: JSON.stringify(template.content.text || '')
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
                    return h.redirect('/admin/templates').takeover();
                },

                params: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/edit',
        async handler(request, h) {
            try {
                await templates.update(
                    request.payload.template,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    {
                        subject: request.payload.subject,
                        html: request.payload.contentHtml,
                        text: request.payload.contentText,
                        previewText: request.payload.previewText
                    }
                );

                await request.flash({ type: 'info', message: `Template settings were updated` });
                return h.redirect(`/admin/templates/template/${request.payload.template}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update template` });
                request.logger.error({ msg: 'Failed to update template', err });

                let template = await templates.get(request.payload.template);
                if (!template) {
                    let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                    throw error;
                }

                let account;
                if (template.account) {
                    let accountObject = new Account({ redis, account: template.account });
                    account = await accountObject.loadAccountData();
                }

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (account) {
                    accountTemplatesLink.searchParams.append('account', account.account);
                }

                return h.view(
                    'templates/edit',
                    {
                        menuTemplates: true,

                        account,

                        accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                        template,

                        formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                        errors: err.details,

                        contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                        contentTextJson: JSON.stringify(request.payload.contentText || '')
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

                    await request.flash({ type: 'danger', message: `Failed to update template` });
                    request.logger.error({ msg: 'Failed to update template', err });

                    let template = await templates.get(request.payload.template);
                    if (!template) {
                        let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                        throw error;
                    }

                    let account;
                    if (template.account) {
                        let accountObject = new Account({ redis, account: template.account });
                        account = await accountObject.loadAccountData();
                    }

                    let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                    if (account) {
                        accountTemplatesLink.searchParams.append('account', account.account);
                    }

                    return h
                        .view(
                            'templates/edit',
                            {
                                menuTemplates: true,

                                account,

                                accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                                template,

                                formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                                errors,

                                contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                                contentTextJson: JSON.stringify(request.payload.contentText || '')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID'),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    subject: templateSchemas.subject,
                    contentText: templateSchemas.text,
                    contentHtml: templateSchemas.html,
                    previewText: templateSchemas.previewText
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/new',
        async handler(request, h) {
            let account;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            const values = {
                account: request.query.account,
                name: '',
                description: '',
                subject: '',
                format: 'html',
                contentHtml: '',
                contentText: '',
                previewText: ''
            };

            return h.view(
                'templates/new',
                {
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === values.format }, format)),

                    values,

                    contentHtmlJson: JSON.stringify(''),
                    contentTextJson: JSON.stringify('')
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
                    return h.redirect('/admin/templates').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/new',
        async handler(request, h) {
            try {
                let createRequest = await templates.create(
                    request.payload.account,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    {
                        subject: request.payload.subject,
                        html: request.payload.contentHtml,
                        text: request.payload.contentText,
                        previewText: request.payload.previewText
                    }
                );

                await request.flash({ type: 'info', message: `Template was created` });
                return h.redirect(`/admin/templates/template/${createRequest.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to create template` });
                request.logger.error({ msg: 'Failed to create template', err });

                let account;
                if (request.payload.account) {
                    let accountObject = new Account({ redis, account: request.payload.account });
                    account = await accountObject.loadAccountData();
                }

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (account) {
                    accountTemplatesLink.searchParams.append('account', account.account);
                }

                return h.view(
                    'templates/new',
                    {
                        menuTemplates: true,

                        account,

                        accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                        formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                        errors: err.details,

                        contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                        contentTextJson: JSON.stringify(request.payload.contentText || '')
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

                    await request.flash({ type: 'danger', message: `Failed to create template` });
                    request.logger.error({ msg: 'Failed to create template', err });

                    let account;
                    if (request.payload.account) {
                        let accountObject = new Account({ redis, account: request.payload.account });
                        account = await accountObject.loadAccountData();
                    }

                    let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                    if (account) {
                        accountTemplatesLink.searchParams.append('account', account.account);
                    }

                    return h
                        .view(
                            'templates/new',
                            {
                                menuTemplates: true,

                                account,

                                accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                                formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                                errors,

                                contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                                contentTextJson: JSON.stringify(request.payload.contentText || '')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    account: accountIdSchema.default(null),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    subject: templateSchemas.subject,
                    contentText: templateSchemas.text,
                    contentHtml: templateSchemas.html,
                    previewText: templateSchemas.previewText
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/delete',
        async handler(request, h) {
            try {
                let templateResponse = await templates.del(request.payload.template);

                await request.flash({ type: 'info', message: `Template was deleted` });

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (templateResponse && templateResponse.account) {
                    accountTemplatesLink.searchParams.append('account', templateResponse.account);
                }

                return h.redirect(accountTemplatesLink.pathname + accountTemplatesLink.search);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete the template` });
                request.logger.error({ msg: 'Failed to delete the template', err, template: request.payload.template, remoteAddress: request.app.ip });
                return h.redirect(`/admin/templates/template/${request.payload.template}`);
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
                    await request.flash({ type: 'danger', message: `Failed to delete the account` });
                    request.logger.error({ msg: 'Failed to delete delete the account', err });

                    return h.redirect('/admin/templates').takeover();
                },

                payload: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/test',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Trying to send test message', payload: request.payload });

                let template = await templates.get(request.payload.template);
                if (!template) {
                    return {
                        error: 'Template was not found'
                    };
                }

                let accountId = template.account || request.payload.account;
                if (!accountId) {
                    return { error: 'Account ID not provided' };
                }

                let accountObject = new Account({ redis, account: accountId, call, secret: await getSecret() });

                let account;
                try {
                    account = await accountObject.loadAccountData();
                } catch (err) {
                    return {
                        error: err.message
                    };
                }

                try {
                    return await accountObject.queueMessage(
                        {
                            account: account.account,
                            template: template.id,
                            from: {
                                name: account.name,
                                address: account.email
                            },
                            to: [{ name: '', address: request.payload.to }],
                            render: {
                                params: request.payload.params || {}
                            },
                            copy: false,
                            deliveryAttempts: 0
                        },
                        { source: 'ui' }
                    );
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'Failed sending test message', err });
                return {
                    success: false,
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
                    account: accountIdSchema.default(null),
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID'),
                    to: Joi.string().email().required().description('Recipient address'),
                    params: Joi.object().description('Optional handlebars values').unknown()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways',
        async handler(request, h) {
            let gatewayObject = new Gateway({ redis });

            let gateways = await gatewayObject.listGateways(request.query.page - 1, request.query.pageSize);

            if (gateways.pages < request.query.page) {
                request.query.page = gateways.pages;
            }

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/gateways`, 'http://localhost');
                url.searchParams.append('page', page);
                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }
                return url.pathname + url.search;
            };

            if (gateways.pages > gateways.page + 1) {
                nextPage = getPagingUrl(gateways.page + 2);
            }

            if (gateways.page > 0) {
                prevPage = getPagingUrl(gateways.page);
            }

            return h.view(
                'gateways/index',
                {
                    menuGateways: true,

                    showPaging: gateways.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: gateways.page === 0,
                    pageLinks: new Array(gateways.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === gateways.page
                    })),

                    gateways: gateways.gateways.map(entry => {
                        let label = {};
                        if (entry.deliveries && !entry.lastError) {
                            label.type = 'success';
                            label.name = 'Connected';
                        } else if (entry.lastError) {
                            label.type = 'danger';
                            label.name = 'Error';
                            label.error = entry.lastError.response;
                        } else {
                            label.type = 'info';
                            label.name = 'Not used';
                        }

                        return Object.assign(entry, {
                            timeStr: entry.lastUse ? entry.lastUse.toISOString() : null,
                            label
                        });
                    })
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
                    return h.redirect('/admin/gateways').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/new',
        async handler(request, h) {
            return h.view(
                'gateways/new',
                {
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key])))
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/gateway/{gateway}',
        async handler(request, h) {
            let gatewayObject = new Gateway({ gateway: request.params.gateway, redis, secret: await getSecret() });
            let gatewayData = await gatewayObject.loadGatewayData();

            let label = {};
            if (gatewayData.deliveries && !gatewayData.lastError) {
                label.type = 'success';
                label.name = 'Connected';
            } else if (gatewayData.lastError) {
                label.type = 'danger';
                label.name = 'Error';
                label.error = gatewayData.lastError.response;
            } else {
                label.type = 'info';
                label.name = 'Not used';
            }

            return h.view(
                'gateways/gateway',
                {
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),

                    gateway: gatewayData,
                    label
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
                    await request.flash({ type: 'danger', message: `Invalid gateway request: ${err.message}` });
                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/edit/{gateway}',
        async handler(request, h) {
            let gatewayObject = new Gateway({ gateway: request.params.gateway, redis, secret: await getSecret() });
            let gatewayData = await gatewayObject.loadGatewayData();

            let hasSMTPPass = !!gatewayData.pass;
            delete gatewayData.pass;

            return h.view(
                'gateways/edit',
                {
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                    values: gatewayData,
                    gatewayData,
                    hasSMTPPass
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
                    await request.flash({ type: 'danger', message: `Invalid gateway request: ${err.message}` });
                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/new',
        async handler(request, h) {
            try {
                let gatewayData = {
                    gateway: request.payload.gateway || null,
                    name: request.payload.name || null,
                    host: request.payload.host || null,
                    port: request.payload.port || null,
                    secure: request.payload.secure || null,
                    user: request.payload.user || null,
                    pass: request.payload.pass || null,
                    tls: {}
                };

                let gatewayObject = new Gateway({ redis, secret: await getSecret() });
                let result = await gatewayObject.create(gatewayData);

                if (result.state === 'new') {
                    await request.flash({ type: 'success', message: `Added new SMTP gateway`, result });
                } else {
                    await request.flash({ type: 'success', message: `Updated SMTP gateway`, result });
                }

                return h.redirect(`/admin/gateways/gateway/${encodeURIComponent(result.gateway)}?state=${result.state}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to add new gateway` });
                request.logger.error({ msg: 'Failed to add new gateway', err });

                return h.view(
                    'gateways/new',
                    {
                        menuGateways: true,
                        wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key])))
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

                    await request.flash({ type: 'danger', message: `Failed to add new gateway` });
                    request.logger.error({ msg: 'Failed to add new gateway', err });

                    return h
                        .view(
                            'gateways/new',
                            {
                                menuGateways: true,
                                wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID'),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().max(1024).default(null).label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/edit',
        async handler(request, h) {
            try {
                let gatewayData = {
                    gateway: request.payload.gateway || null,
                    name: request.payload.name || null,
                    host: request.payload.host || null,
                    port: request.payload.port || null,
                    secure: request.payload.secure || null,
                    user: request.payload.user || null
                };

                if (request.payload.pass) {
                    gatewayData.pass = request.payload.pass;
                }

                if (!request.payload.user && !request.payload.pass) {
                    gatewayData.pass = null;
                }

                let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                let result = await gatewayObject.update(gatewayData);

                await request.flash({ type: 'success', message: `Updated SMTP gateway`, result });

                return h.redirect(`/admin/gateways/gateway/${encodeURIComponent(result.gateway)}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update gateway` });
                request.logger.error({ msg: 'Failed to update gateway', err });

                let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                let gatewayData = await gatewayObject.loadGatewayData();

                let hasSMTPPass = !!gatewayData.pass;

                return h.view(
                    'gateways/edit',
                    {
                        menuGateways: true,
                        wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                        hasSMTPPass,
                        gatewayData
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

                    await request.flash({ type: 'danger', message: `Failed to update gateway` });
                    request.logger.error({ msg: 'Failed to update gateway', err });

                    let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                    let gatewayData = await gatewayObject.loadGatewayData();

                    let hasSMTPPass = !!gatewayData.pass;

                    return h
                        .view(
                            'gateways/edit',
                            {
                                menuGateways: true,
                                wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                                hasSMTPPass,
                                gatewayData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID').required(),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().max(1024).default(null).label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/test',
        async handler(request) {
            let { gateway, host, port, user, pass, secure } = request.payload;

            try {
                if (user && !pass && gateway) {
                    let gatewayObject = new Gateway({ gateway, redis, secret: await getSecret() });
                    try {
                        let gatewayData = await gatewayObject.loadGatewayData();
                        if (gatewayData) {
                            pass = gatewayData.pass || '';
                        }
                    } catch (err) {
                        // ignore
                    }
                }

                let accountData = {
                    smtp: {
                        host,
                        port,
                        secure,
                        auth:
                            user || pass
                                ? {
                                      user,
                                      pass: pass || ''
                                  }
                                : false
                    }
                };

                let verifyResult = await verifyAccountInfo(redis, accountData);

                if (verifyResult) {
                    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
                        switch (verifyResult.smtp.code) {
                            case 'EDNS':
                                verifyResult.smtp.error = gt.gettext('Server hostname was not found');
                                break;
                            case 'EAUTH':
                                verifyResult.smtp.error = gt.gettext('Invalid username or password');
                                break;
                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = gt.gettext('TLS protocol error');
                                }
                                break;
                        }
                    }
                }

                return verifyResult.smtp;
            } catch (err) {
                request.logger.error({ msg: 'Failed posting request', host, port, user, pass: !!pass, err });
                return {
                    success: false,
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
                    gateway: Joi.string().empty('').trim().max(256).example('sendgun').description('Gateway ID'),
                    user: Joi.string().empty('').trim().max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).label('Password'),
                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),
                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/delete/{gateway}',
        async handler(request, h) {
            try {
                let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, secret: await getSecret() });

                let deleted = await gatewayObject.delete();
                if (deleted) {
                    await request.flash({ type: 'info', message: `Gateway was deleted` });
                }

                return h.redirect('/admin/gateways');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete the gateway` });
                request.logger.error({ msg: 'Failed to delete the gateway', err, gateway: request.payload.gateway, remoteAddress: request.app.ip });
                return h.redirect(`/admin/gateways/${request.params.gateway}`);
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
                    await request.flash({ type: 'danger', message: `Failed to delete the gateway` });
                    request.logger.error({ msg: 'Failed to delete delete the gateway', err });

                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/tokens',
        async handler(request, h) {
            let accountData;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                accountData = await accountObject.loadAccountData();
            }

            const data = await tokens.list(request.query.account, request.query.page - 1, request.query.pageSize);

            data.tokens.forEach(entry => {
                entry.access = entry.access || {};
                entry.access.timeStr =
                    entry.access && entry.access.time && typeof entry.access.time.toISOString === 'function' ? entry.access.time.toISOString() : null;
                entry.scopes = entry.scopes
                    ? entry.scopes.map((scope, i) => ({
                          name: scope === '*' ? 'all scopes' : scope,
                          first: !i
                      }))
                    : false;
            });

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/tokens`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/tokens/new', 'http://localhost');
            if (request.query.account) {
                newLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'tokens/index',
                {
                    menuTokens: true,
                    data,

                    account: accountData,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1, request.query.state, request.query.query),
                        title: i + 1,
                        active: i === data.page
                    })),

                    newLink: newLink.pathname + newLink.search
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
                    return h.redirect('/admin/tokens').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null),
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/tokens/new',
        async handler(request, h) {
            let accountTokensLink = new URL('/admin/tokens', 'http://localhost');

            let accountData;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                accountData = await accountObject.loadAccountData();
                accountTokensLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'tokens/new',
                {
                    menuTokens: true,
                    values: {
                        scopesAll: true,
                        allAccounts: !request.query.account,
                        account: request.query.account
                    },
                    account: accountData,
                    accountTokensLink: accountTokensLink.pathname + accountTokensLink.search
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
                    return h.redirect('/admin/tokens').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null)
                })
            }
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

                if (request.payload.account) {
                    let accountObject = new Account({ redis, account: request.payload.account });
                    await accountObject.loadAccountData();
                    data.account = request.payload.account;
                }

                let token = await tokens.provision(data);

                return {
                    success: true,
                    token
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to generate token', err, remoteAddress: request.app.ip, description: request.payload.description });
                if (Boom.isBoom(err)) {
                    return Object.assign({ success: false }, err.output.payload);
                }
                return { success: false, error: err.code || 'Error', message: err.message };
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
                    scopes: Joi.array().items(Joi.string().valid('*', 'api', 'metrics', 'smtp', 'imap-proxy')).required().label('Scopes'),
                    account: accountIdSchema.default(null)
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
                request.logger.error({ msg: 'Failed to delete access token', err, token: request.payload.token, remoteAddress: request.app.ip });
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
                    request.logger.error({ msg: 'Failed to delete access token', err });

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
            await call({ cmd: 'checkLicense' });

            let subexp = await settings.get('subexp');
            let expiresDays;
            if (subexp) {
                let delayMs = new Date(subexp) - Date.now();
                expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);
            }

            return h.view(
                'config/license',
                {
                    menuLicense: true,
                    hideLicenseWarning: true,
                    menuConfig: true,
                    menuConfigLicense: true,

                    subexp,
                    expiresDays,

                    showLicenseText:
                        !request.app.licenseInfo ||
                        !request.app.licenseInfo.active ||
                        (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
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
                request.logger.error({ msg: 'Failed to register license key', err });

                return h.view(
                    'config/license',
                    {
                        menuConfig: true,
                        menuConfigWebhooks: true,

                        errors: err.details,
                        showLicenseText:
                            (err.details && !!err.details.license) ||
                            !request.app.licenseInfo ||
                            !request.app.licenseInfo.active ||
                            (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
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
                    request.logger.error({ msg: 'Failed to register license key', err });

                    return h
                        .view(
                            'config/license',
                            {
                                menuConfig: true,
                                menuConfigWebhooks: true,

                                errors,

                                showLicenseText:
                                    (errors && !!errors.license) ||
                                    !request.app.licenseInfo ||
                                    !request.app.licenseInfo.active ||
                                    (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
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
                request.logger.error({ msg: 'Failed to unregister license key', err, token: request.payload.token, remoteAddress: request.app.ip });
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
                    request.logger.error({ msg: 'Failed to unregister license key', err });

                    return h.redirect('/admin/config/license').takeover();
                },

                payload: Joi.object({})
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license/trial',
        async handler(request) {
            try {
                // provision new trial license

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${LICENSE_HOST}/licenses/trial`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        app: '@postalsys/emailengine-app',
                        hostname: os.hostname() || 'localhost',
                        url: (await settings.get('serviceUrl')) || ''
                    }),
                    headers,
                    dispatcher: fetchAgent
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.status = res.status;

                    try {
                        err.response = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                const data = await res.json();

                let licenseFile = `-----BEGIN LICENSE-----
${Buffer.from(data.content, 'base64url').toString('base64')}
-----END LICENSE-----`;

                const licenseInfo = await call({ cmd: 'updateLicense', license: licenseFile });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `Trial license was activated` });
                    return { success: true, message: `Trial license was activated` };
                }

                throw new Error('Failed to activate provisioned trial license');
            } catch (err) {
                request.logger.error({ msg: 'Failed to provision a trial license key', err, remoteAddress: request.app.ip });
                return { success: false, error: (err.response && err.response.error) || err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/login',
        async handler(request, h) {
            if (request.query.next && request.query.next.indexOf('/admin/login') === 0) {
                // prevent loops where successful login ends up back in the login page
                request.query.next = false;
            }

            // if authenticated and do not have to ask for TOTP, redirect directly to the admin page
            if (request.auth.isAuthenticated && !(request.auth.artifacts && request.auth.artifacts.requireTotp)) {
                return h.redirect(request.query.next || '/admin');
            }

            return h.view(
                'account/login',
                {
                    menuLogin: true,
                    values: {
                        username: 'admin',
                        next: request.query.next
                    },
                    providers: {
                        okta: USE_OKTA_AUTH && (await h.validateOktaConfig())
                    }
                },
                {
                    layout: 'login'
                }
            );
        },
        options: {
            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            },

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate login arguments', err });
                    return h.redirect('/admin/login').takeover();
                },

                query: Joi.object({
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
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
            await request.flash({ type: 'info', message: `User logged out` });
            return h.redirect('/');
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/login',
        async handler(request, h) {
            try {
                let rateLimit = await h.checkRateLimit(`login:${request.payload.username}`, 1, 10, 60);
                if (!rateLimit.success) {
                    request.logger.error({ msg: 'Rate limited', rateLimit });
                    let err = new Error('Rate limited, please wait and try again');
                    err.responseText = err.message;
                    throw err;
                }

                let authData = await settings.get('authData');
                let totpEnabled = (await settings.get('totpEnabled')) || false;

                if (authData && authData.user && authData.user !== request.payload.username) {
                    request.logger.error({ msg: 'Invalid username', username: request.payload.username });
                    let err = new Error('Failed to authenticate');
                    err.details = { password: err.message };
                    throw err;
                }

                if (authData && authData.password) {
                    try {
                        let valid = await pbkdf2.verify(authData.password, request.payload.password);
                        if (!valid) {
                            throw new Error('Invalid password');
                        }
                    } catch (E) {
                        request.logger.error({ msg: 'Failed to verify password hash', err: E, hash: authData.password });
                        let err = new Error('Failed to authenticate');
                        err.details = { password: err.message };
                        throw err;
                    }

                    request.cookieAuth.set({
                        user: authData.user,
                        requireTotp: totpEnabled,
                        passwordVersion: authData.passwordVersion || 0,
                        remember: request.payload.remember
                    });

                    if (request.payload.remember) {
                        request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                    }
                }

                if (totpEnabled) {
                    let url = new URL(`admin/totp`, 'http://localhost');

                    if (request.payload.next) {
                        url.searchParams.append('next', request.payload.next);
                    }

                    return h.redirect(url.pathname + url.search);
                }

                await request.flash({ type: 'info', message: `Authentication successful` });

                if (request.payload.next) {
                    return h.redirect(request.payload.next);
                } else {
                    return h.redirect('/admin');
                }
            } catch (err) {
                await request.flash({ type: 'danger', message: err.responseText || `Failed to authenticate` });
                request.logger.error({ msg: 'Failed to authenticate', err });

                let errors = err.details;

                return h.view(
                    'account/login',
                    {
                        menuLogin: true,
                        errors,
                        providers: {
                            okta: USE_OKTA_AUTH && (await h.validateOktaConfig())
                        }
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

                    await request.flash({ type: 'danger', message: `Failed to authenticate` });
                    request.logger.error({ msg: 'Failed to authenticate', err });

                    return h
                        .view(
                            'account/login',
                            {
                                menuLogin: true,
                                errors,
                                providers: {
                                    okta: USE_OKTA_AUTH && (await h.validateOktaConfig())
                                }
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
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
                })
            },

            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/totp',
        async handler(request, h) {
            return h.view(
                'account/totp',
                {
                    menuLogin: true,
                    values: {
                        username: request.auth.credentials.user,
                        next: request.query.next
                    }
                },
                {
                    layout: 'login'
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
                    request.logger.error({ msg: 'Failed to validate login arguments', err });
                    return h.redirect('/admin/login').takeover();
                },

                query: Joi.object({
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/totp',
        async handler(request, h) {
            try {
                if (!request.auth || !request.auth.artifacts || !request.auth.artifacts.requireTotp) {
                    // TOTP not needed
                    let url = new URL(`admin/login`, 'http://localhost');

                    if (request.payload.next) {
                        url.searchParams.append('next', request.payload.next);
                    }

                    return h.redirect(url.pathname + url.search);
                }

                if (request.auth && request.auth.credentials && request.auth.credentials.user) {
                    // attempt limiter
                    let rateLimit = await h.checkRateLimit(`totp:attempt:${request.auth.credentials.user}`, 1, 10, 60);
                    if (!rateLimit.success) {
                        request.logger.error({ msg: 'Rate limited', rateLimit });
                        let err = new Error('Rate limited, please wait and try again');
                        err.responseText = err.message;
                        throw err;
                    }
                }

                let totpSeed = await settings.get('totpSeed');
                if (!totpSeed) {
                    await request.flash({ type: 'danger', message: `2FA setup not initiated` });
                    return h.redirect(`/admin/login`);
                }

                let verified = speakeasy.totp.verify({
                    secret: base32.encode(Buffer.from(totpSeed)),
                    encoding: 'base32',
                    token: request.payload.code,
                    window: TOTP_WINDOW_SIZE
                });

                if (!verified) {
                    let err = new Error('Failed to verify login');
                    err.details = { code: 'Invalid or expired code' };
                    throw err;
                }

                // code re-use limiter
                let reUseLimit = await h.checkRateLimit(`totp:code:${request.payload.code}`, 1, 1, 12 * 60);
                if (!reUseLimit.success) {
                    request.logger.error({ msg: 'TOTP code recently used', reUseLimit });
                    let err = new Error('This code has been already used, please wait and try another code');
                    err.responseText = err.message;
                    throw err;
                }

                request.cookieAuth.clear('requireTotp');

                if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                    request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                }

                if (request.payload.next) {
                    return h.redirect(request.payload.next);
                } else {
                    return h.redirect('/admin');
                }
            } catch (err) {
                if (!err.details || !err.details.code) {
                    // skip error message if code is invalid
                    await request.flash({ type: 'danger', message: err.responseText || `Failed to verify login` });
                }

                request.logger.error({ msg: 'Failed to verify login', err });

                let errors = err.details;

                return h.view(
                    'account/totp',
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

                    await request.flash({ type: 'danger', message: `Failed to verify login` });
                    request.logger.error({ msg: 'Failed to verify login', err });

                    return h
                        .view(
                            'account/totp',
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
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required(),
                    code: Joi.string().min(6).max(6).description('6-digit TOTP code').required(),
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
                })
            },

            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/account/security',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            let totp = {
                enabled: (await settings.get('totpEnabled')) || false
            };

            let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

            let totpSeed = await settings.get('totpSeed');
            if (!totpSeed) {
                let secret = speakeasy.generateSecret({
                    length: 20,
                    name: username
                });

                totpSeed = secret.ascii;
                await settings.set('totpSeed', totpSeed);
            }

            if (!totp.enabled) {
                // create QR code
                const serviceUrl = (await settings.get('serviceUrl')) || '';

                let otpauth_url = speakeasy.otpauthURL({
                    secret: totpSeed,
                    // label is part of URL and speakeasy as of v2.0.0 does not encode special characters
                    label: encodeURIComponent(serviceUrl.replace(/^https?:\/\/|\/$/g, '')),
                    issuer: 'EmailEngine'
                });

                try {
                    totp.dataUrl = await QRCode.toDataURL(otpauth_url);
                } catch (err) {
                    request.logger.error({ msg: 'QR code generation failed', err });
                }
            }

            return h.view(
                'account/security',
                {
                    menuAccountSecurity: true,
                    activePassword: false,
                    disableAuthWarning: true,

                    username,

                    totp,
                    providers: {
                        okta: USE_OKTA_AUTH && (await h.validateOktaConfig())
                    },
                    serviceUrl: await settings.get('serviceUrl'),
                    okta: {
                        OKTA_OAUTH2_ISSUER,
                        OKTA_OAUTH2_CLIENT_ID,
                        OKTA_OAUTH2_CLIENT_SECRET: OKTA_OAUTH2_CLIENT_SECRET ? OKTA_OAUTH2_CLIENT_SECRET.substring(0, 6) + '…' : null
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
        path: '/admin/account/tfa/enable',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let totpSeed = await settings.get('totpSeed');
                if (!totpSeed) {
                    await request.flash({ type: 'danger', message: `2FA setup not initiated` });
                    return h.redirect(`/admin/account/security`);
                }

                let verified = speakeasy.totp.verify({
                    secret: base32.encode(Buffer.from(totpSeed)),
                    encoding: 'base32',
                    token: request.payload.code,
                    window: TOTP_WINDOW_SIZE
                });

                if (!verified) {
                    await request.flash({ type: 'danger', message: `TOTP code verification failed` });
                    return h.redirect(`/admin/account/security`);
                }

                await settings.set('totpEnabled', true);

                let authData = await settings.get('authData');
                if (authData) {
                    authData.passwordVersion = Date.now();
                    await settings.set('authData', authData);
                    request.cookieAuth.set('passwordVersion', authData.passwordVersion);
                    if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                        request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                    }
                }

                await request.flash({ type: 'success', message: `Two-factor authentication was enabled` });
                return h.redirect(`/admin/account/security`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to enable 2FA` });
                request.logger.error({ msg: 'Failed to enable 2FA', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
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
                    await request.flash({ type: 'danger', message: `Failed to enable 2FA` });
                    request.logger.error({ msg: 'Failed to enable 2FA', err });

                    return h.redirect('/admin').takeover();
                },

                payload: Joi.object({
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required(),
                    code: Joi.string().min(6).max(6).description('6-digit TOTP code').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/tfa/disable',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                await settings.set('totpEnabled', false);
                await settings.set('totpSeed', false);

                await request.flash({ type: 'info', message: `Two-factor authentication was disabled` });
                return h.redirect(`/admin/account/security`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to disable 2FA` });
                request.logger.error({ msg: 'Failed to enable 2FA', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
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
                    await request.flash({ type: 'danger', message: `Failed to disable 2FA` });
                    request.logger.error({ msg: 'Failed to disable 2FA', err });

                    return h.redirect('/admin').takeover();
                },

                payload: Joi.object({
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/logout-all',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let authData = await settings.get('authData');
                if (authData) {
                    authData.passwordVersion = Date.now();
                    await settings.set('authData', authData);
                }
                if (request.cookieAuth) {
                    request.cookieAuth.clear();
                }
                await request.flash({ type: 'info', message: `User logged out` });
                return h.redirect('/');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to log out user sessions` });
                request.logger.error({ msg: 'Failed to log out user sessions', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
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
                    await request.flash({ type: 'danger', message: `Failed to log out user sessions` });
                    request.logger.error({ msg: 'Failed to log out user sessions', err });

                    return h.redirect('/admin').takeover();
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/account/password',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

            return h.view(
                'account/password',
                {
                    menuAccountSecurity: true,
                    activePassword: true,
                    disableAuthWarning: true,

                    username
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
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let authData = await settings.get('authData');
                let hasExistingPassword = !!(authData && authData.password);
                if (hasExistingPassword) {
                    try {
                        let valid = await pbkdf2.verify(authData.password, request.payload.password0);
                        if (!valid) {
                            throw new Error('Invalid current password');
                        }
                    } catch (E) {
                        request.logger.error({ msg: 'Failed to verify password hash', err: E, hash: authData.password });
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
                authData.passwordVersion = Date.now();

                await settings.set('authData', authData);

                if (!server.auth.settings.default) {
                    server.auth.default('session');
                    request.cookieAuth.set({
                        user: authData.user,
                        passwordVersion: authData.passwordVersion
                    });
                } else {
                    request.cookieAuth.set('passwordVersion', authData.passwordVersion);
                }

                if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                    request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                }

                if (!hasExistingPassword) {
                    await request.flash({ type: 'info', message: `Authentication password set` });

                    return h.redirect('/admin');
                }

                await request.flash({ type: 'info', message: `Authentication password updated` });

                return h.redirect('/admin/account/password');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update password` });
                request.logger.error({ msg: 'Failed to update password', err });

                let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                return h.view(
                    'account/password',
                    {
                        menuAccountSecurity: true,
                        activePassword: true,
                        disableAuthWarning: true,
                        errors: err.details,

                        username
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
                    request.logger.error({ msg: 'Failed to update account password', err });

                    let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                    return h
                        .view(
                            'account/password',
                            {
                                menuAccountSecurity: true,
                                activePassword: true,
                                disableAuthWarning: true,
                                errors,

                                username
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

            const accounts = await accountObject.listAccounts(request.query.state, request.query.query, request.query.page - 1, request.query.pageSize);

            if (accounts.pages < request.query.page) {
                request.query.page = accounts.pages;
            }

            for (let account of accounts.accounts) {
                let accountObject = new Account({ redis, account: account.account });
                account.data = await accountObject.loadAccountData();

                if (account.data && account.data.oauth2 && account.data.oauth2.provider) {
                    let oauth2App = await oauth2Apps.get(account.data.oauth2.provider);
                    if (oauth2App) {
                        account.data.oauth2.app = oauth2App;
                    }
                }
            }

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = (page, state, query) => {
                let url = new URL(`admin/accounts`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize && request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                if (query) {
                    url.searchParams.append('query', query);
                }

                if (state) {
                    url.searchParams.append('state', state);
                }

                return url.pathname + url.search;
            };

            if (accounts.pages > accounts.page + 1) {
                nextPage = getPagingUrl(accounts.page + 2, request.query.state, request.query.query);
            }

            if (accounts.page > 0) {
                prevPage = getPagingUrl(accounts.page, request.query.state, request.query.query);
            }

            let stateOptions = [
                {
                    state: false,
                    label: 'All'
                },

                { divider: true },

                {
                    state: 'init',
                    label: 'Initializing'
                },

                {
                    state: 'connecting',
                    label: 'Connecting'
                },

                {
                    state: 'syncing',
                    label: 'Syncing'
                },

                {
                    state: 'connected',
                    label: 'Connected'
                },

                {
                    state: 'disconnected',
                    label: 'Disconnected'
                },

                {
                    state: 'authenticationError',
                    label: 'Authentication failed'
                },

                {
                    state: 'connectError',
                    label: 'Connection failed'
                },

                {
                    state: 'unset',
                    label: 'Unset'
                }
            ].map(entry => {
                let url = getPagingUrl(0, entry.state, request.query.query);
                return Object.assign({ url, selected: entry.state ? entry.state === request.query.state : !request.query.state }, entry);
            });

            return h.view(
                'accounts/index',
                {
                    menuAccounts: true,

                    query: request.query.query,
                    state: request.query.state,
                    pageSize: request.query.pageSize !== DEFAULT_PAGE_SIZE ? request.query.pageSize : false,

                    selectedState: stateOptions.find(entry => entry.state && entry.state === request.query.state),

                    searchTarget: '/admin/accounts',
                    searchPlaceholder: 'Search for accounts…',

                    showPaging: accounts.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: accounts.page === 0,
                    pageLinks: new Array(accounts.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1, request.query.state, request.query.query),
                        title: i + 1,
                        active: i === accounts.page
                    })),

                    stateOptions,

                    accounts: accounts.accounts.map(account => formatAccountData(account.data || account))
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
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
                    query: Joi.string().example('user@example').description('Filter accounts by name/email match').label('AccountQuery'),
                    state: Joi.string()
                        .trim()
                        .empty('')
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/new',

        async handler(request, h) {
            let { data, signature } = await getSignedFormData({
                account: request.payload.account,
                name: request.payload.name,

                // identify request
                n: crypto.randomBytes(NONCE_BYTES).toString('base64'),
                t: Date.now()
            });

            let url = new URL(`accounts/new`, 'http://localhost');

            url.searchParams.append('data', data);
            if (signature) {
                url.searchParams.append('sig', signature);
            }

            let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);

            if (!oauth2apps.length) {
                url.searchParams.append('type', 'imap');
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                payload: Joi.object({
                    account: accountIdSchema.default(null),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name')
                })
            }
        }
    });

    async function accountFormHandler(request, h) {
        const data = await parseSignedFormData(redis, request.payload, gt);

        const oauth2App = await oauth2Apps.get(request.payload.type);

        if (oauth2App && oauth2App.enabled) {
            // prepare account entry

            let accountData = {
                account: data.account
            };

            for (let key of ['name', 'email', 'syncFrom']) {
                if (data[key]) {
                    accountData[key] = data[key];
                }
            }

            accountData.notifyFrom = data.notifyFrom || new Date().toISOString();

            for (let key of ['redirectUrl', 'n', 't']) {
                if (!accountData._meta) {
                    accountData._meta = {};
                }
                accountData._meta[key] = data[key];
            }

            if (data.delegated) {
                accountData.delegated = true;
            } else {
                accountData.copy = false;
            }

            accountData.oauth2 = {
                provider: oauth2App.id
            };

            // throws if invalid or unknown app ID
            const oAuth2Client = await oauth2Apps.getClient(oauth2App.id);

            const nonce = data.n || crypto.randomBytes(NONCE_BYTES).toString('base64url');

            // store account data
            await redis
                .multi()
                .set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData))
                .expire(`${REDIS_PREFIX}account:add:${nonce}`, Math.floor(MAX_FORM_TTL / 1000))
                .exec();

            // Generate the url that will be used for the consent dialog.

            let requestPayload = {
                state: `account:add:${nonce}`
            };

            if (accountData.email) {
                requestPayload.email = accountData.email;
            }

            let authorizeUrl = oAuth2Client.generateAuthUrl(requestPayload);

            return h.redirect(authorizeUrl);
        }

        return h.view(
            'accounts/register/imap',
            {
                values: {
                    data: request.payload.data,
                    sig: request.payload.sig,

                    email: data.email,
                    name: data.name
                }
            },
            {
                layout: 'public'
            }
        );
    }

    server.route({
        method: 'GET',
        path: '/accounts/new',
        async handler(request, h) {
            if (request.query.type) {
                request.payload = request.query;
                return accountFormHandler(request, h);
            }

            // throws if check fails
            await parseSignedFormData(redis, request.query, gt);

            let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);
            oauth2apps.forEach(app => {
                app.providerData = oauth2ProviderData(app.provider);
            });

            return h.view(
                'accounts/register/index',
                {
                    values: {
                        data: request.query.data,
                        sig: request.query.sig
                    },

                    oauth2apps
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
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(gt.gettext('Failed to validate request arguments')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: Joi.string()
                        .empty('')
                        .allow(false)
                        .default(false)
                        .example('imap')
                        .description(
                            'Display the form for the specified account type (either "imap" or an OAuth2 app ID) instead of allowing the user to choose'
                        )
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new',

        handler: accountFormHandler,
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(gt.gettext('Failed to validate request arguments')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: Joi.string()
                        .empty('')
                        .allow(false)
                        .default(false)
                        .example('imap')
                        .description(
                            'Display the form for the specified account type (either "imap" or an OAuth2 app ID) instead of allowing the user to choose'
                        )
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap',

        async handler(request, h) {
            await parseSignedFormData(redis, request.payload, gt);

            let serverSettings;
            try {
                serverSettings = await autodetectImapSettings(request.payload.email);
            } catch (err) {
                request.logger.error({ msg: 'Failed to resolve email server settings', email: request.payload.email, err });
            }

            let values = Object.assign(
                {
                    name: request.payload.name,
                    email: request.payload.email,
                    password: request.payload.password,
                    data: request.payload.data,
                    sig: request.payload.sig
                },
                flattenObjectKeys(serverSettings)
            );

            values.imap_auth_user = values.imap_auth_user || request.payload.email;
            values.smtp_auth_user = values.smtp_auth_user || request.payload.email;

            values.imap_auth_pass = request.payload.password;
            values.smtp_auth_pass = request.payload.password;

            return h.view(
                'accounts/register/imap-server',
                {
                    values,
                    autoTest: values._source && values.imap_auth_user && values.smtp_auth_user && values.imap_auth_pass && values.smtp_auth_pass && true
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

                    await request.flash({ type: 'danger', message: gt.gettext('Failed to process account') });
                    request.logger.error({ msg: 'Failed to process account', err });

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
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
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
                let verifyResult = await verifyAccountInfo(
                    redis,
                    {
                        imap: {
                            host: request.payload.imap_host,
                            port: request.payload.imap_port,
                            secure: request.payload.imap_secure,
                            disabled: request.payload.imap_disabled,
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
                    },
                    request.logger.child({ action: 'verify-account' })
                );

                if (verifyResult) {
                    if (verifyResult.imap && verifyResult.imap.error && verifyResult.imap.code) {
                        switch (verifyResult.imap.code) {
                            case 'ENOTFOUND':
                                verifyResult.imap.error = gt.gettext('Server hostname was not found');
                                break;
                            case 'AUTHENTICATIONFAILED':
                                verifyResult.imap.error = gt.gettext('Invalid username or password');
                                break;
                        }
                    }

                    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
                        switch (verifyResult.smtp.code) {
                            case 'EDNS':
                                verifyResult.smtp.error = gt.gettext('Server hostname was not found');
                                break;
                            case 'EAUTH':
                                verifyResult.smtp.error = gt.gettext('Invalid username or password');
                                break;
                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = gt.gettext('TLS protocol error');
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
                        .integer()
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
                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
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
            const data = await parseSignedFormData(redis, request.payload, gt);

            const accountData = {
                account: data.account || null,
                name: request.payload.name || data.name,
                email: request.payload.email,

                tz: request.payload.tz,

                notifyFrom: data.notifyFrom ? new Date(data.notifyFrom) : new Date(),

                syncFrom: data.syncFrom || null,

                imap: {
                    host: request.payload.imap_host,
                    port: request.payload.imap_port,
                    secure: request.payload.imap_secure,
                    disabled: request.payload.imap_disabled,
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

            if (data.subconnections && data.subconnections.length) {
                accountData.subconnections = data.subconnections;
            }

            const accountObject = new Account({ redis, call, secret: await getSecret() });
            const result = await accountObject.create(accountData);

            if (data.n) {
                // store nonce to prevent this URL to be reused
                const keyName = `${REDIS_PREFIX}account:form:${data.n}`;
                try {
                    await redis
                        .multi()
                        .set(keyName, (data.t || '0').toString())
                        .expire(keyName, Math.floor(MAX_FORM_TTL / 1000))
                        .exec();
                } catch (err) {
                    request.logger.error({ msg: 'Failed to set nonce for an account form request', err });
                }
            }

            let httpRedirectUrl;
            if (data.redirectUrl) {
                const serviceUrl = await settings.get('serviceUrl');
                const url = new URL(data.redirectUrl, serviceUrl);
                url.searchParams.set('account', result.account);
                url.searchParams.set('state', result.state);
                httpRedirectUrl = url.href;
            } else {
                httpRedirectUrl = `/admin/accounts/${result.account}`;
            }

            return h.view(
                'redirect',
                { httpRedirectUrl },
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

                    await request.flash({ type: 'danger', message: gt.gettext('Failed to process account') });
                    request.logger.error({ msg: 'Failed to process account', err });

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
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone for autogenerated date strings'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
                    imap_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    imap_auth_pass: Joi.string().empty('').max(1024).required(),
                    imap_host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .integer()
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

                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
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
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            let accountData;

            try {
                // throws if account does not exist
                accountData = await accountObject.loadAccountData();
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

            let subConnectionInfo;
            try {
                subConnectionInfo = await call({ cmd: 'subconnections', account: request.params.account });
                for (let subconnection of subConnectionInfo) {
                    formatAccountData(subconnection);
                }
            } catch (err) {
                subConnectionInfo = {
                    err
                };
            }

            if (accountData && accountData.oauth2 && accountData.oauth2.provider) {
                let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
                if (oauth2App) {
                    accountData.oauth2.app = oauth2App;
                    accountData.oauth2.providerData = oauth2ProviderData(oauth2App.provider);
                }
            }

            accountData = formatAccountData(accountData);

            if (accountData.path === '*') {
                accountData.path = '';
            }

            accountData.imap = accountData.imap || {
                disabled: !accountData.oauth2
            };

            let gatewayObject = new Gateway({ redis });
            let gateways = await gatewayObject.listGateways(0, 100);

            let capabilities = [];
            if (accountData.imapServerInfo && accountData.imapServerInfo.capabilities) {
                capabilities = await capa(accountData.imapServerInfo.capabilities);
            }

            let authCapabilities = [];
            if (accountData.imapServerInfo && accountData.imapServerInfo.authCapabilities) {
                authCapabilities = await capa(accountData.imapServerInfo.authCapabilities, accountData.imapServerInfo.lastUsedAuthCapability);
            }

            if (accountData.smtpServerEhlo && accountData.smtpServerEhlo.length) {
                let smtpAuthMechanisms = [];
                for (let i = accountData.smtpServerEhlo.length - 1; i >= 0; i--) {
                    let entry = accountData.smtpServerEhlo[i];
                    if (/^auth\b/i.test(entry)) {
                        let authEntries = entry.split(/\s+/).slice(1);
                        if (authEntries.length) {
                            smtpAuthMechanisms = smtpAuthMechanisms.concat(authEntries);
                        }
                        accountData.smtpServerEhlo.splice(i, 1);
                    }
                }
                accountData.smtpAuthMechanisms = Array.from(new Set(smtpAuthMechanisms));

                for (let i = accountData.smtpAuthMechanisms.length - 1; i >= 0; i--) {
                    let entry = accountData.smtpAuthMechanisms[i];
                    switch (entry.toUpperCase()) {
                        case 'LOGIN':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'draft-murchison-sasl-login',
                                url: 'https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login'
                            };
                            break;
                        case 'PLAIN':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'RFC4616',
                                url: 'https://www.rfc-editor.org/rfc/rfc4616.html'
                            };
                            break;
                        case 'XOAUTH2':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'xoauth2-protocol',
                                url: 'https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange'
                            };
                            break;
                        case 'OAUTHBEARER':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'RFC7628',
                                url: 'https://www.rfc-editor.org/rfc/rfc7628.html'
                            };
                            break;
                    }
                }
            }

            return h.view(
                'accounts/account',
                {
                    menuAccounts: true,
                    account: accountData,
                    logs: await settings.get('logs'),
                    smtpError: accountData.smtpStatus && accountData.smtpStatus.status === 'error',

                    showSmtp: accountData.smtp || (accountData.oauth2 && accountData.oauth2.provider),

                    canSend: !!(
                        accountData.smtp ||
                        (accountData.oauth2 && accountData.oauth2.provider) ||
                        (gateways && gateways.gateways && gateways.gateways.length)
                    ),
                    canUseSmtp: !!(accountData.smtp || (accountData.oauth2 && accountData.oauth2.provider)),
                    gateways: gateways && gateways.gateways,

                    testSendTemplate: cachedTemplates.testSend,

                    accountForm: await getSignedFormData({
                        account: request.params.account,
                        name: accountData.name,
                        email: accountData.email,
                        redirectUrl: `/admin/accounts/${request.params.account}`
                    }),

                    showAdvanced: accountData.path || accountData.proxy || accountData.webhooks,

                    subConnectionInfo,

                    capabilities,
                    authCapabilities
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
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/delete',
        async handler(request, h) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, documentsQueue, call, secret: await getSecret() });

                let deleted = await accountObject.delete();
                if (deleted) {
                    await request.flash({ type: 'info', message: `Account was deleted` });
                }

                return h.redirect('/admin/accounts');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete the account` });
                request.logger.error({ msg: 'Failed to delete the account', err, account: request.payload.account, remoteAddress: request.app.ip });
                return h.redirect(`/admin/accounts/${request.params.account}`);
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
                    await request.flash({ type: 'danger', message: `Failed to delete the account` });
                    request.logger.error({ msg: 'Failed to delete delete the account', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/reconnect',
        async handler(request) {
            let account = request.params.account;
            try {
                request.logger.info({ msg: 'Request reconnect for logging', account });
                try {
                    await call({ cmd: 'update', account });
                } catch (err) {
                    request.logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                }

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request reconnect', err, account });
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

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/sync',
        async handler(request) {
            let account = request.params.account;
            try {
                request.logger.info({ msg: 'Request syncing', account });
                try {
                    await call({ cmd: 'sync', account });
                } catch (err) {
                    request.logger.error({ msg: 'Sync request failed', action: 'request_sync', account, err });
                }

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request syncing', err, account });
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

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/logs',
        async handler(request) {
            let account = request.params.account;
            let accountObject = new Account({ redis, account });
            try {
                request.logger.info({ msg: 'Request to update account logging state', account, enabled: request.payload.enabled });

                await redis.hSetExists(accountObject.getAccountKey(), 'logs', request.payload.enabled ? 'true' : 'false');

                return {
                    success: true,
                    enabled: (await redis.hget(accountObject.getAccountKey(), 'logs')) === 'true'
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to update account logging state', err, account, enabled: request.payload.enabled });
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

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/logs-flush',
        async handler(request) {
            let account = request.params.account;
            let accountObject = new Account({ redis, account });
            try {
                request.logger.info({ msg: 'Request to flush logs', account });

                await redis.del(accountObject.getLogKey());

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to flush logs', err, account });
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

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/logs.txt',
        async handler(request) {
            return getLogs(redis, request.params.account);
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
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
        method: 'GET',
        path: '/admin/accounts/{account}/edit',
        async handler(request, h) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            let accountData;
            try {
                // throws if account does not exist
                accountData = await accountObject.loadAccountData();
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

            let values = Object.assign({}, flattenObjectKeys(accountData), {
                imap: true,
                imap_disabled: (!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled),
                smtp: !!accountData.smtp,
                oauth2: !!accountData.oauth2,

                imap_auth_pass: '',
                smtp_auth_pass: ''
            });

            if (values.path === '*') {
                values.path = '';
            }

            let mailboxes = await getMailboxListing(accountObject);

            return h.view(
                'accounts/edit',
                {
                    menuAccounts: true,
                    account: request.params.account,
                    values,
                    availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                    hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                    hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                    defaultSmtpEhloName: await getServiceHostname()
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
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/edit',
        async handler(request, h) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

                let oldData = await accountObject.loadAccountData();

                let updates = {
                    account: request.params.account,
                    name: request.payload.name || '',
                    email: request.payload.email,
                    proxy: request.payload.proxy,
                    smtpEhloName: request.payload.smtpEhloName,
                    path: request.payload.path || '*',
                    webhooks: request.payload.webhooks
                };

                if (request.payload.imap) {
                    let imapAuth = Object.assign((oldData.imap && oldData.imap.auth) || {}, { user: request.payload.imap_auth_user });
                    let imapTls = (oldData.imap && oldData.imap.tls) || {};

                    if (request.payload.imap_auth_pass) {
                        imapAuth.pass = request.payload.imap_auth_pass;
                    }

                    updates.imap = Object.assign(oldData.imap || {}, {
                        host: request.payload.imap_host,
                        port: request.payload.imap_port,
                        secure: request.payload.imap_secure,
                        disabled: request.payload.imap_disabled,
                        sentMailPath: request.payload.imap_sentMailPath,
                        auth: imapAuth,
                        tls: imapTls
                    });

                    if (request.payload.imap_resyncDelay) {
                        updates.imap.resyncDelay = request.payload.imap_resyncDelay;
                    }
                }

                if (request.payload.smtp) {
                    let smtpAuth = Object.assign((oldData.smtp && oldData.smtp.auth) || {}, { user: request.payload.smtp_auth_user });
                    let smtpTls = (oldData.smtp && oldData.smtp.tls) || {};

                    if (request.payload.smtp_auth_pass) {
                        smtpAuth.pass = request.payload.smtp_auth_pass;
                    }

                    updates.smtp = Object.assign(oldData.smtp || {}, {
                        host: request.payload.smtp_host,
                        port: request.payload.smtp_port,
                        secure: request.payload.smtp_secure,
                        auth: smtpAuth,
                        tls: smtpTls
                    });
                }

                await accountObject.update(updates);

                return h.redirect(`/admin/accounts/${request.params.account}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update account settings` });
                request.logger.error({ msg: 'Failed to update account settings', err, account: request.params.account });

                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                let accountData = await accountObject.loadAccountData();

                let mailboxes = await getMailboxListing(accountObject);

                return h.view(
                    'accounts/edit',
                    {
                        menuAccounts: true,
                        account: request.params.account,
                        availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                        hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                        hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                        defaultSmtpEhloName: await getServiceHostname()
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                    let accountData = await accountObject.loadAccountData();
                    let mailboxes = await getMailboxListing(accountObject);

                    return h
                        .view(
                            'accounts/edit',
                            {
                                menuAccounts: true,
                                account: request.params.account,
                                errors,
                                availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                                hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                                hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                                defaultSmtpEhloName: await getServiceHostname()
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    imap_auth_user: Joi.string().empty('').trim().max(1024),
                    imap_auth_pass: Joi.string().empty('').max(1024),
                    imap_host: Joi.string().hostname().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(993)
                        .description('Service port number'),
                    imap_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),
                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    imap_resyncDelay: Joi.number().integer().empty(''),

                    imap_sentMailPath: Joi.string()
                        .empty('')
                        .default(null)
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used. Leave empty to unset."),

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    path: Joi.string().empty('').max(1024).default('').example('INBOX').description('Check changes only on selected path'),

                    smtp: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024),
                    smtp_auth_pass: Joi.string().empty('').max(1024),
                    smtp_host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
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
        path: '/admin/config/document-store',
        async handler(request, h) {
            let documentStoreEnabled = await settings.get('documentStoreEnabled');
            let documentStoreUrl = await settings.get('documentStoreUrl');
            let documentStoreIndex = (await settings.get('documentStoreIndex')) || 'emailengine';
            let documentStoreGenerateEmbeddings = await settings.get('documentStoreGenerateEmbeddings');
            let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
            let documentStoreUsername = await settings.get('documentStoreUsername');
            let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

            return h.view(
                'config/document-store/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreSettings: true,

                    values: {
                        documentStoreEnabled,
                        documentStoreUrl,
                        documentStoreIndex,
                        documentStoreAuthEnabled,
                        documentStoreUsername,
                        documentStoreGenerateEmbeddings
                    },

                    hasDocumentStorePassword,
                    hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey'))
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store',
        async handler(request, h) {
            try {
                if (!request.payload.documentStoreUrl) {
                    request.payload.documentStoreEnabled = false;
                }

                if (!request.payload.documentStoreUsername) {
                    request.payload.documentStoreAuthEnabled = false;
                    // clear password as well if no username set
                    request.payload.documentStorePassword = '';
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/document-store');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                return h.view(
                    'config/document-store/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreSettings: true,

                        hasDocumentStorePassword,
                        hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey'))
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                    return h
                        .view(
                            'config/document-store/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreSettings: true,

                                hasDocumentStorePassword,
                                hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configDocumentStoreSchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/chat',
        async handler(request, h) {
            let documentStoreChatModel = await settings.get('documentStoreChatModel');

            return h.view(
                'config/document-store/chat',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreChat: true,

                    documentStoreEnabled: await settings.get('documentStoreEnabled'),
                    hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                    indexInfo: await settings.get('embeddings:index'),

                    openAiModels: await getOpenAiModels(OPEN_AI_MODELS, documentStoreChatModel),

                    values: {
                        documentStoreGenerateEmbeddings: (await settings.get(`documentStoreGenerateEmbeddings`)) || false
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
        path: '/admin/config/document-store/chat',
        async handler(request, h) {
            try {
                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/document-store/chat');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/document-store/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreChat: true,

                        documentStoreEnabled: await settings.get('documentStoreEnabled'),
                        hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                        indexInfo: await settings.get('embeddings:index'),

                        openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.documentStoreChatModel)
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/document-store/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreChat: true,

                                documentStoreEnabled: await settings.get('documentStoreEnabled'),
                                hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                                indexInfo: await settings.get('embeddings:index'),

                                openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.documentStoreChatModel),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    documentStoreGenerateEmbeddings: settingsSchema.documentStoreGenerateEmbeddings.default(false),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    documentStoreChatModel: settingsSchema.documentStoreChatModel.empty('')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/pre-processing',
        async handler(request, h) {
            return h.view(
                'config/document-store/pre-processing/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStorePreProcessing: true,

                    values: {
                        enabled: (await settings.get(`documentStorePreProcessingEnabled`)) || false,

                        contentFnJson: JSON.stringify(
                            (await settings.get(`documentStorePreProcessingFn`)) ||
                                `// Pass all emails
return true;`
                        ),
                        contentMapJson: JSON.stringify(
                            (await settings.get(`documentStorePreProcessingMap`)) ||
                                `// By default the output payload is returned unmodified.
return payload;`
                        )
                    },

                    examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/pre-processing',
        async handler(request, h) {
            let contentFn, contentMap;
            try {
                if (request.payload.contentFnJson === '') {
                    contentFn = null;
                } else {
                    contentFn = JSON.parse(request.payload.contentFnJson);
                    if (typeof contentFn !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                if (request.payload.contentMapJson === '') {
                    contentMap = null;
                } else {
                    contentMap = JSON.parse(request.payload.contentMapJson);
                    if (typeof contentMap !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentMapJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                await settings.setMulti({
                    documentStorePreProcessingEnabled: request.payload.enabled,
                    documentStorePreProcessingFn: contentFn,
                    documentStorePreProcessingMap: contentMap
                });

                await request.flash({ type: 'info', message: `Pre-processing rules for the Document Store were updated` });
                return h.redirect(`/admin/config/document-store/pre-processing`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update Document Store pre-processing rules` });
                request.logger.error({ msg: 'Failed to update Document Store pre-processing rules', err });

                return h.view(
                    'config/document-store/pre-processing/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStorePreProcessing: true,

                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
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

                    await request.flash({ type: 'danger', message: `Failed to update Document Store pre-processing rules` });
                    request.logger.error({ msg: 'Failed to update Document Store pre-processing rules', err });

                    return h
                        .view(
                            'config/document-store/pre-processing/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStorePreProcessing: true,

                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the pre-processing enabled'),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),
                    contentMapJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Map function')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/mappings',
        async handler(request, h) {
            let customMappings = (await redis.hgetall(`${REDIS_PREFIX}mappings`)) || {};
            const customMappingsList = Object.keys(customMappings)
                .map(key => {
                    let value;
                    try {
                        value = JSON.parse(customMappings[key]);
                    } catch (err) {
                        return null;
                    }

                    let type = value.type || (value.properties ? 'object' : 'text');
                    if (value.analyzer === 'htmlStripAnalyzer') {
                        type += ' (HTML)';
                    }
                    if (value.analyzer === 'filenameIndex') {
                        type += ' (filename)';
                    }
                    return {
                        key,
                        type,
                        indexed: value.index !== false
                    };
                })
                .sort((a, b) => a.key.toLowerCase().localeCompare(b.key.toLowerCase()));
            return h.view(
                'config/document-store/mappings/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreMappings: true,

                    defaultMappingsList,
                    customMappingsList
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/mappings/new',
        async handler(request, h) {
            return h.view(
                'config/document-store/mappings/new',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreMappings: true,

                    fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: false })),

                    values: {
                        indexed: true
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
        path: '/admin/config/document-store/mappings/new',
        async handler(request, h) {
            try {
                const { index, client } = await getESClient(request.logger);
                if (!client) {
                    return;
                }

                let mappingEntry = {};
                switch (request.payload.type) {
                    case 'html':
                        mappingEntry[request.payload.field] = {
                            type: 'text',
                            analyzer: 'htmlStripAnalyzer',
                            index: !!request.payload.indexed
                        };
                        break;
                    case 'filename':
                        mappingEntry[request.payload.field] = {
                            type: 'text',
                            analyzer: 'filenameIndex',
                            search_analyzer: 'filenameSearch',
                            index: !!request.payload.indexed
                        };
                        break;
                    default: {
                        mappingEntry[request.payload.field] = {
                            type: request.payload.type,
                            index: !!request.payload.indexed
                        };
                    }
                }

                try {
                    const updateRes = await client.indices.putMapping({ index, properties: mappingEntry });
                    assert(updateRes && updateRes.acknowledged);
                } catch (err) {
                    if (err.meta && err.meta.body && err.meta.body.error && err.meta.body.error.reason) {
                        let error = Boom.boomify(new Error(err.meta.body.error.reason), { statusCode: err.meta.statusCode || 500 });
                        throw error;
                    }
                    throw err;
                }

                await redis.hset(`${REDIS_PREFIX}mappings`, request.payload.field, JSON.stringify(mappingEntry[request.payload.field]));

                await request.flash({ type: 'info', message: `Mapping created` });
                return h.redirect('/admin/config/document-store/mappings');
            } catch (err) {
                if (Boom.isBoom(err)) {
                    await request.flash({ type: 'danger', message: err.message });
                } else {
                    await request.flash({ type: 'danger', message: err.responseText || `Failed to create mapping` });
                }
                request.logger.error({ msg: 'Failed to create mapping', err });

                return h.view(
                    'config/document-store/mappings/new',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreMappings: true,

                        fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: request.payload.type === entry.type }))
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

                    await request.flash({ type: 'danger', message: `Failed to create mapping` });
                    request.logger.error({ msg: 'Failed to create mapping', err });

                    return h
                        .view(
                            'config/document-store/mappings/new',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreMappings: true,

                                fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: request.payload.type === entry.type })),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    field: Joi.string()
                        .empty('')
                        .trim()
                        .lowercase()
                        .pattern(/^[-_+]|[\\/*?"<>| ,#:]/, { name: 'allowed elasticsearch field', invert: true })
                        .invalid(...Object.keys(defaultMappings))
                        .required()
                        .label('Field name'),
                    type: Joi.string()
                        .empty('')
                        .trim()
                        .valid(...FIELD_TYPES.map(entry => entry.type))
                        .default('text')
                        .label('Field type'),
                    indexed: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/test',
        async handler(request) {
            const { documentStoreUrl, documentStoreAuthEnabled, documentStoreUsername, documentStorePassword } = request.payload;

            let clientConfig = {
                node: { url: new URL(documentStoreUrl), tls: { rejectUnauthorized: false } },
                auth:
                    documentStoreAuthEnabled && documentStoreUsername
                        ? {
                              username: documentStoreUsername,
                              password: documentStorePassword || (await settings.get('documentStorePassword'))
                          }
                        : false
            };

            const client = new ElasticSearch(clientConfig);

            let start = Date.now();
            let duration;
            try {
                let clusterInfo;

                try {
                    clusterInfo = await client.info();
                    duration = Date.now() - start;
                } catch (err) {
                    duration = Date.now() - start;
                    throw err;
                }

                if (!clusterInfo || !clusterInfo.name) {
                    let err = new Error(`Invalid response from server`);
                    throw err;
                }

                return {
                    success: true,
                    duration
                };
            } catch (err) {
                request.logger.error({
                    msg: 'Failed posting request',
                    documentStoreUrl,
                    documentStoreAuthEnabled,
                    documentStoreUsername,
                    command: 'info',
                    err
                });
                return {
                    success: false,
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
                    documentStoreUrl: settingsSchema.documentStoreUrl.required(),
                    documentStoreAuthEnabled: settingsSchema.documentStoreAuthEnabled.default(false),
                    documentStoreUsername: settingsSchema.documentStoreUsername.default(''),
                    documentStorePassword: settingsSchema.documentStorePassword
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/network',
        async handler(request, h) {
            let smtpStrategy = (await settings.get('smtpStrategy')) || 'default';
            let imapStrategy = (await settings.get('imapStrategy')) || 'default';

            let proxyEnabled = await settings.get('proxyEnabled');
            let proxyUrl = await settings.get('proxyUrl');
            let smtpEhloName = await settings.get('smtpEhloName');

            let localAddresses = [].concat((await settings.get('localAddresses')) || []);

            let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: smtpStrategy === entry.key }, entry));
            let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: imapStrategy === entry.key }, entry));

            return h.view(
                'config/network',
                {
                    menuConfig: true,
                    menuConfigNetwork: true,

                    smtpStrategies,
                    imapStrategies,

                    values: {
                        proxyEnabled,
                        proxyUrl,
                        smtpEhloName
                    },

                    addresses: await listPublicInterfaces(localAddresses),
                    addressListTemplate: cachedTemplates.addressList,
                    defaultSmtpEhloName: await getServiceHostname()
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network/reload',
        async handler(request) {
            try {
                await updatePublicInterfaces();

                let localAddresses = [].concat((await settings.get('localAddresses')) || []);

                return {
                    success: true,
                    addresses: await listPublicInterfaces(localAddresses)
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed loading public IP addresses', err });
                return {
                    success: false,
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

                failAction
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network',
        async handler(request, h) {
            try {
                for (let key of ['smtpStrategy', 'imapStrategy', 'localAddresses', 'proxyUrl', 'smtpEhloName', 'proxyEnabled']) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/network');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.smtpStrategy === entry.key }, entry));
                let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.imapStrategy === entry.key }, entry));

                return h.view(
                    'config/network',
                    {
                        menuConfig: true,
                        menuConfigNetwork: true,
                        smtpStrategies,
                        imapStrategies,

                        addresses: await listPublicInterfaces(request.payload.localAddresses),
                        addressListTemplate: cachedTemplates.addressList,
                        defaultSmtpEhloName: await getServiceHostname()
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.smtpStrategy === entry.key }, entry));
                    let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.imapStrategy === entry.key }, entry));

                    return h
                        .view(
                            'config/network',
                            {
                                menuConfig: true,
                                menuConfigNetwork: true,
                                smtpStrategies,
                                imapStrategies,

                                addresses: await listPublicInterfaces(request.payload.localAddresses),
                                addressListTemplate: cachedTemplates.addressList,
                                defaultSmtpEhloName: await getServiceHostname(),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    imapStrategy: settingsSchema.imapStrategy.default('default'),
                    smtpStrategy: settingsSchema.smtpStrategy.default('default'),
                    localAddresses: settingsSchema.localAddresses.default([]),

                    proxyUrl: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,
                    proxyEnabled: settingsSchema.proxyEnabled
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network/delete',
        async handler(request, h) {
            try {
                let localAddress = request.payload.localAddress;
                let localAddresses = [].concat((await settings.get('localAddresses')) || []);
                if (localAddresses.includes(localAddress)) {
                    let list = new Set(localAddresses);
                    list.delete(localAddress);
                    localAddresses = Array.from(list);
                    await settings.set('localAddresses', localAddresses);
                }

                await redis.hdel(`${REDIS_PREFIX}interfaces`, localAddress);

                await request.flash({ type: 'info', message: `Address was removed from the list` });
                return h.redirect('/admin/config/network');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to delete address` });
                request.logger.error({ msg: 'Failed to delete address', err, localAddress: request.payload.localAddress, remoteAddress: request.app.ip });
                return h.redirect('/admin/config/network');
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
                    await request.flash({ type: 'danger', message: `Failed to delete address` });
                    request.logger.error({ msg: 'Failed to delete address', err });

                    return h.redirect('/admin/config/network').takeover();
                },

                payload: Joi.object({
                    localAddress: Joi.string().ip({
                        version: ['ipv4', 'ipv6'],
                        cidr: 'forbidden'
                    })
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/imap-proxy',
        async handler(request, h) {
            let values = {
                imapProxyServerEnabled: await settings.get('imapProxyServerEnabled'),
                imapProxyServerPassword: await settings.get('imapProxyServerPassword'),
                imapProxyServerPort: await settings.get('imapProxyServerPort'),
                imapProxyServerHost: await settings.get('imapProxyServerHost'),
                imapProxyServerProxy: await settings.get('imapProxyServerProxy'),
                imapProxyServerTLSEnabled: await settings.get('imapProxyServerTLSEnabled')
            };

            let availableAddresses = new Set(
                Object.values(os.networkInterfaces())
                    .flatMap(entry => entry)
                    .map(entry => entry.address)
            );
            availableAddresses.add('0.0.0.0');

            let hostname = await h.serviceDomain();
            let certificateData = await h.getCertificate();

            return h.view(
                'config/imap-proxy',
                {
                    menuConfig: true,
                    menuConfigImapProxy: true,

                    values,

                    serverState: await getServerStatus('imapProxy'),
                    availableAddresses: Array.from(availableAddresses).join(','),

                    serviceDomain: hostname,
                    serviceUrl: await settings.get('serviceUrl'),
                    certificateData
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/imap-proxy',
        async handler(request, h) {
            try {
                let existingSetup = {};
                let hasServerChanges = false;

                const systemKeys = ['imapProxyServerEnabled', 'imapProxyServerPort', 'imapProxyServerHost', 'imapProxyServerTLSEnabled'];
                for (let key of systemKeys) {
                    existingSetup[key] = await settings.get(key);
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                    if (systemKeys.includes(key) && request.payload[key] !== existingSetup[key]) {
                        hasServerChanges = true;
                    }
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (hasServerChanges) {
                    // request server restart
                    try {
                        await call({ cmd: 'imapProxyReload' });
                    } catch (err) {
                        request.logger.error({ msg: 'Reload request failed', action: 'request_reload_imap_proxy', err });
                    }
                }

                return h.redirect('/admin/config/imap-proxy');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let availableAddresses = new Set(
                    Object.values(os.networkInterfaces())
                        .flatMap(entry => entry)
                        .map(entry => entry.address)
                );
                availableAddresses.add('0.0.0.0');

                let hostname = await h.serviceDomain();
                let certificateData = await h.getCertificate();

                return h.view(
                    'config/imap-proxy',
                    {
                        menuConfig: true,
                        menuConfigImapProxy: true,

                        serverState: await getServerStatus('imap'),
                        availableAddresses: Array.from(availableAddresses).join(','),

                        serviceDomain: hostname,
                        serviceUrl: await settings.get('serviceUrl'),
                        certificateData
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let availableAddresses = new Set(
                        Object.values(os.networkInterfaces())
                            .flatMap(entry => entry)
                            .map(entry => entry.address)
                    );
                    availableAddresses.add('0.0.0.0');

                    let hostname = await h.serviceDomain();
                    let certificateData = await h.getCertificate();

                    return h
                        .view(
                            'config/imap-proxy',
                            {
                                menuConfig: true,
                                menuConfigImapProxy: true,

                                serverState: await getServerStatus('imapProxy'),
                                availableAddresses: Array.from(availableAddresses).join(','),

                                serviceDomain: hostname,
                                serviceUrl: await settings.get('serviceUrl'),
                                certificateData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configImapProxySchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/smtp',
        async handler(request, h) {
            let values = {
                smtpServerEnabled: await settings.get('smtpServerEnabled'),
                smtpServerPassword: await settings.get('smtpServerPassword'),
                smtpServerAuthEnabled: await settings.get('smtpServerAuthEnabled'),
                smtpServerPort: await settings.get('smtpServerPort'),
                smtpServerHost: await settings.get('smtpServerHost'),
                smtpServerProxy: await settings.get('smtpServerProxy'),
                smtpServerTLSEnabled: await settings.get('smtpServerTLSEnabled')
            };

            let availableAddresses = new Set(
                Object.values(os.networkInterfaces())
                    .flatMap(entry => entry)
                    .map(entry => entry.address)
            );
            availableAddresses.add('0.0.0.0');

            let hostname = await h.serviceDomain();
            let certificateData = await h.getCertificate();

            return h.view(
                'config/smtp',
                {
                    menuConfig: true,
                    menuConfigSmtp: true,

                    values,

                    serverState: await getServerStatus('smtp'),
                    availableAddresses: Array.from(availableAddresses).join(','),

                    serviceDomain: hostname,
                    serviceUrl: await settings.get('serviceUrl'),
                    certificateData
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/smtp',
        async handler(request, h) {
            try {
                let existingSetup = {};
                let hasServerChanges = false;

                const systemKeys = ['smtpServerEnabled', 'smtpServerPort', 'smtpServerHost', 'smtpServerTLSEnabled'];
                for (let key of systemKeys) {
                    existingSetup[key] = await settings.get(key);
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                    if (systemKeys.includes(key) && request.payload[key] !== existingSetup[key]) {
                        hasServerChanges = true;
                    }
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (hasServerChanges) {
                    // request server restart
                    try {
                        await call({ cmd: 'smtpReload' });
                    } catch (err) {
                        request.logger.error({ msg: 'Reload request failed', action: 'request_reload_smtp', err });
                    }
                }

                return h.redirect('/admin/config/smtp');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let availableAddresses = new Set(
                    Object.values(os.networkInterfaces())
                        .flatMap(entry => entry)
                        .map(entry => entry.address)
                );
                availableAddresses.add('0.0.0.0');

                let hostname = await h.serviceDomain();
                let certificateData = await h.getCertificate();

                return h.view(
                    'config/smtp',
                    {
                        menuConfig: true,
                        menuConfigSmtp: true,

                        serverState: await getServerStatus('smtp'),
                        availableAddresses: Array.from(availableAddresses).join(','),

                        serviceDomain: hostname,
                        serviceUrl: await settings.get('serviceUrl'),
                        certificateData
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let availableAddresses = new Set(
                        Object.values(os.networkInterfaces())
                            .flatMap(entry => entry)
                            .map(entry => entry.address)
                    );
                    availableAddresses.add('0.0.0.0');

                    let hostname = await h.serviceDomain();
                    let certificateData = await h.getCertificate();

                    return h
                        .view(
                            'config/smtp',
                            {
                                menuConfig: true,
                                menuConfigSmtp: true,

                                serverState: await getServerStatus('smtp'),
                                availableAddresses: Array.from(availableAddresses).join(','),

                                serviceDomain: hostname,
                                serviceUrl: await settings.get('serviceUrl'),
                                certificateData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configSmtpSchema)
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/smtp/certificate',
        async handler(request, h) {
            try {
                let certificateData = await h.getCertificate(true);
                if (!certificateData) {
                    throw new Error(`Failed to provision a ceritifcate`);
                }

                return {
                    success: true,
                    domain: certificateData.domain,
                    fingerprint: certificateData.fingerprint,
                    altNames: certificateData.altNames,
                    validTo: certificateData.validTo && certificateData.validTo.toISOString(),
                    label: certificateData.label
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request syncing', err });
                return {
                    success: false,
                    error: err.message
                };
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/.well-known/acme-challenge/{token}',
        async handler(request, h) {
            let domain = (request.headers.host || '').toString().replace(/:.*$/g, '').trim().toLowerCase();

            let challenge;
            try {
                challenge = await h.certs.routeHandler(domain, request.params.token);
                if (!challenge) {
                    throw new Error('Empty challenge');
                }
            } catch (err) {
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                throw error;
            }

            const response = h.response('success');
            response.type('text/plain');

            return challenge;
        },

        options: {
            auth: false
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/browser',
        async handler(request) {
            for (let key of ['serviceUrl', 'language', 'timezone']) {
                if (request.payload[key]) {
                    let existingValue = await settings.get(key);
                    if (existingValue === null) {
                        await settings.set(key, request.payload[key]);
                    }
                }
            }
            return { success: true };
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
                    serviceUrl: settingsSchema.serviceUrl.empty('').allow(false),

                    language: Joi.string()
                        .empty('')
                        .lowercase()
                        .regex(/^[a-z0-9]{1,5}([-_][a-z0-9]{1,15})?$/)
                        .allow(false),

                    timezone: Joi.string().empty('').allow(false).max(255)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/smtp/create-test',
        async handler(request) {
            let account = request.payload.account;

            try {
                request.logger.info({ msg: 'Request SMTP test', account });

                let accountObject = new Account({ redis, account, call, secret: await getSecret() });

                let accountData;
                try {
                    accountData = await accountObject.loadAccountData();
                } catch (err) {
                    return {
                        error: err.message
                    };
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        requestor: '@postalsys/emailengine-app'
                    }),
                    headers,
                    dispatcher: fetchAgent
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.status = res.status;

                    try {
                        err.response = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testAccount = await res.json();
                if (!testAccount || !testAccount.user) {
                    let err = new Error(`Invalid test account`);
                    err.status = 500;

                    try {
                        err.response = testAccount;
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                try {
                    let now = new Date().toISOString();
                    let queueResponse = await accountObject.queueMessage(
                        {
                            account: accountData.account,
                            subject: `Delivery test ${now}`,
                            text: `Hello

This is an automated email to test deliverability settings. If you see this email, you can safely delete it.

${now}`,
                            html: `<p>Hello</p>
<p>This is an automated email to test deliverability settings. If you see this email, you can safely delete it.</p>
<p>${now}</p>`,

                            from: {
                                name: accountData.name,
                                address: accountData.email
                            },
                            to: [{ name: 'Delivery Test Server', address: testAccount.address }],
                            copy: false,
                            gateway: request.payload.gateway,
                            feedbackKey: `${REDIS_PREFIX}test-send:${testAccount.user}`,
                            deliveryAttempts: 1
                        },
                        { source: 'test' }
                    );

                    return Object.assign(testAccount, queueResponse || {});
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'Failed to request test account', err, account });
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
                    account: accountIdSchema.required(),
                    gateway: Joi.string().empty('').max(256).example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/smtp/check-test',
        async handler(request) {
            let user = request.payload.user;

            try {
                request.logger.info({ msg: 'Request SMTP test response', user });

                let deliveryStatus = (await redis.hgetall(`${REDIS_PREFIX}test-send:${user}`)) || {};
                if (deliveryStatus.success === 'false') {
                    let err = new Error(`Failed to deliver email: ${deliveryStatus.error}`);
                    err.status = 500;
                    throw err;
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address/${user}`, {
                    method: 'get',
                    headers,
                    dispatcher: fetchAgent
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.status = res.status;

                    try {
                        err.response = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testResponse = await res.json();

                if (testResponse) {
                    let mainSig =
                        testResponse.dkim &&
                        testResponse.dkim.results &&
                        testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass' && entry.status.aligned);

                    if (!mainSig) {
                        mainSig =
                            testResponse.dkim &&
                            testResponse.dkim.results &&
                            testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass');
                    }

                    if (!mainSig) {
                        mainSig = testResponse.dkim && testResponse.dkim.results && testResponse.dkim.results[0];
                    }

                    testResponse.mainSig = mainSig || {
                        status: {
                            result: 'none'
                        }
                    };

                    if (testResponse.spf && testResponse.spf.status && testResponse.spf.status.comment) {
                        testResponse.spf.status.comment = testResponse.spf.status.comment.replace(/^[^:\s]+:s*/, '');
                    }
                }

                return testResponse;
            } catch (err) {
                request.logger.error({ msg: 'Failed to request test response', err, user });
                return { status: 'error', error: err.message };
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
                    user: Joi.string().guid().description('Test ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/unsubscribe',
        async handler(request, h) {
            let data = Buffer.from(request.query.data, 'base64url').toString();
            // do not check signature, validate fields in the submit step

            data = JSON.parse(data);

            if (!data || typeof data !== 'object' || data.act !== 'unsub') {
                throw new Error('Invalid input');
            }

            // throws if account does not exist
            let accountObject = new Account({ redis, account: data.acc });
            await accountObject.loadAccountData();

            return h.view(
                'unsubscribe',
                {
                    unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${data.list}`, data.rcpt),
                    values: {
                        listId: data.list,
                        account: data.acc,
                        messageId: data.msg,
                        email: data.rcpt
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
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(gt.gettext('Failed to validate request arguments')), { statusCode: 400 });
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
        path: '/unsubscribe/address',
        async handler(request, h) {
            try {
                // throws if account does not exist
                let accountObject = new Account({ redis, account: request.payload.account });
                await accountObject.loadAccountData();

                let reSubscribed = false;

                switch (request.payload.action) {
                    case 'unsubscribe': {
                        let isNew = await redis.eeListAdd(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`,
                            request.payload.listId,
                            request.payload.email.toLowerCase().trim(),
                            JSON.stringify({
                                recipient: request.payload.email,
                                account: request.payload.account,
                                source: 'form',
                                reason: 'unsubscribe',
                                messageId: request.payload.messageId,
                                remoteAddress: request.info.remoteAddress,
                                userAgent: request.headers['user-agent'],
                                created: new Date().toISOString()
                            })
                        );

                        if (isNew) {
                            await call({
                                cmd: 'unsubscribe',
                                account: request.payload.account,
                                payload: {
                                    recipient: request.payload.email,
                                    messageId: request.payload.messageId,
                                    listId: request.payload.listId,
                                    remoteAddress: request.info.remoteAddress,
                                    userAgent: request.headers['user-agent']
                                }
                            });
                        }
                        break;
                    }

                    case 'subscribe': {
                        let removed = await redis.eeListRemove(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`,
                            request.payload.listId,
                            request.payload.email.toLowerCase().trim()
                        );

                        if (removed) {
                            await call({
                                cmd: 'subscribe',
                                account: request.payload.account,
                                payload: {
                                    recipient: request.payload.email,
                                    messageId: request.payload.messageId,
                                    listId: request.payload.listId,
                                    remoteAddress: request.info.remoteAddress,
                                    userAgent: request.headers['user-agent']
                                }
                            });
                        }

                        reSubscribed = true;
                        break;
                    }
                }

                return h.view(
                    'unsubscribe',
                    {
                        unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email),
                        values: request.payload,
                        reSubscribed
                    },
                    {
                        layout: 'public'
                    }
                );
            } catch (err) {
                await request.flash({ type: 'danger', message: gt.gettext('Failed to process request') });
                request.logger.error({ msg: 'Failed to process subscription request', err });

                return h.view(
                    'unsubscribe',
                    {
                        unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email)
                    },
                    {
                        layout: 'public'
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

                    await request.flash({ type: 'danger', message: gt.gettext('Failed to process request') });
                    request.logger.error({ msg: 'Failed to process subscription request', err });

                    return h
                        .view(
                            'unsubscribe',
                            {
                                unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email),
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    action: Joi.string().valid('subscribe', 'unsubscribe').required(),
                    account: accountIdSchema.required(),
                    listId: Joi.string().hostname().empty('').example('test-list').label('List ID').required(),
                    email: Joi.string().email().empty('').required().description('Email address').required(),
                    messageId: Joi.string().empty('').max(996).example('<test123@example.com>').description('Message ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/internals',
        async handler(request, h) {
            let threads = await call({ cmd: 'threads' });

            let defaultLocale = (await settings.get('locale')) || 'en';

            let formatter;
            let percentFormatter;
            let bytesFormatter;

            let percentFormatterOpts = {
                style: 'percent',
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            };

            let bytesFormatterOpts = {
                style: 'unit',
                unit: 'byte',
                notation: 'compact',
                unitDisplay: 'narrow'
            };

            try {
                formatter = new Intl.NumberFormat(defaultLocale, {});
                percentFormatter = new Intl.NumberFormat(defaultLocale, percentFormatterOpts);
                bytesFormatter = new Intl.NumberFormat(defaultLocale, bytesFormatterOpts);
            } catch (err) {
                formatter = new Intl.NumberFormat('en-US', {});
                percentFormatter = new Intl.NumberFormat('en-US', percentFormatterOpts);
                bytesFormatter = new Intl.NumberFormat('en-US', bytesFormatterOpts);
            }

            return h.view(
                'internals/index',
                {
                    menuToolsInternals: true,
                    menuTools: true,

                    threads: threads.map(threadInfo => {
                        for (let key of Object.keys(threadInfo)) {
                            switch (key) {
                                case 'online':
                                    threadInfo.timeStr = new Date(threadInfo.online).toISOString();
                                    break;

                                case 'messages':
                                case 'called':
                                case 'accounts':
                                case 'threadId':
                                    threadInfo[key] = formatter.format(threadInfo[key]);
                                    break;

                                case 'used_heap_size':
                                    threadInfo.heapUsed = bytesFormatter.format(threadInfo[key]).replace(/BB$/, 'GB');
                                    threadInfo.heapRelative = percentFormatter.format(threadInfo.used_heap_size / threadInfo.heap_size_limit);
                                    break;

                                case 'heap_size_limit':
                                    threadInfo.heapMax = bytesFormatter.format(threadInfo[key]).replace(/BB$/, 'GB');
                                    break;
                            }
                        }

                        return threadInfo;
                    })
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/internals/kill',
        async handler(request, h) {
            try {
                let killed = await call({ cmd: 'kill-thread', thread: request.payload.thread });
                if (killed) {
                    await request.flash({ type: 'info', message: `Thread was killed` });
                }

                return h.redirect('/admin/internals');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to kill thread` });
                request.logger.error({ msg: 'Failed to kill thread', err, thread: request.payload.thread, remoteAddress: request.app.ip });
                return h.redirect('/admin/internals');
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
                    await request.flash({ type: 'danger', message: `Failed to kill thread` });
                    request.logger.error({ msg: 'Failed to kill thread', err });

                    return h.redirect('/admin/internals').takeover();
                },

                payload: Joi.object({
                    thread: Joi.number().integer().min(1).max(1000000).required().example(1).description('Thread ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/internals/snapshot',
        async handler(request, h) {
            try {
                let snapshot = await call({ cmd: 'snapshot-thread', thread: request.payload.thread, timeout: 10 * 60 * 1000 });
                if (!snapshot) {
                    let error = Boom.boomify(new Error('Snapshot was not found'), { statusCode: 404 });
                    throw error;
                }

                return h
                    .response(Buffer.from(snapshot))
                    .header('Content-Type', 'application/octet-stream')
                    .header(
                        'Content-Disposition',
                        `attachment; filename=Heap-${new Date()
                            .toISOString()
                            .substring(0, 19)
                            .replace(/[^0-9T]+/g, '')}.heapsnapshot`
                    )
                    .header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0')
                    .header('Pragma', 'no-cache')
                    .code(200);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to generate snapshot` });
                request.logger.error({ msg: 'Failed to generate snapshot', err, thread: request.payload.thread, remoteAddress: request.app.ip });
                return h.redirect('/admin/internals');
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
                    await request.flash({ type: 'danger', message: `Failed to generate snapshot` });
                    request.logger.error({ msg: 'Failed to generate snapshot', err });

                    return h.redirect('/admin/internals').takeover();
                },

                payload: Joi.object({
                    thread: Joi.number().integer().empty('').min(0).max(1000000).required().example(1).description('Thread ID')
                })
            }
        }
    });
}

module.exports = (...args) => {
    applyRoutes(...args);
};
