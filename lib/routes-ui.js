'use strict';

const Boom = require('@hapi/boom');
const consts = require('./consts');
const settings = require('./settings');
const tokens = require('./tokens');
const Joi = require('joi');
const logger = require('./logger');
const { failAction, verifyAccountInfo, getLogs, flattenObjectKeys, getStats, getBoolean, getSignedFormData, readEnvValue } = require('./tools');
const packageData = require('../package.json');
const he = require('he');
const crypto = require('crypto');
const pbkdf2 = require('@phc/pbkdf2');
const { Account } = require('./account');
const { Gateway } = require('./gateway');
const { redis, submitQueue, notifyQueue, documentsQueue } = require('./db');
const psl = require('psl');
const { getOAuth2Client } = require('./oauth');
const { autodetectImapSettings } = require('./autodetect-imap-settings');
const getSecret = require('./get-secret');
const humanize = require('humanize');
const { resolvePublicInterfaces } = require('pubface');
const os = require('os');
const { ADDRESS_STRATEGIES, settingsSchema, templateSchemas } = require('./schemas');
const fs = require('fs');
const pathlib = require('path');
const timezonesList = require('timezones-list').default;
const beautifyHtml = require('js-beautify').html;
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
const { templates } = require('./templates');
const { webhooks } = require('./webhooks');
const wellKnownServices = require('nodemailer/lib/well-known/services.json');
const { locales, gt } = require('./translations');
const exampleWebhookPayloads = require('./payload-examples.json');

const nodeFetch = require('node-fetch');
const fetchCmd = global.fetch || nodeFetch;

const { DEFAULT_MAX_LOG_LINES, PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST, LOGIN_PERIOD_TTL, DEFAULT_PAGE_SIZE, REDIS_PREFIX } = require('./consts');

const LICENSE_HOST = 'https://postalsys.com';
const SMTP_TEST_HOST = 'https://api.nodemailer.com';

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
    notifyTextSize: Joi.number().empty(''),
    inboxNewOnly: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false)
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
    maxLogLines: Joi.number().empty('').min(0).max(10000000).default(DEFAULT_MAX_LOG_LINES)
};

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

const configOauthSchema = {
    provider: Joi.string().valid('gmail', 'gmailService', 'outlook', 'mailRu').required().description('OAuth2 provider'),

    oauth2Enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable OAuth2'),

    clientId: Joi.string().trim().allow('').max(256).description('OAuth2 Client ID'),
    clientSecret: Joi.string().trim().empty('').max(256).description('OAuth2 Client Secret'),

    extraScopes: Joi.string().allow('').trim().max(1024).description('OAuth2 Extra Scopes'),

    serviceClient: Joi.string().trim().allow('').max(256).description('OAuth2 Service Client ID'),
    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .description('OAuth2 Secret Service Key'),

    authority: Joi.any()
        .when('provider', {
            switch: [
                {
                    is: 'gmail',
                    then: Joi.string().empty('').optional().valid(false, null).example(false)
                },
                {
                    is: 'gmailService',
                    then: Joi.string().empty('').optional().valid(false, null).example(false)
                },
                {
                    is: 'mailRu',
                    then: Joi.string().empty('').optional().valid(false, null).example(false)
                },

                {
                    is: 'outlook',
                    then: Joi.string().empty('').max(1024).allow('consumers', 'organizations', 'common').default('consumers').example('consumers')
                }
            ]
        })
        .example(false)
        .label('SupportedAccountTypes'),

    redirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('OAuth2 Callback URL')
};

function formatAccountData(account) {
    account.type = {};
    if (account.oauth2 && account.oauth2.provider) {
        account.type.name = 'OAuth2';

        switch (account.oauth2.provider) {
            case 'gmail':
                account.type.comment = 'Gmail';
                account.type.icon = 'fab fa-google';
                break;
            case 'gmailService':
                account.type.comment = 'Gmail service account';
                account.type.icon = 'fab fa-google';
                break;
            case 'outlook':
                account.type.comment = 'Outlook';
                account.type.icon = 'fab fa-microsoft';
                break;
            case 'mailRu':
                account.type.comment = 'Mail.ru';
                account.type.icon = 'fa fa-envelope';
                break;
            default:
                account.type.comment = account.oauth2.provider.replace(/^./, c => c.toUpperCase());
        }
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
    server.route({
        method: 'GET',
        path: '/admin',
        async handler(request, h) {
            let stats = await getStats(redis, call, request.query.seconds || 24 * 3600);

            let counterList = [
                {
                    key: 'events:messageNew',
                    title: 'New messages',
                    color: 'info',
                    icon: 'envelope'
                },

                {
                    key: 'events:messageDeleted',
                    title: 'Deleted messages',
                    color: 'info',
                    icon: 'envelope'
                },
                {
                    key: 'webhooks:success',
                    title: 'Webhooks sent',
                    color: 'success',
                    icon: 'network-wired'
                },

                {
                    key: 'webhooks:fail',
                    title: 'Webhooks failed',
                    color: 'danger',
                    icon: 'network-wired'
                },

                {
                    key: 'apiCall:success',
                    title: 'Successful API calls',
                    color: 'success',
                    icon: 'file-code'
                },

                {
                    key: 'apiCall:failed',
                    title: 'Failed API calls',
                    color: 'danger',
                    icon: 'file-code'
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
                    hasAccounts
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
                    logger.error({ msg: 'Failed to validate queue argument', err });
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
            const notifyTextSize = Number(await settings.get('notifyTextSize')) || 0;
            const inboxNewOnly = (await settings.get('inboxNewOnly')) || false;

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
                notifyTextSize: notifyTextSize ? notifyTextSize : ''
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
                const data = {
                    webhooksEnabled: request.payload.webhooksEnabled,
                    webhooks: request.payload.webhooks,
                    notifyText: request.payload.notifyText,
                    notifyTextSize: request.payload.notifyTextSize || 0,
                    inboxNewOnly: request.payload.inboxNewOnly,

                    webhookEvents: notificationTypes.filter(type => !!request.payload[`notify_${type.name}`]).map(type => type.name),
                    notifyHeaders: (request.payload.notifyHeaders || '')
                        .split(/\r?\n/)
                        .map(line => line.toLowerCase().trim())
                        .filter(line => line)
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
                    logger.error({ msg: 'Failed to update configuration', err });

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
                templateHeader: (await settings.get('templateHeader')) || '',
                enableTokens: !(await settings.get('disableTokens')),
                enableApiProxy: (await settings.get('enableApiProxy')) || false,
                trackSentMessages: (await settings.get('trackSentMessages')) || false,
                resolveGmailCategories: (await settings.get('resolveGmailCategories')) || false,
                labsDocumentStore: (await settings.get('labsDocumentStore')) || (await settings.get('documentStoreEnabled')) || false,
                labsMailRu: (await settings.get('labsMailRu')) || (await settings.get('mailRuEnabled')) || false,
                enableOAuthTokensApi: (await settings.get('enableOAuthTokensApi')) || false,
                locale: (await settings.get('locale')) || false,
                timezone: (await settings.get('timezone')) || false
            };

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
                    disableTokens: !request.payload.enableTokens,
                    enableApiProxy: request.payload.enableApiProxy,
                    trackSentMessages: request.payload.trackSentMessages,
                    resolveGmailCategories: request.payload.resolveGmailCategories,
                    labsDocumentStore: request.payload.labsDocumentStore,
                    labsMailRu: request.payload.labsMailRu,
                    enableOAuthTokensApi: request.payload.enableOAuthTokensApi,
                    locale: request.payload.locale,
                    timezone: request.payload.timezone
                };

                try {
                    data.templateHeader = data.templateHeader ? beautifyHtml(data.templateHeader, {}) : data.templateHeader;
                } catch (err) {
                    request.logger.error({ msg: 'Failed to preprocess provided HTML', err, html: request.payload.templateHeader });
                }

                if (request.payload.serviceUrl) {
                    let url = new URL(request.payload.serviceUrl);
                    data.serviceUrl = url.origin;
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                if (!data.labsDocumentStore && (await settings.get('documentStoreEnabled'))) {
                    await settings.set('documentStoreEnabled', false);
                }

                if (!data.labsDocumentStore && (await settings.get('mailRuEnabled'))) {
                    await settings.set('mailRuEnabled', false);
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
                    logger.error({ msg: 'Failed to update configuration', err });

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
                    templateHeader: settingsSchema.templateHeader.default(''),
                    enableApiProxy: settingsSchema.enableApiProxy.default(false),
                    trackSentMessages: settingsSchema.trackSentMessages.default(false),
                    resolveGmailCategories: settingsSchema.resolveGmailCategories.default(false),

                    // Following options can only be changed via the UI
                    labsDocumentStore: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .description('If true, then allow using the Document Store')
                        .default(false),
                    labsMailRu: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .description('If true, then allow using Mail.ru OAuth2')
                        .default(false),
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
                    res = await fetchCmd(parsed.toString(), {
                        method: 'post',
                        body:
                            request.payload.payload ||
                            JSON.stringify({
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
                        .description('Webhook URL'),
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
        path: '/admin/config/oauth/{provider?}',
        async handler(request, h) {
            let values = {
                provider: request.params.provider
            };

            let hasClientSecret, hasServiceKey;

            switch (values.provider) {
                case 'gmail':
                    values.oauth2Enabled = await settings.get('gmailEnabled');
                    values.clientId = await settings.get('gmailClientId');
                    hasClientSecret = !!(await settings.get('gmailClientSecret'));
                    values.redirectUrl = await settings.get('gmailRedirectUrl');
                    values.extraScopes = [].concat((await settings.get('gmailExtraScopes')) || []).join('\n');

                    if (!values.clientId || !hasClientSecret) {
                        values.oauth2Enabled = false;
                    }
                    break;
                case 'gmailService':
                    values.oauth2Enabled = await settings.get('gmailServiceEnabled');
                    values.serviceClient = await settings.get('gmailServiceClient');
                    hasServiceKey = !!(await settings.get('gmailServiceKey'));
                    values.extraScopes = [].concat((await settings.get('gmailServiceExtraScopes')) || []).join('\n');

                    if (!values.serviceClient || !hasServiceKey) {
                        values.oauth2Enabled = false;
                    }
                    break;
                case 'outlook':
                    values.oauth2Enabled = await settings.get('outlookEnabled');
                    values.clientId = await settings.get('outlookClientId');
                    hasClientSecret = !!(await settings.get('outlookClientSecret'));
                    values.redirectUrl = await settings.get('outlookRedirectUrl');
                    values.authority = (await settings.get('outlookAuthority')) || 'consumers';
                    values.extraScopes = [].concat((await settings.get('outlookExtraScopes')) || []).join('\n');

                    if (!values.clientId || !hasClientSecret) {
                        values.oauth2Enabled = false;
                    }
                    break;
                case 'mailRu':
                    values.oauth2Enabled = await settings.get('mailRuEnabled');
                    values.clientId = await settings.get('mailRuClientId');
                    hasClientSecret = !!(await settings.get('mailRuClientSecret'));
                    values.redirectUrl = await settings.get('mailRuRedirectUrl');
                    values.extraScopes = [].concat((await settings.get('mailRuExtraScopes')) || []).join('\n');

                    if (!values.clientId || !hasClientSecret) {
                        values.oauth2Enabled = false;
                    }
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
                    activeGmailService: values.provider === 'gmailService',
                    activeOutlook: values.provider === 'outlook',
                    activeMailRu: values.provider === 'mailRu',

                    providerName: values.provider.replace(/^./, c => c.toUpperCase()),

                    hasClientSecret,
                    hasServiceKey,
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
                    provider: Joi.string().empty('').valid('gmail', 'gmailService', 'outlook', 'mailRu').default('gmail').label('Provider')
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

                data[`${provider}Enabled`] = request.payload.oauth2Enabled;

                if (request.payload.extraScopes) {
                    request.payload.extraScopes = Array.from(
                        new Set(
                            request.payload.extraScopes
                                .replace(/['"]/g, ' ')
                                .split(/\r?\n|\s/)
                                .map(line => line.trim())
                                .filter(line => line)
                        )
                    );
                }

                switch (provider) {
                    case 'gmail':
                        for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'extraScopes']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                data[`${provider}${key.replace(/^./, c => c.toUpperCase())}`] = request.payload[key];
                            }
                        }

                        break;

                    case 'gmailService':
                        for (let key of ['serviceClient', 'serviceKey', 'extraScopes']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                let dataKey;
                                switch (key) {
                                    case 'extraScopes':
                                        dataKey = 'gmailServiceExtraScopes';
                                        break;
                                    default:
                                        dataKey = `gmail${key.replace(/^./, c => c.toUpperCase())}`;
                                }
                                data[dataKey] = request.payload[key];
                            }
                        }
                        break;

                    case 'outlook':
                        for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'authority', 'extraScopes']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                data[`${provider}${key.replace(/^./, c => c.toUpperCase())}`] = request.payload[key];
                            }
                        }

                        break;

                    case 'mailRu':
                        for (let key of ['clientId', 'clientSecret', 'redirectUrl', 'extraScopes']) {
                            if (typeof request.payload[key] !== 'undefined') {
                                data[`${provider}${key.replace(/^./, c => c.toUpperCase())}`] = request.payload[key];
                            }
                        }

                        break;

                    default:
                        await request.flash({ type: 'danger', message: `Unknown OAuth2 provider requested` });
                        return h.redirect('/admin');
                }

                if (['outlook', 'gmail', 'mailRu'].includes(provider) && request.payload.clientId === '') {
                    // clear secret as well
                    data[`${provider}ClientSecret`] = '';
                }

                if (['gmailService'].includes(provider) && request.payload.serviceClient === '') {
                    // clear secret key as well
                    data.gmailServiceKey = '';
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                // clear alert flag if set
                await settings.clear(`${provider}AuthFlag`);

                await request.flash({ type: 'info', message: `Configuration updated` });

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
                        activeGmailService: request.payload.provider === 'gmailService',
                        activeOutlook: request.payload.provider === 'outlook',
                        activeMailRu: request.payload.provider === 'mailRu',

                        providerName: request.payload.provider.replace(/^./, c => c.toUpperCase()),

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
                                activeGmailService: request.payload.provider === 'gmailService',
                                activeOutlook: request.payload.provider === 'outlook',
                                activeMailRu: request.payload.provider === 'mailRu',

                                providerName: request.payload.provider.replace(/^./, c => c.toUpperCase()),

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
                url.searchParams.append('page', page);

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
                    page: Joi.number().min(1).max(1000000).default(1),
                    pageSize: Joi.number().min(1).max(250).default(DEFAULT_PAGE_SIZE)
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

                    examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
                    notificationTypesJson: JSON.stringify(notificationTypes)
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

            try {
                let createRequest = await webhooks.create(
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled
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
                logger.error({ msg: 'Failed to create webhook routing', err });

                return h.view(
                    'webhooks/new',
                    {
                        menuTemplates: true,
                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
                        notificationTypesJson: JSON.stringify(notificationTypes)
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
                    logger.error({ msg: 'Failed to create webhook routing', err });

                    return h
                        .view(
                            'templates/new',
                            {
                                menuTemplates: true,
                                errors,

                                examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
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
                contentMapJson: JSON.stringify(webhook.content.map || '')
            };

            return h.view(
                'webhooks/edit',
                {
                    menuWebhooks: true,

                    webhook,

                    values,

                    examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
                    notificationTypesJson: JSON.stringify(notificationTypes)
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

            try {
                await webhooks.update(
                    request.payload.webhook,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled
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
                logger.error({ msg: 'Failed to update Webhook Route', err });

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

                        examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
                        notificationTypesJson: JSON.stringify(notificationTypes)
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
                    logger.error({ msg: 'Failed to update Webhook Route', err });

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

                                examplePayloadsJson: JSON.stringify(exampleWebhookPayloads),
                                notificationTypesJson: JSON.stringify(notificationTypes)
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
                logger.error({ msg: 'Failed to delete Webhook Route', err, webhook: request.payload.webhook, remoteAddress: request.app.ip });
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
                    logger.error({ msg: 'Failed to delete delete Webhook Route', err });

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
                    account: Joi.string().empty('').max(256).default(null).example('johnsmith').description('Account ID'),
                    page: Joi.number().min(1).max(1000000).default(1),
                    pageSize: Joi.number().min(1).max(250).default(DEFAULT_PAGE_SIZE)
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
                contentHtml: template.content.html,
                contentText: template.content.text,
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
                logger.error({ msg: 'Failed to update template', err });

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

                        errors: err.details
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
                    logger.error({ msg: 'Failed to update template', err });

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

                                errors
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

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/templates').takeover();
                },

                query: Joi.object({
                    account: Joi.string().empty('').max(256).default(null).example('johnsmith').description('Account ID')
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
                logger.error({ msg: 'Failed to create template', err });

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

                        errors: err.details
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
                    logger.error({ msg: 'Failed to create template', err });

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

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    account: Joi.string().empty('').max(256).default(null).example('johnsmith').description('Account ID'),

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
                logger.error({ msg: 'Failed to delete the template', err, template: request.payload.template, remoteAddress: request.app.ip });
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
                    logger.error({ msg: 'Failed to delete delete the account', err });

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
                logger.info({ msg: 'Trying to send test message', payload: request.payload });

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
                            deliveryAttempts: 1
                        },
                        { source: 'ui' }
                    );
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                logger.error({ msg: 'Failed sending test message', err });
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
                    account: Joi.string().empty('').max(256).default(null).example('johnsmith').description('Account ID'),
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
                    page: Joi.number().min(1).max(1000000).default(1),
                    pageSize: Joi.number().min(1).max(250).default(DEFAULT_PAGE_SIZE)
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
                logger.error({ msg: 'Failed to add new gateway', err });

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
                    logger.error({ msg: 'Failed to add new gateway', err });

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
                logger.error({ msg: 'Failed to update gateway', err });

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
                    logger.error({ msg: 'Failed to update gateway', err });

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
            const { host, port, user, pass, secure } = request.payload;

            try {
                let verifyResult = await verifyAccountInfo({
                    smtp: {
                        host,
                        port,
                        secure,
                        auth:
                            user || pass
                                ? {
                                      user,
                                      pass
                                  }
                                : false
                    }
                });

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
                logger.error({ msg: 'Failed posting request', host, port, user, pass: !!pass, err });
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
                    user: Joi.string().empty('').trim().max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).label('Password'),
                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
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
                logger.error({ msg: 'Failed to delete the gateway', err, gateway: request.payload.gateway, remoteAddress: request.app.ip });
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
                    logger.error({ msg: 'Failed to delete delete the gateway', err });

                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('johnsmith').description('Gateway ID')
                })
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
                    scopes: Joi.array().items(Joi.string().valid('*', 'api', 'metrics', 'smtp', 'imap-proxy')).required().label('Scopes')
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
                logger.error({ msg: 'Failed to register license key', err });

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
                    logger.error({ msg: 'Failed to register license key', err });

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
                    headers
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
                logger.error({ msg: 'Failed to provision a trial license key', err, remoteAddress: request.app.ip });
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

                    await request.flash({ type: 'danger', message: `Failed to authenticate` });
                    logger.error({ msg: 'Failed to authenticate', err });

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
                    next: Joi.string().empty('').uri({ relativeOnly: true }).label('NextUrl')
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

            const accounts = await accountObject.listAccounts(request.query.state, request.query.query, request.query.page - 1, request.query.pageSize);

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
                if (request.query.query) {
                    url.searchParams.append('query', request.query.query);
                }
                return url.pathname + url.search;
            };

            if (accounts.pages > accounts.page + 1) {
                nextPage = getPagingUrl(accounts.page + 2);
            }

            if (accounts.page > 0) {
                prevPage = getPagingUrl(accounts.page);
            }

            return h.view(
                'accounts/index',
                {
                    menuAccounts: true,

                    query: request.query.query,
                    searchTarget: '/admin/accounts',
                    searchPlaceholder: 'Search for accounts…',

                    showPaging: accounts.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: accounts.page === 0,
                    pageLinks: new Array(accounts.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === accounts.page
                    })),

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
                    page: Joi.number().min(1).max(1000000).default(1),
                    pageSize: Joi.number().min(1).max(250).default(DEFAULT_PAGE_SIZE),
                    query: Joi.string().example('user@example').description('Filter accounts by name/email match').label('AccountQuery')
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
                name: request.payload.name
            });

            let url = new URL(`accounts/new`, 'http://localhost');

            url.searchParams.append('data', data);
            if (signature) {
                url.searchParams.append('sig', signature);
            }

            let gmailEnabled = await settings.get('gmailEnabled');
            if (gmailEnabled && (!(await settings.get('gmailClientId')) || !(await settings.get('gmailClientSecret')))) {
                gmailEnabled = false;
            }

            let outlookEnabled = await settings.get('outlookEnabled');
            if (outlookEnabled && (!(await settings.get('outlookClientId')) || !(await settings.get('outlookClientSecret')))) {
                outlookEnabled = false;
            }

            let mailRuEnabled = await settings.get('mailRuEnabled');
            if (mailRuEnabled && (!(await settings.get('mailRuClientId')) || !(await settings.get('mailRuClientSecret')))) {
                mailRuEnabled = false;
            }

            if (!gmailEnabled && !outlookEnabled && !mailRuEnabled) {
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
                    logger.error({ msg: 'Failed to update configuration', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                payload: Joi.object({
                    account: Joi.string().empty('').max(256).default(null).example('johnsmith').description('Account ID'),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name')
                })
            }
        }
    });

    async function accounFormHandler(request, h) {
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

        let oauth2Enabled;

        if (['gmail', 'outlook', 'mailRu'].includes(request.payload.type)) {
            oauth2Enabled = !!(
                (await settings.get(`${request.payload.type}Enabled`)) &&
                (await settings.get(`${request.payload.type}ClientId`)) &&
                (await settings.get(`${request.payload.type}ClientSecret`))
            );
        }

        if (['gmail', 'outlook', 'mailRu'].includes(request.payload.type) && oauth2Enabled) {
            // prepare account entry
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

            if (data.syncFrom) {
                accountData.syncFrom = data.syncFrom;
            }

            const oAuth2Client = await getOAuth2Client(request.payload.type);
            let nonce = crypto.randomBytes(12).toString('hex');

            accountData.notifyFrom = new Date().toISOString();
            accountData.copy = false;
            accountData.oauth2 = {
                provider: request.payload.type
            };

            // store account data
            await redis
                .multi()
                .set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData))
                .expire(`${REDIS_PREFIX}account:add:${nonce}`, 1 * 24 * 3600)
                .exec();

            // Generate the url that will be used for the consent dialog.

            let requestPyload = {
                state: `account:add:${nonce}`
            };

            if (accountData.email) {
                requestPyload.email = accountData.email;
            }

            let authorizeUrl;
            switch (request.payload.type) {
                case 'gmail':
                case 'outlook':
                case 'mailRu':
                    authorizeUrl = oAuth2Client.generateAuthUrl(requestPyload);
                    break;

                default: {
                    let error = Boom.boomify(new Error(gt.gettext('Unknown OAuth provider')), { statusCode: 400 });
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
                return accounFormHandler(request, h);
            }

            let data = Buffer.from(request.query.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.query.sig) {
                    let error = Boom.boomify(new Error(gt.gettext('Signature validation failed')), { statusCode: 403 });
                    throw error;
                }
            }

            let gmailEnabled = await settings.get('gmailEnabled');
            if (gmailEnabled && (!(await settings.get('gmailClientId')) || !(await settings.get('gmailClientSecret')))) {
                gmailEnabled = false;
            }

            let outlookEnabled = await settings.get('outlookEnabled');
            if (outlookEnabled && (!(await settings.get('outlookClientId')) || !(await settings.get('outlookClientSecret')))) {
                outlookEnabled = false;
            }

            let mailRuEnabled = await settings.get('mailRuEnabled');
            if (mailRuEnabled && (!(await settings.get('mailRuClientId')) || !(await settings.get('mailRuClientSecret')))) {
                mailRuEnabled = false;
            }

            return h.view(
                'accounts/register/index',
                {
                    values: {
                        data: request.query.data,
                        sig: request.query.sig
                    },

                    gmailEnabled,
                    outlookEnabled,
                    mailRuEnabled
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
                    let error = Boom.boomify(new Error(gt.gettext('Failed to validate request arguments')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: Joi.string().valid('imap', 'gmail', 'outlook', 'mailRu').empty('').allow(false).default(false)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new',

        handler: accounFormHandler,
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
                    let error = Boom.boomify(new Error(gt.gettext('Failed to validate request arguments')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: Joi.string().valid('imap', 'gmail', 'outlook', 'mailRu').required()
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
                    let error = Boom.boomify(new Error(gt.gettext('Signature validation failed')), { statusCode: 403 });
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
                let verifyResult = await verifyAccountInfo({
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
                });

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
                    let error = Boom.boomify(new Error(gt.gettext('Signature validation failed')), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);

            const accountData = {
                account: data.account,
                name: request.payload.name || data.name,
                email: request.payload.email,

                tz: request.payload.tz,

                notifyFrom: new Date(),

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

            const accountObject = new Account({ redis, call, secret: await getSecret() });
            const result = await accountObject.create(accountData);

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
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone for autogenerated date strings'),
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

            accountData = formatAccountData(accountData);

            let oauth2ProviderEnabled = false;
            if (accountData.oauth2 && accountData.oauth2.provider) {
                let provider = accountData.oauth2.provider;
                oauth2ProviderEnabled = await settings.get(`${provider}Enabled`);
                if (oauth2ProviderEnabled && (!(await settings.get(`${provider}ClientId`)) || !(await settings.get(`${provider}ClientSecret`)))) {
                    oauth2ProviderEnabled = false;
                }
            }

            if (accountData.path === '*') {
                accountData.path = '';
            }

            accountData.imap = accountData.imap || {
                disabled: !accountData.oauth2
            };

            let gatewayObject = new Gateway({ redis });
            let gateways = await gatewayObject.listGateways(0, 100);

            return h.view(
                'accounts/account',
                {
                    menuAccounts: true,
                    account: accountData,
                    logs: await settings.get('logs'),
                    smtpError: accountData.smtpStatus && accountData.smtpStatus.status === 'error',

                    canSend: !!(
                        accountData.smtp ||
                        (accountData.oauth2 && accountData.oauth2.provider) ||
                        (gateways && gateways.gateways && gateways.gateways.length)
                    ),
                    canUseSmtp: !!(accountData.smtp || (accountData.oauth2 && accountData.oauth2.provider)),
                    gateways: gateways && gateways.gateways,

                    testSendTemplate: cachedTemplates.testSend,

                    oauth2ProviderEnabled,
                    accountForm: await getSignedFormData({
                        account: request.params.account,
                        name: accountData.name,
                        email: accountData.email,
                        redirectUrl: `/admin/accounts/${request.params.account}`
                    }),

                    showAdvanced: accountData.path || accountData.proxy || accountData.webhooks
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.error({ msg: 'Failed to delete the account', err, account: request.payload.account, remoteAddress: request.app.ip });
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
                    logger.error({ msg: 'Failed to delete delete the account', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.info({ msg: 'Request reconnect for logging', account });
                try {
                    await call({ cmd: 'update', account });
                } catch (err) {
                    logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                }

                return {
                    success: true
                };
            } catch (err) {
                logger.error({ msg: 'Failed to request reconnect', err, account });
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.info({ msg: 'Request syncing', account });
                try {
                    await call({ cmd: 'sync', account });
                } catch (err) {
                    logger.error({ msg: 'Sync request failed', action: 'request_sync', account, err });
                }

                return {
                    success: true
                };
            } catch (err) {
                logger.error({ msg: 'Failed to request syncing', err, account });
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.info({ msg: 'Request to update account logging state', account, enabled: request.payload.enabled });

                await redis.hSetExists(accountObject.getAccountKey(), 'logs', request.payload.enabled ? 'true' : 'false');

                return {
                    success: true,
                    enabled: (await redis.hget(accountObject.getAccountKey(), 'logs')) === 'true'
                };
            } catch (err) {
                logger.error({ msg: 'Failed to update account logging state', err, account, enabled: request.payload.enabled });
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.info({ msg: 'Request to flush logs', account });

                await redis.del(accountObject.getLogKey());

                return {
                    success: true
                };
            } catch (err) {
                logger.error({ msg: 'Failed to flush logs', err, account });
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                    hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
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
                logger.error({ msg: 'Failed to update account settings', err, account: request.params.account });

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
                        hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass
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
                                hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                params: Joi.object({
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID')
                }),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),

                    proxy: settingsSchema.proxyUrl,

                    imap: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    imap_auth_user: Joi.string().empty('').trim().max(1024),
                    imap_auth_pass: Joi.string().empty('').max(1024),
                    imap_host: Joi.string().hostname().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
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

                    imap_resyncDelay: Joi.number().empty(''),

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
            let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
            let documentStoreUsername = await settings.get('documentStoreUsername');
            let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

            return h.view(
                'config/document-store',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,

                    values: {
                        documentStoreEnabled,
                        documentStoreUrl,
                        documentStoreIndex,
                        documentStoreAuthEnabled,
                        documentStoreUsername
                    },

                    hasDocumentStorePassword
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
                logger.error({ msg: 'Failed to update configuration', err });

                let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                return h.view(
                    'config/document-store',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,

                        hasDocumentStorePassword
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

                    let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                    return h
                        .view(
                            'config/document-store',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,

                                hasDocumentStorePassword,

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
                logger.error({ msg: 'Failed posting request', documentStoreUrl, documentStoreAuthEnabled, documentStoreUsername, command: 'info', err });
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
                        proxyUrl
                    },

                    addresses: await listPublicInterfaces(localAddresses),
                    addressListTemplate: cachedTemplates.addressList
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
        async handler() {
            try {
                await updatePublicInterfaces();

                let localAddresses = [].concat((await settings.get('localAddresses')) || []);

                return {
                    success: true,
                    addresses: await listPublicInterfaces(localAddresses)
                };
            } catch (err) {
                logger.error({ msg: 'Failed loading public IP addresses', err });
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
                for (let key of ['smtpStrategy', 'imapStrategy', 'localAddresses', 'proxyUrl', 'proxyEnabled']) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/network');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

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
                        addressListTemplate: cachedTemplates.addressList
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
                logger.error({ msg: 'Failed to delete address', err, localAddress: request.payload.localAddress, remoteAddress: request.app.ip });
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
                    logger.error({ msg: 'Failed to delete address', err });

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
                        logger.error({ msg: 'Reload request failed', action: 'request_reload_imap_proxy', err });
                    }
                }

                return h.redirect('/admin/config/imap-proxy');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

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
                    logger.error({ msg: 'Failed to update configuration', err });

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
                        logger.error({ msg: 'Reload request failed', action: 'request_reload_smtp', err });
                    }
                }

                return h.redirect('/admin/config/smtp');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Failed to update configuration` });
                logger.error({ msg: 'Failed to update configuration', err });

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
                    logger.error({ msg: 'Failed to update configuration', err });

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
                logger.error({ msg: 'Failed to request syncing', err });
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
                logger.info({ msg: 'Request SMTP test', account });

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
                    headers
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
                            subject: `Test email ${now}`,
                            text: `Hello ${now}`,
                            html: `<p>Hello ${now}</p>`,
                            from: {
                                name: accountData.name,
                                address: accountData.email
                            },
                            to: [{ name: '', address: testAccount.address }],
                            copy: false,
                            gateway: request.payload.gateway,
                            feedbackKey: `${REDIS_PREFIX}test-send:${testAccount.user}`,
                            deliveryAttempts: 3
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
                logger.error({ msg: 'Failed to request test account', err, account });
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
                    account: Joi.string().max(256).required().example('johnsmith').description('Account ID'),
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
                logger.info({ msg: 'Request SMTP test response', user });

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
                    headers
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
                logger.error({ msg: 'Failed to request test response', err, user });
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
}

module.exports = (...args) => {
    applyRoutes(...args);
};
