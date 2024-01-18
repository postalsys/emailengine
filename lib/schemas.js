'use strict';

const Joi = require('joi');
const config = require('wild-config');
const { getByteSize } = require('./tools');
const { locales } = require('./translations');
const featureFlags = require('./feature-flags');

const RESYNC_DELAY = 15 * 60;

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1',
    proxy: false
};

const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024;
const MAX_ATTACHMENT_SIZE = getByteSize(process.env.EENGINE_MAX_SIZE || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

const ADDRESS_STRATEGIES = [
    { key: 'default', title: 'Default' },
    { key: 'dedicated', title: 'Dedicated' },
    { key: 'random', title: 'Random' }
];

const OAUTH_PROVIDERS = {
    gmail: 'Gmail',
    gmailService: 'Gmail Service Accounts',
    outlook: 'Outlook',
    mailRu: 'Mail.ru'
};

// allowed configuration keys
const settingsSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If false then do not emit webhooks'),

    webhooks: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/imap/webhooks')
        .description('Webhook URL'),

    webhookEvents: Joi.array().items(Joi.string().max(256).example('messageNew')),

    webhooksCustomHeaders: Joi.array()
        .items(
            Joi.object({
                key: Joi.string().trim().empty('').max(1024).required(),
                value: Joi.string()
                    .trim()
                    .empty('')
                    .max(10 * 1024)
                    .default('')
            }).label('WebhooksCustomHeader')
        )
        .label('WebhooksCustomHeaders'),

    notifyHeaders: Joi.array().items(Joi.string().max(256).example('List-ID')),

    serviceUrl: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://emailengine.example.com')
        .description('Base URL of EmailEngine')
        .label('ServiceURL'),

    trackSentMessages: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then rewrite html links in sent emails to track opens and clicks'),

    resolveGmailCategories: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then resolve the category tab for incoming emails'),

    ignoreMailCertErrors: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then allow insecure certificates for IMAP/SMTP'),

    generateEmailSummary: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then extracts reply text using OpenAI ChatGPT'),
    generateRiskAssessment: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('(deprecated, not used)'),

    openAiAPIKey: Joi.string().allow('').example('verysecr8t').description('OpenAI API key').label('OpenAiAPIKey'),
    openAiModel: Joi.string().allow('').example('gpt-3.5-turbo').description('OpenAI API Model').label('OpenAiModel'),

    openAiAPIUrl: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://api.openai.com')
        .description('OpenAI API URL')
        .label('openAiAPIUrl'),

    documentStoreChatModel: Joi.string().allow('').example('gpt-3.5-turbo').description('OpenAI API Model for chat').label('DocumentStoreChatModel'),

    openAiTemperature: Joi.number().allow('').min(0).max(2).example(0.8).description('OpenAI Temperature').label('OpenAiTemperature'),
    openAiTopP: Joi.number().allow('').min(0).max(1).example(0.1).description('Top-p sampling').label('OpenAiTopP'),

    openAiPrompt: Joi.string()
        .allow('')
        .max(6 * 1024)
        .example('You are an assistant scanning incoming emails...')
        .description('Prompt to send to LLM for analyzing emails')
        .label('OpenAiPrompt'),

    openAiGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then generates vector embeddings for the email'),

    inboxNewOnly: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then send "New Email" webhooks for incoming emails only'),

    serviceSecret: Joi.string().allow('').example('verysecr8t').description('HMAC secret for signing public requests').label('ServiceSecret'),

    authServer: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/authentication')
        .description('URL to fetch authentication data from')
        .label('AuthServer'),

    proxyEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Is the global proxy enabled or not'),
    proxyUrl: Joi.string()
        .uri({
            scheme: ['http', 'https', 'socks', 'scoks4', 'socks5'],
            allowRelative: false
        })
        .allow('')
        .example('socks://proxy.example.com:1080')
        .description('Proxy URL')
        .label('ProxyURL'),

    smtpEhloName: Joi.string().hostname().allow('', null).example('my.proxy.tld').description('Hostname to use for the SMTP EHLO/HELO greeting'),

    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include message text in webhook notification'),
    notifyWebSafeHtml: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Pre-process HTML in webhook notification to be web safe'),

    notifyTextSize: Joi.number().integer().min(0),

    notifyCalendarEvents: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Include calendar events in webhook notification'),

    gmailEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If true then do not show Gmail account option (deprecated)'),
    gmailClientId: Joi.string().allow('').max(256).description('Gmail OAuth2 Client ID (deprecated)'),
    gmailClientSecret: Joi.string().empty('').max(256).description('Gmail OAuth2 Client Secret (deprecated)'),
    gmailRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Gmail OAuth2 Callback URL (deprecated)'),
    gmailExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('Gmail OAuth2 Extra Scopes (deprecated)'),

    outlookEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If true then do not show Outlook account option (deprecated)'),
    outlookClientId: Joi.string().allow('').max(256).description('Outlook OAuth2 Client ID (deprecated)'),
    outlookClientSecret: Joi.string().empty('').max(256).description('Outlook OAuth2 Client Secret (deprecated)'),
    outlookRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Outlook OAuth2 Callback URL (deprecated)'),
    outlookAuthority: Joi.string()
        .empty('')
        .allow('consumers', 'organizations', 'common')
        .example('consumers')
        .description('Outlook OAuth2 authority (deprecated)'),
    outlookExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Outlook OAuth2 Extra Scopes (deprecated)'),

    mailRuEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If true then do not show Mail.ru account option (deprecated)'),
    mailRuClientId: Joi.string().allow('').max(256).description('Mail.ru OAuth2 Client ID (deprecated)'),
    mailRuClientSecret: Joi.string().empty('').max(256).description('Mail.ru OAuth2 Client Secret (deprecated)'),
    mailRuRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Mail.ru OAuth2 Callback URL (deprecated)'),
    mailRuExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Mail.ru OAuth2 Extra Scopes (deprecated)'),

    serviceClient: Joi.string().trim().allow('').max(256).description('OAuth2 Service Client ID (deprecated)'),
    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .description('OAuth2 Secret Service Key (deprecated)'),
    serviceExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('OAuth2 Service Extra Scopes (deprecated)'),

    logs: Joi.object({
        all: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).example(false).description('Enable logs for all accounts'),
        maxLogLines: Joi.number().integer().min(0).max(1000000).default(10000)
    }).label('LogSettings'),

    imapStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('How to select local IP address for IMAP connections'),
    smtpStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('How to select local IP address for SMTP connections'),
    localAddresses: Joi.array()
        .items(
            Joi.string().ip({
                version: ['ipv4', 'ipv6'],
                cidr: 'forbidden'
            })
        )
        .single()
        .description('A list of pooled local IP addresses that can be used for IMAP and SMTP connections'),

    smtpServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP Interface'),
    smtpServerPort: Joi.number()
        .integer()
        .min(0)
        .max(64 * 1024)
        .empty('')
        .description('SMTP Interface Port'),
    smtpServerHost: Joi.string()
        .ip({
            version: ['ipv4', 'ipv6'],
            cidr: 'forbidden'
        })
        .empty('')
        .description('SMTP Host to bind to'),
    smtpServerProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable PROXY Protocol for SMTP server'),
    smtpServerAuthEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP authentication'),
    smtpServerPassword: Joi.string().empty('').allow(null).max(1024).description('SMTP client password. Set to null to disable.'),

    smtpServerTLSEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable TLS for the SMTP interface. Requires a valid certificate.'),

    imapProxyServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable IMAP Proxy Interface'),
    imapProxyServerPort: Joi.number()
        .integer()
        .min(0)
        .max(64 * 1024)
        .empty('')
        .description('IMAP Proxy Interface Port'),
    imapProxyServerHost: Joi.string()
        .ip({
            version: ['ipv4', 'ipv6'],
            cidr: 'forbidden'
        })
        .empty('')
        .description('IMAP Proxy Host to bind to'),
    imapProxyServerProxy: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable PROXY Protocol for the IMAP proxy server'),
    imapProxyServerPassword: Joi.string().empty('').allow(null).max(1024).description('IMAP proxy client password. Set to null to disable.'),

    imapProxyServerTLSEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable TLS for the IMAP proxy interface. Requires a valid certificate.'),

    queueKeep: Joi.number().integer().empty('').min(0).description('How many completed or failed queue entries to keep'),

    deliveryAttempts: Joi.number().integer().empty('').min(0).description('How many times to retry an email sending before it is considered as failing'),

    templateHeader: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('HTML code displayed on the top of public pages like the hosted authentication form'),

    scriptEnv: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .custom((value /*, helpers*/) => {
            if (!value || !value.trim()) {
                return value;
            }

            let parsed;
            try {
                parsed = JSON.parse(value);
            } catch (err) {
                throw new Error('provided value is not a valid JSON');
            }

            if (!parsed || typeof parsed !== 'object') {
                throw new Error('provided value is not an object');
            }

            return value;
        }, 'JSON validation')
        .example('{"key": "value"}')
        .description('JSON object to be used as the `env` variable in pre-processing scripts'),

    enableApiProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable support for reverse proxies'),

    documentStoreEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable Document Store syncing'),
    documentStoreUrl: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://localhost:9200')
        .description('Document Store URL'),
    documentStoreIndex: Joi.string().empty('').max(1024).description('Document Store index name'),
    documentStoreAuthEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable Document Store authentication'),
    documentStoreUsername: Joi.string().empty('').max(1024).description('Document Store username'),
    documentStorePassword: Joi.string().empty('').max(1024).description('Document Store password'),
    documentStoreGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then generates vector embeddings for the email and stores these in the Document Store'),
    documentStorePreProcessingEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable Document Store pre-processing'),

    locale: Joi.string()
        .max(100)
        .example('fr')
        .valid(...locales.map(locale => locale.locale))
        .description('Default locale identifier'),
    timezone: Joi.string().max(100).example('Europe/Tallinn').description('Default timezone identifier'),

    openAiPreProcessingFn: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return true; // passes all emails')
        .description('Filter function for LLM pre-processing (JavaScript)'),

    documentStorePreProcessingFn: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return true; // passes all emails')
        .description('Filter function for Document Store pre-processing (JavaScript)'),

    documentStorePreProcessingMap: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return payload; // returns unmodified data')
        .description('Mapping function for Document Store pre-processing (JavaScript)')
};

const addressSchema = Joi.object({
    name: Joi.string().trim().empty('').max(256).example('Some Name'),
    address: Joi.string()
        .email({
            ignoreLength: false
        })
        .example('user@example.com')
        .required()
});

// generate a list of boolean values
const settingsQuerySchema = Object.fromEntries(
    Object.keys(Object.assign({ eventTypes: true }, settingsSchema)).map(key => [
        key,
        Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false)
    ])
);

const imapSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Account password')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),

        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string()
        .hostname()
        .when('disabled', {
            is: true,
            then: Joi.optional().allow(false, null),
            otherwise: Joi.required()
        })
        .example('imap.gmail.com')
        .description('Hostname to connect to'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(64 * 1024)
        .when('disabled', {
            is: true,
            then: Joi.optional().allow(false, null),
            otherwise: Joi.required()
        })
        .example(993)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .unknown()
        .description('Optional TLS configuration')
        .label('TLS'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Full resync delay in seconds').default(RESYNC_DELAY),
    disabled: Joi.boolean().example(false).description('Set to true to disable IMAP handling'),

    sentMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Sent Mail')
        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used. Set to `null` to unset."),

    draftsMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Drafts')
        .description("Folder for drafts. By default the account's Draft Mail folder is used. Set to `null` to unset."),
    junkMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Junk')
        .description("Folder for spam. By default the account's Junk Mail folder is used. Set to `null` to unset."),
    trashMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Trash')
        .description("Folder for deleted emails. By default the account's Trash folder is used. Set to `null` to unset."),
    archiveMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Archive')
        .description("Folder for archived emails. By default the account's Archive folder is used. Set to `null` to unset.")
};

const smtpSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Account password')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(64 * 1024)
        .required()
        .example(587)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(false).description('Should connection use TLS. Usually true for port 465'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .unknown()
        .description('Optional TLS configuration')
        .label('TLS')
};

const oauth2Schema = {
    authorize: Joi.boolean().example(false).description('Return a redirect link to the OAuth2 consent screen'),
    redirectUrl: Joi.string()
        .empty('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .example('https://myapp/account/settings.php')
        .description('The user will be redirected to this URL after returning from the OAuth2 consent screen (only valid if `authorize=true`')
        .when('authorize', {
            is: true,
            then: Joi.optional(),
            otherwise: Joi.optional().valid(false, null)
        }),

    provider: Joi.string().max(256).example('gmail').description('OAuth provider'),

    auth: Joi.object({
        user: Joi.string().max(256).required().example('user@oulook.com').description('Account username'),
        delegatedUser: Joi.string().max(256).optional().example('shared.mailbox@oulook.com').description('Shared mailbox username (MS365 only)')
    }).when('authorize', {
        is: true,
        then: Joi.optional().valid(false, null),
        otherwise: Joi.required()
    }),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description("Outloook account type. Either 'consumers', 'organizations', 'common' or an organizartion ID")
        .label('SupportedAccountTypes'),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Token expiration date')
};

const partialSchema = Joi.boolean()
    .example(false)
    .description('Set to `true` if you only want to update provided keys, by default the entire object is replaced')
    .default(false);

const imapUpdateSchema = {
    partial: partialSchema,

    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Account password')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().example('imap.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(64 * 1024)
        .example(993)
        .description('Service port number'),
    secure: Joi.boolean().example(true).description('Should connection use TLS. Usually true for port 993'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .unknown()
        .description('Optional TLS configuration')
        .label('TLS'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Full resync delay in seconds'),

    disabled: Joi.boolean().example(false).description('Set to true to disable IMAP handling'),

    sentMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Sent Mail')
        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used. Set to `null` to unset."),

    draftsMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Drafts')
        .description("Folder for drafts. By default the account's Draft Mail folder is used. Set to `null` to unset."),
    junkMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Junk')
        .description("Folder for spam. By default the account's Junk Mail folder is used. Set to `null` to unset."),
    trashMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Trash')
        .description("Folder for deleted emails. By default the account's Trash folder is used. Set to `null` to unset."),
    archiveMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Archive')
        .description("Folder for archived emails. By default the account's Archive folder is used. Set to `null` to unset.")
};

const smtpUpdateSchema = {
    partial: partialSchema,
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Account password')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(64 * 1024)
        .example(587)
        .description('Service port number'),
    secure: Joi.boolean().example(false).description('Should connection use TLS. Usually true for port 465'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .unknown()
        .description('Optional TLS configuration')
        .label('TLS')
};

const oauth2UpdateSchema = {
    partial: partialSchema,

    authorize: Joi.boolean().example(false).description('Return a redirect link to the OAuth2 consent screen'),
    provider: Joi.string().max(256).example('gmail').description('OAuth provider'),

    auth: Joi.object({
        user: Joi.string().max(256).required().example('user@oulook.com').description('Account username'),
        delegatedUser: Joi.string().max(256).optional().example('shared.mailbox@oulook.com').description('Shared mailbox username (MS365 only)')
    }).when('authorize', {
        is: true,
        then: Joi.optional().valid(false, null),
        otherwise: Joi.optional()
    }),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...'),
    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description("Outloook account type. Either 'consumers', 'organizations', 'common' or an organizartion ID")
        .label('SupportedAccountTypes'),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Token expiration date')
};

const attachmentSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrIyLjI').description('Attachment ID').label('AttachmentId'),
    contentType: Joi.string().example('image/gif').description('Mime type of the attachment'),
    encodedSize: Joi.number()
        .integer()
        .example(48)
        .description('Encoded size of the attachment. Actual file size is usually smaller depending on the encoding'),
    embedded: Joi.boolean().example(true).description('Is this image used in HTML img tag'),
    inline: Joi.boolean().example(true).description('Should this file be included in the message preview somehow'),
    contentId: Joi.string().example('<unique-image-id@localhost>').description('Usually used only for embedded images'),
    filename: Joi.string().example('image.png').description('The file name of the attachment'),
    method: Joi.string().example('REQUEST').description('Calendar event method if this is an ical event attachment')
});

const messageEntrySchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('UID of the message').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique ID (if server supports it)').label('MessageEmailId'),
    threadId: Joi.string().example('1694936993596975454').description('Thread ID (if server supports it)').label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date (internal)'),
    draft: Joi.boolean().example(false).description('Is this message marked as a draft'),
    unseen: Joi.boolean().example(true).description('Is this message unseen'),
    flagged: Joi.boolean().example(true).description('Is this message marked as flagged'),
    size: Joi.number().integer().example(1040).description('Message size in bytes'),
    subject: Joi.string()
        .allow('')
        .example('What a wonderful message')
        .description('Message subject (decoded into unicode, applies to other string values as well)'),

    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).label('FromAddress'),
    replyTo: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    to: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),
    messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Replied Message ID'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('IMAP flags').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Pointer to message text content'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('How many bytes for plain text'),
            html: Joi.number().integer().example(1013).description('How many bytes for html content')
        }).description('Encoded message part sizes')
    }).label('TextInfo'),

    preview: Joi.string().description('Text preview for messages loaded from Document Store')
}).label('MessageListEntry');

const messageDetailsSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('UID of the message').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique ID (if server supports it)').label('MessageEmailId'),
    threadId: Joi.string()
        .example('1694936993596975454')
        .description('Thread ID (if server supports it). Always set for messages retrieved from Document Store.')
        .label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date (internal)'),
    draft: Joi.boolean().example(false).description('Is this message marked as a draft'),
    unseen: Joi.boolean().example(true).description('Is this message unseen'),
    flagged: Joi.boolean().example(true).description('Is this message marked as flagged'),
    size: Joi.number().integer().example(1040).description('Message size in bytes'),
    subject: Joi.string()
        .allow('')
        .example('What a wonderful message')
        .description('Message subject (decoded into unicode, applies to other string values as well)'),

    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).label('FromAddress'),
    sender: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).label('FromAddress'),

    to: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),
    replyTo: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Replied Message ID'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('IMAP flags').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    headers: Joi.object()
        .example({ from: ['From Me <sender@example.com>'], subject: ['What a wonderful message'] })
        .label('MessageHeaders')
        .description('Object where header key is object key and value is an array')
        .unknown(),

    text: Joi.object({
        id: Joi.string()
            .example('AAAAAgAACqiTkaExkaEykA')
            .description('Pointer to message text content. The value is `null` for messages retrieved from Document Store.'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('How many bytes for plain text'),
            html: Joi.number().integer().example(1013).description('How many bytes for html content')
        }).description('Encoded message part sizes'),
        plain: Joi.string().example('Hello from myself!').description('Plaintext content of the message'),
        html: Joi.string().example('<p>Hello from myself!</p>').description('HTML content of the message'),
        hasMore: Joi.boolean()
            .example(false)
            .description('If partial message content was requested then this value indicates if it includes all the content or there is more')
    }).label('TextInfo'),

    bounces: Joi.array()
        .items(
            Joi.object({
                message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Bounce email ID'),
                recipient: Joi.string().email().example('recipient@example.com'),
                action: Joi.string().example('failed'),
                response: Joi.object({
                    message: Joi.string().example('550 5.1.1 No such user'),
                    status: Joi.string().example('5.1.1')
                }).label('BounceResponse'),
                date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Time the bounce was registered by EmailEngine')
            }).label('BounceEntry')
        )
        .label('BounceList'),

    isAutoReply: Joi.boolean().example(false).description('True if this message was detected to be an autoreply email like the Out of Office notice'),

    specialUse: Joi.string()
        .example('\\Sent')
        .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
        .description('Special use flag of the mailbox')
        .label('MailboxSpecialUse'),
    messageSpecialUse: Joi.string()
        .example('\\Sent')
        .valid('\\Drafts', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
        .description('Special use flag of the message. Only relevant for messages listed from the All Mail folder in Gmail.')
        .label('MessageSpecialUse')
}).label('MessageListEntry');

const messageListSchema = Joi.object({
    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),
    messages: Joi.array().items(messageEntrySchema).label('PageMessages')
}).label('MessageList');

const mailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/'),
        parentPath: Joi.string().required().example('Kalender').description('Full path to parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Maibox name').label('MailboxName'),
        listed: Joi.boolean().example(true).description('Was the mailbox found from the output of LIST command').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('Was the mailbox found from the output of LSUB command').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special use flag of the mailbox')
            .label('MailboxSpecialUse'),
        specialUseSource: Joi.string()
            .example('extension')
            .valid('user', 'extension', 'name')
            .description(
                'Where did EmailEngine get the specialUse flag. The source could be `"user"` if it was set through an account creation or update API call, `"extension"` if it was provided by the email server, or `"name"` if EmailEngine determined it based on the folder\'s name.'
            )
            .label('MailboxSpecialUseSource'),
        noInferiors: Joi.boolean().example(false).description('If true, then adding subfolders is forbidden').label('MailboxSpecialUseSource'),
        messages: Joi.number().integer().example(120).description('Count of messages in mailbox').label('MailboxMessages'),
        uidNext: Joi.number().integer().example(121).description('Next expected UID').label('MailboxMUidNext'),
        status: Joi.object({
            messages: Joi.number().integer().example(120).description('Count of messages in mailbox as reported by the STATUS command').label('StatusMessages'),
            unseen: Joi.number()
                .integer()
                .example(120)
                .description('Count of unseen messages in mailbox as reported by the STATUS command')
                .label('StatusUnseenMessages')
        })
            .description('Optional counters info')
            .label('MailboxResponseStatus')
    }).label('MailboxResponseItem')
);

const shortMailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/'),
        parentPath: Joi.string().required().example('Kalender').description('Full path to parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Maibox name').label('MailboxName'),
        listed: Joi.boolean().example(true).description('Was the mailbox found from the output of LIST command').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('Was the mailbox found from the output of LSUB command').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special use flag of the mailbox')
            .label('MailboxSpecialUse')
    }).label('MailboxResponseItem')
);

const licenseSchema = Joi.object({
    active: Joi.boolean().example(true).description('Is there an active license registered'),
    type: Joi.string().example('EmailEngine License').description('Active license type'),
    details: Joi.object({
        application: Joi.string().example('@postalsys/emailengine-app'),
        key: Joi.string().hex().example('1edf01e35e75ed3425808eba').description('License key'),
        licensedTo: Joi.string().hex().example('Kreata OÜ').description('Licensed to'),
        hostname: Joi.string().example('emailengine.example.com').description('Hostname or environment this license applies to'),
        created: Joi.date().example('2021-10-13T07:47:42.695Z').description('Time the license was provisioned')
    })
        .allow(false)
        .label('LicenseDetails'),
    suspended: Joi.boolean().example(false).description('Are email connections closed')
});

const lastErrorSchema = Joi.object({
    response: Joi.string().example('Token request failed'),
    serverResponseCode: Joi.string().example('OauthRenewError'),
    tokenRequest: Joi.object({
        grant: Joi.string().valid('refresh_token', 'authorization_code').example('refresh_token').description('Requested grant type'),
        provider: Joi.string().max(256).example('gmail').description('OAuth2 provider'),
        status: Joi.number().integer().example(400).description('HTTP status code for the OAuth2 request'),
        clientId: Joi.string()
            .example('1023289917884-h3nu00e9cb7h252e24c23sv19l8k57ah.apps.googleusercontent.com')
            .description('OAuth2 client ID used to authenticate this request'),
        scopes: Joi.array()
            .items(Joi.string().example('https://mail.google.com/').label('ScopeEntry').description('OAuth2 scope'))
            .description('List of requested OAuth2 scopes')
            .label('OauthScopes'),
        response: Joi.object()
            .example({
                error: 'invalid_grant',
                error_description: 'Bad Request'
            })
            .description('Server response')
            .unknown()
    }).description('OAuth2 error info if token request failed')
}).label('AccountErrorEntry');

const templateSchemas = {
    subject: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .example('What a wonderful message')
        .description('Message subject'),
    text: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),
    html: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),
    previewText: Joi.string().allow('').max(1024).example('Welcome to our newsletter!').description('Preview text appears in the inbox after the subject line')
};

const documentStoreSchema = Joi.boolean()
    .empty('')
    .truthy('Y', 'true', '1')
    .falsy('N', 'false', 0)
    .description('If enabled then fetch the data from the Document Store instead of IMAP')
    .label('UseDocumentStore');

const searchSchema = Joi.object({
    seq: Joi.string()
        .max(8 * 1024)
        .description('Sequence number range. Not allowed with `documentStore`.'),

    answered: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is answered or not').label('AnsweredFlag'),
    deleted: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Check if message is marked for being deleted or not')
        .label('DeletedFlag'),
    draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is a draft').label('DraftFlag'),
    unseen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is marked as unseen or not').label('UnseenFlag'),
    flagged: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is flagged or not').label('Flagged'),
    seen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is marked as seen or not').label('SeenFlag'),

    from: Joi.string().max(256).description('Match From: header').label('From'),
    to: Joi.string().max(256).description('Match To: header').label('To'),
    cc: Joi.string().max(256).description('Match Cc: header').label('Cc'),
    bcc: Joi.string().max(256).description('Match Bcc: header').label('Bcc'),

    body: Joi.string().max(256).description('Match text body').label('MessageBody'),
    subject: Joi.string()
        .allow('')
        .max(10 * 256)
        .description('Match message subject')
        .label('Subject'),

    larger: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Matches messages larger than value')
        .label('MessageLarger'),

    smaller: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Matches messages smaller than value')
        .label('MessageSmaller'),

    uid: Joi.string()
        .max(8 * 1024)
        .description('UID range')
        .label('UIDRange'),

    modseq: Joi.number()
        .integer()
        .min(0)
        .description('Matches messages with modseq higher than value. Not allowed with `documentStore`.')
        .label('ModseqLarger'),

    before: Joi.date().description('Matches messages received before date').label('EnvelopeBefore'),
    since: Joi.date().description('Matches messages received after date').label('EnvelopeSince'),

    sentBefore: Joi.date().description('Matches messages sent before date').label('HeaderBefore'),
    sentSince: Joi.date().description('Matches messages sent after date').label('HeaderSince'),

    emailId: Joi.string().max(256).description('Match specific Gmail unique email UD'),
    threadId: Joi.string().max(256).description('Match specific Gmail unique thread UD'),

    header: Joi.object().description('Headers to match against').label('Headers').unknown(),

    gmailRaw: Joi.string()
        .max(1024)
        .example('has:attachment in:unread')
        .description('Raw Gmail search string. Will return an error if used for other account types.')
})
    .required()
    .description('Search query to filter messages')
    .label('SearchQuery');

const messageUpdateSchema = Joi.object({
    flags: Joi.object({
        add: Joi.array().items(Joi.string().max(128)).single().description('Add new flags').example(['\\Seen']).label('AddFlags'),
        delete: Joi.array().items(Joi.string().max(128)).single().description('Delete specific flags').example(['\\Flagged']).label('DeleteFlags'),
        set: Joi.array().items(Joi.string().max(128)).single().description('Override all flags').example(['\\Seen', '\\Flagged']).label('SetFlags')
    })
        .description('Flag updates')
        .label('FlagUpdate'),

    labels: Joi.object({
        add: Joi.array().items(Joi.string().max(128)).single().description('Add new labels').example(['Some label']).label('AddLabels'),
        delete: Joi.array().items(Joi.string().max(128)).single().description('Delete specific labels').example(['Some label']).label('DeleteLabels'),
        set: Joi.array().items(Joi.string().max(128)).single().description('Override all labels').example(['First label', 'Second label']).label('SetLabels')
    })
        .description('Label updates')
        .label('LabelUpdate')
}).label('MessageUpdate');

const accountSchemas = {
    syncFrom: Joi.date()
        .iso()
        .allow(null)
        .example('2021-07-08T07:06:34.336Z')
        .description('Sync messages to document store starting from provided date. If not set, all emails are synced.'),

    notifyFrom: Joi.date()
        .iso()
        .allow(null)
        .example('2021-07-08T07:06:34.336Z')
        .description('Send webhooks for messages starting from provided date. The default is the account creation date.'),

    subconnections: Joi.array()
        .items(Joi.string().max(256))
        .single()
        .example(['[Gmail]/Spam', '\\Sent'])
        .description(
            'An array of mailbox paths. If set, then EmailEngine opens additional IMAP connections against these paths to detect changes faster. NB! connection counts are usually highly limited.'
        )
        .label('SubconnectionPaths')
};

const oauthCreateSchema = {
    name: Joi.string().trim().empty('').max(256).example('My Gmail App').required().description('Application name'),
    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Application description'),
    title: Joi.string().allow('').trim().max(256).example('App title').description('Title for the application button'),

    provider: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .valid(...Object.keys(OAUTH_PROVIDERS))
        .example('gmail')
        .required()
        .description('OAuth2 provider'),

    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).example(true).description('Enable this app'),

    clientId: Joi.string()
        .trim()
        .allow('')
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('52422112755-3uov8bjwlrullq122rdm6l8ui25ho7qf.apps.googleusercontent.com')
        .description('Client or Application ID for 3-legged OAuth2 applications'),

    clientSecret: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('boT7Q~dUljnfFdVuqpC11g8nGMjO8kpRAv-ZB')
        .description('Client secret for 3-legged OAuth2 applications'),

    baseScopes: Joi.string()
        .empty('')
        .trim()
        .valid(...['imap'].concat(featureFlags.enabled('gmail api') ? 'api' : []))
        .example('imap')
        .description('OAuth2 Base Scopes'),

    extraScopes: Joi.any()
        .alter({
            web: () =>
                Joi.string()
                    .allow('')
                    .trim()
                    .example('User.Read')
                    .max(10 * 1024),
            api: () => Joi.array().items(Joi.string().trim().max(255).example('User.Read'))
        })
        .description('OAuth2 Extra Scopes'),

    skipScopes: Joi.any()
        .alter({
            web: () =>
                Joi.string()
                    .allow('')
                    .trim()
                    .example('SMTP.Send')
                    .max(10 * 1024),
            api: () => Joi.array().items(Joi.string().trim().max(255).example('SMTP.Send'))
        })
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
        .example('7103296518315821565203')
        .description('Service client ID for 2-legged OAuth2 applications'),

    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .when('provider', {
            is: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...')
        .description('PEM formatted service secret for 2-legged OAuth2 applications'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .when('provider', {
            is: 'outlook',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('common')
        .description('Authorization tenant value for Outlook OAuth2 applications')
        .label('SupportedAccountTypes'),

    redirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('https://myservice.com/oauth')
        .description('Redirect URL for 3-legged OAuth2 applications')
};

const tokenRestrictionsSchema = Joi.object({
    referrers: Joi.array()
        .items(Joi.string())
        .empty('')
        .single()
        .allow(false)
        .default(false)
        .example(['*web.domain.org/*', '*.domain.org/*', 'https://domain.org/*'])
        .label('ReferrerAllowlist')
        .description('HTTP referrer allowlist for API requests'),
    addresses: Joi.array()
        .items(
            Joi.string().ip({
                version: ['ipv4', 'ipv6'],
                cidr: 'optional'
            })
        )
        .empty('')
        .single()
        .allow(false)
        .default(false)
        .example(['1.2.3.4', '5.6.7.8', '127.0.0.0/8'])
        .label('AddressAllowlist')
        .description('IP address allowlist'),
    rateLimit: Joi.object({
        maxRequests: Joi.number().integer().min(1).example(20).description('Allowed count of requests in the rate limit time window'),
        timeWindow: Joi.number().integer().min(1).example(2).description('Rate limit time window in seconds')
    })
        .allow(false)
        .default(false)
        .example({ maxRequests: 20, timeWindow: 2 })
        .label('AddressRateLimit')
        .description('Rate limits for the token')
})
    .empty('')
    .allow(false)
    .label('TokenRestrictions')
    .description('Access restrictions');

const ipSchema = Joi.string()
    .empty('')
    .trim()
    .ip({
        version: ['ipv4', 'ipv6'],
        cidr: 'forbidden'
    })
    .example('127.0.0.1');

const accountIdSchema = Joi.string().empty('').trim().max(256).example('example').description('Account ID');

const accountCountersSchema = Joi.object({
    events: Joi.object().unknown().description('Lifetime event counters').label('AcountCountersEvents').example({ messageNew: 30, messageDeleted: 5 })
}).label('AccountCounters');

module.exports = {
    ADDRESS_STRATEGIES,

    settingsSchema,
    accountSchemas,
    addressSchema,
    settingsQuerySchema,
    imapSchema,
    smtpSchema,
    oauth2Schema,
    imapUpdateSchema,
    smtpUpdateSchema,
    oauth2UpdateSchema,
    attachmentSchema,
    messageEntrySchema,
    messageDetailsSchema,
    messageListSchema,
    mailboxesSchema,
    shortMailboxesSchema,
    licenseSchema,
    lastErrorSchema,
    templateSchemas,
    documentStoreSchema,
    searchSchema,
    messageUpdateSchema,
    oauthCreateSchema,
    tokenRestrictionsSchema,
    accountIdSchema,
    ipSchema,
    accountCountersSchema
};

/*
let schema = Joi.object(imapSchema);
let res = schema.validate({
    host: false,
    port: 124,
    auth: { user: 'tere', pass: 'kere', accessToken: false },
    useAuthServer: false,
    disabled: false
});
console.log(res);
process.exit();
*/
