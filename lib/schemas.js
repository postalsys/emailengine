'use strict';

const Joi = require('joi');
const config = require('wild-config');
const { getByteSize } = require('./tools');
const { locales } = require('./translations');

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

const accountIdSchema = Joi.string().empty('').trim().max(256).example('user123').description('Account ID');

// allowed configuration keys
// Allowed configuration keys
const settingsSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If set to false, webhooks will not be emitted'),

    webhooks: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://myservice.com/imap/webhooks')
        .description('The URL where webhooks will be sent'),

    webhookEvents: Joi.array().items(Joi.string().max(256).example('messageNew')).description('List of webhook events to subscribe to'),

    webhooksCustomHeaders: Joi.array()
        .items(
            Joi.object({
                key: Joi.string().trim().empty('').max(1024).required().example('Authorization'),
                value: Joi.string()
                    .trim()
                    .empty('')
                    .max(10 * 1024)
                    .default('')
                    .example('Bearer <secret-token>')
            }).label('WebhooksCustomHeader')
        )
        .description('Custom HTTP headers added to webhook requests')
        .label('WebhooksCustomHeaders'),

    notifyHeaders: Joi.array()
        .items(Joi.string().max(256).example('List-ID'))
        .description('List of additional email headers to include in webhook notifications'),

    serviceUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://emailengine.example.com')
        .description('The base URL of the EmailEngine service. If path is also provided then it is ignored.')
        .label('ServiceURL'),

    notificationBaseUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('', null)
        .example('https://emailengine.example.com')
        .description(
            'Base URL of EmailEngine for receiving external notifications like MS Graph webhooks. Can contain a path value. Defaults to `serviceUrl` if not set.'
        )
        .label('NotificationBaseUrl'),

    trackSentMessages: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, rewrites HTML links in sent emails to track opens and clicks')
        .meta({ swaggerHidden: true }),

    trackClicks: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, rewrites HTML links in sent emails to track link clicks'),

    trackOpens: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, inserts a tracking beacon image in HTML emails to monitor email opens'),

    imapIndexer: Joi.string()
        .empty('')
        .trim()
        .valid('full', 'fast')
        .example('full')
        .description(
            'Sets the indexing method for IMAP accounts. Choose "full" to build a complete index that tracks deleted and updated emails, or "fast" to only detect newly received emails'
        ),

    resolveGmailCategories: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description(
            'Enables Gmail category tab detection for incoming emails when set to true. Applies only to Gmail IMAP accounts; Gmail API accounts automatically include category information'
        ),

    ignoreMailCertErrors: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description(
            'If true, allows connections to servers with insecure or untrusted SSL/TLS certificates. Applies to both IMAP and SMTP connections. Use with caution'
        ),

    generateEmailSummary: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, generates a summary of the email using OpenAI ChatGPT'),

    generateRiskAssessment: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('(Deprecated, not used)')
        .meta({ swaggerHidden: true }),

    openAiAPIKey: Joi.string().allow('').example('verysecret').description('OpenAI API key').label('OpenAiAPIKey'),
    openAiModel: Joi.string().allow('').example('gpt-3.5-turbo').description('OpenAI API model').label('OpenAiModel'),

    openAiAPIUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://api.openai.com')
        .description('OpenAI API URL')
        .label('OpenAiAPIUrl'),

    documentStoreChatModel: Joi.string().allow('').example('gpt-3.5-turbo').description('OpenAI API model for chat').label('DocumentStoreChatModel'),

    openAiTemperature: Joi.number()
        .allow('')
        .min(0)
        .max(2)
        .example(0.8)
        .description(
            'Controls the randomness of the OpenAI API responses. Higher values (up to 2) make output more random, while lower values make it more focused and deterministic'
        )
        .label('OpenAiTemperature'),

    openAiTopP: Joi.number()
        .allow('')
        .min(0)
        .max(1)
        .example(0.1)
        .description('Controls the cumulative probability for nucleus sampling in the OpenAI API. A value between 0 and 1')
        .label('OpenAiTopP'),

    openAiPrompt: Joi.string()
        .allow('')
        .max(6 * 1024)
        .example('You are an assistant scanning incoming emails...')
        .description('Prompt to send to the LLM for analyzing emails')
        .label('OpenAiPrompt'),

    openAiGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, generates vector embeddings for the email'),

    inboxNewOnly: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, sends "New Email" webhooks for incoming emails only'),

    serviceSecret: Joi.string().allow('').example('verysecret').description('HMAC secret for signing public requests').label('ServiceSecret'),

    authServer: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://myservice.com/authentication')
        .description('The URL of the authentication server to fetch authentication data from')
        .label('AuthServer'),

    proxyEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('If true, the global proxy is enabled'),

    proxyUrl: Joi.string()
        .uri({ scheme: ['http', 'https', 'socks', 'socks4', 'socks5'], allowRelative: false })
        .allow('')
        .example('socks://proxy.example.com:1080')
        .description('Proxy URL')
        .label('ProxyURL'),

    smtpEhloName: Joi.string().hostname().allow('', null).example('my.proxy.tld').description('Hostname to use for the SMTP EHLO/HELO greeting'),

    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include message text in webhook notifications'),

    notifyWebSafeHtml: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Pre-process HTML in webhook notifications to be web-safe'),

    notifyTextSize: Joi.number().integer().min(0).description('Maximum size of message text to include in webhook notifications (in bytes)'),

    notifyAttachments: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include attachments in webhook notifications'),
    notifyAttachmentSize: Joi.number().integer().min(0).description('Maximum size of attachment to include in webhook notifications (in bytes)'),

    notifyCalendarEvents: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Include calendar events in webhook notifications'),

    gmailEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('If true, do not show Gmail account option (deprecated)')
        .meta({ swaggerHidden: true }),
    gmailClientId: Joi.string().allow('').max(256).description('Gmail OAuth2 Client ID (deprecated)').meta({ swaggerHidden: true }),
    gmailClientSecret: Joi.string().empty('').max(256).description('Gmail OAuth2 Client Secret (deprecated)').meta({ swaggerHidden: true }),
    gmailRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Gmail OAuth2 Callback URL (deprecated)')
        .meta({ swaggerHidden: true }),
    gmailExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('Gmail OAuth2 Extra Scopes (deprecated)')
        .meta({ swaggerHidden: true }),

    outlookEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('If true, do not show Outlook account option (deprecated)')
        .meta({ swaggerHidden: true }),
    outlookClientId: Joi.string().allow('').max(256).description('Outlook OAuth2 Client ID (deprecated)').meta({ swaggerHidden: true }),
    outlookClientSecret: Joi.string().empty('').max(256).description('Outlook OAuth2 Client Secret (deprecated)').meta({ swaggerHidden: true }),
    outlookRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Outlook OAuth2 Callback URL (deprecated)')
        .meta({ swaggerHidden: true }),
    outlookAuthority: Joi.string()
        .empty('')
        .allow('consumers', 'organizations', 'common')
        .example('consumers')
        .description('Outlook OAuth2 authority (deprecated)')
        .meta({ swaggerHidden: true }),
    outlookExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Outlook OAuth2 Extra Scopes (deprecated)')
        .meta({ swaggerHidden: true }),

    mailRuEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('If true, do not show Mail.ru account option (deprecated)')
        .meta({ swaggerHidden: true }),
    mailRuClientId: Joi.string().allow('').max(256).description('Mail.ru OAuth2 Client ID (deprecated)').meta({ swaggerHidden: true }),
    mailRuClientSecret: Joi.string().empty('').max(256).description('Mail.ru OAuth2 Client Secret (deprecated)').meta({ swaggerHidden: true }),
    mailRuRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Mail.ru OAuth2 Callback URL (deprecated)')
        .meta({ swaggerHidden: true }),
    mailRuExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Mail.ru OAuth2 Extra Scopes (deprecated)')
        .meta({ swaggerHidden: true }),

    serviceClient: Joi.string().trim().allow('').max(256).description('OAuth2 Service Client ID (deprecated)').meta({ swaggerHidden: true }),
    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .description('OAuth2 Secret Service Key (deprecated)')
        .meta({ swaggerHidden: true }),

    serviceExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('OAuth2 Service Extra Scopes (deprecated)')
        .meta({ swaggerHidden: true }),

    logs: Joi.object({
        all: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).example(false).description('Enable logs for all accounts'),
        maxLogLines: Joi.number().integer().min(0).max(1000000).default(10000).description('Maximum number of log lines to keep')
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
        .items(Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }))
        .single()
        .description('A list of pooled local IP addresses that can be used for IMAP and SMTP connections'),

    smtpServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP interface'),

    smtpServerPort: Joi.number()
        .integer()
        .min(0)
        .max(64 * 1024)
        .empty('')
        .description('SMTP interface port'),

    smtpServerHost: Joi.string()
        .ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' })
        .empty('')
        .description('SMTP host to bind to'),

    smtpServerProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable PROXY protocol for SMTP server'),

    smtpServerAuthEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP authentication'),

    smtpServerPassword: Joi.string().empty('').allow(null).max(1024).description('SMTP client password. Set to `null` to disable'),

    smtpServerTLSEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable TLS for the SMTP interface. Requires a valid certificate'),

    imapProxyServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable IMAP proxy interface'),

    imapProxyServerPort: Joi.number()
        .integer()
        .min(0)
        .max(64 * 1024)
        .empty('')
        .description('IMAP proxy interface port'),

    imapProxyServerHost: Joi.string()
        .ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' })
        .empty('')
        .description('IMAP proxy host to bind to'),

    imapProxyServerProxy: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable PROXY protocol for the IMAP proxy server'),

    imapProxyServerPassword: Joi.string().empty('').allow(null).max(1024).description('IMAP proxy client password. Set to `null` to disable'),

    imapProxyServerTLSEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable TLS for the IMAP proxy interface. Requires a valid certificate'),

    queueKeep: Joi.number().integer().empty('').min(0).description('Number of completed or failed queue entries to keep'),

    deliveryAttempts: Joi.number().integer().empty('').min(0).description('Number of times to retry sending an email before it is considered as failed'),

    templateHeader: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('HTML code displayed at the top of public pages like the hosted authentication form'),

    templateHtmlHead: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('HTML code added to the HEAD tag of public pages like the hosted authentication form'),

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
                throw new Error('Provided value is not valid JSON');
            }

            if (!parsed || typeof parsed !== 'object') {
                throw new Error('Provided value is not an object');
            }

            return value;
        }, 'JSON validation')
        .example('{"key": "value"}')
        .description('JSON object to be used as the `env` variable in pre-processing scripts'),

    enableApiProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable support for reverse proxies'),

    documentStoreEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated. Enable Document Store syncing')
        .meta({ swaggerHidden: true }),
    documentStoreUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://localhost:9200')
        .description('Deprecated. Document Store URL')
        .meta({ swaggerHidden: true }),
    documentStoreIndex: Joi.string().empty('').max(1024).description('Deprecated. Document Store index name').meta({ swaggerHidden: true }),
    documentStoreAuthEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated. Enable Document Store authentication')
        .meta({ swaggerHidden: true }),
    documentStoreUsername: Joi.string().empty('').max(1024).description('Deprecated. Document Store username').meta({ swaggerHidden: true }),
    documentStorePassword: Joi.string().empty('').max(1024).description('Deprecated. Document Store password').meta({ swaggerHidden: true }),
    documentStoreGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated. If true, generates vector embeddings for the email and stores them in the Document Store')
        .meta({ swaggerHidden: true }),
    documentStorePreProcessingEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated. Enable Document Store pre-processing')
        .meta({ swaggerHidden: true }),

    locale: Joi.string()
        .max(100)
        .example('fr')
        .valid(...locales.map(locale => locale.locale))
        .description('Default locale identifier'),

    timezone: Joi.string().max(100).example('Europe/Tallinn').description('Default timezone identifier'),

    pageBrandName: Joi.string().allow('', null).max(1024).example('EmailEngine').description('Brand name to use in the HTML title element'),

    openAiPreProcessingFn: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return true; // passes all emails')
        .description('Filter function for LLM pre-processing (JavaScript)'),

    documentStorePreProcessingFn: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return true; // passes all emails')
        .description('Deprecated. Filter function for Document Store pre-processing (JavaScript)')
        .meta({ swaggerHidden: true }),

    documentStorePreProcessingMap: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return payload; // returns unmodified data')
        .description('Deprecated. Mapping function for Document Store pre-processing (JavaScript)')
        .meta({ swaggerHidden: true })
};

const addressSchema = Joi.object({
    name: Joi.string().trim().empty('').max(256).example('Some Name'),
    address: Joi.string().email({ ignoreLength: false }).example('user@example.com').required()
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
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('The username of the email account'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('The password for the email account')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token for the email account')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the email account')
        .label('Authentication'),

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of providing username/password directly'),

    host: Joi.string()
        .hostname()
        .when('disabled', {
            is: true,
            then: Joi.optional().allow(false, null),
            otherwise: Joi.required()
        })
        .example('imap.gmail.com')
        .description('The hostname of the IMAP server to connect to'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(65535)
        .when('disabled', {
            is: true,
            then: Joi.optional().allow(false, null),
            otherwise: Joi.required()
        })
        .example(993)
        .description('The port number of the IMAP service'),
    secure: Joi.boolean().default(false).example(true).description('Whether to use TLS for the connection (usually true for port 993)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('Whether to reject invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('The minimum TLS version to allow')
    })
        .unknown()
        .description('Optional TLS configuration settings')
        .label('TLS'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Delay in seconds between full resynchronizations').default(RESYNC_DELAY),
    disabled: Joi.boolean().example(false).description('Set to true to disable IMAP handling for this account'),

    sentMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Sent Mail')
        .description("Folder where sent messages are uploaded. Defaults to the account's 'Sent Mail' folder. Set to `null` to unset."),
    draftsMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Drafts')
        .description("Folder for drafts. Defaults to the account's 'Drafts' folder. Set to `null` to unset."),
    junkMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Junk')
        .description("Folder for spam messages. Defaults to the account's 'Junk' folder. Set to `null` to unset."),
    trashMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Trash')
        .description("Folder for deleted emails. Defaults to the account's 'Trash' folder. Set to `null` to unset."),
    archiveMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Archive')
        .description("Folder for archived emails. Defaults to the account's 'Archive' folder. Set to `null` to unset.")
};

const smtpSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('The username of the email account'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('The password for the email account')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token for the email account')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the email account')
        .label('Authentication'),

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of providing username/password directly'),

    host: Joi.string().hostname().required().example('smtp.gmail.com').description('The hostname of the SMTP server to connect to'),
    port: Joi.number().integer().min(1).max(65535).required().example(587).description('The port number of the SMTP service'),
    secure: Joi.boolean().default(false).example(false).description('Whether to use TLS for the connection (usually true for port 465)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('Whether to reject invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('The minimum TLS version to allow')
    })
        .unknown()
        .description('Optional TLS configuration settings')
        .label('TLS')
};

const oauth2AuthSchema = Joi.object({
    user: Joi.string()
        .max(256)
        .when('delegatedAccount', {
            is: Joi.exist().not(false, null),
            then: Joi.optional(),
            otherwise: Joi.required()
        })
        .example('user@outlook.com')
        .description('Email account username'),
    delegatedUser: Joi.string().max(256).optional().example('shared.mailbox@outlook.com').description('Username of the shared mailbox (Microsoft 365 only)'),
    delegatedAccount: accountIdSchema
        .when('delegatedUser', {
            is: Joi.exist().not(false, null),
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description(
            'Account ID of another account to authenticate the shared mailbox. If provided, EmailEngine uses the credentials of this account instead of the current one.'
        )
})
    .required()
    .when('authorize', {
        is: true,
        then: Joi.optional().valid(false, null)
    })
    .label('OAuth2Authentication');

const oauth2Schema = {
    authorize: Joi.boolean().example(false).description('Set to true to obtain a redirect link to the OAuth2 consent screen.'),
    redirectUrl: Joi.string()
        .empty('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .example('https://myapp/account/settings.php')
        .description('URL to redirect the user after the OAuth2 consent screen. Only valid if `authorize` is true.')
        .when('authorize', {
            is: true,
            then: Joi.optional(),
            otherwise: Joi.optional().valid(false, null)
        }),

    provider: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 Application ID for an application configured in EmailEngine.'),

    auth: oauth2AuthSchema,

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of EmailEngine managing access tokens.'),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...')
        .description('OAuth2 access token for the email account.'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...')
        .description('OAuth2 refresh token for the email account.'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description("Specifies the Outlook account type: 'consumers', 'organizations', 'common', or an organization ID.")
        .label('SupportedAccountTypes'),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Expiration date and time of the access token.')
};

const partialSchema = Joi.boolean()
    .example(false)
    .description('Set to true to update only the provided keys; by default, the entire object is replaced')
    .default(false);

const imapUpdateSchema = {
    partial: partialSchema,

    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('The username of the email account'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('The password for the email account')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token for the email account')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the email account')
        .label('Authentication'),

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of providing username/password directly'),

    host: Joi.string().hostname().example('imap.gmail.com').description('The hostname of the IMAP server to connect to'),
    port: Joi.number().integer().min(1).max(65535).example(993).description('The port number of the IMAP service'),
    secure: Joi.boolean().example(true).description('Whether to use TLS for the connection (usually true for port 993)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('Whether to reject invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('The minimum TLS version to allow')
    })
        .unknown()
        .description('Optional TLS configuration settings')
        .label('TLS'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Delay in seconds between full resynchronizations'),

    disabled: Joi.boolean().example(false).description('Set to true to disable IMAP handling for this account'),

    sentMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Sent Mail')
        .description("Folder where sent messages are uploaded. Defaults to the account's 'Sent Mail' folder. Set to `null` to unset."),
    draftsMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Drafts')
        .description("Folder for drafts. Defaults to the account's 'Drafts' folder. Set to `null` to unset."),
    junkMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Junk')
        .description("Folder for spam messages. Defaults to the account's 'Junk' folder. Set to `null` to unset."),
    trashMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Trash')
        .description("Folder for deleted emails. Defaults to the account's 'Trash' folder. Set to `null` to unset."),
    archiveMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Archive')
        .description("Folder for archived emails. Defaults to the account's 'Archive' folder. Set to `null` to unset.")
};

const smtpUpdateSchema = {
    partial: partialSchema,
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('The username of the email account'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('The password for the email account')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token for the email account')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the email account')
        .label('Authentication'),

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of providing username/password directly'),

    host: Joi.string().hostname().example('smtp.gmail.com').description('The hostname of the SMTP server to connect to'),
    port: Joi.number().integer().min(1).max(65535).example(587).description('The port number of the SMTP service'),
    secure: Joi.boolean().example(false).description('Whether to use TLS for the connection (usually true for port 465)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('Whether to reject invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('The minimum TLS version to allow')
    })
        .unknown()
        .description('Optional TLS configuration settings')
        .label('TLS')
};

const oauth2UpdateSchema = {
    partial: partialSchema,

    authorize: Joi.boolean().example(false).description('Set to true to obtain a redirect link to the OAuth2 consent screen.'),
    provider: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 Application ID for an application configured in EmailEngine.'),

    auth: oauth2AuthSchema,

    useAuthServer: Joi.boolean()
        .example(false)
        .description('Set to true to use an external authentication server instead of EmailEngine managing access tokens.'),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...')
        .description('OAuth2 access token for the email account.'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...')
        .description('OAuth2 refresh token for the email account.'),
    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description("Specifies the Outlook account type: 'consumers', 'organizations', 'common', or an organization ID.")
        .label('SupportedAccountTypes'),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Expiration date and time of the access token.')
};

const attachmentSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrIyLjI').description('Unique identifier for the attachment').label('AttachmentId'),
    contentType: Joi.string().example('image/gif').description('MIME type of the attachment'),
    encodedSize: Joi.number()
        .integer()
        .example(48)
        .description('Size of the attachment in bytes when encoded (actual file size may be smaller due to encoding)'),
    embedded: Joi.boolean().example(true).description('Indicates if the attachment is an embedded image used in an HTML `<img>` tag'),
    inline: Joi.boolean().example(true).description('Indicates if the attachment should be displayed inline in the message preview'),
    contentId: Joi.string().example('<unique-image-id@localhost>').description('Content ID used for embedded images'),
    filename: Joi.string().example('image.png').description('Filename of the attachment'),
    method: Joi.string().example('REQUEST').description('Calendar event method if the attachment is an iCalendar event')
}).label('AttachmentEntry');

const AddressListSchema = Joi.array().items(addressSchema.label('RcptAddressEntry')).description('An array of email address entries').label('AddressList');

const fromAddressSchema = addressSchema
    .example({ name: 'From Me', address: 'sender@example.com' })
    .description("The sender's email address")
    .label('FromAddress');

const messageEntrySchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Unique identifier for the message').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('Unique identifier of the message within the mailbox').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique email ID assigned by the server (if supported)').label('MessageEmailId'),
    threadId: Joi.string()
        .example('1694936993596975454')
        .description('Unique identifier for the thread to which this message belongs (if supported by the server)')
        .label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date when the message was added to the mailbox (INTERNALDATE)'),
    draft: Joi.boolean().example(false).description('True if this message is marked as a draft'),
    unseen: Joi.boolean().example(true).description('True if the message is marked as unseen (unread)'),
    flagged: Joi.boolean().example(true).description('True if this message is flagged'),
    size: Joi.number().integer().example(1040).description('Size of the message in bytes'),
    subject: Joi.string().allow('').example('What a wonderful message').description('Subject of the message, decoded into Unicode'),

    from: fromAddressSchema,
    replyTo: AddressListSchema,
    to: AddressListSchema,
    cc: AddressListSchema,
    bcc: AddressListSchema,
    messageId: Joi.string().example('<test123@example.com>').description('The Message-ID header value of the message'),
    inReplyTo: Joi.string()
        .example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>')
        .description('The In-Reply-To header value (Message-ID of the message this is a reply to)'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('List of IMAP flags associated with the message').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('List of Gmail labels associated with the message').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('Array of attachment objects').label('AttachmentList'),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Identifier for fetching the message text content'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('Size in bytes of the plain text content'),
            html: Joi.number().integer().example(1013).description('Size in bytes of the HTML content')
        }).description('Size of the encoded message parts in bytes')
    }).label('TextInfo'),

    preview: Joi.string().description('A short text preview of the message content')
}).label('MessageListEntry');

const messageSpecialUseSchema = Joi.string()
    .example('\\Sent')
    .valid('\\Drafts', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
    .description('Special use flag associated with the message, indicating the mailbox special use')
    .label('MessageSpecialUse');

const messageDetailsSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Unique identifier for the message').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('Unique identifier of the message within the mailbox').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique email ID assigned by the server (if supported)').label('MessageEmailId'),
    threadId: Joi.string()
        .example('1694936993596975454')
        .description('Unique identifier for the thread to which this message belongs (if supported by the server)')
        .label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date when the message was added to the mailbox (INTERNALDATE)'),
    draft: Joi.boolean().example(false).description('True if this message is marked as a draft'),
    unseen: Joi.boolean().example(true).description('True if the message is marked as unseen (unread)'),
    flagged: Joi.boolean().example(true).description('True if this message is flagged'),
    size: Joi.number().integer().example(1040).description('Size of the message in bytes'),
    subject: Joi.string().allow('').example('What a wonderful message').description('Subject of the message, decoded into Unicode'),

    from: fromAddressSchema,
    sender: fromAddressSchema,

    to: AddressListSchema,

    cc: AddressListSchema,

    bcc: AddressListSchema,
    replyTo: AddressListSchema,

    messageId: Joi.string().example('<test123@example.com>').description('The Message-ID header value of the message'),
    inReplyTo: Joi.string()
        .example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>')
        .description('The In-Reply-To header value (Message-ID of the message this is a reply to)'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('List of IMAP flags associated with the message').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('List of Gmail labels associated with the message').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('Array of attachment objects').label('AttachmentList'),

    headers: Joi.object()
        .example({ from: ['From Me <sender@example.com>'], subject: ['What a wonderful message'] })
        .label('MessageHeaders')
        .description(
            'An object where each header field name is a key, and the value is an array of header field values. Not available for MS Graph API emails.'
        )
        .unknown(),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Identifier for fetching the message text content'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('Size in bytes of the plain text content'),
            html: Joi.number().integer().example(1013).description('Size in bytes of the HTML content')
        }).description('Size of the encoded message parts in bytes'),
        plain: Joi.string().example('Hello from myself!').description('Plaintext content of the message'),
        html: Joi.string().example('<p>Hello from myself!</p>').description('HTML content of the message'),
        hasMore: Joi.boolean()
            .example(false)
            .description('True if there is more content available beyond what was fetched; false if the entire content is included')
    }).label('TextInfoDetails'),

    bounces: Joi.array()
        .items(
            Joi.object({
                message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Identifier of the bounce email message'),
                recipient: Joi.string().email().example('recipient@example.com').description('Email address of the recipient that bounced'),
                action: Joi.string().example('failed').description('Action taken, e.g., "failed"'),
                response: Joi.object({
                    message: Joi.string().example('550 5.1.1 No such user').description('Server response message'),
                    status: Joi.string().example('5.1.1').description('Status code from the server')
                }).label('BounceResponse'),
                date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Time the bounce was registered by EmailEngine')
            }).label('BounceEntry')
        )
        .label('BounceList'),

    isAutoReply: Joi.boolean().example(false).description('True if this message was detected to be an auto-reply email, like an Out of Office notice'),

    specialUse: Joi.string()
        .example('\\Sent')
        .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
        .description('Special use flag of the mailbox containing this message')
        .label('MailboxSpecialUse'),
    messageSpecialUse: messageSpecialUseSchema
}).label('MessageDetails');

const messageListSchema = Joi.object({
    total: Joi.number()
        .integer()
        .example(120)
        .description('Total number of matching messages. This number is exact for IMAP accounts, but approximate for Gmail API accounts.')
        .label('TotalNumber'),
    page: Joi.number().integer().example(0).description('Current page index (0-based)').label('PageNumber'),
    pages: Joi.number()
        .integer()
        .example(24)
        .description('Total number of pages. This number is exact for IMAP accounts, but approximate for Gmail API accounts.')
        .label('PagesNumber'),
    nextPageCursor: Joi.string()
        .allow(null)
        .example('imap_kcQIji3UobDDTxc')
        .description('Paging cursor for the next page. Continue paging until this value is null.')
        .label('NextPageCursor'),
    prevPageCursor: Joi.string().allow(null).example('imap_kcQIji3UobDDTxc').description('Paging cursor for the previous page').label('PrevPageCursor'),
    messages: Joi.array().items(messageEntrySchema).label('PageMessages')
}).label('MessageList');

const mailboxesSchema = Joi.array()
    .items(
        Joi.object({
            path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to the mailbox').label('MailboxPath'),
            delimiter: Joi.string().example('/').description('Hierarchy delimiter used in the mailbox path'),
            parentPath: Joi.string().required().example('Kalender').description('Full path to the parent mailbox').label('MailboxParentPath'),
            name: Joi.string().required().example('Sünnipäevad').description('Name of the mailbox').label('MailboxName'),
            listed: Joi.boolean().example(true).description('True if the mailbox was returned in response to the LIST command').label('MailboxListed'),
            subscribed: Joi.boolean().example(true).description('True if the mailbox was returned in response to the LSUB command').label('MailboxSubscribed'),
            specialUse: Joi.string()
                .example('\\Sent')
                .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
                .description('Special use flag of the mailbox')
                .label('MailboxSpecialUse'),
            specialUseSource: Joi.string()
                .example('extension')
                .valid('user', 'extension', 'name')
                .description(
                    'Source of the specialUse flag. Can be "user" (set via API), "extension" (provided by the email server), or "name" (determined based on the folder name).'
                )
                .label('MailboxSpecialUseSource'),
            noInferiors: Joi.boolean().example(false).description('True if adding subfolders is not allowed').label('MailboxNoInferiors'),
            messages: Joi.number().integer().example(120).description('Number of messages in the mailbox').label('MailboxMessages'),
            uidNext: Joi.number().integer().example(121).description('Next expected UID').label('MailboxUidNext'),
            status: Joi.object({
                messages: Joi.number()
                    .integer()
                    .example(120)
                    .description('Number of messages in the mailbox as reported by the STATUS command')
                    .label('StatusMessages'),
                unseen: Joi.number()
                    .integer()
                    .example(120)
                    .description('Number of unseen messages in the mailbox as reported by the STATUS command')
                    .label('StatusUnseenMessages')
            })
                .description('Optional mailbox status information')
                .label('MailboxResponseStatus')
        }).label('MailboxResponseItem')
    )
    .label('MailboxesList');

const shortMailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to the mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/').description('Hierarchy delimiter used in the mailbox path'),
        parentPath: Joi.string().required().example('Kalender').description('Full path to the parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Name of the mailbox').label('MailboxName'),
        listed: Joi.boolean().example(true).description('True if the mailbox was returned in response to the LIST command').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('True if the mailbox was returned in response to the LSUB command').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special use flag of the mailbox')
            .label('MailboxSpecialUse')
    }).label('MailboxShortResponseItem')
);

const licenseSchema = Joi.object({
    active: Joi.boolean().example(true).description('Indicates whether an active license is registered'),
    type: Joi.string().example('EmailEngine License').description('Type of the active license'),
    details: Joi.object({
        application: Joi.string().example('@postalsys/emailengine-app').description('Application associated with the license'),
        key: Joi.string().hex().example('1edf01e35e75ed3425808eba').description('License key'),
        licensedTo: Joi.string().example('Kreata OÜ').description('Entity the license is issued to'),
        hostname: Joi.string().example('emailengine.example.com').description('Hostname or environment this license applies to'),
        created: Joi.date().example('2021-10-13T07:47:42.695Z').description('Time the license was provisioned')
    })
        .allow(false)
        .label('LicenseDetails'),
    suspended: Joi.boolean().example(false).description('Indicates whether email connections are suspended due to licensing issues')
});

const lastErrorSchema = Joi.object({
    response: Joi.string().example('Token request failed').description('Error message from EmailEngine'),
    serverResponseCode: Joi.string().example('OauthRenewError').description('Server response code or error identifier'),
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
    }).description('Information about the OAuth2 token request that failed')
}).label('AccountErrorEntry');

const templateSchemas = {
    subject: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .example('What a wonderful message')
        .description('Message subject'),
    text: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Plaintext content of the message'),
    html: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('HTML content of the message'),
    previewText: Joi.string()
        .allow('')
        .max(1024)
        .example('Welcome to our newsletter!')
        .description('Preview text that appears in the inbox after the subject line')
};

const documentStoreSchema = Joi.boolean()
    .empty('')
    .truthy('Y', 'true', '1')
    .falsy('N', 'false', 0)
    .description('Deprecated. If enabled then fetch the data from the Document Store instead of IMAP')
    .label('UseDocumentStore')
    .meta({ swaggerHidden: true });

const searchSchema = Joi.object({
    seq: Joi.string()
        .max(8 * 1024)
        .description('Sequence number range. Only supported for IMAP accounts.'),

    answered: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Check if message is answered or not. Only supported for IMAP accounts.')
        .label('AnsweredFlag'),
    deleted: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Check if message is marked for deletion or not. Only supported for IMAP accounts.')
        .label('DeletedFlag'),
    draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is a draft.').label('DraftFlag'),
    unseen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is marked as unseen.').label('UnseenFlag'),
    flagged: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is flagged or not.').label('Flagged'),
    seen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is marked as seen.').label('SeenFlag'),

    from: Joi.string().max(256).description('Match From: header').label('From'),
    to: Joi.string().max(256).description('Match To: header. Not supported for MS Graph API accounts.').label('To'),
    cc: Joi.string().max(256).description('Match Cc: header. Not supported for MS Graph API accounts.').label('Cc'),
    bcc: Joi.string().max(256).description('Match Bcc: header. Not supported for MS Graph API accounts.').label('Bcc'),

    body: Joi.string().max(256).description('Match text body').label('MessageBody'),
    subject: Joi.string()
        .allow('')
        .max(10 * 256)
        .example('Hello world')
        .description('Match message subject')
        .label('Subject'),

    larger: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Matches messages larger than value in bytes. Not supported for MS Graph API accounts.')
        .label('MessageLarger'),

    smaller: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Matches messages smaller than value in bytes. Not supported for MS Graph API accounts.')
        .label('MessageSmaller'),

    uid: Joi.string()
        .max(8 * 1024)
        .description('UID range. Only supported for IMAP accounts.')
        .label('UIDRange'),

    modseq: Joi.number()
        .integer()
        .min(0)
        .description('Matches messages with modseq higher than value. Only supported for IMAP accounts.')
        .label('ModseqLarger'),

    before: Joi.date().description('Matches messages received before date').label('EnvelopeBefore'),
    since: Joi.date().description('Matches messages received after date').label('EnvelopeSince'),

    sentBefore: Joi.date().description('Matches messages sent before date').label('HeaderBefore'),
    sentSince: Joi.date().description('Matches messages sent after date').label('HeaderSince'),

    emailId: Joi.string().max(256).example('1278455344230334865').description('Match specific Gmail unique email ID'),
    threadId: Joi.string().max(256).example('1278455344230334865').description('Match specific Gmail unique thread ID'),

    header: Joi.object().description('Headers to match against').label('Headers').unknown().example({ 'Message-ID': '<1DAF52A51E674A2@example.com>' }),

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
        add: Joi.array().items(Joi.string().max(128)).single().description('Add flags.').example(['\\Seen']).label('AddFlags'),
        delete: Joi.array().items(Joi.string().max(128)).single().description('Remove flags.').example(['\\Flagged']).label('DeleteFlags'),
        set: Joi.array().items(Joi.string().max(128)).single().description('Replace all existing flags.').example(['\\Seen', '\\Flagged']).label('SetFlags')
    })
        .description('Updates for message flags.')
        .label('FlagUpdate'),

    labels: Joi.object({
        add: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Add labels. Each label is a mailbox ID or a path if the ID is not set.')
            .example(['Label_971539351003152516'])
            .label('AddLabels'),
        delete: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Remove labels. Each label is a mailbox ID or a path if the ID is not set.')
            .example(['Label_971539351003152516'])
            .label('DeleteLabels'),
        set: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Replace all existing labels.')
            .example(['Inbox', 'Important'])
            .label('SetLabels')
            .meta({ swaggerHidden: true })
    })
        .description('Updates for message labels. Labels can only be used with Gmail IMAP or Gmail API.')
        .label('LabelUpdate')
})
    .label('MessageUpdate')
    .example({
        flags: {
            add: '\\Seen',
            delete: '\\Flagged'
        }
    });

const accountSchemas = {
    syncFrom: Joi.date()
        .iso()
        .allow(null)
        .example('2021-07-08T07:06:34.336Z')
        .description('Deprecated. Sync messages to document store starting from provided date. If not set, all emails are synced.')
        .meta({ swaggerHidden: true }),

    notifyFrom: Joi.date()
        .iso()
        .allow(null)
        .example('2021-07-08T07:06:34.336Z')
        .description('Send webhooks for messages starting from provided date. The default is the account creation date. Only applies for IMAP accounts.'),

    subconnections: Joi.array()
        .items(Joi.string().max(256))
        .single()
        .example(['[Gmail]/Spam', '\\Sent'])
        .description(
            'An array of mailbox paths. If set, then EmailEngine opens additional IMAP connections against these paths to detect changes faster. Note: Connection counts are usually highly limited.'
        )
        .label('SubconnectionPaths'),

    imapIndexer: Joi.string()
        .empty('')
        .trim()
        .allow(null)
        .valid('full', 'fast')
        .example('full')
        .description(
            'Sets the account-specific IMAP indexing method. Choose "full" to build a complete index that tracks deleted and updated emails, or "fast" to only detect newly received emails. Defaults to global setting.'
        )
        .label('IMAPIndexer')
};

const googleProjectIdSchema = Joi.string().trim().allow('', false, null).max(256).example('project-name-425411').description('Google Cloud Project ID');

const googleWorkspaceAccountsSchema = Joi.boolean()
    .truthy('Y', 'true', '1', 'on')
    .falsy('N', 'false', 0, '')
    .example(false)
    .description('Show only Google Workspace accounts on the OAuth2 login page');

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

    baseScopes: Joi.string().empty('').trim().valid('imap', 'api', 'pubsub').example('imap').description('OAuth2 Base Scopes'),

    pubSubApp: Joi.string()
        .empty('')
        .base64({ paddingRequired: false, urlSafe: true })
        .max(512)
        .example('AAAAAQAACnA')
        .allow(false, null)
        .description('Cloud Pub/Sub app for Gmail API webhooks'),

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

    googleProjectId: googleProjectIdSchema,
    googleWorkspaceAccounts: googleWorkspaceAccountsSchema,

    serviceClientEmail: Joi.string()
        .trim()
        .allow('')
        .email()
        .when('provider', {
            is: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('name@project-123.iam.gserviceaccount.com')
        .description('Service Client Email for 2-legged OAuth2 applications'),

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
        .label('Authority'),

    cloud: Joi.string()
        .trim()
        .empty('')
        .when('provider', {
            is: 'outlook',
            then: Joi.valid('global', 'gcc-high', 'dod', 'china').default('global'),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('global')
        .description('Azure cloud type for Outlook OAuth2 applications')
        .label('AzureCloud'),

    tenant: Joi.any().alter({
        web: () =>
            Joi.string()
                .trim()
                .empty('')
                .max(1024)
                .example('f8cdef31-a31e-4b4a-93e4-5f571e91255a')
                .description('Directory tenant ID for Azure Active Directory')
                .label('DirectoryTenantId'),
        api: schema => schema.forbidden().meta({ swaggerHidden: true })
    }),

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

const accountCountersSchema = Joi.object({
    events: Joi.object().unknown().description('Lifetime event counters').label('AccountCountersEvents').example({ messageNew: 30, messageDeleted: 5 })
}).label('AccountCounters');

const pathSchemaDescription =
    'Check changes only on selected paths. Either a single string path or an array of paths. Can use references like "\\Sent" or "\\Inbox". Set to `null` to unset.';
const pathSchema = Joi.string().empty('').max(1024).example('INBOX').description(pathSchemaDescription);
const accountPathSchema = Joi.array()
    .items(pathSchema)
    .single()
    .allow(null)
    .description(pathSchemaDescription)
    .description(
        'Specifies which mailbox folders to monitor for changes. The wildcard "*" includes all folders (also the default). Although you can still make API requests to folders not listed here, you will not receive webhooks for changes in those unlisted folders.'
    );

const defaultAccountTypeSchema = Joi.string()
    .empty('')
    .allow(false)
    .default(false)
    .example('imap')
    .description('Display the form for the specified account type (either "imap" or an OAuth2 app ID) instead of allowing the user to choose')
    .label('DefaultAccountType');

const outboxEntrySchema = Joi.object({
    queueId: Joi.string().example('1869c5692565f756b33').description('Outbox queue ID'),
    account: accountIdSchema.required(),
    source: Joi.string().example('smtp').valid('smtp', 'api').description('How this message was added to the queue'),

    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
    envelope: Joi.object({
        from: Joi.string().email().allow('').example('sender@example.com'),
        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com'))
    }).description('SMTP envelope'),

    subject: Joi.string()
        .allow('')
        .max(10 * 1024)
        .example('What a wonderful message')
        .description('Message subject'),

    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this message was queued'),
    scheduled: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('When this message is supposed to be delivered'),
    nextAttempt: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Next delivery attempt'),

    attemptsMade: Joi.number().integer().example(3).description('How many times EmailEngine has tried to deliver this email'),
    attempts: Joi.number().integer().example(3).description('How many delivery attempts to make until message is considered as failed'),

    progress: Joi.object({
        status: Joi.string().valid('queued', 'processing', 'submitted', 'error').example('queued').description('Current state of the sending'),
        response: Joi.string().example('250 Message Accepted').description('Response from the SMTP server. Only if status is "processing"'),
        error: Joi.object({
            message: Joi.string().example('Authentication failed').description('Error message'),
            code: Joi.string().example('EAUTH').description('Error code'),
            statusCode: Joi.string().example(502).description('SMTP response code')
        })
            .label('OutboxListProgressError')
            .description('Error information if status is "error"')
    }).label('OutboxEntryProgress')
}).label('OutboxEntry');

const messageReferenceSchema = Joi.object({
    message: Joi.string()
        .base64({ paddingRequired: false, urlSafe: true })
        .max(256)
        .required()
        .example('AAAAAQAACnA')
        .description('EmailEngine internal ID of the referenced message (not the Message-ID in email headers).'),

    action: Joi.string()
        .lowercase()
        .valid('forward', 'reply', 'reply-all')
        .example('reply')
        .default('reply')
        .description(
            "Specifies the action. Valid values: 'forward', 'reply', 'reply-all'. For 'reply' and 'forward', if a 'to' field is provided in the request, it overrides the original recipient. For 'reply-all', EmailEngine merges to/cc/bcc from the original email and the request."
        ),

    inline: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('If set to true, includes the original message content as blockquoted text.')
        .label('InlineReply'),

    forwardAttachments: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('If set to true, includes the original attachments in the forwarded message.')
        .when('action', {
            is: 'forward',
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .label('ForwardAttachments'),

    ignoreMissing: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('If set to true, continues even if the referenced message is missing.')
        .label('IgnoreMissing'),

    messageId: Joi.string()
        .max(996)
        .example('<test123@example.com>')
        .description(
            "Optional check for the referenced email's Message-ID. If set, only proceeds when the referenced email's Message-ID matches this value, otherwise returns an error."
        ),

    documentStore: documentStoreSchema.default(false).meta({ swaggerHidden: true })
})
    .description('Contains options for replying to or forwarding an email.')
    .label('MessageReference');

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
    accountCountersSchema,
    accountPathSchema,
    messageSpecialUseSchema,
    defaultAccountTypeSchema,
    fromAddressSchema,
    outboxEntrySchema,
    googleProjectIdSchema,
    googleWorkspaceAccountsSchema,
    messageReferenceSchema
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
