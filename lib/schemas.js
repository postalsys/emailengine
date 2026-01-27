'use strict';

const Joi = require('joi');
const config = require('@zone-eu/wild-config');
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

const accountIdSchema = Joi.string().empty('').trim().max(256).example('user123').description('Unique identifier for the email account');

// Allowed configuration keys
const settingsSchema = {
    /* ──────────────  Webhooks  ────────────── */

    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Enable or disable webhook delivery for all accounts'),

    webhooks: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://api.example.com/email/webhooks')
        .description('Target URL that will receive webhook notifications via POST requests'),

    webhookEvents: Joi.array().items(Joi.string().max(256).example('messageNew')).description('List of event types that will trigger webhook notifications'),

    webhooksCustomHeaders: Joi.array()
        .items(
            Joi.object({
                key: Joi.string().trim().empty('').max(1024).required().example('Authorization'),
                value: Joi.string()
                    .trim()
                    .empty('')
                    .max(10 * 1024)
                    .default('')
                    .example('Bearer <token>')
            }).label('WebhooksCustomHeader')
        )
        .description('Additional HTTP headers to include with every webhook request for authentication or tracking')
        .label('WebhooksCustomHeaders'),

    notifyHeaders: Joi.array()
        .items(Joi.string().max(256).example('List-ID'))
        .description('Email headers to include in webhook payloads for additional context'),

    /* ──────────────  URLs  ────────────── */

    serviceUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://emailengine.example.com')
        .description('Base URL of this EmailEngine instance (used for generating public URLs, path component is ignored)')
        .label('ServiceURL'),

    notificationBaseUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('', null)
        .example('https://emailengine.example.com/notifications')
        .description('Public callback URL for external OAuth providers. Falls back to serviceUrl if not set')
        .label('NotificationBaseUrl'),

    /* ──────────────  Tracking  ────────────── */

    trackSentMessages: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable tracking features for outgoing messages (deprecated - use trackClicks and trackOpens instead)')
        .meta({ swaggerHidden: true }),

    trackClicks: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Rewrite links in outgoing HTML emails to track click-through rates'),

    trackOpens: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Insert a tracking pixel in outgoing HTML emails to detect when messages are opened'),

    /* ──────────────  IMAP  ────────────── */

    imapIndexer: Joi.string()
        .empty('')
        .trim()
        .valid('full', 'fast')
        .example('full')
        .description(
            'IMAP indexing strategy:\n  * full - Detect new, changed, and deleted messages (slower but complete)\n  * fast - Detect only new messages'
        ),

    resolveGmailCategories: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Automatically detect and categorize Gmail tabs (Primary, Social, Promotions, etc.) for IMAP connections'),

    ignoreMailCertErrors: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Allow connections to mail servers with self-signed or invalid TLS certificates (not recommended for production)'),

    /* ──────────────  OpenAI  ────────────── */

    generateEmailSummary: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Generate AI-powered summaries for incoming emails using OpenAI'),

    generateRiskAssessment: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated - This feature has been removed')
        .meta({ swaggerHidden: true }),

    openAiAPIKey: Joi.string().allow('').example('sk-…').description('Your OpenAI API key for AI features').label('OpenAiAPIKey'),
    openAiModel: Joi.string().allow('').example('gpt-3.5-turbo').description('OpenAI model to use for text generation').label('OpenAiModel'),

    openAiAPIUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://api.openai.com')
        .description('Base URL for OpenAI API (change for OpenAI-compatible services)')
        .label('OpenAiAPIUrl'),

    documentStoreChatModel: Joi.string()
        .allow('')
        .example('gpt-3.5-turbo')
        .description('OpenAI model for Document Store chat (deprecated feature)')
        .label('DocumentStoreChatModel')
        .meta({ swaggerHidden: true }),

    openAiTemperature: Joi.number()
        .allow('')
        .min(0)
        .max(2)
        .example(0.8)
        .description('Controls randomness in AI responses (0 = deterministic, 2 = very creative)')
        .label('OpenAiTemperature'),

    openAiTopP: Joi.number()
        .allow('')
        .min(0)
        .max(1)
        .example(0.1)
        .description('Nucleus sampling parameter for AI text generation (0-1, lower = more focused)')
        .label('OpenAiTopP'),

    openAiMaxTokens: Joi.number()
        .allow('')
        .min(0)
        .example(3000)
        .description('Maximum tokens limit for OpenAI API requests (defaults: GPT-5: 18000, GPT-4: 6500, GPT-3.5: 3000)')
        .label('OpenAiMaxTokens'),

    openAiPrompt: Joi.string()
        .allow('')
        .max(1024 * 1024)
        .example('You are an assistant scanning incoming emails…')
        .description('Custom system prompt to guide AI behavior when processing emails')
        .label('OpenAiPrompt'),

    openAiGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Generate vector embeddings for semantic search and similarity matching'),

    /* ──────────────  Webhook Filters  ────────────── */

    inboxNewOnly: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Trigger "messageNew" webhooks only for messages arriving in the Inbox folder'),

    /* ──────────────  Security  ────────────── */

    serviceSecret: Joi.string()
        .allow('')
        .example('verysecret')
        .description('HMAC secret for signing API requests and validating webhooks')
        .label('ServiceSecret'),

    authServer: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://api.example.com/email/auth')
        .description('External authentication service URL for retrieving mailbox credentials dynamically')
        .label('AuthServer'),

    /* ──────────────  Proxy  ────────────── */

    proxyEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Route outbound connections through a proxy server'),
    proxyUrl: Joi.string()
        .uri({ scheme: ['http', 'https', 'socks', 'socks4', 'socks5'], allowRelative: false })
        .allow('')
        .example('socks5://proxy.example.com:1080')
        .description('Proxy server URL for outbound connections')
        .label('ProxyURL'),

    /* ──────────────  SMTP  ────────────── */

    smtpEhloName: Joi.string()
        .hostname()
        .allow('', null)
        .example('relay.example.com')
        .description('Hostname to use in SMTP EHLO/HELO commands (defaults to system hostname)'),

    /* ──────────────  Webhook Payload  ────────────── */

    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include plain text message content in webhook payloads'),
    notifyWebSafeHtml: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Sanitize HTML content to remove potentially dangerous elements before including in webhooks'),
    notifyTextSize: Joi.number().integer().min(0).description('Maximum size (in bytes) of text content to include in webhook payloads'),
    notifyAttachments: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include attachment data in webhook payloads'),
    notifyAttachmentSize: Joi.number().integer().min(0).description('Maximum size (in bytes) per attachment to include in webhook payloads'),
    notifyCalendarEvents: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Include parsed calendar event data in webhook payloads'),

    /* ──────────────  OAuth - Gmail (Deprecated)  ────────────── */

    gmailEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Deprecated - Controls visibility of Gmail account type')
        .meta({ swaggerHidden: true }),

    gmailClientId: Joi.string().allow('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    gmailClientSecret: Joi.string().empty('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    gmailRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),
    gmailExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),

    /* ──────────────  OAuth - Outlook (Deprecated)  ────────────── */

    outlookEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Deprecated - Controls visibility of Outlook account type')
        .meta({ swaggerHidden: true }),
    outlookClientId: Joi.string().allow('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    outlookClientSecret: Joi.string().empty('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    outlookRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),
    outlookAuthority: Joi.string()
        .empty('')
        .allow('consumers', 'organizations', 'common')
        .example('consumers')
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),
    outlookExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),

    /* ──────────────  OAuth - Mail.ru (Deprecated)  ────────────── */

    mailRuEnabled: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Deprecated - Controls visibility of Mail.ru account type')
        .meta({ swaggerHidden: true }),
    mailRuClientId: Joi.string().allow('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    mailRuClientSecret: Joi.string().empty('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    mailRuRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),
    mailRuExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('offline_access'))
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),

    /* ──────────────  Generic OAuth2 Service (Deprecated)  ────────────── */

    serviceClient: Joi.string().trim().allow('').max(256).description('Deprecated - Use OAuth2 Applications instead').meta({ swaggerHidden: true }),
    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),
    serviceExtraScopes: Joi.array()
        .items(Joi.string().empty('').trim().max(256).example('https://mail.google.com/'))
        .description('Deprecated - Use OAuth2 Applications instead')
        .meta({ swaggerHidden: true }),

    /* ──────────────  Document Store (Deprecated)  ────────────── */

    documentStoreEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated - Document Store feature has been removed')
        .meta({ swaggerHidden: true }),

    documentStoreUrl: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://localhost:9200')
        .description('Deprecated - Document Store feature has been removed')
        .meta({ swaggerHidden: true }),

    documentStoreIndex: Joi.string().empty('').max(1024).description('Deprecated - Document Store feature has been removed').meta({ swaggerHidden: true }),

    documentStoreAuthEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated - Document Store feature has been removed')
        .meta({ swaggerHidden: true }),

    documentStoreUsername: Joi.string().empty('').max(1024).description('Deprecated - Document Store feature has been removed').meta({ swaggerHidden: true }),

    documentStorePassword: Joi.string().empty('').max(1024).description('Deprecated - Document Store feature has been removed').meta({ swaggerHidden: true }),

    documentStoreGenerateEmbeddings: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated - Document Store feature has been removed')
        .meta({ swaggerHidden: true }),

    documentStorePreProcessingEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Deprecated - Document Store feature has been removed')
        .meta({ swaggerHidden: true }),

    /* ──────────────  Logging  ────────────── */

    logs: Joi.object({
        all: Joi.boolean()
            .truthy('Y', 'true', '1')
            .falsy('N', 'false', 0)
            .default(false)
            .example(false)
            .description('Enable detailed logging for all email accounts'),
        maxLogLines: Joi.number().integer().min(0).max(1000000).default(10000).description('Maximum number of log entries to retain per account')
    }).label('LogSettings'),

    /* ──────────────  Local Address Strategy  ────────────── */

    imapStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('IP address selection strategy for outbound IMAP connections when multiple local addresses are available'),

    smtpStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('IP address selection strategy for outbound SMTP connections when multiple local addresses are available'),

    localAddresses: Joi.array()
        .items(Joi.string().ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' }))
        .single()
        .description('List of local IP addresses to use for outbound connections (requires appropriate network configuration)'),

    /* ──────────────  Built-in SMTP Server  ────────────── */

    smtpServerEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable the built-in SMTP server for receiving emails'),
    smtpServerPort: Joi.number().integer().min(0).max(65535).empty('').description('Port number for the built-in SMTP server'),
    smtpServerHost: Joi.string()
        .ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' })
        .empty('')
        .description('IP address to bind the SMTP server to (empty = all interfaces)'),
    smtpServerProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable PROXY protocol support for the SMTP server'),
    smtpServerAuthEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Require SMTP authentication for incoming connections'),
    smtpServerPassword: Joi.string().empty('').allow(null).max(1024).description('Password for SMTP authentication (null = disable authentication)'),
    smtpServerTLSEnabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable TLS/STARTTLS support for the SMTP server'),

    /* ──────────────  IMAP Proxy  ────────────── */

    imapProxyServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable the IMAP proxy server'),
    imapProxyServerPort: Joi.number().integer().min(0).max(65535).empty('').description('Port number for the IMAP proxy server'),
    imapProxyServerHost: Joi.string()
        .ip({ version: ['ipv4', 'ipv6'], cidr: 'forbidden' })
        .empty('')
        .description('IP address to bind the IMAP proxy to (empty = all interfaces)'),
    imapProxyServerProxy: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Enable PROXY protocol support for the IMAP proxy'),
    imapProxyServerPassword: Joi.string().empty('').allow(null).max(1024).description('Password for IMAP proxy authentication (null = disable authentication)'),
    imapProxyServerTLSEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable TLS support for the IMAP proxy'),

    /* ──────────────  Queue & Delivery  ────────────── */

    queueKeep: Joi.number().integer().empty('').min(0).description('Number of completed and failed queue entries to retain for debugging'),
    deliveryAttempts: Joi.number().integer().empty('').min(0).description('Maximum number of delivery attempts before marking a message as permanently failed'),

    /* ──────────────  Templates  ────────────── */

    templateHeader: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('Custom HTML to inject at the top of hosted pages (e.g., for branding)'),
    templateHtmlHead: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('Custom HTML to inject into the <head> section of hosted pages (e.g., for analytics)'),

    /* ──────────────  Pre-processing  ────────────── */

    scriptEnv: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .custom(value => {
            if (!value?.trim()) return value;
            let parsed;
            try {
                parsed = JSON.parse(value);
            } catch {
                throw new Error('Value must be valid JSON');
            }
            if (typeof parsed !== 'object' || parsed === null) throw new Error('Value must be a JSON object');
            return value;
        }, 'JSON validation')
        .example('{"key":"value"}')
        .description('JSON object containing environment variables available to pre-processing scripts'),

    /* ──────────────  Reverse Proxy  ────────────── */

    enableApiProxy: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('Trust X-Forwarded-* headers when behind a reverse proxy'),

    /* ──────────────  Locale & Branding  ────────────── */

    locale: Joi.string()
        .max(100)
        .example('fr')
        .valid(...locales.map(l => l.locale))
        .description('Default language/locale for the user interface'),
    timezone: Joi.string().max(100).example('Europe/Tallinn').description('Default timezone for date/time display (IANA timezone identifier)'),
    pageBrandName: Joi.string().allow('', null).max(1024).example('EmailEngine').description('Brand name displayed in page titles'),

    /* ──────────────  LLM Pre-processing  ────────────── */

    openAiPreProcessingFn: Joi.string()
        .allow('')
        .max(512 * 1024)
        .example('return true; // pass every email')
        .description('JavaScript function to filter emails before AI processing (return true to process, false to skip)'),

    /* ──────────────  IMAP ID Extension  ────────────── */

    imapClientName: Joi.string().allow('').max(1024).example('EmailEngine').description('Client name advertised via IMAP ID extension'),
    imapClientVersion: Joi.string().allow('').max(1024).example('1.3.45').description('Client version advertised via IMAP ID extension'),
    imapClientVendor: Joi.string().allow('').max(1024).example('Postal Systems').description('Vendor name advertised via IMAP ID extension'),
    imapClientSupportUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https', 'mailto'], allowRelative: false })
        .example('https://github.com/postalsys/emailengine/issues')
        .description('Support URL advertised via IMAP ID extension'),

    /* ──────────────  Export  ────────────── */

    exportMaxConcurrent: Joi.number().integer().min(1).max(100).example(2).description('Maximum concurrent exports per account'),

    exportMaxGlobalConcurrent: Joi.number().integer().min(1).max(100).example(8).description('Maximum concurrent exports system-wide across all accounts'),

    gmailExportBatchSize: Joi.number()
        .integer()
        .min(1)
        .max(50)
        .example(10)
        .description('Number of parallel message fetch requests for Gmail export operations (default: 10, max: 50)'),

    outlookExportBatchSize: Joi.number()
        .integer()
        .min(1)
        .max(20)
        .example(20)
        .description('Number of messages per batch request for Outlook export operations (default: 20, max: 20 - MS Graph API limit)')
};

const addressSchema = Joi.object({
    name: Joi.string().trim().empty('').max(256).example('Some Name').description('Display name for the email address'),
    address: Joi.string().email({ ignoreLength: false }).example('user@example.com').required().description('Email address')
})
    .description('Email address with optional display name')
    .label('EmailAddress');

// generate a list of boolean values
const settingsQuerySchema = Object.fromEntries(
    Object.keys(Object.assign({ eventTypes: true }, settingsSchema)).map(key => [
        key,
        Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false)
    ])
);

const imapSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Username or email address for IMAP authentication'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Password for IMAP authentication')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token (when using OAuth2 instead of password authentication)')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the IMAP server')
        .label('ImapAuthentication'),

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server to retrieve credentials dynamically'),

    host: Joi.string()
        .hostname()
        .when('disabled', {
            is: true,
            then: Joi.optional().allow(false, null),
            otherwise: Joi.required()
        })
        .example('imap.gmail.com')
        .description('IMAP server hostname'),
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
        .description('IMAP server port (typically 993 for IMAP over TLS, 143 for STARTTLS)'),
    secure: Joi.boolean().default(false).example(true).description('Use TLS encryption for the connection (true for port 993, false for STARTTLS on port 143)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('Reject connections to servers with invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimum TLS version to accept (e.g., "TLSv1.2", "TLSv1.3")')
    })
        .unknown()
        .description('Advanced TLS configuration options')
        .label('ImapTlsOptions'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Delay in seconds between full mailbox resynchronizations').default(RESYNC_DELAY),
    disabled: Joi.boolean().example(false).description('Temporarily disable IMAP operations for this account'),

    sentMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Sent Mail')
        .description('Custom folder path for sent messages. Defaults to auto-detected "Sent" folder. Set to null to use default.'),
    draftsMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Drafts')
        .description('Custom folder path for draft messages. Defaults to auto-detected "Drafts" folder. Set to null to use default.'),
    junkMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Junk')
        .description('Custom folder path for spam/junk messages. Defaults to auto-detected "Junk" folder. Set to null to use default.'),
    trashMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Trash')
        .description('Custom folder path for deleted messages. Defaults to auto-detected "Trash" folder. Set to null to use default.'),
    archiveMailPath: Joi.string()
        .allow(null)
        .max(1024)
        .example('Archive')
        .description('Custom folder path for archived messages. Defaults to auto-detected "Archive" folder. Set to null to use default.')
};

const smtpSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Username or email address for SMTP authentication'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Password for SMTP authentication')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token (when using OAuth2 instead of password authentication)')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the SMTP server')
        .label('SmtpAuthentication'),

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server to retrieve credentials dynamically'),

    host: Joi.string().hostname().required().example('smtp.gmail.com').description('SMTP server hostname'),
    port: Joi.number()
        .integer()
        .min(1)
        .max(65535)
        .required()
        .example(587)
        .description('SMTP server port (typically 587 for STARTTLS, 465 for SMTP over TLS, 25 for unencrypted)'),
    secure: Joi.boolean()
        .default(false)
        .example(false)
        .description('Use TLS encryption from the start (true for port 465, false for STARTTLS on ports 587/25)'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('Reject connections to servers with invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimum TLS version to accept (e.g., "TLSv1.2", "TLSv1.3")')
    })
        .unknown()
        .description('Advanced TLS configuration options')
        .label('SmtpTlsOptions')
};

const oauth2AuthSchema = Joi.object({
    user: Joi.string().max(256).example('user@outlook.com').description('Primary email account username'),
    delegatedUser: Joi.string().max(256).optional().example('shared.mailbox@outlook.com').description('Shared mailbox username (Microsoft 365 delegation)'),
    delegatedAccount: accountIdSchema
        .when('delegatedUser', {
            is: Joi.exist().not(false, null),
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description(
            "Account ID to use for authenticating the shared mailbox. When provided, EmailEngine uses this account's credentials instead of creating new ones."
        )
})
    .required()
    .when('authorize', {
        is: true,
        then: Joi.optional()
    })
    .label('OAuth2Authentication');

const oauth2Schema = {
    authorize: Joi.boolean().example(false).description('Request an OAuth2 authorization URL instead of directly configuring credentials'),
    redirectUrl: Joi.string()
        .empty('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .example('https://myapp/account/settings.php')
        .description('URL to redirect to after OAuth2 authorization completes (only used when authorize=true)')
        .when('authorize', {
            is: true,
            then: Joi.optional(),
            otherwise: Joi.optional().valid(false, null)
        }),

    provider: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 Application ID configured in EmailEngine'),

    auth: oauth2AuthSchema,

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server for token management instead of EmailEngine'),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...')
        .description('OAuth2 access token for the email account'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...')
        .description('OAuth2 refresh token for obtaining new access tokens'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description('Deprecated - Authority is set by the OAuth2 application configuration')
        .label('SupportedAccountTypes')
        .meta({ swaggerHidden: true }),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Access token expiration timestamp')
};

const partialSchema = Joi.boolean().example(false).description('Update only the provided fields instead of replacing the entire configuration').default(false);

const imapUpdateSchema = {
    partial: partialSchema,

    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Username or email address for IMAP authentication'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Password for IMAP authentication')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token (when using OAuth2 instead of password authentication)')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the IMAP server')
        .label('ImapUpdateAuthentication'),

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server to retrieve credentials dynamically'),

    host: Joi.string().hostname().example('imap.gmail.com').description('IMAP server hostname'),
    port: Joi.number().integer().min(1).max(65535).example(993).description('IMAP server port'),
    secure: Joi.boolean().example(true).description('Use TLS encryption for the connection'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('Reject connections to servers with invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimum TLS version to accept')
    })
        .unknown()
        .description('Advanced TLS configuration options')
        .label('ImapUpdateTlsOptions'),
    resyncDelay: Joi.number().integer().example(RESYNC_DELAY).description('Delay in seconds between full mailbox resynchronizations'),

    disabled: Joi.boolean().example(false).description('Temporarily disable IMAP operations for this account'),

    sentMailPath: Joi.string().allow(null).max(1024).example('Sent Mail').description('Custom folder path for sent messages. Set to null to use default.'),
    draftsMailPath: Joi.string().allow(null).max(1024).example('Drafts').description('Custom folder path for draft messages. Set to null to use default.'),
    junkMailPath: Joi.string().allow(null).max(1024).example('Junk').description('Custom folder path for spam/junk messages. Set to null to use default.'),
    trashMailPath: Joi.string().allow(null).max(1024).example('Trash').description('Custom folder path for deleted messages. Set to null to use default.'),
    archiveMailPath: Joi.string().allow(null).max(1024).example('Archive').description('Custom folder path for archived messages. Set to null to use default.')
};

const smtpUpdateSchema = {
    partial: partialSchema,
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Username or email address for SMTP authentication'),
        pass: Joi.string()
            .max(256)
            .example('verysecret')
            .description('Password for SMTP authentication')
            .when('accessToken', {
                is: Joi.exist().not(false, null),
                then: Joi.optional().valid(false, null),
                otherwise: Joi.required()
            }),
        accessToken: Joi.string()
            .allow(false)
            .max(4 * 4096)
            .example(false)
            .description('OAuth2 access token (when using OAuth2 instead of password authentication)')
    })
        .allow(false)
        .when('useAuthServer', {
            is: true,
            then: Joi.optional().valid(false, null),
            otherwise: Joi.optional()
        })
        .description('Authentication credentials for the SMTP server')
        .label('SmtpUpdateAuthentication'),

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server to retrieve credentials dynamically'),

    host: Joi.string().hostname().example('smtp.gmail.com').description('SMTP server hostname'),
    port: Joi.number().integer().min(1).max(65535).example(587).description('SMTP server port'),
    secure: Joi.boolean().example(false).description('Use TLS encryption from the start'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('Reject connections to servers with invalid TLS certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimum TLS version to accept')
    })
        .unknown()
        .description('Advanced TLS configuration options')
        .label('SmtpUpdateTlsOptions')
};

const oauth2UpdateSchema = {
    partial: partialSchema,

    authorize: Joi.boolean().example(false).description('Request an OAuth2 authorization URL instead of directly configuring credentials'),
    provider: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 Application ID configured in EmailEngine'),

    auth: oauth2AuthSchema,

    useAuthServer: Joi.boolean().example(false).description('Use external authentication server for token management instead of EmailEngine'),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...')
        .description('OAuth2 access token for the email account'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...')
        .description('OAuth2 refresh token for obtaining new access tokens'),
    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .example('consumers')
        .description('Deprecated - Authority is set by the OAuth2 application configuration')
        .label('SupportedAccountTypes')
        .meta({ swaggerHidden: true }),

    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Access token expiration timestamp')
};

const attachmentSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrIyLjI').description('Unique identifier for the attachment').label('AttachmentId'),
    contentType: Joi.string().example('image/gif').description('MIME type of the attachment'),
    encodedSize: Joi.number()
        .integer()
        .example(48)
        .description('Size of the attachment as stored in the email (base64 encoded). The actual decoded file size is approximately 75% of this value.'),
    embedded: Joi.boolean().example(true).description('Whether the attachment is embedded in the HTML content'),
    inline: Joi.boolean().example(true).description('Whether the attachment should be displayed inline rather than as a download'),
    contentId: Joi.string().example('<unique-image-id@localhost>').description('Content-ID header value used for embedding images in HTML'),
    filename: Joi.string().example('image.png').description('Original filename of the attachment'),
    method: Joi.string().example('REQUEST').description('Calendar method (REQUEST, REPLY, CANCEL, etc.) for iCalendar attachments')
}).label('AttachmentEntry');

const AddressListSchema = Joi.array().items(addressSchema.label('RcptAddressEntry')).description('List of email addresses').label('AddressList');

const fromAddressSchema = addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).description('Sender email address').label('FromAddress');

const emailIdSchema = Joi.string()
    .max(256)
    .example('1278455344230334865')
    .description('Globally unique email identifier (when supported by the email server)')
    .label('MessageEmailId');

const threadIdSchema = Joi.string()
    .example('1694936993596975454')
    .description('Thread identifier for email conversations (when supported by the email server)')
    .label('MessageThreadId');

const messageEntrySchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('EmailEngine message identifier').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('IMAP UID (unique identifier within the mailbox)').label('MessageUid'),
    emailId: emailIdSchema,
    threadId: threadIdSchema,
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date when the message was received by the mail server'),
    draft: Joi.boolean().example(false).description('Whether this message is a draft'),
    unseen: Joi.boolean().example(true).description('Whether this message is unread'),
    flagged: Joi.boolean().example(true).description('Whether this message is flagged/starred'),
    size: Joi.number().integer().example(1040).description('Message size in bytes'),
    subject: Joi.string().allow('').example('What a wonderful message').description('Message subject line'),

    from: fromAddressSchema,
    replyTo: AddressListSchema,
    to: AddressListSchema,
    cc: AddressListSchema,
    bcc: AddressListSchema,
    messageId: Joi.string().example('<test123@example.com>').description('Message-ID header value'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Message-ID of the message this is replying to'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('IMAP flags set on this message').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels applied to this message').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Identifier for fetching the full message text'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('Size of the plain text part in bytes'),
            html: Joi.number().integer().example(1013).description('Size of the HTML part in bytes')
        }).description('Sizes of different message parts')
    }).label('TextInfo'),

    preview: Joi.string().description('Short preview of the message content')
}).label('MessageListEntry');

const messageSpecialUseSchema = Joi.string()
    .example('\\Sent')
    .valid('\\Drafts', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
    .description('Special folder type where this message is stored')
    .label('MessageSpecialUse');

const messageDetailsSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('EmailEngine message identifier').label('MessageEntryId'),
    uid: Joi.number().integer().example(12345).description('IMAP UID (unique identifier within the mailbox)').label('MessageUid'),
    emailId: emailIdSchema,
    threadId: threadIdSchema,
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date when the message was received by the mail server'),
    draft: Joi.boolean().example(false).description('Whether this message is a draft'),
    unseen: Joi.boolean().example(true).description('Whether this message is unread'),
    flagged: Joi.boolean().example(true).description('Whether this message is flagged/starred'),
    size: Joi.number().integer().example(1040).description('Message size in bytes'),
    subject: Joi.string().allow('').example('What a wonderful message').description('Message subject line'),

    from: fromAddressSchema,
    sender: fromAddressSchema,

    to: AddressListSchema,

    cc: AddressListSchema,

    bcc: AddressListSchema,
    replyTo: AddressListSchema,

    messageId: Joi.string().example('<test123@example.com>').description('Message-ID header value'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Message-ID of the message this is replying to'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('IMAP flags set on this message').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels applied to this message').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    headers: Joi.object()
        .example({ from: ['From Me <sender@example.com>'], subject: ['What a wonderful message'] })
        .label('MessageHeaders')
        .description(
            'Raw email headers as key-value pairs (arrays contain multiple values for headers that appear multiple times). Not available for MS Graph API.'
        )
        .unknown(),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Identifier for fetching additional text content'),
        encodedSize: Joi.object({
            plain: Joi.number().integer().example(1013).description('Size of the plain text part in bytes'),
            html: Joi.number().integer().example(1013).description('Size of the HTML part in bytes')
        }).description('Sizes of different message parts'),
        plain: Joi.string().example('Hello from myself!').description('Plain text version of the message'),
        html: Joi.string().example('<p>Hello from myself!</p>').description('HTML version of the message'),
        hasMore: Joi.boolean().example(false).description('Whether the message content was truncated (true if more content is available via separate API call)')
    }).label('TextInfoDetails'),

    bounces: Joi.array()
        .items(
            Joi.object({
                message: Joi.string().max(256).required().example('AAAAAQAACnA').description('EmailEngine identifier of the bounce notification'),
                recipient: Joi.string().email().example('recipient@example.com').description('Email address that bounced'),
                action: Joi.string().example('failed').description('Bounce action (failed, delayed, etc.)'),
                response: Joi.object({
                    message: Joi.string().example('550 5.1.1 No such user').description('Error message from the receiving server'),
                    status: Joi.string().example('5.1.1').description('SMTP status code')
                }).label('BounceResponse'),
                date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('When the bounce was detected')
            }).label('BounceEntry')
        )
        .label('BounceList'),

    isAutoReply: Joi.boolean().example(false).description('Whether this message appears to be an automatic reply (out of office, vacation responder, etc.)'),

    specialUse: Joi.string()
        .example('\\Sent')
        .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
        .description('Special folder type of the mailbox containing this message')
        .label('MailboxSpecialUse'),
    messageSpecialUse: messageSpecialUseSchema
}).label('MessageDetails');

const messageListSchema = Joi.object({
    total: Joi.number()
        .integer()
        .example(120)
        .description('Total number of messages matching the query (exact for IMAP, approximate for Gmail API)')
        .label('TotalNumber'),
    page: Joi.number().integer().example(0).description('Current page number (zero-based)').label('PageNumber'),
    pages: Joi.number().integer().example(24).description('Total number of pages available (exact for IMAP, approximate for Gmail API)').label('PagesNumber'),
    nextPageCursor: Joi.string()
        .allow(null)
        .example('imap_kcQIji3UobDDTxc')
        .description('Cursor for fetching the next page (null when no more pages)')
        .label('NextPageCursor'),
    prevPageCursor: Joi.string().allow(null).example('imap_kcQIji3UobDDTxc').description('Cursor for fetching the previous page').label('PrevPageCursor'),
    messages: Joi.array().items(messageEntrySchema).label('PageMessages')
}).label('MessageList');

const mailboxesSchema = Joi.array()
    .items(
        Joi.object({
            path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to the mailbox').label('MailboxPath'),
            delimiter: Joi.string().example('/').description('Hierarchy delimiter character used in paths'),
            parentPath: Joi.string().required().example('Kalender').description('Path to the parent mailbox').label('MailboxParentPath'),
            name: Joi.string().required().example('Sünnipäevad').description('Display name of the mailbox').label('MailboxName'),
            listed: Joi.boolean().example(true).description('Whether this mailbox appears in LIST command results').label('MailboxListed'),
            subscribed: Joi.boolean().example(true).description('Whether the user is subscribed to this mailbox').label('MailboxSubscribed'),
            specialUse: Joi.string()
                .example('\\Sent')
                .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
                .description('Special folder type (Inbox, Sent, Drafts, etc.)')
                .label('MailboxSpecialUse'),
            specialUseSource: Joi.string()
                .example('extension')
                .valid('user', 'extension', 'name')
                .description('How the special use was determined: "user" (set via API), "extension" (server-provided), or "name" (guessed from folder name)')
                .label('MailboxSpecialUseSource'),
            noInferiors: Joi.boolean().example(false).description('Whether this mailbox can contain child mailboxes').label('MailboxNoInferiors'),
            messages: Joi.number().integer().example(120).description('Total number of messages in the mailbox').label('MailboxMessages'),
            uidNext: Joi.number().integer().example(121).description('Next UID value that will be assigned').label('MailboxUidNext'),
            status: Joi.object({
                messages: Joi.number().integer().example(120).description('Message count from STATUS command').label('StatusMessages'),
                unseen: Joi.number().integer().example(120).description('Unread message count from STATUS command').label('StatusUnseenMessages')
            })
                .description('Additional mailbox statistics')
                .label('MailboxResponseStatus')
        }).label('MailboxResponseItem')
    )
    .label('MailboxesList');

const shortMailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to the mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/').description('Hierarchy delimiter character used in paths'),
        parentPath: Joi.string().required().example('Kalender').description('Path to the parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Display name of the mailbox').label('MailboxName'),
        listed: Joi.boolean().example(true).description('Whether this mailbox appears in LIST command results').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('Whether the user is subscribed to this mailbox').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special folder type (Inbox, Sent, Drafts, etc.)')
            .label('MailboxSpecialUse')
    }).label('MailboxShortResponseItem')
);

const licenseSchema = Joi.object({
    active: Joi.boolean().example(true).description('Whether a valid license is currently active'),
    type: Joi.string().example('EmailEngine License').description('License type/product name'),
    details: Joi.object({
        application: Joi.string().example('@postalsys/emailengine-app').description('Licensed application identifier'),
        key: Joi.string().hex().example('1edf01e35e75ed3425808eba').description('License key'),
        licensedTo: Joi.string().example('Kreata OÜ').description('Organization or individual the license is issued to'),
        hostname: Joi.string().example('emailengine.example.com').description('Licensed hostname or environment'),
        created: Joi.date().example('2021-10-13T07:47:42.695Z').description('License creation date')
    })
        .allow(false)
        .label('LicenseDetails'),
    suspended: Joi.boolean().example(false).description('Whether email operations are suspended due to license issues')
}).label('LicenseInfo');

const lastErrorSchema = Joi.object({
    response: Joi.string().example('Token request failed').description('Human-readable error message'),
    serverResponseCode: Joi.string().example('OauthRenewError').description('Error code or classification'),
    tokenRequest: Joi.object({
        grant: Joi.string().valid('refresh_token', 'authorization_code').example('refresh_token').description('OAuth2 grant type being requested'),
        provider: Joi.string().max(256).example('gmail').description('OAuth2 provider name'),
        status: Joi.number().integer().example(400).description('HTTP status code from the OAuth2 server'),
        clientId: Joi.string()
            .example('1023289917884-h3nu00e9cb7h252e24c23sv19l8k57ah.apps.googleusercontent.com')
            .description('OAuth2 client ID used for authentication'),
        scopes: Joi.array()
            .items(Joi.string().example('https://mail.google.com/').label('ScopeEntry').description('OAuth2 permission scope'))
            .description('Requested OAuth2 permission scopes')
            .label('OauthScopes'),
        response: Joi.object()
            .example({
                error: 'invalid_grant',
                error_description: 'Bad Request'
            })
            .description('Raw error response from the OAuth2 server')
            .unknown()
            .label('OAuthTokenErrorResponse')
    })
        .description('Details about the failed OAuth2 token request')
        .label('OAuthTokenRequestError')
}).label('AccountErrorEntry');

const templateSchemas = {
    subject: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .example('What a wonderful message')
        .description('Email subject line'),
    text: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Plain text message content'),
    html: Joi.string().allow('').trim().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('HTML message content'),
    previewText: Joi.string()
        .allow('')
        .max(1024)
        .example('Welcome to our newsletter!')
        .description('Preview text shown in email clients after the subject line')
};

const documentStoreSchema = Joi.boolean()
    .empty('')
    .truthy('Y', 'true', '1')
    .falsy('N', 'false', 0)
    .description('Deprecated feature - Document Store has been removed')
    .label('UseDocumentStore')
    .meta({ swaggerHidden: true });

const searchSchema = Joi.object({
    seq: Joi.string()
        .max(8 * 1024)
        .description('Sequence number range (e.g., "1:10" or "1,3,5"). Only supported for IMAP.'),

    answered: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Filter for messages that have been replied to. Only supported for IMAP.')
        .label('AnsweredFlag'),
    deleted: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .description('Filter for messages marked for deletion. Only supported for IMAP.')
        .label('DeletedFlag'),
    draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Filter for draft messages').label('DraftFlag'),
    unseen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Filter for unread messages').label('UnseenFlag'),
    flagged: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Filter for flagged/starred messages').label('Flagged'),
    seen: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Filter for read messages').label('SeenFlag'),

    from: Joi.string().max(256).description('Search in From addresses').label('From'),
    to: Joi.string().max(256).description('Search in To addresses. Not supported for MS Graph API.').label('To'),
    cc: Joi.string().max(256).description('Search in Cc addresses. Not supported for MS Graph API.').label('Cc'),
    bcc: Joi.string().max(256).description('Search in Bcc addresses. Not supported for MS Graph API.').label('Bcc'),

    body: Joi.string().max(256).description('Search in message body content').label('MessageBody'),
    subject: Joi.string()
        .allow('')
        .max(10 * 256)
        .example('Hello world')
        .description('Search in message subject')
        .label('Subject'),

    larger: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Find messages larger than specified size in bytes. Not supported for MS Graph API.')
        .label('MessageLarger'),

    smaller: Joi.number()
        .integer()
        .min(0)
        .max(1024 * 1024 * 1024)
        .description('Find messages smaller than specified size in bytes. Not supported for MS Graph API.')
        .label('MessageSmaller'),

    uid: Joi.string()
        .max(8 * 1024)
        .description('UID range (e.g., "100:200" or "150,200,250"). Only supported for IMAP.')
        .label('UIDRange'),

    modseq: Joi.number()
        .integer()
        .min(0)
        .description('Find messages with modification sequence higher than specified value. Only supported for IMAP with CONDSTORE.')
        .label('ModseqLarger'),

    before: Joi.date().description('Find messages received before this date').label('EnvelopeBefore'),
    since: Joi.date().description('Find messages received after this date').label('EnvelopeSince'),

    sentBefore: Joi.date().description('Find messages sent before this date').label('HeaderBefore'),
    sentSince: Joi.date().description('Find messages sent after this date').label('HeaderSince'),

    emailId: emailIdSchema,
    threadId: threadIdSchema,

    header: Joi.object().description('Search specific email headers').label('Headers').unknown().example({ 'Message-ID': '<1DAF52A51E674A2@example.com>' }),

    gmailRaw: Joi.string().max(1024).example('has:attachment in:unread').description('Gmail search syntax (only works with Gmail accounts)'),

    emailIds: Joi.array()
        .items(emailIdSchema)
        .single()
        .description('List of specific email IDs to fetch. When provided, other search criteria are ignored. Useful for bulk operations on known messages.')
        .example(['1278455344230334865'])
        .label('EmailIds')
})
    .required()
    .description('Search criteria for filtering messages')
    .label('SearchQuery');

const messageUpdateSchema = Joi.object({
    flags: Joi.object({
        add: Joi.array().items(Joi.string().max(128)).single().description('Flags to add to the message').example(['\\Seen']).label('AddFlags'),
        delete: Joi.array().items(Joi.string().max(128)).single().description('Flags to remove from the message').example(['\\Flagged']).label('DeleteFlags'),
        set: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Replace all flags with this list')
            .example(['\\Seen', '\\Flagged'])
            .label('SetFlags')
    })
        .description('Flag operations to perform')
        .label('FlagUpdate'),

    labels: Joi.object({
        add: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Gmail labels to add (use label ID or path)')
            .example(['Label_971539351003152516'])
            .label('AddLabels'),
        delete: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Gmail labels to remove (use label ID or path)')
            .example(['Label_971539351003152516'])
            .label('DeleteLabels'),
        set: Joi.array()
            .items(Joi.string().max(128))
            .single()
            .description('Replace all labels with this list')
            .example(['Inbox', 'Important'])
            .label('SetLabels')
            .meta({ swaggerHidden: true })
    })
        .description('Label operations to perform (Gmail only)')
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
        .description('Deprecated - Document Store sync start date')
        .meta({ swaggerHidden: true }),

    notifyFrom: Joi.date()
        .iso()
        .allow(null)
        .example('2021-07-08T07:06:34.336Z')
        .description('Only send webhooks for messages received after this date. Defaults to account creation time. IMAP only.'),

    subconnections: Joi.array()
        .items(Joi.string().max(256))
        .single()
        .example(['[Gmail]/Spam', '\\Sent'])
        .description(
            'Additional mailbox paths to monitor with dedicated IMAP connections for faster change detection. Use sparingly as connection limits are strict.'
        )
        .label('SubconnectionPaths'),

    imapIndexer: Joi.string()
        .empty('')
        .trim()
        .allow(null)
        .valid('full', 'fast')
        .example('full')
        .description(
            'Override global IMAP indexing strategy for this account. "full" tracks all changes including deletions, "fast" only detects new messages.'
        )
        .label('AccountImapIndexer')
};

const googleProjectIdSchema = Joi.string().trim().allow('', false, null).max(256).example('project-name-425411').description('Google Cloud Project ID');
const googleTopicNameSchema = Joi.string()
    .trim()
    .allow('', false, null)
    .pattern(/^(?!goog)[A-Za-z][A-Za-z0-9\-_.~+%]{2,254}$/)
    .max(256)
    .example('ee-pub-12345')
    .description('Google Pub/Sub topic name for Gmail push notifications');

const googleSubscriptionNameSchema = Joi.string()
    .trim()
    .allow('', false, null)
    .pattern(/^(?!goog)[A-Za-z][A-Za-z0-9\-_.~+%]{2,254}$/)
    .max(256)
    .example('ee-sub-12345')
    .description('Google Pub/Sub subscription name');

const googleWorkspaceAccountsSchema = Joi.boolean()
    .truthy('Y', 'true', '1', 'on')
    .falsy('N', 'false', 0, '')
    .example(false)
    .description('Restrict OAuth2 login to Google Workspace accounts only');

const oauthCreateSchema = {
    name: Joi.string().trim().empty('').max(256).example('My Gmail App').required().description('Display name for the OAuth2 application'),
    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Detailed description of the application'),
    title: Joi.string().allow('').trim().max(256).example('App title').description('Short title shown on the OAuth2 button'),

    provider: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .valid(...Object.keys(OAUTH_PROVIDERS))
        .example('gmail')
        .required()
        .description('OAuth2 provider type'),

    enabled: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .default(false)
        .example(true)
        .description('Whether this OAuth2 app is active'),

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
        .description('OAuth2 client ID from the provider'),

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
        .description('OAuth2 client secret from the provider'),

    baseScopes: Joi.string().empty('').trim().valid('imap', 'api', 'pubsub').example('imap').description('Connection type (IMAP, API, or Pub/Sub)'),

    pubSubApp: Joi.string()
        .empty('')
        .base64({ paddingRequired: false, urlSafe: true })
        .max(512)
        .example('AAAAAQAACnA')
        .allow(false, null)
        .description('Pub/Sub application ID for Gmail push notifications'),

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
        .description('Additional OAuth2 permission scopes'),

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
        .description('OAuth2 scopes to exclude from the default set'),

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
        .description('Service account unique ID (for 2-legged OAuth2)'),

    googleProjectId: googleProjectIdSchema,
    googleWorkspaceAccounts: googleWorkspaceAccountsSchema,
    googleTopicName: googleTopicNameSchema,
    googleSubscriptionName: googleSubscriptionNameSchema,

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
        .description('Service account email address'),

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
        .description('Service account private key in PEM format'),

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
        .description('Microsoft tenant configuration (common, organizations, consumers, or tenant ID)')
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
        .description('Microsoft Azure cloud environment')
        .label('AzureCloud'),

    tenant: Joi.any().alter({
        web: () =>
            Joi.string()
                .trim()
                .empty('')
                .max(1024)
                .example('f8cdef31-a31e-4b4a-93e4-5f571e91255a')
                .description('Azure Active Directory tenant ID')
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
        .description('OAuth2 redirect URI configured in the provider')
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
        .description('HTTP referrer patterns that are allowed to use this token (wildcards supported)'),
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
        .description('IP addresses or CIDR ranges allowed to use this token'),
    rateLimit: Joi.object({
        maxRequests: Joi.number().integer().min(1).example(20).description('Maximum requests allowed in the time window'),
        timeWindow: Joi.number().integer().min(1).example(2).description('Time window duration in seconds')
    })
        .allow(false)
        .default(false)
        .example({ maxRequests: 20, timeWindow: 2 })
        .label('AddressRateLimit')
        .description('Rate limiting configuration for this token')
})
    .empty('')
    .allow(false)
    .label('TokenRestrictions')
    .description('Security restrictions for API token usage');

const ipSchema = Joi.string()
    .empty('')
    .trim()
    .ip({
        version: ['ipv4', 'ipv6'],
        cidr: 'forbidden'
    })
    .example('127.0.0.1');

const accountCountersSchema = Joi.object({
    events: Joi.object()
        .unknown()
        .description('Cumulative event counters for the account lifetime')
        .label('AccountCountersEvents')
        .example({ messageNew: 30, messageDeleted: 5 })
}).label('AccountCounters');

const pathSchemaDescription =
    'Mailbox paths to monitor for changes. Use folder names, special-use flags like "\\Sent", or "*" for all folders. Set to null to reset to default.';
const pathSchema = Joi.string().empty('').max(1024).example('INBOX').description(pathSchemaDescription);
const accountPathSchema = Joi.array()
    .items(pathSchema)
    .single()
    .allow(null)
    .description(
        'Mailbox folders to monitor for changes (IMAP only). Use "*" to monitor all folders (default). While you can still access unmonitored folders via API, you won\'t receive webhooks for changes in those folders.'
    );

const defaultAccountTypeSchema = Joi.string()
    .empty('')
    .allow(false)
    .default(false)
    .example('imap')
    .description('Pre-select a specific account type (use "imap" or an OAuth2 app ID) instead of showing the selection screen')
    .label('DefaultAccountType');

const outboxEntrySchema = Joi.object({
    queueId: Joi.string().example('1869c5692565f756b33').description('Unique queue entry identifier'),
    account: accountIdSchema.required(),
    source: Joi.string().example('smtp').valid('smtp', 'api').description('How this message entered the queue'),

    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message-ID header value'),
    envelope: Joi.object({
        from: Joi.string().email().allow('').example('sender@example.com'),
        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com'))
    })
        .description('SMTP envelope information')
        .label('OutboxEnvelope'),

    subject: Joi.string()
        .allow('')
        .max(10 * 1024)
        .example('What a wonderful message')
        .description('Email subject line'),

    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('When this message was added to the queue'),
    scheduled: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Scheduled delivery time'),
    nextAttempt: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Next delivery attempt time'),

    attemptsMade: Joi.number().integer().example(3).description('Number of delivery attempts made'),
    attempts: Joi.number().integer().example(3).description('Maximum delivery attempts before marking as failed'),

    progress: Joi.object({
        status: Joi.string().valid('queued', 'processing', 'submitted', 'error').example('queued').description('Current delivery status'),
        response: Joi.string().example('250 Message Accepted').description('SMTP server response (when status is "processing")'),
        error: Joi.object({
            message: Joi.string().example('Authentication failed').description('Error description'),
            code: Joi.string().example('EAUTH').description('Error code'),
            statusCode: Joi.string().example(502).description('SMTP response code')
        })
            .label('OutboxListProgressError')
            .description('Error details (when status is "error")')
    }).label('OutboxEntryProgress')
}).label('OutboxEntry');

const messageReferenceSchema = Joi.object({
    message: Joi.string()
        .base64({ paddingRequired: false, urlSafe: true })
        .max(256)
        .required()
        .example('AAAAAQAACnA')
        .description('EmailEngine message ID to reply to or forward'),

    action: Joi.string()
        .lowercase()
        .valid('forward', 'reply', 'reply-all')
        .example('reply')
        .default('reply')
        .description('Action type: "reply" (reply to sender), "reply-all" (reply to all recipients), or "forward" (forward to new recipients)'),

    inline: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('Include the original message as quoted text in the response')
        .label('InlineReply'),

    forwardAttachments: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('Include original attachments when forwarding')
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
        .description('Continue sending even if the referenced message cannot be found')
        .label('IgnoreMissing'),

    messageId: Joi.string()
        .max(996)
        .example('<test123@example.com>')
        .description('Verify the Message-ID of the referenced email matches this value before proceeding'),

    documentStore: documentStoreSchema.default(false).meta({ swaggerHidden: true })
})
    .description('Configuration for replying to or forwarding an existing message')
    .label('MessageReference');

const idempotencyKeySchema = Joi.string()
    .empty('')
    .trim()
    .min(0)
    .max(1024)
    .optional()
    .replace(/^\s*"\s*|\s*"\s*$|/g, '')
    .replace(/\\([\\"])/g, '$1')
    .description('Unique key to prevent duplicate processing of the same request')
    .label('Idempotency-Key');

const headerTimeoutSchema = Joi.number()
    .integer()
    .min(0)
    .max(2 * 3600 * 1000)
    .optional()
    .description('Request timeout in milliseconds (overrides EENGINE_TIMEOUT environment variable)')
    .label('X-EE-Timeout');

// Export schemas
const exportRequestSchema = Joi.object({
    folders: Joi.array()
        .items(Joi.string().max(1024).example('INBOX'))
        .single()
        .description(
            'Folder paths or special-use flags (e.g., \\Inbox, \\Sent, \\All) to export from. If empty/omitted, Gmail/Outlook API accounts export from All Mail folder; other accounts export all folders except Junk and Trash.'
        )
        .label('ExportFolders'),
    startDate: Joi.date().iso().required().example('2024-01-01T00:00:00Z').description('Export messages from this date'),
    endDate: Joi.date().iso().required().example('2024-12-31T23:59:59Z').description('Export messages until this date'),
    textType: Joi.string()
        .valid('plain', 'html', '*')
        .default('*')
        .example('*')
        .description('Text content to include: "plain", "html", "*" (both), or omit for metadata only'),
    maxBytes: Joi.number()
        .integer()
        .min(0)
        .default(5 * 1024 * 1024)
        .example(5242880)
        .description('Maximum bytes for text content (0 = unlimited)'),
    includeAttachments: Joi.boolean()
        .truthy('Y', 'true', '1')
        .falsy('N', 'false', 0)
        .default(false)
        .description('Include attachment content as base64 blob in attachments array')
}).label('ExportRequest');

const exportProgressSchema = Joi.object({
    foldersScanned: Joi.number().integer().example(1).description('Number of folders scanned'),
    foldersTotal: Joi.number().integer().example(2).description('Total number of folders to scan'),
    messagesQueued: Joi.number().integer().example(1500).description('Number of messages queued for export'),
    messagesExported: Joi.number().integer().example(500).description('Number of messages exported'),
    messagesSkipped: Joi.number().integer().example(5).description('Number of messages skipped (deleted or inaccessible)'),
    bytesWritten: Joi.number().integer().example(52428800).description('Bytes written to export file')
}).label('ExportProgress');

const exportStatusSchema = Joi.object({
    exportId: Joi.string().example('exp_abc123def456').description('Export job identifier'),
    status: Joi.string().valid('queued', 'processing', 'completed', 'failed', 'cancelled').example('processing').description('Export status'),
    phase: Joi.string().valid('indexing', 'exporting', 'complete').example('indexing').description('Current export phase'),
    folders: Joi.array().items(Joi.string()).description('Folders being exported'),
    startDate: Joi.date().iso().example('2024-01-01T00:00:00Z').description('Export start date filter'),
    endDate: Joi.date().iso().example('2024-12-31T23:59:59Z').description('Export end date filter'),
    progress: exportProgressSchema,
    created: Joi.date().iso().example('2024-01-15T10:30:00Z').description('When export was created'),
    expiresAt: Joi.date().iso().example('2024-01-16T10:30:00Z').description('When export file expires'),
    error: Joi.string().allow(null).description('Error message if export failed'),
    isResumable: Joi.boolean().description('Whether the failed export can be resumed (only present when status is failed)')
}).label('ExportStatus');

const exportListEntrySchema = Joi.object({
    exportId: Joi.string().example('exp_abc123def456').description('Export job identifier'),
    status: Joi.string().valid('queued', 'processing', 'completed', 'failed', 'cancelled').example('completed').description('Export status'),
    created: Joi.date().iso().example('2024-01-15T10:30:00Z').description('When export was created'),
    expiresAt: Joi.date().iso().example('2024-01-16T10:30:00Z').description('When export file expires')
}).label('ExportListEntry');

const exportListSchema = Joi.object({
    total: Joi.number().integer().example(5).description('Total number of exports'),
    page: Joi.number().integer().example(0).description('Current page number'),
    pages: Joi.number().integer().example(1).description('Total number of pages'),
    exports: Joi.array().items(exportListEntrySchema).description('Export entries')
}).label('ExportList');

const exportIdSchema = Joi.string()
    .pattern(/^exp_[a-f0-9]{24}$/)
    .required()
    .example('exp_abc123def456abc123def456')
    .description('Export job identifier')
    .label('ExportId');

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
    googleTopicNameSchema,
    googleSubscriptionNameSchema,
    googleWorkspaceAccountsSchema,
    messageReferenceSchema,
    idempotencyKeySchema,
    headerTimeoutSchema,
    exportRequestSchema,
    exportStatusSchema,
    exportListSchema,
    exportProgressSchema,
    exportIdSchema
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
