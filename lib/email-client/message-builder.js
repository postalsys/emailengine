'use strict';

const { Gateway } = require('../gateway');
const { oauth2ProviderData } = require('../oauth2-apps');
const { useAuthServerForConnection, redactUrlCredentials } = require('../tools');
const { resolveAuthServerCredentials } = require('./credential-errors');
const { getLocalAddress } = require('../utils/network');
const settings = require('../settings');
const { TLS_DEFAULTS } = require('../consts');
const util = require('util');

/**
 * Builds SMTP transport configuration from various authentication sources
 */
class SmtpConfigBuilder {
    /**
     * Creates a new SmtpConfigBuilder
     * @param {Object} options - Builder options
     * @param {Object} options.redis - Redis client instance
     * @param {string} options.secret - Secret key for decryption
     * @param {Object} options.logger - Logger instance
     * @param {string} options.account - Account identifier
     */
    constructor(options) {
        this.redis = options.redis;
        this.secret = options.secret;
        this.logger = options.logger;
        this.account = options.account;
    }

    /**
     * Loads gateway data if a gateway is specified
     * @param {string} gatewayId - Gateway identifier
     * @param {string} messageId - Message ID for logging
     * @returns {Promise<Object|null>} Gateway data and object, or null
     */
    async loadGateway(gatewayId, messageId) {
        if (!gatewayId) {
            return { gatewayData: null, gatewayObject: null };
        }

        const gatewayObject = new Gateway({
            gateway: gatewayId,
            redis: this.redis,
            secret: this.secret
        });

        // The message was queued for this gateway, so it must not go out through the account's
        // own SMTP server instead: a Redis failure is thrown as is and the job retries, a gateway
        // that no longer exists throws GatewayNotFound and the job is discarded
        const gatewayData = await gatewayObject.loadGatewayData();
        return { gatewayData, gatewayObject };
    }

    /**
     * Builds base SMTP connection configuration
     * @param {Object} options - Configuration options
     * @param {Object} options.gatewayData - Gateway configuration data
     * @param {Object} options.accountData - Account data
     * @param {Function} options.loadOAuth2Credentials - OAuth2 credential loader
     * @param {Object} options.context - Context object for OAuth2 loading
     * @returns {Promise<Object>} SMTP connection configuration
     */
    async buildConnectionConfig(options) {
        const { gatewayData, accountData, loadOAuth2Credentials, context } = options;

        if (gatewayData) {
            return this.buildGatewayConfig(gatewayData);
        }

        if (accountData.oauth2 && accountData.oauth2.auth) {
            return this.buildOAuth2Config(accountData, loadOAuth2Credentials, context);
        }

        // Deep copy of SMTP settings
        return JSON.parse(JSON.stringify(accountData.smtp));
    }

    /**
     * Builds configuration from gateway data
     * @param {Object} gatewayData - Gateway configuration
     * @returns {Object} SMTP connection config
     */
    buildGatewayConfig(gatewayData) {
        const config = {
            host: gatewayData.host,
            port: gatewayData.port,
            secure: gatewayData.secure
        };

        if (gatewayData.user || gatewayData.pass) {
            config.auth = {
                user: gatewayData.user || '',
                pass: gatewayData.pass || ''
            };
        }

        return config;
    }

    /**
     * Builds OAuth2-based SMTP configuration
     * @param {Object} accountData - Account data with OAuth2 settings
     * @param {Function} loadOAuth2Credentials - Credential loader function
     * @param {Object} context - Context for credential loading
     * @returns {Promise<Object>} SMTP connection config with OAuth2
     */
    async buildOAuth2Config(accountData, loadOAuth2Credentials, context) {
        const { oauth2User, accessToken, oauth2App } = await loadOAuth2Credentials(accountData, context, 'smtp');
        const providerData = oauth2ProviderData(oauth2App.provider, oauth2App.cloud);

        return Object.assign(
            {
                auth: {
                    user: oauth2User,
                    accessToken
                },
                resyncDelay: 900
            },
            providerData.smtp || {}
        );
    }

    /**
     * Resolves authentication from auth server if configured
     * @param {Object} smtpConnectionConfig - Current SMTP config
     * @returns {Promise<Object|null>} Resolved auth credentials
     */
    async resolveAuthServer(smtpConnectionConfig) {
        if (await useAuthServerForConnection(smtpConnectionConfig, this.logger, { account: this.account, target: 'smtp' })) {
            // Shared with the IMAP and API paths so all three draw the same line between an
            // authentication server that refused the account and one that is briefly unavailable.
            // The builder carries no account state and sends no webhooks of its own, so the
            // context only has to absorb what the shared helper reports
            return await resolveAuthServerCredentials(this.account, 'smtp', {
                logger: this.logger,
                notify: async () => {},
                state: null
            });
        }

        return smtpConnectionConfig.auth;
    }

    /**
     * Builds complete SMTP settings with all configuration applied
     * @param {Object} options - Configuration options
     * @param {Object} options.smtpConnectionConfig - Base SMTP config
     * @param {Object} options.smtpAuth - Authentication credentials
     * @param {Object} options.accountData - Account data
     * @param {Object} options.data - Request data
     * @returns {Promise<Object>} Complete SMTP settings
     */
    async buildSmtpSettings(options) {
        const { smtpConnectionConfig, smtpAuth, accountData, data } = options;

        // Get local address for outbound connection
        const { localAddress: address, name, addressSelector: selector } = await getLocalAddress(this.redis, 'smtp', this.account, data.localAddress);

        this.logger.debug({
            msg: 'Selected local address',
            account: this.account,
            proto: 'SMTP',
            address,
            name,
            selector,
            requestedLocalAddress: data.localAddress
        });

        // Build SMTP logger wrapper
        const smtpLogger = this.buildSmtpLogger();

        // Create settings object
        const smtpSettings = Object.assign(
            {
                name,
                localAddress: address,
                transactionLog: true,
                logger: smtpLogger
            },
            smtpConnectionConfig
        );

        // Apply authentication
        if (smtpAuth) {
            smtpSettings.auth = { user: smtpAuth.user };
            if (smtpAuth.accessToken) {
                smtpSettings.auth.type = 'OAuth2';
                smtpSettings.auth.accessToken = smtpAuth.accessToken;
            } else {
                smtpSettings.auth.pass = smtpAuth.pass;
            }
        }

        // Apply TLS defaults
        this.applyTlsDefaults(smtpSettings);

        // Apply proxy configuration
        await this.applyProxyConfig(smtpSettings, accountData, data);

        // Override EHLO hostname if configured
        if (accountData.smtpEhloName) {
            smtpSettings.name = accountData.smtpEhloName;
        }

        // Handle certificate error configuration
        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
        if (ignoreMailCertErrors && smtpSettings?.tls?.rejectUnauthorized !== false) {
            smtpSettings.tls = smtpSettings.tls || {};
            smtpSettings.tls.rejectUnauthorized = false;
        }

        return smtpSettings;
    }

    /**
     * Creates SMTP logger wrapper that forwards to main logger
     * @returns {Object} Logger object with level methods
     */
    buildSmtpLogger() {
        const smtpLogger = {};
        const logger = this.logger;

        for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
            smtpLogger[level] = (data, message, ...args) => {
                if (args && args.length) {
                    message = util.format(message, ...args);
                }
                data.msg = message;
                data.sub = 'nodemailer';
                if (typeof logger[level] === 'function') {
                    logger[level](data);
                } else {
                    logger.debug(data);
                }
            };
        }

        return smtpLogger;
    }

    /**
     * Applies TLS defaults to SMTP settings
     * @param {Object} smtpSettings - SMTP settings to modify
     */
    applyTlsDefaults(smtpSettings) {
        if (!smtpSettings.tls) {
            smtpSettings.tls = {};
        }
        for (const key of Object.keys(TLS_DEFAULTS)) {
            if (!(key in smtpSettings.tls)) {
                smtpSettings.tls[key] = TLS_DEFAULTS[key];
            }
        }
    }

    /**
     * Applies proxy configuration from various sources
     * @param {Object} smtpSettings - SMTP settings to modify
     * @param {Object} accountData - Account data
     * @param {Object} data - Request data
     */
    async applyProxyConfig(smtpSettings, accountData, data) {
        if (data.proxy) {
            smtpSettings.proxy = data.proxy;
        } else if (accountData.proxy) {
            smtpSettings.proxy = accountData.proxy;
        } else {
            const proxyUrl = await settings.get('proxyUrl');
            const proxyEnabled = await settings.get('proxyEnabled');
            if (proxyEnabled && proxyUrl && !smtpSettings.proxy) {
                smtpSettings.proxy = proxyUrl;
            }
        }
    }
}

/**
 * Builds network routing information for notifications
 */
class NetworkRoutingBuilder {
    /**
     * Builds network routing info from SMTP settings
     * @param {Object} smtpSettings - SMTP settings
     * @param {Object} data - Request data with optional localAddress
     * @returns {Object|null} Network routing info or null
     */
    static build(smtpSettings, data) {
        const hasRoutingInfo = smtpSettings.localAddress || smtpSettings.proxy;
        if (!hasRoutingInfo) {
            return null;
        }

        const networkRouting = {};

        if (smtpSettings.localAddress) {
            networkRouting.localAddress = smtpSettings.localAddress;
        }

        if (smtpSettings.proxy) {
            // This object ends up in messageSent / messageDeliveryError webhooks, job progress and
            // the gateway's lastError, so the proxy password must not travel with it.
            networkRouting.proxy = redactUrlCredentials(smtpSettings.proxy);
        }

        if (smtpSettings.name) {
            networkRouting.name = smtpSettings.name;
        }

        if (data.localAddress && data.localAddress !== networkRouting.localAddress) {
            networkRouting.requestedLocalAddress = data.localAddress;
        }

        return networkRouting;
    }
}

/**
 * Builds notification payloads for email delivery events
 */
class NotificationBuilder {
    /**
     * Builds success notification payload
     * @param {Object} options - Notification options
     * @param {Object} options.info - SMTP send result info
     * @param {string} options.originalMessageId - Original message ID if overridden
     * @param {string} options.queueId - Queue ID
     * @param {Object} options.envelope - Message envelope
     * @param {Object} options.networkRouting - Network routing info
     * @returns {Object} Success notification payload
     */
    static buildSuccessPayload(options) {
        const { info, originalMessageId, queueId, envelope, networkRouting } = options;

        return {
            messageId: info.messageId,
            originalMessageId,
            response: info.response,
            queueId,
            envelope,
            networkRouting
        };
    }

    /**
     * Builds error notification payload
     * @param {Object} options - Notification options
     * @param {Error} options.error - The error that occurred
     * @param {string} options.queueId - Queue ID
     * @param {Object} options.envelope - Message envelope
     * @param {string} options.messageId - Original message ID
     * @param {Object} options.networkRouting - Network routing info
     * @param {Object} options.jobData - Job data
     * @returns {Object} Error notification payload
     */
    static buildErrorPayload(options) {
        const { error, queueId, envelope, messageId, networkRouting, jobData } = options;

        return {
            queueId,
            envelope,
            messageId,
            error: error.message,
            errorCode: error.code,
            smtpResponse: error.response,
            smtpResponseCode: error.responseCode,
            smtpCommand: error.command,
            networkRouting,
            job: jobData
        };
    }
}

/**
 * Handles provider-specific message ID extraction and transformation
 */
class ProviderMessageIdHandler {
    /**
     * Extracts actual message ID from Hotmail/Outlook response
     * The server may override the message ID in its response
     * @param {Object} info - SMTP send result info
     * @returns {string|undefined} Original message ID if overridden
     */
    static handleHotmail(info) {
        const response = (info.response || '').toString();
        const match = response.match(/^250 2.0.0 OK (<[^>]+\.prod\.outlook\.com>)/);

        if (match && match[1] !== info.messageId) {
            const originalMessageId = info.messageId;
            info.messageId = match[1];
            return originalMessageId;
        }

        return undefined;
    }

    /**
     * Constructs message ID from AWS SES response
     * SES returns a message ID in the response that should be used
     * @param {Object} info - SMTP send result info
     * @param {string} smtpHost - SMTP host name
     * @returns {string|undefined} Original message ID if overridden
     */
    static handleAwsSes(info, smtpHost) {
        const hostMatch = (smtpHost || '').toString().match(/\.([^.]+)\.(amazonaws\.com|awsapps\.com)$/i);
        const responseMatch = (info.response || '').toString().match(/^250 Ok ([0-9a-f-]+)$/);

        if (hostMatch && responseMatch) {
            let region = hostMatch[1].toLowerCase().trim();
            const messageIdPart = responseMatch[1].toLowerCase().trim();

            if (region === 'us-east-1') {
                region = 'email';
            }

            const originalMessageId = info.messageId;
            info.messageId = '<' + messageIdPart + (!/@/.test(messageIdPart) ? '@' + region + '.amazonses.com' : '') + '>';
            return originalMessageId;
        }

        return undefined;
    }

    /**
     * Processes SMTP response to extract provider-specific message ID
     * @param {Object} info - SMTP send result info
     * @param {string} smtpHost - SMTP host name
     * @returns {string|undefined} Original message ID if it was overridden
     */
    static processResponse(info, smtpHost) {
        // Try Hotmail first
        let originalMessageId = this.handleHotmail(info);
        if (originalMessageId) {
            return originalMessageId;
        }

        // Try AWS SES
        originalMessageId = this.handleAwsSes(info, smtpHost);
        if (originalMessageId) {
            return originalMessageId;
        }

        return undefined;
    }
}

/**
 * Error code to description mapping for SMTP errors. A code that is absent here, or whose entry
 * returns nothing, falls back to the error's own message in buildStatus() - the table turns a
 * known failure into a sentence an operator can act on, it does not decide what gets recorded.
 */
const SMTP_ERROR_DESCRIPTIONS = {
    ESOCKET: (settings, err) => {
        if (err.cert && err.reason) {
            return `Certificate check for ${settings.host}:${settings.port} failed. ${err.reason}`;
        }
        return null;
    },
    EMESSAGE: () => null,
    ESTREAM: () => null,
    EENVELOPE: () => null,
    ETIMEDOUT: settings => `Request timed out. Possibly a firewall issue or a wrong hostname/port (${settings.host}:${settings.port}).`,
    ETLS: settings => `EmailEngine failed to set up TLS session with ${settings.host}:${settings.port}`,
    EDNS: settings => `EmailEngine failed to resolve DNS record for ${settings.host}`,
    ECONNECTION: settings => `EmailEngine failed to establish TCP connection against ${settings.host}`,
    EPROTOCOL: settings => `Unexpected response from ${settings.host}`,
    EAUTH: () => 'Authentication failed',
    ENOAUTH: () => 'Authentication credentials were not provided',
    EOAUTH2: () => 'OAuth2 token generation or refresh failed'
};

/**
 * Builds SMTP error status information for tracking and notifications
 */
class SmtpErrorBuilder {
    /**
     * Builds SMTP status object from error. Always produces a status: it used to return null for
     * any error SMTP_ERROR_DESCRIPTIONS could not describe (a 5xx rejection arriving without the
     * EENVELOPE marker, a nodemailer code added since the table was written), and the caller then
     * left the gateway's lastError and the account's smtpStatus showing the previous attempt. The
     * caller decides whether there is an SMTP attempt to describe at all.
     * @param {Error} err - The error that occurred
     * @param {Object} smtpSettings - SMTP settings for context
     * @param {Object} networkRouting - Network routing info
     * @returns {Object} SMTP status object
     */
    static buildStatus(err, smtpSettings, networkRouting) {
        const descriptionBuilder = SMTP_ERROR_DESCRIPTIONS[err.code];
        const description = (descriptionBuilder && descriptionBuilder(smtpSettings, err)) || err.message || 'Failed to send email';

        return {
            created: Date.now(),
            status: 'error',
            response: err.response,
            responseCode: err.responseCode,
            code: err.code,
            command: err.command,
            networkRouting,
            description
        };
    }
}

/**
 * Determines whether to copy sent message to Sent folder
 */
class SentMailCopyDecider {
    /**
     * Whether the provider files SMTP-submitted messages into the Sent Mail folder on its
     * own. True for Gmail and for non-delegated Outlook when no gateway is used - both store
     * the sent message themselves, so an upload would duplicate it. Emails for delegated
     * Outlook accounts are still uploaded as the sender is different (SMTP is disabled for
     * shared mailboxes, so the message is sent using the main account).
     * @param {Object} options - Decision options
     * @param {Object} options.accountData - Account data
     * @param {boolean} options.isGmail - Whether account is Gmail
     * @param {boolean} options.isOutlook - Whether account is Outlook
     * @param {Object} options.gatewayData - Gateway data if using gateway
     * @returns {boolean} Whether the provider stores the sent copy itself
     */
    static providerSavesSentCopy(options) {
        const { accountData, isGmail, isOutlook, gatewayData } = options;

        const skipIfOutlook = isOutlook && (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.delegatedUser);

        return Boolean((isGmail || skipIfOutlook) && !gatewayData);
    }

    /**
     * Determines if sent mail should be copied to Sent folder
     * @param {Object} options - Decision options
     * @param {Object} options.accountData - Account data
     * @param {Object} options.data - Request data
     * @param {boolean} options.isGmail - Whether account is Gmail
     * @param {boolean} options.isOutlook - Whether account is Outlook
     * @param {Object} options.gatewayData - Gateway data if using gateway
     * @returns {boolean} Whether to copy to Sent folder
     */
    static shouldCopy(options) {
        const { accountData, data } = options;

        // The default is to copy message to Sent Mail folder
        let shouldCopy = !Object.prototype.hasOwnProperty.call(accountData, 'copy');

        // Account specific setting
        if (typeof accountData.copy === 'boolean') {
            shouldCopy = accountData.copy;
        }

        // Suppress uploads when the provider stores the sent copy itself.
        // Unfortunately, previous default schema for all added accounts was copy=true,
        // so can't prefer account specific setting here
        if (this.providerSavesSentCopy(options)) {
            shouldCopy = false;
        }

        // Message specific setting, overrides all other settings
        if (typeof data.copy === 'boolean') {
            shouldCopy = data.copy;
        }

        // Check if IMAP is available
        if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
            // IMAP is disabled for this account
            shouldCopy = false;
        }

        return shouldCopy;
    }
}

/**
 * Merges a stored template into the message being queued.
 *
 * `render: false` is the documented way to send a template as-is, and the format carried by the
 * template used to be applied with `data.render = data.render || {}`, which turned that explicit false
 * into an empty options object - and an options object renders. So the one value that asked for no
 * rendering was the one value that could not be expressed. Extracted from queueMessageHandler(),
 * which a test cannot reach without a connection, an account record and a license answer.
 *
 * Mutates `data`, as the caller's own merge did.
 *
 * @param {Object} data - the message being queued, carrying `template` and optionally `render`
 * @param {Object} templateData - the stored template
 * @returns {Object} the same `data`
 */
function applyTemplate(data, templateData) {
    if (data.render !== false && templateData.content && templateData.content.html && templateData.format) {
        data.render = data.render || {};
        data.render.format = templateData.format;
    }

    for (let key of Object.keys(templateData.content || {})) {
        data[key] = templateData.content[key];
    }

    delete data.template;

    return data;
}

module.exports = {
    applyTemplate,
    SmtpConfigBuilder,
    NetworkRoutingBuilder,
    NotificationBuilder,
    ProviderMessageIdHandler,
    SmtpErrorBuilder,
    SentMailCopyDecider
};
