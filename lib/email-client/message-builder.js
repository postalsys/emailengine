'use strict';

const { Gateway } = require('../gateway');
const { oauth2ProviderData } = require('../oauth2-apps');
const { getLocalAddress, resolveCredentials } = require('../tools');
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

        try {
            const gatewayData = await gatewayObject.loadGatewayData();
            return { gatewayData, gatewayObject };
        } catch (err) {
            this.logger.info({
                msg: 'Failed to load gateway data',
                messageId,
                gateway: gatewayId,
                err
            });
            return { gatewayData: null, gatewayObject };
        }
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
        const { oauth2User, accessToken, oauth2App } = await loadOAuth2Credentials(
            accountData,
            context,
            'smtp'
        );
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
        if (!smtpConnectionConfig.useAuthServer) {
            return smtpConnectionConfig.auth;
        }

        try {
            return await resolveCredentials(this.account, 'smtp');
        } catch (err) {
            err.authenticationFailed = true;
            this.logger.error({
                account: this.account,
                err
            });
            throw err;
        }
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
        const { localAddress: address, name, addressSelector: selector } = await getLocalAddress(
            this.redis,
            'smtp',
            this.account,
            data.localAddress
        );

        this.logger.info({
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
            networkRouting.proxy = smtpSettings.proxy;
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
 * Error code to description mapping for SMTP errors
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
    ETIMEDOUT: (settings) =>
        `Request timed out. Possibly a firewall issue or a wrong hostname/port (${settings.host}:${settings.port}).`,
    ETLS: (settings) =>
        `EmailEngine failed to set up TLS session with ${settings.host}:${settings.port}`,
    EDNS: (settings) =>
        `EmailEngine failed to resolve DNS record for ${settings.host}`,
    ECONNECTION: (settings) =>
        `EmailEngine failed to establish TCP connection against ${settings.host}`,
    EPROTOCOL: (settings) =>
        `Unexpected response from ${settings.host}`,
    EAUTH: () => 'Authentication failed'
};

/**
 * Builds SMTP error status information for tracking and notifications
 */
class SmtpErrorBuilder {
    /**
     * Builds SMTP status object from error
     * @param {Error} err - The error that occurred
     * @param {Object} smtpSettings - SMTP settings for context
     * @param {Object} networkRouting - Network routing info
     * @returns {Object|null} SMTP status object or null
     */
    static buildStatus(err, smtpSettings, networkRouting) {
        const descriptionBuilder = SMTP_ERROR_DESCRIPTIONS[err.code];
        if (!descriptionBuilder) {
            return null;
        }

        const description = descriptionBuilder(smtpSettings, err);
        if (!description) {
            return null;
        }

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
        const { accountData, data, isGmail, isOutlook, gatewayData } = options;

        // The default is to copy message to Sent Mail folder
        let shouldCopy = !Object.prototype.hasOwnProperty.call(accountData, 'copy');

        // Account specific setting
        if (typeof accountData.copy === 'boolean') {
            shouldCopy = accountData.copy;
        }

        // Suppress uploads for Gmail and Outlook
        // Unfortunately, previous default schema for all added accounts was copy=true,
        // so can't prefer account specific setting here
        // Emails for delegated accounts will be uploaded as the sender is different.
        // SMTP is disabled for shared mailboxes, so we need to send using the main account.
        const skipIfOutlook = isOutlook &&
            (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.delegatedUser);

        if ((isGmail || skipIfOutlook) && !gatewayData) {
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

module.exports = {
    SmtpConfigBuilder,
    NetworkRoutingBuilder,
    NotificationBuilder,
    ProviderMessageIdHandler,
    SmtpErrorBuilder,
    SentMailCopyDecider
};
