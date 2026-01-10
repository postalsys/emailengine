'use strict';

const { GMAIL_API_SCOPES } = require('./gmail');
const { OUTLOOK_API_SCOPES } = require('./outlook');

// Known Microsoft Graph API endpoints across different cloud environments
const MS_GRAPH_DOMAINS = [
    'graph.microsoft.com', // Global cloud
    'graph.microsoft.us', // GCC-High cloud
    'dod-graph.microsoft.us', // DoD cloud
    'microsoftgraph.chinacloudapi.cn' // China cloud
];

/**
 * Normalizes Microsoft Graph scope URLs to their scope names.
 * Supports multiple MS Graph endpoints (global, GCC-High, DoD, China).
 *
 * Examples:
 *   https://graph.microsoft.com/Mail.Send -> Mail.Send
 *   https://graph.microsoft.us/Mail.ReadWrite -> Mail.ReadWrite
 *   https://dod-graph.microsoft.us/Mail.Send -> Mail.Send
 *   https://microsoftgraph.chinacloudapi.cn/Mail.Send -> Mail.Send
 *   offline_access -> offline_access (passed through)
 *
 * @param {string} scope - The scope string to normalize
 * @param {Object} [logger] - Optional logger for warnings
 * @returns {string} Normalized scope name
 */
function normalizeMsGraphScope(scope, logger) {
    // Handle plain scope names (e.g., offline_access, openid)
    // These are not URLs and should be passed through as-is
    if (!scope.includes('://')) {
        return scope;
    }

    // Try to parse as URL to validate it's a Microsoft Graph endpoint
    try {
        const url = new URL(scope);

        // Validate protocol - must be https
        if (url.protocol !== 'https:') {
            if (logger) {
                logger.warn({
                    msg: 'Invalid protocol in MS Graph scope URL, expected https',
                    scope,
                    protocol: url.protocol
                });
            }
            return scope; // Return as-is for non-https URLs
        }

        // Check if this is a recognized MS Graph domain
        if (MS_GRAPH_DOMAINS.includes(url.hostname)) {
            // Extract scope name from path only (ignoring query params and fragments)
            // Examples:
            //   /Mail.Send -> Mail.Send
            //   /Mail.Send?foo=bar -> Mail.Send
            //   /Mail.Send#section -> Mail.Send
            //   /Mail.Send/ -> Mail.Send (removes trailing slash)
            const scopeName = url.pathname.substring(1).replace(/\/$/, '');
            if (scopeName) {
                return scopeName;
            }
            if (logger) {
                logger.warn({
                    msg: 'MS Graph scope URL has no scope name in path',
                    scope
                });
            }
        }
    } catch (err) {
        // Invalid URL format
        if (logger) {
            logger.warn({
                msg: 'Failed to parse MS Graph scope URL',
                scope,
                err: err.message
            });
        }
    }

    // Return as-is if not a recognized Graph URL or parsing failed
    return scope;
}

/**
 * Checks OAuth2 scopes to determine account capabilities.
 *
 * @param {string} provider - OAuth2 provider name ('gmail' or 'outlook')
 * @param {Array<string>} scopes - Array of OAuth2 scope strings
 * @param {Object} [logger] - Optional logger for warnings (used for Outlook scope parsing)
 * @returns {{hasSendScope: boolean, hasReadScope: boolean}} Object indicating send and read capabilities
 *
 * @example
 * // Gmail send-only account
 * checkAccountScopes('gmail', ['https://www.googleapis.com/auth/gmail.send'])
 * // Returns: { hasSendScope: true, hasReadScope: false }
 *
 * @example
 * // Gmail full access account
 * checkAccountScopes('gmail', ['https://www.googleapis.com/auth/gmail.modify'])
 * // Returns: { hasSendScope: false, hasReadScope: true }
 *
 * @example
 * // Outlook send-only account (global cloud)
 * checkAccountScopes('outlook', ['https://graph.microsoft.com/Mail.Send', 'offline_access'])
 * // Returns: { hasSendScope: true, hasReadScope: false }
 *
 * @example
 * // Outlook full access account (GCC-High cloud)
 * checkAccountScopes('outlook', ['https://graph.microsoft.us/Mail.ReadWrite', 'https://graph.microsoft.us/Mail.Send'])
 * // Returns: { hasSendScope: true, hasReadScope: true }
 *
 * @example
 * // Outlook send-only account (DoD cloud)
 * checkAccountScopes('outlook', ['https://dod-graph.microsoft.us/Mail.Send', 'offline_access'])
 * // Returns: { hasSendScope: true, hasReadScope: false }
 */
function checkAccountScopes(provider, scopes, logger) {
    if (!scopes || !Array.isArray(scopes)) {
        return { hasSendScope: false, hasReadScope: false };
    }

    if (provider === 'gmail') {
        const hasSendScope = scopes.some(s => s.includes(GMAIL_API_SCOPES.send));
        const hasReadScope = scopes.some(
            s =>
                s.includes(GMAIL_API_SCOPES.modify) ||
                s.includes(GMAIL_API_SCOPES.readonly) ||
                s.includes(GMAIL_API_SCOPES.labels) ||
                s.includes('mail.google.com')
        );
        return { hasSendScope, hasReadScope };
    }

    if (provider === 'outlook') {
        // Normalize scopes by extracting the scope name from the full URL
        const normalizedScopes = scopes.map(s => normalizeMsGraphScope(s, logger));

        const hasSendScope = normalizedScopes.some(s => s === OUTLOOK_API_SCOPES.send);
        const hasReadScope = normalizedScopes.some(s => s === OUTLOOK_API_SCOPES.read || s === OUTLOOK_API_SCOPES.readWrite);
        return { hasSendScope, hasReadScope };
    }

    return { hasSendScope: false, hasReadScope: false };
}

/**
 * Checks Gmail-specific scope requirements from account data.
 *
 * @param {Object} accountData - Account configuration object with oauth2 property
 * @returns {{hasSendScope: boolean, hasReadScope: boolean}} Object indicating send and read capabilities
 *
 * @example
 * checkGmailScopes({ oauth2: { scope: ['https://www.googleapis.com/auth/gmail.send'] } })
 * // Returns: { hasSendScope: true, hasReadScope: false }
 */
function checkGmailScopes(accountData) {
    const scopes = accountData?.oauth2?.accessToken?.scope || accountData?.oauth2?.scope || [];
    return checkAccountScopes('gmail', scopes);
}

/**
 * Checks Outlook-specific scope requirements from account data.
 *
 * @param {Object} accountData - Account configuration object with oauth2 property
 * @param {Object} [logger] - Optional logger for warnings
 * @returns {{hasSendScope: boolean, hasReadScope: boolean}} Object indicating send and read capabilities
 *
 * @example
 * checkOutlookScopes({ oauth2: { scope: ['https://graph.microsoft.com/Mail.Send'] } })
 * // Returns: { hasSendScope: true, hasReadScope: false }
 */
function checkOutlookScopes(accountData, logger) {
    const scopes = accountData?.oauth2?.accessToken?.scope || accountData?.oauth2?.scope || [];
    return checkAccountScopes('outlook', scopes, logger);
}

/**
 * Determines if an account is in send-only mode based on its scopes.
 *
 * @param {string} provider - OAuth2 provider name ('gmail' or 'outlook')
 * @param {Object} accountData - Account configuration object with oauth2 property
 * @param {Object} [logger] - Optional logger for warnings
 * @returns {boolean} True if account has send scope but not read scope
 */
function isSendOnlyByScopes(provider, accountData, logger) {
    const scopes = accountData?.oauth2?.accessToken?.scope || accountData?.oauth2?.scope || [];
    const { hasSendScope, hasReadScope } = checkAccountScopes(provider, scopes, logger);
    return hasSendScope && !hasReadScope;
}

module.exports = {
    checkAccountScopes,
    checkGmailScopes,
    checkOutlookScopes,
    isSendOnlyByScopes,
    normalizeMsGraphScope,
    GMAIL_API_SCOPES,
    OUTLOOK_API_SCOPES,
    MS_GRAPH_DOMAINS
};
