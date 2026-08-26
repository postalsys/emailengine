'use strict';

const logger = require('./logger');
const Boom = require('@hapi/boom');
const msgpack = require('./msgpack');
const {
    normalizePath,
    formatAccountListingResponse,
    unpackUIDRangeForSearch,
    mergeObjects,
    download,
    resolveCredentials,
    useAuthServerForOAuth2,
    isEmail,
    resolveDelegatedAccount,
    escapeRedisGlob,
    getMailboxStatusKey,
    cidReferenceRegex
} = require('./tools');
const { MessageChannel } = require('worker_threads');
const { MessagePortReadable } = require('./message-port-stream');
const { isDeepStrictEqual } = require('util');
const { encrypt, decrypt } = require('./encrypt');
const { oauth2Apps, isApiBasedApp } = require('./oauth2-apps');
const settings = require('./settings');
const { buildRetentionPolicy } = require('./queue-retention');
const { isDocumentStoreEnabled, documentStoreFeatureEnabled } = require('./document-store');
const redisScanDelete = require('./redis-scan-delete');
const { extractMultiValues, createTransaction } = require('./redis-operations');
const outbox = require('./outbox');
const tokens = require('./tokens');
const { customAlphabet } = require('nanoid');
const Lock = require('ioredfour');
const { redis } = require('./db');
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 16);
const { REDIS_PREFIX, ACCOUNT_DELETED_NOTIFY, AUTH_FAILURE_DISABLED_FIELD, AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION } = require('./consts');
const { messageWebSafeHtml, webSafeTextResponse, applyWebSafeHtmlOptions } = require('./web-safe-html');
const { checkAccountScopes: checkScopes } = require('./oauth/scope-checker');
const { ACCOUNT_STATES, ERROR_STATES, calculateEffectiveState, validateAccountState, getDisplayState, formatLastError } = require('./account/account-state');
const { decodeStoredMailboxEntry } = require('./email-client/imap/listing-diff');
const { readImapData } = require('./account/imap-data');

// Shared Lock instance to prevent Redis connection leak (one subscriber per Lock instance)
// Previously, each Account created its own Lock, causing ~30k connections with 30k accounts
const defaultLock = new Lock({
    redis,
    namespace: 'ee'
});

// Serialization window for Account.update(). The critical section is a few Redis round trips, so
// the TTL only has to cover a stalled writer, and the wait only has to outlast a normal one.
const ACCOUNT_UPDATE_LOCK_TTL = 10 * 1000;
const ACCOUNT_UPDATE_LOCK_WAIT = 5 * 1000;

/**
 * What an incoming account payload asks of `imap.disabled`.
 *
 * Must be read before persistUpdate() merges a `partial` payload into the stored object, which
 * would otherwise pull `disabled` in from the old blob and make every partial update look like a
 * decision about the flag.
 *
 * @param {Object} accountData - Account fields about to be written
 * @returns {Boolean|null} What the payload sets the flag to, or null when it says nothing about it
 */
function imapDisabledIntent(accountData) {
    if (!accountData.imap || typeof accountData.imap !== 'object' || !('disabled' in accountData.imap)) {
        return null;
    }
    return !!accountData.imap.disabled;
}

/**
 * Whether syncing was switched off for an account, by either route.
 *
 * @param {Object} accountData - An unserialized account
 * @returns {Boolean} True when `imap.disabled` is set
 */
function isImapDisabled(accountData) {
    return !!(accountData && accountData.imap && accountData.imap.disabled);
}

/**
 * When the auth-failure safety net switched an account off, as opposed to the operator doing it.
 *
 * The single answer to "is this account parked", used by every surface that reports one: the API
 * field, the admin state badge, the page alert, and the reconnect dispatches in create()/update().
 *
 * Both halves of the test matter. The marker can outlive the flag - an operator re-enables the
 * account by hand and the stale marker is only retired on the next recovery pass - so reading it
 * alone would report a healthy, syncing account as switched off. And re-authorizing a healthy
 * account must not trigger the reconnect that un-parking one does.
 *
 * @param {Object} accountData - An unserialized account, carrying `_authFailureDisabledAt`
 * @returns {String|null} ISO timestamp of the disable, or null when the safety net did not park it
 */
function authFailureDisabledAt(accountData) {
    if (!accountData || !accountData._authFailureDisabledAt || !isImapDisabled(accountData)) {
        return null;
    }
    return accountData._authFailureDisabledAt;
}

/**
 * Whether the safety net switched an account off, counting parks recorded before the marker
 * existed: those left `imap.disabled` plus the threshold description in `lastErrorState`, and
 * nothing but the park writes that description (why only the OAuth2 ones were stamped with a
 * marker is in lib/account/auth-failure-backfill.js). Display only - the reconnect refusal, the API
 * field and "Resume syncing" stay keyed on the marker.
 *
 * @param {Object} accountData - An unserialized account
 * @returns {Boolean} True when either generation of the safety net parked the account
 */
function isAuthFailureDisabled(accountData) {
    return (
        !!authFailureDisabledAt(accountData) ||
        (isImapDisabled(accountData) && accountData.lastErrorState?.description === AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION)
    );
}

/**
 * Whether the operator switched IMAP off - the send-only switch - as opposed to the safety net
 * parking the account. Send-only is a configuration, a park is a fault, and the surfaces that
 * present one must not present the other.
 *
 * @param {Object} accountData - An unserialized account
 * @returns {Boolean} True when `imap.disabled` is set and the safety net did not set it
 */
function isOperatorDisabled(accountData) {
    return isImapDisabled(accountData) && !authFailureDisabledAt(accountData);
}

class Account {
    constructor(options) {
        this.redis = options.redis;
        this.account = options.account || false;

        this.documentsQueue = options.documentsQueue || false;

        this.secret = options.secret;

        this.timeout = options.timeout ? Number(options.timeout) : 0;

        this.esClient = options.esClient;

        this.call = options.call; // async method to request data from parent

        this.logger = options.logger || logger;
    }

    getLock() {
        return this.lock || defaultLock;
    }

    /**
     * Checks OAuth2 scopes to determine account capabilities.
     * Delegates to centralized scope-checker module.
     *
     * @param {string} provider - OAuth2 provider name ('gmail' or 'outlook')
     * @param {Array<string>} scopes - Array of OAuth2 scope strings
     * @returns {{hasSendScope: boolean, hasReadScope: boolean}} Object indicating send and read capabilities
     */
    checkAccountScopes(provider, scopes) {
        return checkScopes(provider, scopes, this.logger);
    }

    /**
     * Determines if an account is configured for send-only mode
     *
     * This method handles ALL types of send-only accounts:
     * 1. OAuth2 API accounts (Gmail/Outlook) with only send scopes
     * 2. Traditional SMTP-only accounts (IMAP disabled or missing)
     * 3. Delegated accounts (checks the parent account)
     *
     * @param {Object} accountData - Account configuration object
     * @param {Object} [app] - OAuth2 app configuration object (optional, for OAuth2 accounts)
     * @returns {boolean} True if account is send-only (can send but not read)
     *
     * @example
     * // Send-only Gmail API account (has gmail.send scope only)
     * isSendOnlyAccount(accountData, { provider: 'gmail' })
     * // Returns: true
     *
     * @example
     * // Send-only Outlook Graph API account (has Mail.Send scope only)
     * isSendOnlyAccount(accountData, { provider: 'outlook' })
     * // Returns: true
     *
     * @example
     * // SMTP-only account (IMAP disabled)
     * isSendOnlyAccount({ smtp: {...}, imap: { disabled: true } })
     * // Returns: true
     *
     * @example
     * // SMTP-only account (no IMAP configured)
     * isSendOnlyAccount({ smtp: {...} })
     * // Returns: true
     *
     * @example
     * // Full access IMAP account
     * isSendOnlyAccount({ smtp: {...}, imap: { host: 'imap.example.com' } })
     * // Returns: false
     */
    /**
     * Checks if an OAuth2 account has send-only scope configuration
     * @private
     * @param {Object} accountData - Account configuration object
     * @param {string} provider - OAuth2 provider ('gmail' or 'outlook')
     * @returns {boolean} True if account has send scope but not read scope
     */
    _hasOAuth2SendOnlyScopes(accountData, provider) {
        const scopes = accountData.oauth2?.accessToken?.scope || accountData.oauth2?.scope || [];
        const { hasSendScope, hasReadScope } = this.checkAccountScopes(provider, scopes);
        return hasSendScope && !hasReadScope;
    }

    isSendOnlyAccount(accountData, app) {
        // Check OAuth2 API accounts (Gmail, Outlook Graph API)
        if (app && ['gmail', 'outlook'].includes(app.provider)) {
            return this._hasOAuth2SendOnlyScopes(accountData, app.provider);
        }

        // Check traditional SMTP-only accounts
        // An account is send-only if:
        // - IMAP is explicitly disabled, OR
        // - IMAP is not configured (missing or empty)
        if (accountData.imap) {
            // IMAP exists - check if the operator switched it off. A park by the safety net is not
            // send-only: reporting it as such hid the IMAP card, and the stored error with it,
            // behind the "API Send-only" presentation.
            return isOperatorDisabled(accountData);
        }

        // No IMAP configuration at all
        // Check if this is an OAuth2 account without an app parameter
        // (delegated accounts or OAuth2 accounts where app lookup failed)
        if (accountData.oauth2 && !app) {
            // For OAuth2 without app info, we can't determine scope-based send-only
            // Default to false (assume full access) unless IMAP is explicitly disabled
            return false;
        }

        // No IMAP, no OAuth2 - this is a traditional SMTP-only account
        // Return true only if SMTP is configured (otherwise it's an invalid config)
        return !!accountData.smtp;
    }

    /**
     * Lists accounts, filtered by state and by a substring search.
     *
     * The provider enrichment below is not optional, however little of it a caller reads: it
     * resolves each account's OAuth2 app, and `isApi` falls out of that. getDisplayState() reads
     * `isApi` to decide whether a stored state can be trusted when the run index is behind, so an
     * API account listed without it reports `init` rather than what it is actually doing. A "lean"
     * listing that skipped the loop was tried and reverted for exactly that: it made the cheap
     * fields cheaper and the one field every caller renders wrong.
     *
     * @param {String|Array} state - state filter, 'errors' for every attention state, falsy for all
     * @param {String} query - substring matched against account id, name and address
     * @param {Number} page - zero-based page
     * @param {Number} limit - page size
     * @returns {Promise<Object>} `{ total, pages, page, query, state, accounts }`
     */
    async listAccounts(state, query, page, limit) {
        limit = Number(limit) || 20;
        page = Math.max(Number(page) || 0, 0);
        let skip = page * limit;

        const runIndex = await this.call({
            cmd: 'runIndex'
        });

        // 'errors' is a virtual filter value covering every error state; the Lua script
        // takes a comma-separated state list, which stays a private detail of this boundary
        if (state === 'errors') {
            state = ERROR_STATES;
        }
        let filterState = Array.isArray(state) ? state.join(',') : state || '*';

        // The search is a plain substring match against the lowercased fields, and two things about
        // that were left to the caller to get right:
        //
        //   - the needle was passed through as typed, so anything with a capital in it matched
        //     nothing at all - on a search box, the account you can see is the one you cannot find.
        //     The script folds the needle too, so any caller gets a case-insensitive search; this
        //     fold is the one that also covers non-ASCII, which string.lower() leaves alone.
        //   - "no search" was spelled `false` by some callers, and ioredis sends that as the string
        //     "false", which the script then dutifully searched for. Anything that is not a string
        //     is one of those, and means no search.
        let search = typeof query === 'string' ? query.toLowerCase() : '';

        let result = await this.redis.sListAccounts(`${REDIS_PREFIX}ia:accounts`, filterState, skip, limit, `${REDIS_PREFIX}`, search);

        let accounts = result[2].map(formatAccountListingResponse).map(this.unserializeAccountData.bind(this));
        let oauthApps = new Map();

        for (let accountData of accounts) {
            if (accountData.oauth2 && accountData.oauth2.provider) {
                let app;
                if (oauthApps.has(accountData.oauth2.provider)) {
                    app = oauthApps.get(accountData.oauth2.provider);
                } else {
                    app = await oauth2Apps.get(accountData.oauth2.provider);
                }
                oauthApps.set(accountData.oauth2.provider, app || null);
                if (app) {
                    accountData.type = app.provider;
                    if (isApiBasedApp(app)) {
                        accountData.isApi = true;
                    }

                    // Check if this is a send-only OAuth2 API account (Gmail or Outlook, regardless of baseScopes setting)
                    if (this.isSendOnlyAccount(accountData, app)) {
                        accountData.isApi = true;
                        accountData.sendOnly = true;
                    }
                } else {
                    accountData.type = 'oauth2';
                }
            } else if (accountData.oauth2 && accountData.oauth2.auth && accountData.oauth2.auth.delegatedAccount) {
                accountData.type = 'delegated';
                try {
                    let delegatedAccount = await resolveDelegatedAccount(this.redis, accountData.account);
                    if (delegatedAccount) {
                        accountData.delegatedAccount = delegatedAccount;
                        let delegatedAccountRow = await this.redis.hgetall(`${REDIS_PREFIX}iad:${delegatedAccount}`);
                        let delegatedAccountData = this.unserializeAccountData(delegatedAccountRow);
                        if (delegatedAccountData.oauth2 && delegatedAccountData.oauth2.provider) {
                            let app;
                            if (oauthApps.has(delegatedAccountData.oauth2.provider)) {
                                app = oauthApps.get(delegatedAccountData.oauth2.provider);
                            } else {
                                app = await oauth2Apps.get(delegatedAccountData.oauth2.provider);
                            }
                            oauthApps.set(delegatedAccountData.oauth2.provider, app || null);
                            if (isApiBasedApp(app)) {
                                accountData.isApi = true;
                            }
                        }
                    }
                } catch (err) {
                    this.logger.warn({
                        msg: 'Failed to resolve delegated account',
                        account: accountData.account,
                        delegatedAccount: accountData.oauth2.auth.delegatedAccount,
                        err
                    });
                    accountData.type = 'invalid';
                    accountData.delegationError = err.message;
                }
            } else if (accountData.imap && !isOperatorDisabled(accountData)) {
                // A parked account is still an IMAP account, only switched off
                accountData.type = 'imap';
            } else {
                // Default to 'sending' type for accounts without IMAP
                // Use unified detection to determine if truly send-only
                accountData.type = 'sending';
                accountData.sendOnly = this.isSendOnlyAccount(accountData);
            }
        }

        let list = {
            total: result[0],
            pages: Math.ceil(result[0] / limit),
            page,
            query: query || false,
            state: state || '*',
            accounts: accounts.map(accountData => ({
                account: accountData.account,
                name: accountData.name,
                email: accountData.email,
                type: accountData.type,
                app:
                    accountData.oauth2 && accountData.oauth2.provider && accountData.oauth2.provider !== accountData.type
                        ? accountData.oauth2.provider
                        : undefined,
                state: getDisplayState(accountData, runIndex),

                webhooks: accountData.webhooks || undefined,
                proxy: accountData.proxy || undefined,
                smtpEhloName: accountData.smtpEhloName || undefined,

                counters: accountData.counters,

                syncTime: accountData.sync,

                // Lets a caller find every account the safety net parked without opening each one.
                // Omitted rather than null when it did not, like the optional fields above.
                authFailureDisabledAt: authFailureDisabledAt(accountData) || undefined,

                lastError: formatLastError(accountData),

                delegationError: accountData.delegationError || undefined
            }))
        };

        return list;
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getExternalQueueKey() {
        return `${REDIS_PREFIX}iap:${this.account}`;
    }

    // Shared log entry for unserializeAccountData() failures. The raw value is withheld on
    // purpose: imap/smtp/oauth2 payloads may carry cleartext credentials when no EENGINE_SECRET is
    // set, so only its length is logged. `ownerAccount` is the row's own marker when available -
    // listAccounts() unserializes other accounts' rows on an instance whose own account id is false.
    logUnserializeFailure(msg, key, rawValue, ownerAccount, err) {
        this.logger.error({
            msg,
            key,
            valueLength: (rawValue || '').toString().length,
            account: ownerAccount || this.account || undefined,
            err
        });
    }

    unserializeAccountData(accountData) {
        const result = {};

        // The loop below drops every `_`-prefixed field, which is what keeps the auth-failure marker
        // out of API responses - but the state label and the recovery paths both need it, and it is
        // already in every hash read. Carry it across explicitly, under a name that is NOT the
        // stored field's: a loaded account fed back through serializeAccountData then cannot
        // resurrect a marker that has since been retired.
        if (accountData[AUTH_FAILURE_DISABLED_FIELD]) {
            result._authFailureDisabledAt = accountData[AUTH_FAILURE_DISABLED_FIELD];
        }

        const counters = {};

        Object.keys(accountData).forEach(key => {
            if (key.startsWith('_')) {
                return; //ignore
            }

            let countMatch = key.match(/^stats:count:([^:]+):([^:]+)/);
            if (countMatch) {
                const [, type, counter] = countMatch;
                if (!counters[type]) {
                    counters[type] = {};
                }

                if (!counters[type][counter]) {
                    counters[type][counter] = 0;
                }

                counters[type][counter] = Number(accountData[key]);
                return;
            }

            switch (key) {
                case 'notifyFrom':
                case 'syncFrom':
                case 'lastWatch':
                    // Date object
                    if (accountData[key]) {
                        if (accountData[key] === 'null') {
                            result[key] = null;
                        } else {
                            let date = new Date(accountData[key]);
                            if (date.toString() !== 'Invalid Date') {
                                result[key] = date;
                            }
                        }
                    }
                    break;

                // boolean values
                case 'copy':
                case 'logs':
                    if (accountData[key] && accountData[key] !== 'null') {
                        result[key] = accountData[key] === 'true' ? true : false;
                    }
                    break;

                case 'expectedEmail':
                    // '' is the cleared marker written by serializeAccountData - report it as unset.
                    if (accountData[key]) {
                        result[key] = accountData[key];
                    }
                    break;

                case 'path':
                    if (!accountData[key] || !accountData[key].length) {
                        break;
                    }
                    if (accountData[key].length > 1 && (/^"|"$/.test(accountData[key]) || /^\[|\]$/.test(accountData[key]))) {
                        // seems like JSON array or string
                        try {
                            let value = JSON.parse(accountData[key]);
                            if (value === null) {
                                break;
                            }
                            result[key] = value;
                        } catch (err) {
                            this.logUnserializeFailure('Failed to parse input from Redis', key, accountData[key], accountData.account, err);
                        }
                    } else {
                        // regular string
                        result[key] = accountData[key];
                    }
                    break;

                // generic JSON values
                case 'webhooksCustomHeaders':
                case 'subconnections':
                case 'watchResponse':
                case 'watchFailure':
                    try {
                        let value = JSON.parse(accountData[key]);
                        if (value === null) {
                            break;
                        }
                        result[key] = value;
                    } catch (err) {
                        this.logUnserializeFailure('Failed to parse input from Redis', key, accountData[key], accountData.account, err);
                    }
                    break;

                case 'outlookSubscription':
                    try {
                        let value = JSON.parse(accountData[key]);
                        if (value === null) {
                            break;
                        }

                        if (value.expirationDateTime) {
                            let expirationDateTime = new Date(value.expirationDateTime);
                            if (expirationDateTime.toString() === 'Invalid Date') {
                                expirationDateTime = null;
                            }
                            value.expirationDateTime = expirationDateTime;
                        }

                        result[key] = value;
                    } catch (err) {
                        this.logUnserializeFailure('Failed to parse input from Redis', key, accountData[key], accountData.account, err);
                    }
                    break;

                case 'imap':
                case 'smtp':
                case 'imapServerInfo':
                case 'smtpServerEhlo':
                case 'oauth2':
                case 'lastErrorState':
                case 'syncError':
                case 'smtpStatus':
                case 'webhookErrorFlag':
                    try {
                        let value = JSON.parse(accountData[key]);
                        if (value === null) {
                            break;
                        }
                        result[key] = value;
                        for (let subKey of ['created', 'expires', 'generated']) {
                            if (result[key][subKey]) {
                                let dateVal = /^[0-9]+$/.test(result[key][subKey]) ? Number(result[key][subKey]) : result[key][subKey];
                                let date = new Date(dateVal);
                                if (date.toString() !== 'Invalid Date') {
                                    result[key][subKey] = date;
                                }
                            }
                        }
                        for (let subKey of Object.keys(result[key])) {
                            if (result[key][subKey] === null) {
                                delete result[key][subKey];
                            }
                        }
                    } catch (err) {
                        this.logUnserializeFailure('Failed to parse input from Redis', key, accountData[key], accountData.account, err);
                    }
                    break;

                // number values
                case 'connections':
                case 'listRegistry':
                case 'runIndex':
                    result[key] = Number(accountData[key]) || 0;
                    break;

                default:
                    result[key] = accountData[key];
                    break;
            }
        });

        // decrypt secrets
        if (this.secret) {
            for (let type of ['imap', 'smtp', 'oauth2']) {
                if (result[type] && result[type].auth) {
                    for (let key of ['pass', 'accessToken', 'refreshToken']) {
                        if (key in result[type].auth) {
                            try {
                                result[type].auth[key] = decrypt(result[type].auth[key], this.secret);
                            } catch (err) {
                                // ignore??
                                this.logUnserializeFailure('Failed to decrypt value', key, result[type].auth[key], result.account, err);
                            }
                        } else if (key in result[type]) {
                            try {
                                result[type][key] = decrypt(result[type][key], this.secret);
                            } catch (err) {
                                // ignore??
                                this.logUnserializeFailure('Failed to decrypt value', key, result[type][key], result.account, err);
                            }
                        }
                    }
                }
            }
        }

        if (!result.path) {
            // by default listen changes on all folders
            result.path = '*';
        }

        if (typeof result.account === 'undefined') {
            result.account = null;
        }

        // falls back to oauth2 username as the email address if email address is not set
        if (!result.email && result?.oauth2?.auth?.user && isEmail(result?.oauth2?.auth?.user)) {
            result.email = result.oauth2.auth.user;
        }

        result.counters = counters;

        return result;
    }

    serializeAccountData(accountData) {
        let result = {};

        Object.keys(accountData).forEach(key => {
            if (key.startsWith('_')) {
                // ignore
                return;
            }
            switch (key) {
                case 'notifyFrom':
                case 'syncFrom':
                case 'lastWatch':
                    // Date object
                    if (accountData[key] === 'now') {
                        result[key] = new Date().toISOString();
                    } else if (
                        accountData[key] &&
                        typeof accountData[key] === 'object' &&
                        typeof accountData[key].toISOString === 'function' &&
                        accountData[key].toString() !== 'Invalid Date'
                    ) {
                        result[key] = accountData[key].toISOString();
                    } else if (typeof accountData[key] === 'string') {
                        let date = new Date(accountData[key]);
                        if (date.toString() !== 'Invalid Date') {
                            result[key] = date.toISOString();
                        }
                    } else if (accountData[key] === null) {
                        result[key] = 'null';
                    }
                    break;

                case 'path':
                    if (
                        accountData[key] === null ||
                        accountData[key] === '*' ||
                        (Array.isArray(accountData[key]) && (accountData[key].length === 0 || (accountData[key].length === 1 && accountData[key][0] === '*')))
                    ) {
                        result[key] = '';
                    } else {
                        try {
                            result[key] = JSON.stringify(accountData[key]);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to stringify input for Redis', key, account: this.account, err });
                        }
                    }
                    break;

                // generic JSON values
                case 'subconnections':
                case 'webhooksCustomHeaders':
                case 'watchResponse':
                case 'watchFailure':
                    try {
                        let value = JSON.stringify(accountData[key]);

                        result[key] = value;
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to stringify input for Redis', key, account: this.account, err });
                    }

                    break;

                case 'outlookSubscription':
                    try {
                        let objValue = Object.assign({}, accountData[key]);

                        if (['number', 'string'].includes(typeof objValue.expirationDateTime)) {
                            objValue.expirationDateTime = new Date(objValue.expirationDateTime);
                        }

                        if (
                            objValue.expirationDateTime &&
                            typeof objValue.expirationDateTime === 'object' &&
                            typeof objValue.expirationDateTime.toISOString === 'function' &&
                            objValue.expirationDateTime.toString() !== 'Invalid Date'
                        ) {
                            objValue.expirationDateTime = objValue.expirationDateTime.toISOString();
                        } else if (objValue.expirationDateTime) {
                            objValue.expirationDateTime = null;
                        }

                        let value = JSON.stringify(objValue);

                        result[key] = value;
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to stringify input for Redis', key, account: this.account, err });
                    }

                    break;

                case 'imap':
                case 'smtp':
                case 'oauth2':
                    try {
                        // make a deep copy for manipulation
                        let connectData = JSON.parse(JSON.stringify(accountData[key]));

                        // if possible encrypt passwords
                        if (this.secret && connectData.auth) {
                            for (let key of ['pass', 'accessToken', 'refreshToken']) {
                                if (key in connectData.auth) {
                                    try {
                                        connectData.auth[key] = encrypt(connectData.auth[key], this.secret);
                                    } catch (err) {
                                        this.logger.error({ msg: 'Failed to encrypt value', key, account: this.account, err });
                                    }
                                } else if (key in connectData) {
                                    try {
                                        connectData[key] = encrypt(connectData[key], this.secret);
                                    } catch (err) {
                                        this.logger.error({ msg: 'Failed to encrypt value', key, account: this.account, err });
                                    }
                                }
                            }
                        }

                        for (let subKey of ['created', 'expires', 'generated']) {
                            if (
                                accountData[key][subKey] &&
                                typeof accountData[key][subKey] === 'object' &&
                                accountData[key][subKey].toString() !== 'Invalid Date'
                            ) {
                                connectData[subKey] = accountData[key][subKey].toISOString();
                            }
                        }

                        result[key] = JSON.stringify(connectData);
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to stringify input for Redis', key, account: this.account, err });
                    }
                    break;

                case 'webhooks':
                    if (typeof accountData[key] !== 'undefined' && accountData[key] !== null && typeof accountData[key].toString === 'function') {
                        result[key] = accountData[key].toString();
                        if (!result[key]) {
                            // clear potential error flag
                            result.webhookErrorFlag = '{}';
                        }
                    }
                    break;

                // boolean values
                case 'copy':
                case 'logs':
                    if (typeof accountData[key] === 'boolean') {
                        result[key] = accountData[key].toString();
                    } else if (accountData[key] === null) {
                        result[key] = '';
                    }
                    break;

                case 'expectedEmail':
                    // Clearable, so it cannot ride the default branch: that drops nulls, and hmset only
                    // ever adds keys, which would leave an identity pin settable but never removable.
                    // Follows the same convention as `copy` above - null serializes to the empty marker
                    // and unserialize treats it as unset - rather than adding a per-field delete to
                    // persistUpdate.
                    if (typeof accountData[key] === 'string' || accountData[key] === null) {
                        result[key] = accountData[key] || '';
                    }
                    break;

                default:
                    if (typeof accountData[key] !== 'undefined' && accountData[key] !== null && typeof accountData[key].toString === 'function') {
                        result[key] = accountData[key].toString();
                    }
                    break;
            }
        });

        return result;
    }

    async loadAccountData(account, requireValid, runIndex) {
        if (!this.account || (account && account !== this.account)) {
            let message = 'Invalid account ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let result = await this.redis.hgetall(this.getAccountKey());

        if (!result || !result.account) {
            let message = 'Account record was not found for requested ID';
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            throw error;
        }

        let accountData = this.unserializeAccountData(result);

        if (accountData.oauth2 && accountData.oauth2.provider) {
            let app = await oauth2Apps.get(accountData.oauth2.provider);
            if (app) {
                if (isApiBasedApp(app)) {
                    accountData.isApi = true;
                }

                // Check if this is a send-only OAuth2 API account (Gmail or Outlook, regardless of baseScopes setting)
                if (this.isSendOnlyAccount(accountData, app)) {
                    accountData.isApi = true;
                    accountData.sendOnly = true;
                }

                accountData._app = app;
            }
        } else if (accountData.oauth2 && accountData.oauth2.auth && accountData.oauth2.auth.delegatedAccount) {
            try {
                let delegatedAccount = await resolveDelegatedAccount(this.redis, accountData.account);
                if (delegatedAccount) {
                    accountData.delegatedAccount = delegatedAccount;
                    let delegatedAccountRow = await this.redis.hgetall(`${REDIS_PREFIX}iad:${delegatedAccount}`);
                    let delegatedAccountData = this.unserializeAccountData(delegatedAccountRow);
                    if (delegatedAccountData.oauth2 && delegatedAccountData.oauth2.provider) {
                        let app = await oauth2Apps.get(delegatedAccountData.oauth2.provider);
                        if (app) {
                            accountData._app = app;
                            if (isApiBasedApp(app)) {
                                accountData.isApi = true;
                            }
                        }
                    }
                }
            } catch (err) {
                this.logger.warn({
                    msg: 'Failed to resolve delegated account',
                    account: accountData.account,
                    delegatedAccount: accountData.oauth2.auth.delegatedAccount,
                    err
                });
                accountData.delegationError = err.message;
            }
        }

        accountData.state = calculateEffectiveState(accountData, runIndex);

        if (requireValid) {
            validateAccountState(accountData);
        }

        return accountData;
    }

    /**
     * Applies an account update, serialized per account.
     *
     * persistUpdate() is a read-modify-write: it loads the stored account, merges partial
     * `imap`/`smtp`/`oauth2` objects into what it read, and writes the result back. Two writers
     * interleaving there silently lose one of the merges - the case that matters is an unattended
     * OAuth2 token refresh landing between an admin update's read and its write, which puts the
     * stale refreshToken back and leaves the account unable to authenticate until someone
     * reauthorizes it by hand. The same check-then-set applies to the OAuth2 user uniqueness
     * check inside. The lock covers that half only; see dispatchPostUpdateCommands().
     *
     * Lock acquisition failing is not treated as an error. The critical section is a handful of
     * Redis round trips, so a timeout here means Redis is already in trouble; refusing the write
     * would take out token refreshes for every account rather than losing a rare merge.
     *
     * @param {Object} accountData - Account fields to write
     * @param {Object} [opts]
     * @param {boolean} [opts.reauthorized] - Marks an update carrying credentials supplied by an
     *   external caller, i.e. possible operator re-authorization. Only the public account-update
     *   API route sets it; every unattended writer (token renewal, client initialize(),
     *   invalidateAccessToken) leaves it false and can therefore never trigger the reconnect gate.
     * @returns {Promise<Object>} `{ account }`
     */
    async update(accountData, { reauthorized = false } = {}) {
        // Captured before persistUpdate() merges a `partial` payload into the stored object
        const disabledIntent = imapDisabledIntent(accountData);

        const lock = this.getLock();
        const lockKey = `account:update:${accountData.account}`;
        let updateLock;

        let lockErr;
        try {
            updateLock = await lock.waitAcquireLock(lockKey, ACCOUNT_UPDATE_LOCK_TTL, ACCOUNT_UPDATE_LOCK_WAIT);
        } catch (err) {
            lockErr = err;
        }

        if (!updateLock?.success) {
            this.logger.warn({ msg: 'Failed to get account update lock, proceeding unserialized', account: accountData.account, lockKey, err: lockErr });
        }

        let oldAccountData;
        try {
            oldAccountData = await this.persistUpdate(accountData);
        } finally {
            if (updateLock?.success) {
                try {
                    await lock.releaseLock(updateLock);
                } catch (err) {
                    // The lock expires on its own, so a failed release must not mask the result
                    this.logger.warn({ msg: 'Failed to release account update lock', account: accountData.account, lockKey, err });
                }
            }
        }

        await this.dispatchPostUpdateCommands(accountData, oldAccountData, reauthorized, disabledIntent);

        return {
            account: this.account
        };
    }

    /**
     * The read-modify-write half of update(): loads the stored account, merges partial credential
     * objects into it and writes the result back. Runs under the update lock.
     *
     * @param {Object} accountData - Account fields to write
     * @returns {Promise<Object>} The account as it was before the write
     */
    async persistUpdate(accountData) {
        let oldAccountData = await this.loadAccountData(accountData.account);

        if (accountData.oauth2?.provider) {
            // check if this OAuth2 provider exists
            let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                let message = 'Invalid or missing OAuth2 provider';
                let error = Boom.boomify(new Error(message), { statusCode: 400 });
                throw error;
            }
        }

        let removeProvider;
        let addProvider;

        if (accountData.oauth2?.provider) {
            addProvider = accountData.oauth2.provider;
            if (oldAccountData.oauth2?.provider && oldAccountData.oauth2.provider !== accountData.oauth2.provider) {
                removeProvider = oldAccountData.oauth2.provider;
            }
        }

        for (let subKey of ['imap', 'smtp', 'oauth2']) {
            if (!accountData[subKey] || typeof accountData[subKey] !== 'object') {
                continue;
            }
            let partial = accountData[subKey].partial;
            delete accountData[subKey].partial;
            if (!partial) {
                continue;
            }

            // merge old and new values
            if (!oldAccountData[subKey]) {
                // nothing to merge
                continue;
            }

            mergeObjects(accountData[subKey], oldAccountData[subKey]);
        }

        // An update whose payload serializes to nothing - an empty request, say - must not reach hmset:
        // Redis rejects a write with no field/value pairs outright ("wrong number of arguments"), which
        // surfaced as a 500 on a perfectly valid request.
        const updatedFields = this.serializeAccountData(accountData);

        let pipeline = this.redis.multi();
        if (Object.keys(updatedFields).length) {
            pipeline = pipeline.hmset(this.getAccountKey(), updatedFields);
        }

        if (addProvider) {
            pipeline = pipeline.sadd(`${REDIS_PREFIX}oapp:a:${addProvider}`, this.account);
            if (accountData._oldOAuth2User && accountData._oldOAuth2User.toLowerCase() !== accountData.oauth2.auth?.user?.toLowerCase()) {
                pipeline = pipeline.hdel(`${REDIS_PREFIX}oapp:h:${addProvider}`, accountData._oldOAuth2User.toLowerCase());
            }
            if (accountData.oauth2?.auth?.user) {
                // check if already exists
                let existingAppBinding = await this.redis.hget(
                    `${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`,
                    accountData.oauth2.auth?.user?.toLowerCase()
                );
                if (existingAppBinding && existingAppBinding !== this.account) {
                    let existingAccount;
                    try {
                        existingAccount = await this.loadAccountData(existingAppBinding);
                    } catch (err) {
                        // account not found
                    }

                    if (existingAccount?.oauth2?.auth?.user === accountData.oauth2.auth?.user) {
                        let message = 'Another account for the same OAuth2 user already exists';
                        let error = Boom.boomify(new Error(message), { statusCode: 400 });
                        error.output.payload.code = 'AccountAlreadyExists';
                        error.output.payload.existingAccount = existingAppBinding;
                        throw error;
                    }
                }
                pipeline = pipeline.hset(`${REDIS_PREFIX}oapp:h:${addProvider}`, accountData.oauth2?.auth?.user?.toLowerCase(), this.account);
            }
        }

        if (removeProvider) {
            pipeline = pipeline.srem(`${REDIS_PREFIX}oapp:a:${removeProvider}`, this.account);
            if (oldAccountData.oauth2?.auth?.user) {
                pipeline = pipeline.hdel(`${REDIS_PREFIX}oapp:h:${removeProvider}`, oldAccountData.oauth2?.auth?.user?.toLowerCase());
            }
        }

        // Surface the first failing reply. Checked by scanning rather than by reading a fixed index: the
        // hmset is now conditional, so a positional read would silently start asserting against whichever
        // command happened to be queued first.
        for (let [err] of (await pipeline.exec()) || []) {
            if (err) {
                throw err;
            }
        }

        return oldAccountData;
    }

    /**
     * Dispatches the reconnect/update commands a persisted change implies.
     *
     * Deliberately runs outside the update lock. These are RPCs into the IMAP worker, and the
     * connection setup they trigger can itself persist an account change (a token renewal during
     * connect), so holding the lock across them would make a writer wait on its own dispatch.
     * Nothing here writes account data; it only compares what was read against what was written.
     *
     * @param {Object} accountData - The fields that were just written
     * @param {Object} oldAccountData - The account as it was before the write
     * @param {boolean} reauthorized - Whether the caller supplied fresh operator credentials
     * @param {Boolean|null} disabledIntent - What the payload asked of `imap.disabled`, read before
     *   persistUpdate() merged it
     * @returns {Promise<void>} Resolves once the dispatch has been attempted
     */
    async dispatchPostUpdateCommands(accountData, oldAccountData, reauthorized, disabledIntent) {
        const reconnectRequested =
            ('imap' in accountData && !isDeepStrictEqual(oldAccountData.imap, accountData.imap)) ||
            ('path' in accountData && JSON.stringify(oldAccountData.path || '*') !== JSON.stringify(accountData.path || '*')) ||
            ('subconnections' in accountData && !isDeepStrictEqual(oldAccountData.subconnections, accountData.subconnections));

        // Whether this update carries OAuth2 credentials the operator just re-authorized. The
        // `reauthorized` intent has to be explicit: account state cannot be used to infer it,
        // because unattended token renewal persists through update() as well, and it runs while
        // the stored state is still the error state. A state-only gate re-fired on every renewal
        // and dispatched cmd:'reconnect'. That rebuilt the client, discarding its backoff, and
        // invalidateAccessToken() forced the next cycle to renew again - latching a reconnect
        // loop that pinned the CPU at ~100%.
        const oauth2Reauthorized =
            reauthorized &&
            !!accountData.oauth2?.accessToken &&
            (accountData.oauth2.accessToken !== oldAccountData.oauth2?.accessToken || accountData.oauth2.refreshToken !== oldAccountData.oauth2?.refreshToken);

        // The password-account counterpart: new IMAP credentials from the same flagged route. The
        // API documents that saving new IMAP settings resumes a switched-off account, and the
        // documented way to save them is a `partial` write of `imap.auth` - which persistUpdate()
        // has by now merged the stored `disabled: true` into, so the intent captured before the
        // merge says nothing and this is what carries the lift.
        const imapReauthorized = reauthorized && !!accountData.imap?.auth && !isDeepStrictEqual(accountData.imap.auth, oldAccountData.imap?.auth);

        // A reconnect cannot resume an account the auth-failure safety net has switched off, so
        // settle that first, before any dispatch: the worker acts on the stored flag, so an update
        // sent ahead of the lift finds the account still switched off and reports `unset`. For a
        // password account the operator clears the flag by saving new IMAP settings, but an OAuth2
        // account has none to save - the re-authorization IS the fix, and without this the account
        // stays off until somebody hand-edits it through the API.
        //
        // The lift is deliberately NOT gated on the account state, unlike the reconnect below: a
        // parked account does not sit in an error state, it reports `unset` (persisted on every
        // init for Gmail API and Outlook accounts), so by the time the operator re-authorizes, the
        // error state the old gate required is long gone.
        await this.resolveAuthFailureDisable(disabledIntent, oldAccountData, oauth2Reauthorized || imapReauthorized);

        // Re-authorization for an account that is currently non-operational triggers a full
        // reconnect so syncing resumes without a manual "Reconnect". Being switched off is such a
        // state, and one the account cannot leave on its own. Read off the account as it stood
        // before the write, for the same reason as in create().
        const wasParked = !!authFailureDisabledAt(oldAccountData);

        if (oauth2Reauthorized && (ERROR_STATES.includes(oldAccountData.state) || wasParked)) {
            this.logger.info({
                msg: 'OAuth2 credentials re-authorized for non-operational account, requesting reconnect',
                account: this.account,
                state: oldAccountData.state,
                wasParked
            });

            if (typeof this.call === 'function') {
                try {
                    await this.call({
                        cmd: 'reconnect',
                        account: this.account,
                        timeout: this.timeout
                    });
                } catch (err) {
                    // Credentials are already persisted; a failed reconnect dispatch must not turn a
                    // saved credential update into an error response. The next periodic reconnect
                    // recovers. Log and continue.
                    this.logger.error({ msg: 'Failed to request reconnect after credential update', account: this.account, state: oldAccountData.state, err });
                }
            } else {
                // This Account instance has no parent RPC channel (constructed without `call`).
                // Skip the dispatch instead of throwing - credentials are already persisted and the
                // next periodic reconnect recovers. Warn rather than error so this is not reported
                // as a handled crash.
                this.logger.warn({
                    msg: 'Skipping reconnect request after credential update, no parent RPC channel',
                    account: this.account,
                    state: oldAccountData.state
                });
            }
        } else if (reconnectRequested) {
            // Changes detected. The full reconnect above supersedes this: it assigns a fresh
            // client, which reads the changed settings on its way in.
            this.logger.info({ msg: 'IMAP configuration changed for account', account: this.account });
            if (typeof this.call === 'function') {
                await this.call({
                    cmd: 'update',
                    account: this.account,
                    timeout: this.timeout
                });
            } else {
                // This Account instance has no parent RPC channel (constructed without `call`).
                // Skip the dispatch instead of throwing - the persisted change stands.
                this.logger.warn({ msg: 'Skipping update command dispatch, no parent RPC channel', account: this.account });
            }
        }
    }

    async genId() {
        let id;
        let retries = 0;
        while (retries++ < 20) {
            id = nanoid();
            let alreadyExists = await this.redis.hexists(`${REDIS_PREFIX}iad:${id}`, 'account');
            if (alreadyExists) {
                id = false;
            } else {
                break;
            }
        }
        return id;
    }

    /**
     * Resolves the auth-failure disable against an account write that has just been persisted.
     *
     * @param {Boolean|null} disabledIntent - What the write asked of `imap.disabled`, from
     *   imapDisabledIntent(), read before any partial merge
     * @param {Object} oldAccountData - The account as it stood before the write
     * @param {Boolean} mayLift - Whether this write is an explicit re-authorization, the only kind
     *   that may resume a parked account on its own
     * @returns {Promise<Boolean>} True when this call re-enabled the account
     */
    async resolveAuthFailureDisable(disabledIntent, oldAccountData, mayLift) {
        if (disabledIntent === true) {
            // The write asks for IMAP to stay off, so there is nothing to lift. It takes ownership
            // of the flag only when it is what turned it on: the admin edit form submits its
            // "Disable IMAP" checkbox on every save, pre-checked from the stored flag, so treating
            // that restatement as a decision would let an unrelated save silently convert an
            // automatic park into a deliberate one - taking the page alert, the state badge and
            // "Resume syncing" with it, and leaving the account unrecoverable by re-authorization.
            if (!isImapDisabled(oldAccountData)) {
                await this.redis.hdel(this.getAccountKey(), AUTH_FAILURE_DISABLED_FIELD);
            }
            return false;
        }

        // An explicit `disabled: false` has already re-enabled the account by itself, and the call
        // below retires the marker it leaves behind. Anything else may only lift a park when the
        // operator actually re-authorized.
        if (disabledIntent === false || mayLift) {
            return await this.clearAuthFailureDisable();
        }

        return false;
    }

    /**
     * Re-enables an account that setErrorState() switched off after a run of authentication
     * failures. Called whenever fresh credentials arrive for the account, and by the admin UI's
     * "Resume syncing" action.
     *
     * Only ever lifts the safety net's own disable, never the operator's send-only switch - see
     * AUTH_FAILURE_DISABLED_FIELD for why the two need telling apart.
     *
     * Reads the stored values rather than trusting the copy loaded before the update, because the
     * same update may have rewritten the `imap` field.
     *
     * @returns {Promise<Boolean>} True when a disable flag was actually lifted
     */
    async clearAuthFailureDisable() {
        const accountKey = this.getAccountKey();

        const [disabledAt, imapInfo] = await this.redis.hmget(accountKey, AUTH_FAILURE_DISABLED_FIELD, 'imap');
        if (!disabledAt) {
            // Either never parked, or an operator has already dealt with it. Not ours to lift.
            return false;
        }

        const { imapData, invalid } = await readImapData(this.redis, accountKey, this.logger, imapInfo);
        if (invalid) {
            // Leave an unreadable configuration alone rather than replacing it with a bare flag.
            return false;
        }

        if (!imapData || !imapData.disabled) {
            // The flag is already gone - an operator re-enabled the account by hand, or a full
            // `imap` rewrite dropped it. Retire the marker so it cannot authorize lifting a
            // later, deliberate disable.
            await this.redis.hdel(accountKey, AUTH_FAILURE_DISABLED_FIELD);
            return false;
        }

        imapData.disabled = false;

        // hSetExists rather than hset, so a concurrent account delete cannot be resurrected as a
        // hash holding nothing but this flag. Same reason disableAfterAuthFailures() writes it
        // that way.
        const clearTxn = createTransaction(this.redis, { logger: this.logger });
        clearTxn.add('hSetExists', accountKey, 'imap', JSON.stringify(imapData));
        clearTxn.add('hdel', accountKey, AUTH_FAILURE_DISABLED_FIELD);
        const { error } = await clearTxn.exec();

        if (error) {
            // Report what happened rather than a lifted flag the caller would follow with a
            // reconnect into an account that is still switched off.
            this.logger.error({ msg: 'Failed to re-enable IMAP for account', account: this.account, err: error });
            return false;
        }

        this.logger.info({ msg: 'Re-enabled IMAP for account after re-authorization', account: this.account, disabledAt });

        return true;
    }

    async create(accountData) {
        this.account = accountData.account;
        if (this.account === null) {
            // auogenerate ID
            this.account = accountData.account = await this.genId();
        }

        if (!this.account) {
            let message = 'Invalid account ID';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            throw error;
        }

        let oauth2App;
        if (accountData.oauth2 && accountData.oauth2.provider) {
            // check if this OAuth2 provider exists
            oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                let message = 'Invalid or missing OAuth2 provider';
                let error = Boom.boomify(new Error(message), { statusCode: 400 });
                throw error;
            }
        }

        if (!accountData.imapIndexer && (accountData.imap || (oauth2App && (!oauth2App.baseScopes || oauth2App.baseScopes === 'imap')))) {
            accountData.imapIndexer = (await settings.get('imapIndexer')) || 'full';
        }

        const runIndex = await this.call({
            cmd: 'runIndex'
        });

        let pipeline = this.redis
            .multi()
            .hgetall(this.getAccountKey())
            .hmset(this.getAccountKey(), this.serializeAccountData(accountData))
            .hsetnx(this.getAccountKey(), 'state', ACCOUNT_STATES.INIT)
            .hsetnx(this.getAccountKey(), 'runIndex', runIndex.toString())
            .hsetnx(this.getAccountKey(), `state:count:${ACCOUNT_STATES.CONNECTED}`, '0')
            .sadd(`${REDIS_PREFIX}ia:accounts`, this.account);

        if (accountData.oauth2 && accountData.oauth2.provider) {
            pipeline = pipeline.sadd(`${REDIS_PREFIX}oapp:a:${accountData.oauth2.provider}`, this.account);
            if (accountData.oauth2.auth?.user) {
                // check if already exists
                let existingAppBinding = await this.redis.hget(
                    `${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`,
                    accountData.oauth2.auth?.user?.toLowerCase()
                );
                if (existingAppBinding && existingAppBinding !== this.account) {
                    let existingAccount;
                    try {
                        existingAccount = await this.loadAccountData(existingAppBinding);
                    } catch (err) {
                        // account not found
                    }

                    if (existingAccount?.oauth2?.auth?.user === accountData.oauth2.auth?.user) {
                        let message = 'Another account for the same OAuth2 user already exists';
                        let error = Boom.boomify(new Error(message), { statusCode: 400 });
                        error.output.payload.code = 'AccountAlreadyExists';
                        error.output.payload.existingAccount = existingAppBinding;
                        throw error;
                    }
                }

                pipeline = pipeline.hset(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user?.toLowerCase(), this.account);
            }
        }

        let result = await pipeline.exec();

        if (!result || !result[1] || result[1][0] || result[1][1] !== 'OK') {
            let message = 'Something went wrong';
            let error = Boom.boomify(new Error(message), { statusCode: 500 });
            throw error;
        }

        let state;
        if (result[0][1] && result[0][1].account) {
            // existing user
            state = 'existing';

            // The account as it stood before the hmset above, from the snapshot the same pipeline
            // took. Read twice below - for the provider rebinding and for the recovery dispatch -
            // so it is unserialized once, outside the guard that only covers the rebinding.
            let oldAccountData = {};
            try {
                oldAccountData = this.unserializeAccountData(result[0][1]);
            } catch (err) {
                this.logger.error({ msg: 'Failed to read the stored account', account: this.account, err });
            }

            try {
                if (oldAccountData?.oauth2?.provider && oldAccountData?.oauth2?.auth?.user && oldAccountData.oauth2.provider !== accountData.oauth2?.provider) {
                    // remove previous entry if provider was updated
                    await this.redis.hdel(`${REDIS_PREFIX}oapp:h:${oldAccountData.oauth2.provider}`, oldAccountData.oauth2.auth?.user?.toLowerCase());
                }
            } catch (err) {
                // ignore
            }

            // Re-registration is the operator supplying fresh credentials, and for an account the
            // auth-failure safety net has switched off it is the whole fix: the hosted
            // authentication form and POST /v1/account both land here, and neither has any other
            // way to reach the flag. Without this an OAuth2 account stayed parked no matter how
            // many times it was re-authorized, because create() writes no `imap` field of its own
            // and the synthesized `{"disabled":true}` blob survived untouched.
            //
            // The reconnect is decided by what was stored BEFORE this write, not by whether the
            // flag ended up lifted: a payload asking for IMAP to stay off lifts nothing, and either
            // way the account was not connecting and this write is what changed that.
            const wasParked = !!authFailureDisabledAt(oldAccountData);

            // A password configuration means nothing on an OAuth2 account: getImapConfig() builds
            // the connection from the provider table and reads `imap` only when there is no OAuth2
            // credential. So when a re-registration switches the account to OAuth2, the stored one
            // is left over from the account's previous life, and left in place its `disabled` flag
            // switches the new account off - the API clients honor the flag since the safety net
            // started writing it - with no marker, no badge, and no IMAP card to clear it from. A
            // password account the safety net parked, then re-registered with OAuth2 under the same
            // id, is exactly that account.
            const credentialTypeChanged = !!(accountData.oauth2 && !('imap' in accountData) && oldAccountData.imap?.host);
            if (credentialTypeChanged) {
                // The marker goes with the blob: a dropped configuration carries no park to lift
                await this.redis.hdel(this.getAccountKey(), 'imap', AUTH_FAILURE_DISABLED_FIELD);
                this.logger.info({ msg: 'Dropped the stored IMAP configuration of an account re-registered with OAuth2', account: this.account });
            } else {
                await this.resolveAuthFailureDisable(imapDisabledIntent(accountData), oldAccountData, true);
            }

            const oldState = result[0][1].state;
            // The credential type changing is a reason of its own for the full reconnect: the
            // assigned client is of the old type, and cmd:'update' cannot switch it.
            if (ERROR_STATES.includes(oldState) || wasParked || credentialTypeChanged) {
                // Re-registration of an account that is not operational (the interactive OAuth
                // re-auth redirect and the IMAP re-credentials form both land here).
                // cmd:'update' only calls reconnect() on the existing client instance, which cannot
                // switch client type (IMAP to API or back) and is a no-op against a torn-down
                // connection, so syncing would not resume without a manual "Reconnect". cmd:'reconnect'
                // closes and re-assigns a fresh client of the correct provider type. assignConnection
                // sets the state to "connecting" before any network work, so this cannot loop.
                // Needs no credential-change check (unlike update()): create() runs only on explicit
                // re-registration, never on routine token renewal, so there is no healthy-account
                // churn to suppress here.
                this.logger.info({
                    msg: 'Account re-created while not operational, requesting full reconnect',
                    account: this.account,
                    state: oldState,
                    wasParked
                });
                try {
                    await this.call({
                        cmd: 'reconnect',
                        account: this.account,
                        timeout: this.timeout
                    });
                } catch (err) {
                    // Credentials are already persisted (the hmset above returned OK). A failed
                    // reconnect dispatch must not fail the re-auth or surface a 500; the next periodic
                    // reconnect or a manual Reconnect will recover. Log and continue.
                    this.logger.error({ msg: 'Failed to request reconnect after re-auth', account: this.account, state: oldState, err });
                }
            } else {
                await this.call({
                    cmd: 'update',
                    account: this.account,
                    timeout: this.timeout
                });
            }
        } else {
            state = 'new';
            await this.call({
                cmd: 'new',
                account: this.account,
                timeout: this.timeout
            });
        }

        return { account: this.account, state };
    }

    async delete(opts) {
        opts = opts || {};

        let accountData = await this.loadAccountData(this.account);

        if (opts.revoke && accountData.oauth2?.provider) {
            // Prefer refresh token over access token: revoking either invalidates the grant per Google's docs,
            // but the stored access token may be expired (a 400 from the provider would leave the grant intact),
            // while the refresh token is long-lived. Skip gmailService - Workspace service accounts have no
            // per-user grant to revoke.
            let token = accountData.oauth2.refreshToken || accountData.oauth2.accessToken;
            if (token) {
                try {
                    let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
                    if (oauth2App && oauth2App.provider !== 'gmailService') {
                        let oauthClient = await oauth2Apps.getClient(accountData.oauth2.provider, { logger: this.logger });
                        if (oauthClient && typeof oauthClient.revokeToken === 'function') {
                            await oauthClient.revokeToken(token);
                        }
                    }
                } catch (err) {
                    this.logger.warn({ msg: 'Failed to revoke OAuth2 grant before account delete', account: this.account, err });
                }
            }
        }

        const dateKeyTdy = new Date().toISOString().substring(0, 10).replace(/-/g, '');
        const dateKeyYdy = new Date(Date.now() - 24 * 3600 * 1000).toISOString().substring(0, 10).replace(/-/g, '');

        const tombstoneTdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyTdy}`;
        const tombstoneYdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyYdy}`;

        // UNLINK rather than DEL throughout: none of these need the memory reclaimed synchronously,
        // and the outbox and the message ID index can hold enough entries that freeing them inline
        // would block Redis for every other worker.
        //
        // The outbox is read and unlinked in the same transaction, because that hash is the only
        // mapping from an account to the submit queue jobs of the messages it has not delivered
        // yet, and those jobs outlive the account otherwise. Reading it here means the ID list is
        // exactly what was unlinked, and costs no extra round trip.
        let pipeline = this.redis
            .multi()
            .hkeys(`${REDIS_PREFIX}iaq:${this.account}`) // queued message IDs, removed from the submit queue below
            .unlink(this.getAccountKey())
            .srem(`${REDIS_PREFIX}ia:accounts`, this.account)
            .unlink(this.getMailboxListKey()) // mailbox list
            .unlink(this.getMailboxHashKey()) // mailbox list for ID references
            .unlink(`${REDIS_PREFIX}iar:b:${this.account}`) // bounce list
            .unlink(`${REDIS_PREFIX}iar:s:${this.account}`) // seen messages list
            .unlink(`${REDIS_PREFIX}iaq:${this.account}`) // delayed message queue
            .unlink(`${REDIS_PREFIX}iac:${this.account}`) // cache hash
            .unlink(`${REDIS_PREFIX}iap:${this.account}`) // external event notification queue

            .unlink(tombstoneTdy)
            .unlink(tombstoneYdy)

            .unlink(`${REDIS_PREFIX}tpl:${this.account}:i`) // stored templates index
            .unlink(`${REDIS_PREFIX}tpl:${this.account}:c`); // stored templates index

        if (accountData.oauth2?.provider) {
            pipeline = pipeline.srem(`${REDIS_PREFIX}oapp:a:${accountData.oauth2.provider}`, this.account);
            if (accountData.oauth2?.auth?.user) {
                pipeline = pipeline.hdel(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user?.toLowerCase());
            }
        }

        let result = await pipeline.exec();

        // The account's access tokens go with it - see tokens.deleteForAccount(), which owns the
        // account's token index too. Deliberately on this side of the transaction: while the account
        // record exists a token can still be minted against it, and both mint paths check that
        // record first, so revoking once it is unlinked closes all but a vanishing window. Best
        // effort, like the queued messages below - the account still has to go, and anything left
        // behind stays on the access token listing, marked as bound to a deleted account.
        try {
            await tokens.deleteForAccount(this.account);
        } catch (err) {
            this.logger.error({ msg: 'Failed to delete the access tokens of an account', account: this.account, err });
        }

        // Results are positional: [0] is the outbox HKEYS, [1] the account key UNLINK. Both indexes
        // move if a command is inserted ahead of them.
        let queuedMessageIds = (result && result[0] && result[0][1]) || [];
        if (queuedMessageIds.length) {
            // Best effort: the account is already gone, so a queue that will not cooperate must not
            // turn a completed deletion into an error.
            try {
                let removed = await outbox.removeJobs(queuedMessageIds, { account: this.account, logger: this.logger });
                this.logger.info({ msg: 'Removed queued messages of a deleted account', account: this.account, queued: queuedMessageIds.length, removed });
            } catch (err) {
                this.logger.error({ msg: 'Failed to remove queued messages of a deleted account', account: this.account, err });
            }
        }

        // scan and delete keys
        // should we wait though? might take a lot of time
        await redisScanDelete(this.redis, this.logger, `${REDIS_PREFIX}iam:${escapeRedisGlob(this.account)}:*`);

        if (!result || !result[1] || !result[1][1]) {
            return {
                account: this.account,
                deleted: false
            };
        }

        // Only notify the documents queue when the deprecated Document Store feature is enabled.
        // When it is off the documents worker is not running, so an enqueued job would never be
        // consumed and would pile up in Redis.
        if (documentStoreFeatureEnabled) {
            try {
                let queueKeep = (await settings.get('queueKeep')) ?? true;
                let serviceUrl = (await settings.get('serviceUrl')) || null;

                let payload = {
                    serviceUrl,
                    account: this.account,
                    date: new Date().toISOString(),
                    event: ACCOUNT_DELETED_NOTIFY
                };

                await this.documentsQueue.add(ACCOUNT_DELETED_NOTIFY, payload, {
                    ...buildRetentionPolicy(queueKeep),
                    attempts: 10,
                    backoff: {
                        type: 'exponential',
                        delay: 5000
                    }
                });
            } catch (err) {
                this.logger.error({ msg: 'Failed to add entry to documents queue', account: this.account, err });
            }
        }

        await this.call({
            cmd: 'delete',
            account: this.account,
            timeout: this.timeout
        });

        return {
            account: this.account,
            deleted: true
        };
    }

    // Creates the consumer side of a cross-thread download stream, with a guard listener:
    // the producer can post {error} before Hapi attaches its own 'error' listeners (or
    // while the setup call is still pending). Without a listener that emission is an
    // uncaught exception that kills the API worker.
    createDownloadStream(failureLogMessage) {
        const { port1, port2 } = new MessageChannel();
        const stream = new MessagePortReadable(port1);

        stream.on('error', err => {
            this.logger.error({ msg: failureLogMessage, account: this.account, err });
        });

        return { stream, port2 };
    }

    async getRawMessage(message) {
        await this.loadAccountData(this.account, true);

        const { stream, port2 } = this.createDownloadStream('Message source stream failed');

        let streamCreated;
        try {
            streamCreated = await this.call(
                {
                    cmd: 'getRawMessage',
                    account: this.account,
                    message,
                    timeout: this.timeout,
                    port: port2
                },
                [port2]
            );
        } catch (err) {
            // The setup call failed (timeout, worker gone, 404). Destroy the reader so
            // its MessagePort + listener are released instead of leaking, and so any
            // late producer data is not buffered forever.
            stream.destroy();
            throw err;
        }

        if (streamCreated && streamCreated.headers) {
            stream.headers = streamCreated.headers;
        }

        return stream;
    }

    async getAttachment(attachment) {
        await this.loadAccountData(this.account, true);

        const { stream, port2 } = this.createDownloadStream('Attachment stream failed');

        let streamCreated;
        try {
            streamCreated = await this.call(
                {
                    cmd: 'getAttachment',
                    account: this.account,
                    attachment,
                    timeout: this.timeout,
                    port: port2
                },
                [port2]
            );
        } catch (err) {
            // The setup call failed (timeout, worker gone, 404). Destroy the reader so
            // its MessagePort + listener are released instead of leaking, and so any
            // late producer data is not buffered forever.
            stream.destroy();
            throw err;
        }

        if (streamCreated && streamCreated.headers) {
            stream.headers = streamCreated.headers;
        }

        return stream;
    }

    async getMailboxListing(query) {
        let accountData = await this.loadAccountData(this.account, false);

        let mailboxListing;
        if (await this.isApiClient(accountData)) {
            mailboxListing = await this.listMailboxes(query);

            if (mailboxListing && mailboxListing.error) {
                let error = Boom.boomify(new Error(mailboxListing.error), { statusCode: mailboxListing.statusCode || 500 });
                if (mailboxListing.code) {
                    error.output.payload.code = mailboxListing.code;
                }
                throw error;
            }

            // just pass through, do nothing
            return mailboxListing;
        } else if (accountData.state === ACCOUNT_STATES.CONNECTED || query.counters) {
            // run LIST
            mailboxListing = await this.listMailboxes(query);
            if (mailboxListing && mailboxListing.error) {
                let error = Boom.boomify(new Error(mailboxListing.error), { statusCode: mailboxListing.statusCode || 500 });
                if (mailboxListing.code) {
                    error.output.payload.code = mailboxListing.code;
                }
                throw error;
            }
        } else if (accountData.state === ACCOUNT_STATES.UNSET) {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Syncing is disabled for the requested account'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            error.output.payload.code = 'NotSyncing';
            throw error;
        } else if (accountData.state === ACCOUNT_STATES.INIT || !(await this.redis.exists(this.getMailboxListKey()))) {
            // account has not been set up yet
            let error = Boom.boomify(new Error('Requested account is not yet initialized'), { statusCode: 503 });
            if (accountData.state) {
                error.output.payload.state = accountData.state;
            }
            error.output.payload.code = 'NotYetConnected';
            throw error;
        }

        let mailboxes = [];
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());

        let mailboxListingMap;
        if (mailboxListing) {
            mailboxListingMap = new Map();
            for (let entry of mailboxListing) {
                if (entry.status) {
                    delete entry.status.path;
                }
                mailboxListingMap.set(entry.path, entry);
            }
        }

        let paths = Object.keys(storedListing || {});

        // Batch into a single round-trip to avoid per-mailbox latency with many folders
        let pipeline = this.redis.pipeline();
        for (let path of paths) {
            pipeline.hgetall(getMailboxStatusKey(this.account, path));
        }
        let pipelineResults = await pipeline.exec();

        for (let i = 0; i < paths.length; i++) {
            let path = paths[i];
            try {
                // Returns false for a corrupt value. Skipping the folder (rather than pushing a
                // boxed primitive into the response) keeps the rest of the listing usable; the
                // IMAP sync purges the entry on its next pass (see getCurrentListing), which is
                // also where the corruption is escalated to the error tracker - once, with every
                // affected folder, instead of once per request from here. Until that pass runs
                // the folder is simply missing from a 200 response, which a client reconciling
                // its own state against this endpoint reads as a deletion.
                let decoded = decodeStoredMailboxEntry(storedListing[path]);
                if (!decoded) {
                    this.logger.warn({ msg: 'Skipping corrupt stored mailbox listing entry', path, account: this.account });
                    continue;
                }

                if (decoded.path && decoded.delimiter && decoded.path.indexOf(decoded.delimiter) >= 0) {
                    decoded.parentPath = decoded.path.substring(0, decoded.path.lastIndexOf(decoded.delimiter));
                }

                let listedMailboxInfo = mailboxListingMap ? mailboxListingMap.get(path) : undefined;

                let mailboxInfo = {};
                let [pipelineErr, data] = pipelineResults[i] || [];
                if (!pipelineErr && data && Object.keys(data).length) {
                    mailboxInfo = {
                        path: data.path || path,
                        messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
                        uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false
                    };
                }

                mailboxes.push(
                    Object.assign(
                        decoded,
                        mailboxInfo,
                        listedMailboxInfo && listedMailboxInfo.status
                            ? {
                                  status: listedMailboxInfo.status
                              }
                            : {}
                    )
                );
            } catch (err) {
                // should not happen
                if (logger.notifyError) {
                    logger.notifyError(err, { user: this.account, meta: { path, mailboxListing: typeof mailboxListing } });
                }

                let message = 'Failed to process stored mailbox listing';
                this.logger.error({ msg: message, path, mailboxListing: typeof mailboxListing, account: this.account, err });
                let error = Boom.boomify(new Error(message), { statusCode: 503 });
                error.output.payload.code = err.code;
                throw error;
            }
        }

        return mailboxes;
    }

    // Worker backends return false for entities they can not find (e.g. an unknown mailbox path
    // or message ID on IMAP). Convert such results into a 404 error for the API.
    assertFound(result, message, code) {
        if (!result) {
            let error = Boom.boomify(new Error(message), { statusCode: 404 });
            error.output.payload.code = code;
            throw error;
        }
        return result;
    }

    assertMessageFound(result) {
        return this.assertFound(result, 'Requested message was not found', 'MessageNotFound');
    }

    assertFolderFound(result) {
        return this.assertFound(result, 'Requested mailbox folder was not found', 'FolderNotFound');
    }

    async updateMessage(message, updates) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'updateMessage',
            account: this.account,
            message,
            updates,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown messages and folders
        return this.assertMessageFound(result);
    }

    async updateMessages(path, search, updates) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'updateMessages',
            account: this.account,
            path,
            search,
            updates,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown folders
        return this.assertFolderFound(result);
    }

    async listMailboxes(query) {
        let options = {};
        if (query && query.counters) {
            options.statusQuery = {
                messages: true,
                unseen: true
            };
        }
        let x = await this.call({
            cmd: 'listMailboxes',
            account: this.account,
            options,
            timeout: this.timeout
        });

        return x;
    }

    async moveMessage(message, target, options) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'moveMessage',
            account: this.account,
            message,
            target,
            options,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown messages and folders
        return this.assertMessageFound(result);
    }

    async moveMessages(source, search, target) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'moveMessages',
            account: this.account,
            source,
            search,
            target,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown folders
        return this.assertFolderFound(result);
    }

    async deleteMessage(message, force) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'deleteMessage',
            account: this.account,
            message,
            force,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown messages and folders
        return this.assertMessageFound(result);
    }

    async deleteMessages(path, search, force) {
        await this.loadAccountData(this.account, true);

        let result = await this.call({
            cmd: 'deleteMessages',
            account: this.account,
            path,
            search,
            force,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown folders
        return this.assertFolderFound(result);
    }

    async getQuota() {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'getQuota',
            account: this.account,
            timeout: this.timeout
        });
    }

    async createMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'createMailbox',
            account: this.account,
            path,
            timeout: this.timeout
        });
    }

    async modifyMailbox(path, newPath, subscribed) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'modifyMailbox',
            account: this.account,
            path,
            newPath,
            subscribed,
            timeout: this.timeout
        });
    }

    async deleteMailbox(path) {
        await this.loadAccountData(this.account, true);

        return await this.call({
            cmd: 'deleteMailbox',
            account: this.account,
            path,
            timeout: this.timeout
        });
    }

    async getText(text, options) {
        if (options.webSafeHtml) {
            // Both bodies are needed to build the web-safe rendering: the generator falls back to
            // the plaintext part when the message carries no HTML one, and the thread-collapse
            // analysis reads whichever of the two the extractor picks.
            options = Object.assign({}, options, { textType: '*' });
        }

        if (options.documentStore && (await isDocumentStoreEnabled())) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            let buf = Buffer.from(text, 'base64url');
            let message = buf.subarray(0, 8).toString('base64url');

            let getResult = await client.get({
                index,
                id: `${this.account}:${message}`
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'get', index, id: `${this.account}:${message}` },
                results: getResult && getResult._source ? 1 : 0
            });

            let messageData = this.assertMessageFound(getResult && getResult._source);
            let response = {};

            response.hasMore = false;
            for (let textType of Object.keys(messageData.text || {})) {
                if (['plain', 'html'].includes(textType) && (options.textType === '*' || options.textType === textType)) {
                    if (options.maxBytes && messageData.text[textType].length > options.maxBytes) {
                        response[textType] = messageData.text[textType].substring(0, options.maxBytes);
                        response.hasMore = true;
                    } else {
                        response[textType] = messageData.text[textType];
                    }
                }
            }

            return this.textResponse(response, options);
        }

        await this.loadAccountData(this.account, true);

        let textData = await this.call({
            cmd: 'getText',
            account: this.account,
            text,
            options,
            timeout: this.timeout
        });

        // IMAP backend returns false for unknown messages and folders
        return this.textResponse(this.assertMessageFound(textData), options);
    }

    // The one exit of getText(), so the document-store branch and the live one cannot answer a
    // webSafeHtml request differently
    async textResponse(textData, options) {
        return options.webSafeHtml ? webSafeTextResponse(textData) : textData;
    }

    async getMessage(message, options) {
        applyWebSafeHtmlOptions(options);

        if (options.documentStore && (await isDocumentStoreEnabled())) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            const reqOpts = {
                index,
                id: `${this.account}:${message}`,
                _source_excludes: 'preview,seemsLikeNew,account,created,updateTime'
            };

            switch (options.textType) {
                case '*':
                    break;
                case 'html':
                    reqOpts._source_excludes += ',text.plain';
                    break;
                case 'plain':
                    reqOpts._source_excludes += ',text.html,text._generatedHtml';
                    break;
                default:
                    reqOpts._source_excludes += ',text.plain,text.html,text._generatedHtml';
            }

            let getResult = await client.get(reqOpts);

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'get', index, id: `${this.account}:${message}` },
                results: getResult && getResult._source ? 1 : 0
            });

            let messageData = this.assertMessageFound(getResult && getResult._source);

            // restore headers and text object as per the API response
            let headersObj = {};
            for (let { key, value } of messageData.headers) {
                headersObj[key] = value;
            }
            messageData.headers = headersObj;

            if (messageData.text && (messageData.text.html || messageData.text.plain)) {
                messageData.text.hasMore = false;

                for (let textType of Object.keys(messageData.text || {})) {
                    if (['plain', 'html'].includes(textType) && options.maxBytes && messageData.text[textType].length > options.maxBytes) {
                        messageData.text[textType] = messageData.text[textType].substring(0, options.maxBytes);
                        messageData.text.hasMore = true;
                    }
                }
            }

            for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                if (messageData[key] === false) {
                    delete messageData[key];
                }
            }

            if (options.preProcessHtml && messageData.text && (messageData.text.html || messageData.text.plain)) {
                // If available, use the cached version
                messageData.text.html = messageData.text._generatedHtml || (await messageWebSafeHtml(messageData));
                messageData.text.webSafe = true;
                messageData.text._cachedWebSafe = !!messageData.text._generatedHtml;
            }

            if (options.embedAttachedImages && messageData.text && messageData.text.html && messageData.attachments && messageData.attachments.length) {
                // map both content id forms (bare and <bracketed>) to the first attachment carrying them,
                // so the passes below cost one lookup per reference instead of a scan of all attachments
                let attachmentsByContentId = new Map();
                for (let attachment of messageData.attachments) {
                    if (!attachment.contentId) {
                        continue;
                    }
                    for (let key of [attachment.contentId, attachment.contentId.replace(/^<(.*)>$/, '$1')]) {
                        if (!attachmentsByContentId.has(key)) {
                            attachmentsByContentId.set(key, attachment);
                        }
                    }
                }

                // first pass, find attachments to inline
                let attachmentsToDownload = new Set();
                for (let match of messageData.text.html.matchAll(cidReferenceRegex())) {
                    let attachment = attachmentsByContentId.get(match[1]);
                    if (attachment && !attachment.content) {
                        attachmentsToDownload.add(attachment);
                    }
                }

                // download large inline attachments not stored in ES
                for (let attachment of attachmentsToDownload) {
                    let downloadStream;
                    try {
                        downloadStream = await this.getAttachment(attachment.id);
                        if (downloadStream) {
                            let content = await download(downloadStream);
                            this.logger.trace({ msg: 'Fetched attachment content', account: this.account, attachment, size: content.length });
                            attachment.content = content.toString('base64');
                        }
                    } catch (err) {
                        // Release the reader if download() failed mid-stream so its
                        // MessagePort is not left open (destroy() is idempotent).
                        if (downloadStream) {
                            downloadStream.destroy();
                        }
                        this.logger.error({ msg: 'Failed to fetch attachment content', account: this.account, attachment, err });
                    }
                }

                // second pass, replace placeholders with inline attachments
                messageData.text.html = messageData.text.html.replace(cidReferenceRegex(), (fullMatch, cidMatch) => {
                    let attachment = attachmentsByContentId.get(cidMatch);
                    if (attachment && attachment.content) {
                        return `data:${attachment.contentType || 'application/octet-stream'};base64,${attachment.content}`;
                    }
                    return fullMatch;
                });
            }

            if (messageData.text && messageData.text._generatedHtml) {
                // remove cached pre-processed HTML from output
                delete messageData.text._generatedHtml;
            }

            // Add event file content if the attachment exists
            if (messageData.calendarEvents) {
                for (let calendarEvent of messageData.calendarEvents) {
                    if (!calendarEvent.content && calendarEvent.attachment) {
                        let attachment = messageData.attachments && messageData.attachments.find(attachment => attachment.id === calendarEvent.attachment);
                        if (attachment && attachment.content) {
                            calendarEvent.encoding = 'base64';
                            calendarEvent.content = attachment.content;
                        }
                    }
                }
            }

            if (messageData.attachments) {
                for (let attachment of messageData.attachments) {
                    delete attachment.content;
                }
            }

            if (options.markAsSeen && (!messageData.flags || !messageData.flags.includes('\\Seen'))) {
                // mark message as seen
                if (!messageData.flags) {
                    messageData.flags = [];
                }
                messageData.flags.push('\\Seen');
                // do not wait until the update is completed, return immediately
                this.updateMessage(message, { flags: { add: ['\\Seen'] } }).catch(err => {
                    this.logger.error({ msg: 'Failed to mark message as Seen', account: this.account, message, err });
                });
            }

            if (messageData.specialUse && !messageData.messageSpecialUse) {
                for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
                    if (messageData.specialUse === specialUseTag || (messageData.labels && messageData.labels.includes(specialUseTag))) {
                        messageData.messageSpecialUse = specialUseTag;
                        break;
                    }
                }
            }

            return messageData;
        }

        await this.loadAccountData(this.account, true);

        let messageData = await this.call({
            cmd: 'getMessage',
            account: this.account,
            message,
            options,
            timeout: this.timeout
        });

        return this.assertMessageFound(messageData);
    }

    async getMessages(messageIds, options) {
        await this.loadAccountData(this.account, true);
        return await this.call({
            cmd: 'getMessages',
            account: this.account,
            messageIds,
            options,
            timeout: this.timeout
        });
    }

    async listMessages(query) {
        if (query.documentStore && (await isDocumentStoreEnabled())) {
            await this.loadAccountData(this.account, false);

            const { index, client } = this.esClient;

            let inboxData = decodeStoredMailboxEntry(await this.redis.hgetBuffer(this.getMailboxListKey(), 'INBOX'));
            let delimiter = inboxData ? inboxData.delimiter : '/'; // hope for the best

            inboxData = inboxData || {
                path: 'INBOX',
                delimiter
            };

            inboxData.specialUse = inboxData.specialUse || '\\Inbox';

            let path = normalizePath(query.path, delimiter);
            let mailboxData = path === 'INBOX' ? inboxData : false;
            if (!mailboxData) {
                mailboxData = decodeStoredMailboxEntry(await this.redis.hgetBuffer(this.getMailboxListKey(), path));
            }

            let searchQuery = {
                bool: {
                    must: [
                        {
                            term: {
                                account: this.account
                            }
                        }
                    ]
                }
            };

            searchQuery.bool.must.push({
                bool: {
                    should: [
                        {
                            term: {
                                path
                            }
                        },
                        {
                            term: {
                                labels: (mailboxData && mailboxData.specialUse) || path
                            }
                        }
                    ],
                    minimum_should_match: 1
                }
            });

            let page = Number(query.page) || 0;
            let pageSize = Math.abs(Number(query.pageSize) || 20);

            if (page < 0) {
                page = 0;
            }

            let searchResult = await client.search({
                index,
                size: pageSize,
                from: pageSize * page,
                query: searchQuery,
                sort: { uid: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,text._generatedHtml,seemsLikeNew,attachments.content,summary,riskAssessment,updateTime'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: { type: 'search', index, size: pageSize, from: pageSize * page, query: searchQuery, sort: { uid: 'desc' } },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / pageSize), 1),
                messages: searchResult.hits.hits.map(entry => {
                    let messageData = entry._source;

                    // normalize as per the API response

                    for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                        if (messageData[key] === false) {
                            messageData[key] = undefined;
                        }
                    }

                    for (let key of ['account', 'created', 'specialUse']) {
                        if (messageData[key]) {
                            messageData[key] = undefined;
                        }
                    }

                    return messageData;
                })
            };

            return response;
        }

        await this.loadAccountData(this.account, true);

        let listing = await this.call(
            Object.assign(
                {
                    cmd: 'listMessages',
                    account: this.account
                },
                query,
                { timeout: this.timeout }
            )
        );

        // IMAP and Gmail backends return false for unknown folders
        return this.assertFolderFound(listing);
    }

    async searchMessages(query, searchOpts) {
        searchOpts = searchOpts || {};
        if (query.documentStore && (await isDocumentStoreEnabled())) {
            if (!searchOpts.unified) {
                await this.loadAccountData(this.account, false);
            }

            const { index, client } = this.esClient;

            let searchQuery = {
                bool: {
                    must: []
                }
            };

            if (this.account) {
                searchQuery.bool.must.push({
                    term: {
                        account: this.account
                    }
                });
            }

            if (searchOpts.unified && query.accounts && query.accounts.length) {
                searchQuery.bool.must.push({
                    bool: {
                        should: query.accounts.map(account => ({
                            term: {
                                account
                            }
                        })),
                        minimum_should_match: 1
                    }
                });
            }

            if (query.path) {
                let inboxData = decodeStoredMailboxEntry(await this.redis.hgetBuffer(this.getMailboxListKey(), 'INBOX'));
                let delimiter = inboxData ? inboxData.delimiter : '/'; // hope for the best

                inboxData = inboxData || {
                    path: 'INBOX',
                    delimiter
                };

                inboxData.specialUse = inboxData.specialUse || '\\Inbox';

                let path = normalizePath(query.path, delimiter);
                let mailboxData = path === 'INBOX' ? inboxData : false;
                if (!mailboxData) {
                    mailboxData = decodeStoredMailboxEntry(await this.redis.hgetBuffer(this.getMailboxListKey(), path));
                }

                searchQuery.bool.must.push({
                    bool: {
                        should: [
                            {
                                term: {
                                    path
                                }
                            },
                            {
                                term: {
                                    labels: (mailboxData && mailboxData.specialUse) || path
                                }
                            }
                        ],
                        minimum_should_match: 1
                    }
                });
            }

            if (searchOpts.unified && query.paths && query.paths.length) {
                searchQuery.bool.must.push({
                    bool: {
                        should: query.paths.flatMap(path => {
                            let res = [
                                {
                                    term: {
                                        path
                                    }
                                },
                                {
                                    term: {
                                        labels: path
                                    }
                                },
                                {
                                    term: {
                                        messageSpecialUse: path
                                    }
                                }
                            ];

                            if (/^inbox$/i.test(path)) {
                                res.push({
                                    term: {
                                        messageSpecialUse: '\\Inbox'
                                    }
                                });
                            }

                            return res;
                        }),
                        minimum_should_match: 1
                    }
                });
            }

            for (let key of ['answered', 'deleted', 'draft', 'unseen', 'flagged']) {
                if (typeof query.search[key] === 'boolean') {
                    searchQuery.bool.must.push({
                        term: {
                            [key]: query.search[key]
                        }
                    });
                }
            }

            if (typeof query.search.seen === 'boolean') {
                searchQuery.bool.must.push({
                    term: {
                        unseen: !query.search.seen
                    }
                });
            }

            for (let key of ['from', 'to', 'cc', 'bcc']) {
                if (query.search[key]) {
                    searchQuery.bool.must.push({
                        bool: {
                            should: [
                                {
                                    match: {
                                        [`${key}.name`]: {
                                            query: query.search[key],
                                            operator: 'and'
                                        }
                                    }
                                },
                                {
                                    term: {
                                        [`${key}.address`]: query.search[key]
                                    }
                                }
                            ],
                            minimum_should_match: 1
                        }
                    });
                }
            }

            if (query.search.uid) {
                let uidEntries = unpackUIDRangeForSearch(query.search.uid);
                if (uidEntries && uidEntries.length) {
                    let mustList = [];
                    for (let entry of uidEntries) {
                        if (typeof entry === 'number') {
                            mustList.push({
                                match: {
                                    uid: {
                                        query: entry,
                                        operator: 'and'
                                    }
                                }
                            });
                        } else if (typeof entry === 'object') {
                            mustList.push({
                                range: {
                                    uid: entry
                                }
                            });
                        }
                    }

                    if (mustList.length) {
                        searchQuery.bool.must.push({
                            bool: {
                                should: mustList,
                                minimum_should_match: 1
                            }
                        });
                    }
                }
            }

            for (let key of ['emailId', 'threadId']) {
                if (query.search[key]) {
                    searchQuery.bool.must.push({
                        term: {
                            [key]: query.search[key]
                        }
                    });
                }
            }

            if (query.search.subject) {
                searchQuery.bool.must.push({
                    match: {
                        subject: {
                            query: query.search.subject,
                            operator: 'and'
                        }
                    }
                });
            }

            if (query.search.body) {
                searchQuery.bool.must.push({
                    bool: {
                        should: [
                            {
                                match: {
                                    'text.plain': {
                                        query: query.search.body,
                                        operator: 'and'
                                    }
                                }
                            },
                            {
                                match: {
                                    'text.html': {
                                        query: query.search.body,
                                        operator: 'and'
                                    }
                                }
                            }
                        ],
                        minimum_should_match: 1
                    }
                });
            }

            let dateMatch = {};

            for (let key of ['before', 'sentBefore']) {
                if (query.search[key]) {
                    dateMatch.lte = query.search[key];
                }
            }

            for (let key of ['since', 'sentSince']) {
                if (query.search[key]) {
                    dateMatch.gte = query.search[key];
                }
            }

            if (Object.keys(dateMatch).length) {
                searchQuery.bool.must.push({
                    range: { date: dateMatch }
                });
            }

            let sizeMatch = {};

            if (query.search.larger) {
                sizeMatch.gte = query.search.larger;
            }

            if (query.search.smaller) {
                sizeMatch.lte = query.search.smaller;
            }

            if (Object.keys(sizeMatch).length) {
                searchQuery.bool.must.push({
                    range: { size: sizeMatch }
                });
            }

            // headers, nested query
            if (Object.keys(query.search.header || {}).length) {
                Object.keys(query.search.header).forEach(header => {
                    searchQuery.bool.must.push({
                        nested: {
                            path: 'headers',
                            query: {
                                bool: {
                                    must: [
                                        {
                                            term: {
                                                'headers.key': header.toLowerCase()
                                            }
                                        },
                                        {
                                            match: {
                                                'headers.value': {
                                                    query: (query.search.header[header] || '').toString(),
                                                    operator: 'and'
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    });
                });
            }

            if (query.documentQuery) {
                searchQuery.bool.must.push(query.documentQuery);
            }

            let page = Number(query.page) || 0;
            let pageSize = Math.abs(Number(query.pageSize) || 20);

            if (page < 0) {
                page = 0;
            }

            let searchResult = await client.search({
                index,
                size: pageSize,
                from: pageSize * page,
                query: searchQuery,
                sort: { [!searchOpts.unified ? 'uid' : 'date']: 'desc' },
                _source_excludes: 'headers,text.plain,text.html,text._generatedHtml,seemsLikeNew,attachments.content,summary,riskAssessment,updateTime'
            });

            this.logger.trace({
                msg: 'Executed ES query',
                query: {
                    type: 'search',
                    index,
                    size: pageSize,
                    from: pageSize * page,
                    query: searchQuery,
                    sort: { [!searchOpts.unified ? 'uid' : 'date']: 'desc' }
                },
                results: searchResult.hits.total.value
            });

            let response = {
                total: searchResult.hits.total.value,
                page,
                pages: Math.max(Math.ceil(searchResult.hits.total.value / pageSize), 1)
            };

            if (query.exposeQuery) {
                response.documentStoreQuery = query;
            }

            if (query.accounts) {
                response.accounts = query.accounts;
            }

            if (query.paths) {
                response.paths = query.paths;
            }

            response.messages = searchResult.hits.hits.map(entry => {
                let messageData = entry._source;

                // normalize as per the API response

                for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                    if (messageData[key] === false) {
                        messageData[key] = undefined;
                    }
                }

                for (let key of ['created', 'specialUse'].concat(!searchOpts.unified ? 'account' : [])) {
                    if (messageData[key]) {
                        messageData[key] = undefined;
                    }
                }

                return messageData;
            });

            return response;
        }

        await this.loadAccountData(this.account, true);

        let listing = await this.call(
            Object.assign(
                {
                    cmd: 'listMessages',
                    account: this.account
                },
                query,
                { timeout: this.timeout }
            )
        );

        // IMAP and Gmail backends return false for unknown folders
        return this.assertFolderFound(listing);
    }

    async uploadMessage(data) {
        await this.loadAccountData(this.account, true);

        let messageData = await this.call({
            cmd: 'uploadMessage',
            account: this.account,
            data,
            timeout: this.timeout
        });
        return messageData;
    }

    async submitMessage(data) {
        await this.loadAccountData(this.account, false);

        let messageData = await this.call(
            {
                cmd: 'submitMessage',
                account: this.account,
                data,
                // extended wait period when sending emails
                timeout: Math.max(this.timeout, 10 * 60 * 1000)
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );

        return messageData;
    }

    async queueMessage(data, meta) {
        await this.loadAccountData(this.account, false);

        let messageData = await this.call(
            {
                cmd: 'queueMessage',
                account: this.account,
                data,
                meta,
                timeout: this.timeout
            }
            //typeof data.raw === 'object' ? [data.raw] : []
        );
        return messageData;
    }

    async listSignatures(query) {
        await this.loadAccountData(this.account, true);

        return await this.call(
            Object.assign(
                {
                    cmd: 'listSignatures',
                    account: this.account
                },
                query,
                { timeout: this.timeout }
            )
        );
    }

    /**
     * Requests a fresh connection for the account.
     *
     * Answers false rather than reporting a reconnect it knows will not happen. A reconnect
     * rebuilds the client, but init() checks the auth-failure disable before it dials out and
     * returns without connecting, so for a parked account the dispatch is a no-op - and saying
     * "reconnecting" to a caller whose account then stays offline is worse than saying no.
     * Recovering it takes fresh credentials, or the admin UI's "Resume syncing".
     *
     * @param {Object} data
     * @param {Boolean} data.reconnect - Only reconnect when true
     * @returns {Promise<Boolean>} Whether a reconnect was actually requested
     */
    async requestReconnect(data) {
        const accountData = await this.loadAccountData(this.account, false);

        if (!data.reconnect) {
            return false;
        }

        const disabledAt = authFailureDisabledAt(accountData);
        if (disabledAt) {
            this.logger.info({ msg: 'Skipped reconnect request for an account that is switched off', account: this.account, disabledAt });
            return false;
        }

        await this.call({
            cmd: 'reconnect',
            account: this.account,
            timeout: this.timeout
        });
        return true;
    }

    async requestSync(data) {
        await this.loadAccountData(this.account, true);

        if (data.sync) {
            await this.call({
                cmd: 'sync',
                account: this.account,
                timeout: this.timeout
            });
            return true;
        }
        return false;
    }

    async flush(data) {
        await this.loadAccountData(this.account);

        if (!data.flush) {
            return false;
        }

        // use a global lock to decrease Redis scanning operations
        let lockKey = ['flush' /*, this.account*/].join(':');

        let lock = this.getLock();
        let flushLock;

        try {
            flushLock = await lock.acquireLock(lockKey, 30 * 60 * 1000);
            if (!flushLock.success) {
                // contention: another flush already holds the lock
                this.logger.warn({ msg: 'Failed to get flush lock, another flush is already running', account: this.account, lockKey });

                let error = Boom.boomify(new Error('One flush operation at a time allowed, try again later'), { statusCode: 429 });
                error.output.payload.code = 'LockFail';
                throw error;
            }
        } catch (err) {
            if (Boom.isBoom(err)) {
                // contention was already logged above
                throw err;
            }
            this.logger.error({ msg: 'Failed to get flush lock', account: this.account, lockKey, err });
            let error = Boom.boomify(new Error('Failed to get flush lock, try again later'), { statusCode: 500 });
            if (err.code) {
                error.output.payload.code = err.code || 'LockFail';
            }
            throw error;
        }

        try {
            await this.call({
                cmd: 'pause',
                account: this.account,
                timeout: this.timeout
            });

            let notifyFrom = data.notifyFrom && data.notifyFrom !== 'now' ? data.notifyFrom : new Date();
            let imapIndexer = data.imapIndexer;

            const dateKeyTdy = new Date().toISOString().substring(0, 10).replace(/-/g, '');
            const dateKeyYdy = new Date(Date.now() - 24 * 3600 * 1000).toISOString().substring(0, 10).replace(/-/g, '');

            const tombstoneTdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyTdy}`;
            const tombstoneYdy = `${REDIS_PREFIX}tomb:${this.account}:${dateKeyYdy}`;

            try {
                let pipeline = this.redis
                    .multi()
                    // start syncing new messages from current time
                    .hset(this.getAccountKey(), 'notifyFrom', notifyFrom.toISOString())
                    // mark connection count to 0 to trigger `accountInitialized` event
                    .hset(this.getAccountKey(), `state:count:${ACCOUNT_STATES.CONNECTED}`, '0')
                    .del(this.getMailboxListKey()) // mailbox list
                    // Note: mailbox ID hash (iah:) and listRegistry are intentionally NOT deleted
                    // to preserve message ID stability across reconnections. Message IDs depend on
                    // the specific mailbox ID entries, so deleting them would invalidate existing IDs.
                    .del(`${REDIS_PREFIX}iar:b:${this.account}`) // bounce list
                    .del(`${REDIS_PREFIX}iar:s:${this.account}`) // seen messages list
                    .del(tombstoneTdy)
                    .del(tombstoneYdy);

                if (imapIndexer) {
                    pipeline = pipeline.hset(this.getAccountKey(), 'imapIndexer', imapIndexer);
                }

                if (data.syncFrom || data.syncFrom === null) {
                    pipeline = pipeline.hset(this.getAccountKey(), 'syncFrom', data.syncFrom ? data.syncFrom.toISOString() : 'null');
                }

                await pipeline.exec();

                // scan and delete keys
                await redisScanDelete(this.redis, this.logger, `${REDIS_PREFIX}iam:${escapeRedisGlob(this.account)}:*`);

                if (await isDocumentStoreEnabled()) {
                    // Flush ElasticSearch index for this account
                    const { index, client } = this.esClient;
                    if (!client) {
                        // Account data in Redis was already flushed, only the index cleanup was skipped
                        this.logger.error({ msg: 'Document store is enabled but the ElasticSearch client is not available', action: 'flush' });
                        return true;
                    }

                    let deleteResult = {};
                    let deletedCount = 0;

                    let filterQuery = {
                        match: {
                            account: this.account
                        }
                    };

                    for (let indexName of [index, `${index}.threads`, `${index}.embeddings`]) {
                        try {
                            deleteResult[indexName] = await client.deleteByQuery({
                                index: indexName,
                                query: filterQuery
                            });
                            deletedCount += deleteResult[indexName].deleted || 0;
                        } catch (err) {
                            this.logger.error({
                                msg: 'Failed to delete account emails from index',
                                action: 'flush',
                                code: 'document_delete_account_error',
                                index: indexName,
                                request: filterQuery,
                                err
                            });
                            if (indexName === index) {
                                throw err;
                            }
                        }
                    }

                    this.logger.trace({
                        msg: 'Deleted account emails from index',
                        action: 'flush',
                        code: 'document_delete_account',
                        account: this.account,
                        deletedCount,
                        deleteResult
                    });
                }

                return true;
            } finally {
                let finalize = async () => {
                    // Wait a bit before resuming. Just to be sure all pending processes have been completed.
                    await new Promise(r => setTimeout(r, 5 * 1000));
                    await this.call({
                        cmd: 'resume',
                        account: this.account,
                        timeout: this.timeout
                    });
                };
                finalize().catch(err => {
                    this.logger.error({ msg: 'Failed to finish flushing', account: this.account, err });
                });
            }
        } finally {
            if (flushLock?.success) {
                await lock.releaseLock(flushLock);
            }
        }
    }

    async renewAccessToken(oauth2Opts) {
        let lockKey = ['oauth', this.account].join(':');

        let accountData = await this.loadAccountData(this.account, false);
        if (accountData.oauth2?.expires > new Date(Date.now() + 30 * 1000)) {
            return accountData;
        }

        let lock = this.getLock();
        let renewLock;

        try {
            renewLock = await lock.waitAcquireLock(lockKey, 5 * 60 * 1000, 1 * 60 * 1000);
            if (!renewLock.success) {
                // contention: timed out waiting for the current lock holder
                this.logger.warn({ msg: 'Failed to get renewal lock, timed out waiting for the current holder', account: this.account, lockKey });
                throw new Error('Failed to get renewal lock');
            }
        } catch (err) {
            if (!renewLock) {
                // unexpected lock-layer error; contention was already logged above
                this.logger.error({ msg: 'Failed to get renewal lock', account: this.account, lockKey, err });
            }
            let error = Boom.boomify(new Error('Failed to get renewal lock'), { statusCode: 500 });
            if (err.code) {
                error.output.payload.code = err.code || 'LockFail';
            }
            throw error;
        }

        try {
            let accountData = await this.loadAccountData(this.account, false);

            // check if the token was already renewed
            if (
                accountData.oauth2 &&
                accountData.oauth2.accessToken &&
                accountData.oauth2.expires &&
                accountData.oauth2.expires > new Date(Date.now() + 30 * 1000)
            ) {
                this.logger.info({
                    msg: 'OAuth2 access token renewed while locked',
                    action: 'ensureAccessToken',
                    account: this.account,
                    user: accountData.oauth2.auth.user,
                    expires: accountData.oauth2.expires,
                    scopes: accountData.oauth2.scope,
                    oauth2App: accountData.oauth2.provider
                });
                return accountData;
            }

            const oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, oauth2Opts);

            let r = await oAuth2Client.refreshToken({
                refreshToken: accountData.oauth2.refreshToken,
                // user is needed if it's a service account
                user: accountData.oauth2.auth.user
            });

            if (r.tokenRequest?.userFlag) {
                await this.update({ account: accountData.account, oauth2: { partial: true, userFlag: r.tokenRequest?.userFlag } });
            }

            if (!r.access_token) {
                throw new Error('Failed to renew token');
            }

            let now = new Date();

            let updates = {
                accessToken: r.access_token,
                expires: new Date(now.getTime() + r.expires_in * 1000).toISOString(),
                generated: now.toISOString()
            };

            if (r.refresh_token) {
                updates.refreshToken = r.refresh_token;
                updates.refreshTokenGenerated = now.toISOString();
            }

            if (r.scope) {
                updates.scope = r.scope.split(/\s+/);
            }

            accountData.oauth2 = Object.assign(accountData.oauth2 || {}, updates);
            delete accountData.oauth2.userFlag;

            this.logger.info({
                msg: 'Renewed OAuth2 access token',
                action: 'ensureAccessToken',
                account: this.account,
                user: accountData.oauth2.auth.user,
                expires: updates.expires,
                scopes: updates.scope,
                oauth2App: accountData.oauth2.provider
            });

            await this.update({ account: accountData.account, oauth2: accountData.oauth2 });

            return accountData;
        } catch (err) {
            this.logger.warn({
                msg: 'Failed to renew OAuth2 access token',
                action: 'ensureAccessToken',
                account: this.account,
                err
            });

            if (err.tokenRequest?.userFlag) {
                await this.update({ account: this.account, oauth2: { partial: true, userFlag: err.tokenRequest?.userFlag } });
            }

            throw err;
        } finally {
            if (renewLock?.success) {
                await lock.releaseLock(renewLock);
            }
        }
    }

    async invalidateAccessToken() {
        let accountData = await this.loadAccountData(this.account, false);
        if (accountData.oauth2) {
            accountData.oauth2.expires = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
            await this.update({ account: accountData.account, oauth2: accountData.oauth2 });
            this.logger.info({ msg: 'Invalidated the OAuth2 access token', account: this.account, expires: accountData.oauth2.expires });
        }
        return accountData;
    }

    async getActiveAccessTokenData() {
        // throws if account does not exist
        let accountData = await this.loadAccountData(this.account);
        if (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.user || !accountData.oauth2.provider) {
            let error = Boom.boomify(new Error('Not an OAuth2 account'), { statusCode: 403 });
            error.output.payload.code = 'AccountNotOAuth2';
            throw error;
        }

        if (await useAuthServerForOAuth2(accountData.oauth2, this.logger, { account: this.account, target: 'api' })) {
            // resolve credentials

            let authData = await resolveCredentials(this.account, 'api');

            return {
                account: accountData.account,
                user: authData.user,
                accessToken: authData.accessToken,
                provider: accountData.oauth2.provider,
                registeredScopes: accountData.oauth2.scope,
                cached: false
            };
        }

        let now = Date.now();
        let accessToken;
        let cached = false;

        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now + 30 * 1000)) {
            // renew access token
            try {
                await this.renewAccessToken();
                accountData = await this.loadAccountData(this.account);
                accessToken = accountData.oauth2.accessToken;
            } catch (err) {
                let error = Boom.boomify(err, { statusCode: 403 });
                error.output.payload.code = 'OauthRenewError';
                error.output.payload.authenticationFailed = true;
                if (err.tokenRequest) {
                    error.output.payload.tokenRequest = err.tokenRequest;
                }
                throw error;
            }
        } else {
            accessToken = accountData.oauth2.accessToken;
            cached = true;
        }

        return {
            account: accountData.account,
            user: accountData.oauth2.auth.user,
            accessToken,
            provider: accountData.oauth2.provider,
            registeredScopes: accountData.oauth2.scope,
            expires:
                accountData.oauth2.expires && typeof accountData.oauth2.expires.toISOString === 'function'
                    ? accountData.oauth2.expires.toISOString()
                    : accountData.oauth2.expires,
            cached
        };
    }

    async isApiClient(accountData) {
        if (accountData.oauth2?.auth?.delegatedAccount) {
            try {
                let delegatedAccount = await resolveDelegatedAccount(this.redis, accountData.account);
                if (delegatedAccount) {
                    accountData.delegatedAccount = delegatedAccount;
                    let delegatedAccountRow = await this.redis.hgetall(`${REDIS_PREFIX}iad:${delegatedAccount}`);
                    let delegatedAccountData = this.unserializeAccountData(delegatedAccountRow);
                    if (delegatedAccountData?.oauth2?.provider) {
                        let app = await oauth2Apps.get(delegatedAccountData.oauth2.provider);
                        return isApiBasedApp(app);
                    } else {
                        return false;
                    }
                }
            } catch (err) {
                // Invalid delegation config - treat as non-API client
                return false;
            }
        }

        if (accountData.oauth2?.provider) {
            let app = await oauth2Apps.get(accountData.oauth2.provider);
            return isApiBasedApp(app);
        }
        return false;
    }

    async oauth2Request(url, method, payload, options) {
        let accountData = await this.loadAccountData(this.account);
        if (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.user || !accountData.oauth2.provider) {
            let error = Boom.boomify(new Error('Not an OAuth2 account'), { statusCode: 403 });
            error.output.payload.code = 'AccountNotOAuth2';
            throw error;
        }

        let oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, {
            logger: this.logger
        });

        const tokenData = await this.getActiveAccessTokenData();
        if (!tokenData?.accessToken) {
            let error = Boom.boomify(new Error('Can not provide access token'), { statusCode: 403 });
            error.output.payload.code = 'MissingAccessToken';
            throw error;
        }

        if (oAuth2Client.apiBase) {
            let urlObj = new URL(url, oAuth2Client.apiBase);
            url = urlObj.href;
        }

        return await oAuth2Client.request(tokenData?.accessToken, url, method, payload, options);
    }

    async pushQueueEvent(event) {
        let evObj = {
            t: new Date(),
            e: event
        };
        try {
            let res = await this.redis.lpush(this.getExternalQueueKey(), msgpack.encode(evObj));

            this.logger.debug({
                msg: 'MS Graph subscription event',
                type: 'event',
                account: this.account,
                event,
                res
            });
        } catch (err) {
            this.logger.error({ msg: 'Failed to insert event to account queue', account: this.account, event, err });
        }

        try {
            await this.call({ cmd: 'externalNotify', accounts: [this.account] });
        } catch (err) {
            this.logger.error({ msg: 'Failed to notify about queue changes', account: this.account, err });
        }
    }

    async pullQueueEvent() {
        let event;
        try {
            let evBuf = await this.redis.rpopBuffer(this.getExternalQueueKey());
            if (evBuf) {
                let { t, e } = msgpack.decode(evBuf);
                event = e;
                this.logger.debug({ msg: 'Processing event from the account queue', event, queueTime: t, queueDelay: (Date.now() - t.getTime()) / 1000 });
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to pull event from the account queue', err });
        }

        return event || null;
    }
}

// Cheap existence probe that does not load or decrypt account data. The `account` field is
// the mandatory marker field of the account hash (the same idiom the notify worker and
// genId() rely on), so its presence is the canonical "this account exists" signal.
async function accountExists(redis, account) {
    return (await redis.hexists(`${REDIS_PREFIX}iad:${account}`, 'account')) === 1;
}

/**
 * Same question as accountExists(), asked about a list of accounts in one round trip.
 *
 * lib/db.js enables no auto-pipelining, so probing a listing page's accounts one at a time is a
 * socket write each - up to 250 on the admin listings that call this.
 *
 * @param {Object} redis - Redis client
 * @param {Array} accounts - Account IDs to probe
 * @returns {Promise<Map<String, Boolean>>} keyed by account ID, in the order given
 */
async function accountsExist(redis, accounts) {
    if (!accounts || !accounts.length) {
        return new Map();
    }

    let pipeline = redis.pipeline();
    for (let account of accounts) {
        pipeline = pipeline.hexists(`${REDIS_PREFIX}iad:${account}`, 'account');
    }

    // A pipeline reports a per-command failure in its results rather than rejecting, and
    // extractMultiValues() reads such an entry as undefined - an account that could not be probed is
    // not an account that is known to exist
    let values = extractMultiValues(await pipeline.exec());

    return new Map(accounts.map((account, i) => [account, values[i] === 1]));
}

/**
 * The display fields of one account, without loading or decrypting anything.
 *
 * What a form that already holds an account id needs in order to show it back as something a
 * person recognises: a name, an address and a connection state. loadAccountData() answers the same
 * question by reading and decrypting the whole record, which is a lot of work for three strings on
 * a page that is not about that account.
 *
 * @param {Object} redis - Redis client
 * @param {String} account - Account ID
 * @returns {Promise<Object|null>} `{ account, name, email, state }`, or null when no such account exists
 */
async function accountSummary(redis, account) {
    if (!account) {
        return null;
    }

    // `account` is the existence marker (see accountExists); the rest are optional on a record
    let [exists, name, email, state] = await redis.hmget(`${REDIS_PREFIX}iad:${account}`, 'account', 'name', 'email', 'state');
    if (!exists) {
        return null;
    }

    return { account, name: name || '', email: email || '', state: state || 'init' };
}

module.exports = { Account, accountExists, accountsExist, accountSummary, authFailureDisabledAt, isAuthFailureDisabled, isOperatorDisabled };
