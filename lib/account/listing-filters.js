'use strict';

// The filters an account listing takes beyond the search: several states at once, an email domain
// and an account kind. Shared by Account#listAccounts(), GET /v1/accounts and the admin accounts
// page, so all three accept and mean the same values.

const { ERROR_STATES } = require('./account-state');

// What an account is, coarsely: how its mailbox is reached. The values match the `type`
// Account#listAccounts() reports for the IMAP, sending-only and delegated cases; an OAuth2 account
// takes the family of its app's provider instead of the provider itself, so a service-account app
// and a delegated one of the same provider are one kind.
const ACCOUNT_KINDS = [
    { value: 'imap', label: 'IMAP' },
    { value: 'sending', label: 'SMTP only' },
    { value: 'gmail', label: 'Gmail' },
    { value: 'outlook', label: 'Outlook' },
    { value: 'mailRu', label: 'Mail.ru' },
    { value: 'delegated', label: 'Delegated' }
];

const ACCOUNT_KIND_VALUES = ACCOUNT_KINDS.map(entry => entry.value);

// OAuth2 provider to kind
const PROVIDER_KINDS = {
    gmail: 'gmail',
    gmailService: 'gmail',
    outlook: 'outlook',
    outlookService: 'outlook',
    mailRu: 'mailRu'
};

// Kinds an instance can hold without any OAuth2 app
const BASE_KINDS = ['imap', 'sending'];

/**
 * The "appId=kind" lines s-list-accounts.lua classifies OAuth2 accounts with.
 *
 * @param {Array<Object>} apps - OAuth2 apps, each with `id` and `provider`
 * @returns {String} Newline-separated entries; an app of an unknown provider is left out, so its
 *   accounts read as the "oauth2" kind, which no filter value selects
 */
function appKindEntries(apps) {
    return (apps || [])
        .filter(app => app && app.id && PROVIDER_KINDS[app.provider])
        .map(app => `${app.id}=${PROVIDER_KINDS[app.provider]}`)
        .join('\n');
}

/**
 * The kinds worth offering as filter values on an instance: the two that need no app, and the
 * provider kinds of the apps it has (delegated accounts borrow an Outlook credential).
 *
 * @param {Array<Object>} apps - OAuth2 apps, each with `provider`
 * @returns {Array<Object>} Entries of ACCOUNT_KINDS, in their order
 */
function availableAccountKinds(apps) {
    const present = new Set(BASE_KINDS);
    for (const app of apps || []) {
        const kind = app && PROVIDER_KINDS[app.provider];
        if (kind) {
            present.add(kind);
            if (kind === 'outlook') {
                present.add('delegated');
            }
        }
    }
    return ACCOUNT_KINDS.filter(entry => present.has(entry.value));
}

/**
 * Expands a state filter into the comma-separated list the listing script takes. 'errors' is a
 * virtual value covering every attention state, alone or among others.
 *
 * @param {String|Array} state - One state, several, or nothing
 * @returns {String} The state list, '*' for no state filter
 */
function stateFilterList(state) {
    const entries = [].concat(state || []).flatMap(entry => (entry === 'errors' ? ERROR_STATES : [entry]));
    return entries.length ? Array.from(new Set(entries)).join(',') : '*';
}

/**
 * A domain filter value as the listing compares it: lowercased, with a leading "@" (as pasted from
 * an address) and a trailing dot dropped.
 *
 * @param {String} domain - The value as entered
 * @returns {String} The domain, '' for none
 */
function normalizeDomainFilter(domain) {
    if (typeof domain !== 'string') {
        return '';
    }
    return domain.trim().toLowerCase().replace(DOMAIN_FILTER_NOISE, '');
}

// What a pasted domain may carry around it: a leading "@" from an address and the root dot. Shared
// with the joi schema (accountListingSchemas.domain), which converts the same way
const DOMAIN_FILTER_NOISE = /^@+|\.+$/g;

/**
 * The kind of an account, the same rule s-list-accounts.lua applies when it filters by kind: its
 * OAuth2 app first, then a delegated credential, then an IMAP configuration the operator has not
 * switched off (a park by the auth-failure safety net is still IMAP), and "sending" otherwise.
 * test/redis-lua-scripts-test.js runs both over the same records, so the Lua copy cannot drift.
 *
 * @param {Object} accountData - An unserialized account, with `_authFailureDisabledAt`
 * @param {Object} appKinds - OAuth2 app id to kind
 * @returns {String} The kind; "oauth2" for an app missing from `appKinds`
 */
function accountKind(accountData, appKinds) {
    const oauth2 = accountData.oauth2;
    if (oauth2 && oauth2.provider) {
        return appKinds[oauth2.provider] || 'oauth2';
    }
    if (oauth2 && oauth2.auth && oauth2.auth.delegatedAccount) {
        return 'delegated';
    }
    const imap = accountData.imap;
    if (imap && (imap.disabled !== true || accountData._authFailureDisabledAt)) {
        return 'imap';
    }
    return 'sending';
}

module.exports = {
    ACCOUNT_KIND_VALUES,
    PROVIDER_KINDS,
    DOMAIN_FILTER_NOISE,
    accountKind,
    appKindEntries,
    availableAccountKinds,
    stateFilterList,
    normalizeDomainFilter
};
