'use strict';

// The filter pills of the admin lists other than accounts (gateways, webhook routes, templates,
// access tokens, OAuth2 apps): what each one offers and the query each accepts. The pills themselves
// are built by listPageView() in list-filters.js; the accounts list has its own module,
// account-listing.js, because its filters reach into the Lua listing.

const Joi = require('joi');

const { accountIdSchema } = require('../schemas');
const { OAUTH_PROVIDERS } = require('../oauth2-apps');
const { accountPickerEntry } = require('./route-helpers');
const { multiValue } = require('./list-filters');

// Every scope the admin token form can mint, in the order and with the names the form uses. One
// list, because the listing's scope filter validates against the same vocabulary and a scope added
// to one side must not leave the other behind. Deliberately wider than the /v1/tokens set, which
// excludes '*' and 'metrics'.
const TOKEN_SCOPE_OPTIONS = [
    { value: '*', label: 'All scopes' },
    { value: 'api', label: 'API' },
    { value: 'smtp', label: 'SMTP' },
    { value: 'imap-proxy', label: 'IMAP Proxy' },
    { value: 'metrics', label: 'Metrics' },
    { value: 'mcp-manage', label: 'MCP management' },
    { value: 'mcp', label: 'MCP mail' }
];
const ADMIN_TOKEN_SCOPES = TOKEN_SCOPE_OPTIONS.map(entry => entry.value);

// What the gateways list shows for each gatewayState() value
const GATEWAY_STATE_LABELS = {
    connected: { type: 'success', name: 'Connected' },
    error: { type: 'error', name: 'Error' },
    unused: { type: 'info', name: 'Not used' }
};

const GATEWAY_STATE_OPTIONS = Object.entries(GATEWAY_STATE_LABELS).map(([value, { name }]) => ({ value, label: name }));

// What the webhook routes list shows for each webhookStatus() value
const WEBHOOK_STATUS_LABELS = {
    enabled: { type: 'success', name: 'Enabled' },
    failing: { type: 'error', name: 'Failing' },
    disabled: { type: 'warning', name: 'Disabled' }
};

const WEBHOOK_STATUS_OPTIONS = Object.entries(WEBHOOK_STATUS_LABELS).map(([value, { name }]) => ({ value, label: name }));

const OAUTH_PROVIDER_OPTIONS = Object.entries(OAUTH_PROVIDERS).map(([value, label]) => ({ value, label }));

// Why and how a suppression list entry was added. Both are free-form words (the API takes any
// reason), so the pills offer the ones the list actually holds, spelled as the table shows them
const entryOptions = values => (values || []).map(value => ({ value, label: value }));

const LIST_FILTER_QUERY = {
    // A free-form entry value: any short string, repeatable
    entryValue: Joi.array().items(Joi.string().trim().max(256)).single().default([]),
    gatewayState: multiValue(GATEWAY_STATE_OPTIONS),
    webhookStatus: multiValue(WEBHOOK_STATUS_OPTIONS),
    oauthProvider: multiValue(OAUTH_PROVIDER_OPTIONS),
    tokenScope: multiValue(TOKEN_SCOPE_OPTIONS),
    account: accountIdSchema.empty('').default(null)
};

/**
 * The account pill of a list that can be narrowed to one account's entries.
 *
 * @param {Object} [accountData] - The chosen account, when one is
 * @param {String} label - The pill label
 * @param {String} hint - What the filter does, shown under the picker
 * @returns {Object} A filter definition for listPageView()
 */
function accountFilter(accountData, label, hint) {
    const filter = { name: 'account', label, type: 'account', hint };
    if (accountData) {
        filter.summary = accountData.name || accountData.email || accountData.account;
        filter.selected = accountPickerEntry(accountData);
    }
    return filter;
}

const LIST_FILTERS = {
    gateways: [{ name: 'state', label: 'Status', type: 'multi', options: GATEWAY_STATE_OPTIONS }],
    webhooks: [{ name: 'status', label: 'Status', type: 'multi', options: WEBHOOK_STATUS_OPTIONS }],
    oauthApps: [{ name: 'provider', label: 'Provider', type: 'multi', options: OAUTH_PROVIDER_OPTIONS }],
    templates: accountData => [accountFilter(accountData, 'Account', 'Shows the templates of one account instead of the shared ones.')],
    suppressionEntries: (values, accountData) => [
        { name: 'reason', label: 'Reason', type: 'multi', options: entryOptions(values && values.reason) },
        { name: 'source', label: 'Source', type: 'multi', options: entryOptions(values && values.source) },
        accountFilter(accountData, 'Account', 'Shows only the addresses suppressed for this account.')
    ],
    tokens: accountData => [
        accountFilter(accountData, 'Bound to', 'Shows only the tokens that work for this one account.'),
        { name: 'scope', label: 'Scope', type: 'multi', options: TOKEN_SCOPE_OPTIONS }
    ]
};

module.exports = { ADMIN_TOKEN_SCOPES, GATEWAY_STATE_LABELS, WEBHOOK_STATUS_LABELS, LIST_FILTER_QUERY, LIST_FILTERS };
