'use strict';

// Shared helpers used by more than one extracted UI route module - and still by
// lib/routes-ui.js for the route groups not yet extracted. Lifting these here lets each
// consumer import the single canonical copy instead of the monolith, so a route group can
// be extracted without stranding a helper its sibling groups still need. Pure functions
// and cached data only - this module registers no routes.
//
// Every symbol below was moved verbatim from lib/routes-ui.js. The only change is in
// cachedTemplates: its __dirname-relative paths gain one extra '..' because this file
// lives one directory deeper (lib/ui-routes/) than the original (lib/).

const Boom = require('@hapi/boom');
const util = require('util');
const fs = require('fs');
const pathlib = require('path');
const psl = require('psl');

const settings = require('../settings');
const { redis } = require('../db');
const { toolGrants } = require('../mcp/tools');
const { Account, accountsExist, accountSummary, isAuthFailureDisabled } = require('../account');
const { REDIS_PREFIX, DEFAULT_PAGE_SIZE } = require('../consts');
const { oauth2ProviderData } = require('../oauth2-apps');
const exampleDocumentsPayloads = require('../payload-examples-documents.json');

// Fallback model list, shown until the first successful "Refresh Models" call
// replaces it with the models actually available on the configured endpoint
// (stored in the openAiModels setting)
const OPEN_AI_MODELS = [
    {
        name: 'GPT-5 Mini',
        id: 'gpt-5-mini'
    },

    {
        name: 'GPT-5',
        id: 'gpt-5'
    },

    {
        name: 'GPT-5 Nano',
        id: 'gpt-5-nano'
    }
];

const cachedTemplates = {
    addressList: fs.readFileSync(pathlib.join(__dirname, '..', '..', 'views', 'partials', 'address_list.hbs'), 'utf-8'),
    testSend: fs.readFileSync(pathlib.join(__dirname, '..', '..', 'views', 'partials', 'test_send.hbs'), 'utf-8')
};

const getOpenAiModels = async (models, selectedModel) => {
    let modelList = (await settings.get('openAiModels')) || structuredClone(models);

    if (selectedModel && !modelList.find(model => model.id === selectedModel)) {
        modelList.unshift({
            name: selectedModel,
            id: selectedModel
        });
    }

    return modelList.map(model => {
        model.selected = model.id === selectedModel;
        return model;
    });
};

// Ordered display table for account states: the single source for every UI surface
// that lists states side by side (the accounts-page filter dropdown, the dashboard
// state chips). Unlike accountStateLabel below - which intentionally merges the two
// error states into one "Connection failed" badge - this table keeps them distinct,
// because each row maps to its own ?state= filter.
const ACCOUNT_STATE_DISPLAY = [
    { state: 'init', label: 'Initializing', variant: 'info' },
    { state: 'connecting', label: 'Connecting', variant: 'info' },
    { state: 'syncing', label: 'Syncing', variant: 'info' },
    { state: 'connected', label: 'Connected', variant: 'success' },
    { state: 'disconnected', label: 'Disconnected', variant: 'warning' },
    { state: 'paused', label: 'Paused', variant: 'neutral' },
    { state: 'authenticationError', label: 'Authentication failed', variant: 'error' },
    { state: 'connectError', label: 'Connection failed', variant: 'error' },
    { state: 'unset', label: 'Not syncing', variant: 'neutral' }
];

// The wording for the two ImapFlow closed-after-connect codes, shared by the account state
// badge (accountStateLabel below) and the connection check on the account form
// (lib/ui-routes/account-routes.js), so the two cannot drift. The Text variant keeps the TLS
// hint because a wrong port/TLS pairing is the usual cause. Null for any other code.
function closedAfterConnectMessage(code, gt) {
    switch (code) {
        case 'ClosedAfterConnectTLS':
            return gt.gettext('The server unexpectedly closed the connection.');
        case 'ClosedAfterConnectText':
            return gt.gettext(
                'The server unexpectedly closed the connection. This usually happens when attempting to connect to a TLS port without TLS enabled.'
            );
        default:
            return null;
    }
}

// State badge descriptor for an account, shared by the server-rendered views
// (formatAccountData below) and the live SSE change feed (publishChangeEvent in
// workers/api.js), so the badge cannot drift between page load and repaint.
// opts: { lastErrorState, disabledReason }
function accountStateLabel(state, opts, gt) {
    let { lastErrorState, disabledReason } = opts || {};

    switch (state) {
        case 'init':
            return {
                type: 'info',
                name: 'Initializing',
                spinner: true
            };

        case 'connecting':
            return {
                type: 'info',
                name: 'Connecting'
            };

        case 'syncing':
            return {
                type: 'info',
                name: 'Syncing',
                spinner: true
            };

        case 'connected':
            return {
                type: 'success',
                name: 'Connected'
            };

        case 'disabled':
            return {
                type: 'neutral',
                name: 'Disabled',
                error: disabledReason
            };

        case 'authenticationError':
        case 'connectError': {
            let errorMessage = lastErrorState ? lastErrorState.response : false;
            if (lastErrorState) {
                switch (lastErrorState.serverResponseCode) {
                    case 'ETIMEDOUT':
                        errorMessage = gt.gettext('Connection timed out. This usually occurs if you are behind a firewall or connecting to the wrong port.');
                        break;
                    case 'ClosedAfterConnectTLS':
                    case 'ClosedAfterConnectText':
                        errorMessage = closedAfterConnectMessage(lastErrorState.serverResponseCode, gt);
                        break;
                    case 'ECONNREFUSED':
                        errorMessage = gt.gettext(
                            'The server refused the connection. This typically occurs if the server is not running, is overloaded, or you are connecting to the wrong host or port.'
                        );
                        break;
                }
            }

            return {
                type: 'error',
                name: 'Connection failed',
                error: errorMessage
            };
        }
        case 'unset':
            return {
                type: 'neutral',
                name: 'Not syncing'
            };
        case 'disconnected':
            return {
                type: 'warning',
                name: 'Disconnected'
            };
        case 'paused':
            return {
                type: 'neutral',
                name: 'Paused'
            };
        default:
            return {
                type: 'neutral',
                name: 'N/A'
            };
    }
}

function formatAccountData(account, gt) {
    account.type = {};

    if (account.oauth2 && account.oauth2.app) {
        let providerData = oauth2ProviderData(account.oauth2.app.provider);
        account.type = providerData;
    } else if (account.oauth2 && account.oauth2.provider) {
        account.type = oauth2ProviderData(account.oauth2.provider);
    } else if (account.imap && !account.imap.disabled) {
        account.type.icon = 'icon-[tabler--mail]';
        account.type.name = 'IMAP';
        account.type.comment = psl.get(account.imap.host) || account.imap.host;
    } else if (account.smtp) {
        account.type.icon = 'icon-[tabler--send]';
        account.type.name = 'SMTP';
        account.type.comment = psl.get(account.smtp.host) || account.smtp.host;
    } else if (account.oauth2 && account.oauth2.auth && account.oauth2.auth.delegatedAccount) {
        account.type.icon = 'icon-[tabler--arrow-right-circle]';
        account.type.name = gt.gettext('Delegated');
        account.type.comment = util.format(gt.gettext('Using credentials from "%s"'), account.oauth2.auth.delegatedAccount);
    } else {
        account.type.name = 'N/A';
    }

    // composed hover label for the type icon (used by ui/tooltip in the views)
    account.type.label = `${account.type.name || ''}${account.type.comment ? ` (${account.type.comment})` : ''}`;

    account.stateLabel = accountStateLabel(account.state, { lastErrorState: account.lastErrorState, disabledReason: account.disabledReason }, gt);

    // An account the auth-failure safety net switched off reports the neutral "Not syncing", which
    // says nothing about why it stopped or that a human has to act. Override the label to say so.
    //
    // Keyed on the marker the safety net writes, or on the exact signature the releases before the
    // marker left behind, not on `imap.disabled` plus any leftover error: that flag is also the
    // operator's send-only switch, so the old guess badged a deliberately send-only account
    // "Connection failed" if it had ever failed to connect.
    if (isAuthFailureDisabled(account)) {
        account.stateLabel = {
            type: 'error',
            name: 'Syncing switched off',
            error: account.lastErrorState && (account.lastErrorState.description || account.lastErrorState.response)
        };
    }

    if (account.oauth2) {
        account.oauth2.scopes = []
            .concat(account.oauth2.scope || [])
            .concat(account.oauth2.scopes || [])
            .flatMap(entry => entry.split(/\s+/))
            .map(entry => entry.trim())
            .filter(entry => entry);

        account.oauth2.expiresStr = account.oauth2.expires ? account.oauth2.expires.toISOString() : false;
        account.oauth2.generatedStr = account.oauth2.generated ? account.oauth2.generated.toISOString() : false;

        if (account.outlookSubscription) {
            account.outlookSubscription.subscriptionExpiresStr = account.outlookSubscription.expirationDateTime
                ? account.outlookSubscription.expirationDateTime.toISOString()
                : false;

            let state = account.outlookSubscription.state || {};

            account.outlookSubscription.isValid =
                state.state !== 'error' && account.outlookSubscription.expirationDateTime && account.outlookSubscription.expirationDateTime > new Date();

            account.outlookSubscription.stateLabel = (state.state || '').replace(/^./, c => c.toUpperCase());

            if ((state.state === 'created' && !account.outlookSubscription.expirationDateTime) || account.outlookSubscription.expirationDateTime < new Date()) {
                account.outlookSubscription.stateLabel = 'Expired';
            }
        }
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
                type: 'error',
                name: state,
                error: (payload && payload.error && payload.error.message) || null
            };

        default:
            return {
                type: 'neutral',
                name: 'N/A'
            };
    }
}

async function getExampleDocumentsPayloads() {
    let date = new Date().toISOString();

    let examplePayloads = structuredClone(exampleDocumentsPayloads);

    examplePayloads.forEach(payload => {
        if (payload && payload.content) {
            if (typeof payload.content.date === 'string') {
                payload.content.date = date;
            }

            if (typeof payload.content.created === 'string') {
                payload.content.created = date;
            }
        }
    });
    return examplePayloads;
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

// True for failures the client caused (a Boom 4xx, e.g. a stale tab polling a deleted entity).
// Used by catch blocks to skip or demote logging for them, so bot and stale-UI traffic does not
// land in the error stream.
function isClientError(err) {
    return Boom.isBoom(err) && err.output.statusCode < 500;
}

// An unauthenticated attempt rejected with Boom.forbidden is an auth event worth auditing at
// warn, not a server failure. Returns the log level for a catch block that serves both cases.
function authAwareLevel(err) {
    return Boom.isBoom(err) && err.output.statusCode === 403 ? 'warn' : 'error';
}

function throwAsBoom(err) {
    if (Boom.isBoom(err)) {
        throw err;
    }
    let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
}

// Shapes an error for the admin UI's JSON endpoints, which answer 200 with `success: false`
// rather than an HTTP error - the client branches on the body. Boom errors keep their status
// and message; anything else degrades to its code.
function jsonErrorPayload(err) {
    if (Boom.isBoom(err)) {
        return Object.assign({ success: false }, err.output.payload);
    }
    return { success: false, error: err.code || 'Error', message: err.message };
}

// The "wrong account" page, shown when a setup link pinned to one address is completed as another.
// Rendered from both arms of the hosted form - the OAuth2 callback in workers/api.js and the IMAP arm in
// ./account-routes.js - which live in different workers, so the view name, the layout and the refusal
// status are kept here rather than written out twice. Only `retryUrl` is arm-specific: the OAuth arm
// sends the user back to the provider, the IMAP arm back to the form.
//
// 403 rather than the 200 that the sibling views/oauth-scope-error.hbs returns: this is a refused
// request, the surrounding refusals in the same flow already answer 403, and both call sites are plain
// form navigations, so the browser still renders the page.
function identityErrorView(request, h, { expectedEmail, actualEmail, retryUrl }) {
    return h
        .view(
            'account-identity-error',
            {
                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                templateLocale: request.app.locale,
                expectedEmail,
                actualEmail,
                retryUrl
            },
            {
                layout: 'public'
            }
        )
        .code(403);
}

// View-model for the ui/pagination partial: prev/next URLs plus the numbered page links.
// basePath is the URL path without a query string (leading slash optional, matching the
// `new URL(path, base)` convention the route modules already use); data is a listing
// response carrying zero-based `page` and total `pages`; query is the validated request
// query whose `pageSize` is appended to the URLs only when it differs from the default.
// Tagged template for redirect paths that interpolate an identifier: percent-encodes every
// interpolated value, so a raw ID cannot break the path or turn into a URL fragment whichever
// call site forgets. The JS-layer counterpart of the `urlpart` Handlebars helper that closed
// the same bug class in the templates - use this instead of hand-placing encodeURIComponent.
function adminUrl(strings, ...values) {
    return strings.reduce((url, part, i) => url + part + (i < values.length ? encodeURIComponent(values[i]) : ''), '');
}

/**
 * The submitted form fields for an error re-render, minus the secrets.
 *
 * A form re-rendered after a failed save shows what was typed rather than the stored record, so
 * a validation error does not clear the form. The named secret fields are blanked, not echoed
 * into the page: a password or a client secret is typed again, the way the account form treats
 * its passwords.
 *
 * @param {Object} request - the Hapi request, whose payload is the submitted form
 * @param {...String} secretFields - payload keys to blank
 * @returns {Object}
 */
function submittedValues(request, ...secretFields) {
    const values = Object.assign({}, request.payload);
    for (const field of secretFields) {
        values[field] = '';
    }
    return values;
}

function buildPagingView(basePath, data, query) {
    const getPagingUrl = page => {
        let url = new URL(basePath, 'http://localhost');

        if (page) {
            url.searchParams.append('page', page);
        }

        if (query.pageSize !== DEFAULT_PAGE_SIZE) {
            url.searchParams.append('pageSize', query.pageSize);
        }

        return url.pathname + url.search;
    };

    return {
        showPaging: data.pages > 1,
        nextPage: data.pages > data.page + 1 ? getPagingUrl(data.page + 2) : false,
        prevPage: data.page > 0 ? getPagingUrl(data.page) : false,
        firstPage: data.page === 0,
        pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
            url: getPagingUrl(i + 1),
            title: i + 1,
            active: i === data.page
        }))
    };
}

/**
 * Resolves which of the accounts a listing refers to still exist.
 *
 * Rows outlive the account they name: deleting an account leaves its suppression-list entries in
 * place and leaves its access tokens valid. A row naming a dead account must not be rendered as a
 * link to a page that 404s, so the listings ask this before rendering. One probe per distinct
 * account rather than per row, all of them in one round trip, and each is a single HEXISTS - no
 * account load, nothing decrypted.
 *
 * @param {Array} entries - listing rows, each optionally carrying an `account`
 * @returns {Promise<Map<String, Boolean>>} keyed by account ID; rows without one are absent
 */
async function resolveKnownAccounts(entries) {
    return accountsExist(redis, Array.from(new Set(entries.map(entry => entry.account).filter(Boolean))));
}

// How many accounts one suggestion request answers with. The picker is a search box, not a
// listing: past a screenful the answer to "I cannot see mine" is to type more of it, and a longer
// list only makes the response slower to fetch and harder to scan.
const ACCOUNT_SUGGESTION_LIMIT = 10;

/**
 * One account as the account picker renders it.
 *
 * The picker shows the same three things everywhere it appears - who the account belongs to, which
 * address it syncs, and whether it is connected - so the shape is built once here rather than by
 * each page that feeds it. `state` is the badge descriptor the account listings already use, so a
 * suggestion row cannot describe a connection differently from the page it was picked on.
 *
 * @param {Object} entry - an account record, from listAccounts() or accountSummary()
 * @returns {Object} `{ account, name, email, state: { type, name } }`
 */
function accountPickerEntry(entry) {
    // No lastErrorState is passed on purpose: the picker has room for a state, not for the reason
    // behind it, and that reason is the only thing the label needs translating for
    const badge = accountStateLabel(entry.state, {});

    return {
        account: entry.account,
        name: entry.name || '',
        email: entry.email || '',
        state: { type: badge.type, name: badge.name }
    };
}

/**
 * Account suggestions for the account picker, shared by every page that carries one.
 *
 * Search rather than a preloaded list: an instance can hold far more accounts than a page could
 * usefully ship, and the id a person is looking for is one they can start typing. A listing
 * failure costs the suggestions and nothing else - the picker still accepts a typed id, and the
 * form that submits it resolves it server-side either way.
 *
 * @param {Function} call - RPC helper for talking to the main thread
 * @param {Object} [opts]
 * @param {String} [opts.query] - search string matched against id, name and address
 * @param {Object} [opts.logger] - request logger for the failure branch
 * @returns {Promise<{accounts: Array, total: Number}>}
 */
async function accountSuggestions(call, opts) {
    const { query, logger } = opts || {};

    try {
        const listing = await new Account({ redis, call }).listAccounts(false, query, 0, ACCOUNT_SUGGESTION_LIMIT);
        return {
            accounts: (listing.accounts || []).map(accountPickerEntry),
            total: listing.total || 0
        };
    } catch (err) {
        if (logger) {
            logger.error({ msg: 'Failed to list account suggestions', err });
        }
        return { accounts: [], total: 0 };
    }
}

/**
 * The picker entry for an account a form already holds, or null when it names none.
 *
 * A form re-rendered after a validation error starts with an id rather than with a choice, and so
 * does the token form opened from an account's own token list. Without this the picker would have
 * to show the raw id back as if the person had never picked anything.
 *
 * @param {String} account - Account ID, possibly empty or naming a deleted account
 * @param {Object} [logger] - request logger for the failure branch
 * @returns {Promise<Object|null>}
 */
async function accountPickerSelection(account, logger) {
    if (!account) {
        return null;
    }

    try {
        const summary = await accountSummary(redis, account);
        return summary ? accountPickerEntry(summary) : null;
    } catch (err) {
        if (logger) {
            logger.error({ msg: 'Failed to resolve the selected account', account, err });
        }
        return null;
    }
}

/**
 * The MCP tool grants for a page that shows the tool count, or an empty list if the registry
 * cannot be built.
 *
 * The three pages that mint an mcp-scoped token all want this, and all want it the same way: the
 * count is a nicety and the page's real job is not, so a registry failure costs the count and
 * nothing else. Wrapped once here rather than three times, so the pages cannot disagree about
 * that - one of them letting the failure through would take down a token form or a consent
 * decision over a line of text.
 *
 * @param {Object} server - the Hapi server
 * @param {Object} logger - where to report a failure (a request logger, or the server's)
 * @returns {Array} toolGrants() output, or []
 */
function mcpToolGrants(server, logger) {
    try {
        return toolGrants(server);
    } catch (err) {
        logger.error({ msg: 'Failed to derive the MCP tool catalog', err });
        return [];
    }
}

module.exports = {
    jsonErrorPayload,
    mcpToolGrants,
    resolveKnownAccounts,
    accountSuggestions,
    accountPickerEntry,
    accountPickerSelection,
    identityErrorView,
    OPEN_AI_MODELS,
    cachedTemplates,
    getOpenAiModels,
    closedAfterConnectMessage,
    accountStateLabel,
    ACCOUNT_STATE_DISPLAY,
    formatServerState,
    formatAccountData,
    getExampleDocumentsPayloads,
    getServerStatus,
    throwAsBoom,
    isClientError,
    authAwareLevel,
    buildPagingView,
    adminUrl,
    submittedValues
};
