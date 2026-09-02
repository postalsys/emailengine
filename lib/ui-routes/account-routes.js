'use strict';

// Admin UI routes for account management: /admin/accounts (listing), /admin/accounts/new and
// /accounts/new* (the add-account wizard incl. IMAP autoconfig/test/server steps), and
// /admin/accounts/{account}* (view, edit, delete, reconnect, sync, logs, browse). Extracted
// verbatim from lib/routes-ui.js. DISABLE_MESSAGE_BROWSER and the getMailboxListing helper move
// with the routes (only these account pages use them).

const Joi = require('joi');
const crypto = require('crypto');
const Boom = require('@hapi/boom');

const settings = require('../settings');
const consts = require('../consts');
const tokens = require('../tokens');
const { redis, documentsQueue } = require('../db');
const getSecret = require('../get-secret');
const capa = require('../capa');
const { Account, authFailureDisabledAt, isOperatorDisabled } = require('../account');
const { Gateway } = require('../gateway');
const { autodetectImapSettings, resolveAppPassword, getAppPassword } = require('../autodetect-imap-settings');
const { atomicIncrement } = require('../redis-operations');
const { oauth2Apps, oauth2ProviderData, SERVICE_ACCOUNT_PROVIDERS } = require('../oauth2-apps');
const {
    getServiceHostname,
    getSignedFormData,
    parseSignedFormData,
    claimFormNonce,
    releaseFormNonce,
    getLogs,
    verifyAccountInfo,
    flattenObjectKeys,
    getBoolean,
    readEnvValue,
    failAction
} = require('../tools');
const {
    settingsSchema,
    accountSchemas,
    accountIdSchema,
    defaultAccountTypeSchema,
    ACCOUNT_DISPLAY_STATES,
    signedFormBlobFields: signedBlobFields
} = require('../schemas');
const {
    formatAccountData,
    cachedTemplates,
    identityErrorView,
    ACCOUNT_STATE_DISPLAY,
    adminUrl,
    accountSuggestions,
    isClientError,
    closedAfterConnectMessage
} = require('./route-helpers');
const { webhooks: Webhooks } = require('../webhooks');
const { describeEffectiveRouting, isDeliverableRoute } = require('../webhook-routing');
const { matchesExpectedIdentity, resolveExpectedIdentity } = require('../account/expected-identity');

const { REDIS_PREFIX, DEFAULT_PAGE_SIZE, NONCE_BYTES, MAX_FORM_TTL, MAX_FORM_PROBE_ATTEMPTS } = consts;

const DISABLE_MESSAGE_BROWSER = getBoolean(readEnvValue('EENGINE_DISABLE_MESSAGE_BROWSER'));

// Per-API-worker, in-process memo for the custom-domain app-password hint resolved on the page-2
// failAction re-render. The hint is cosmetic (a provider label/instructions from a static table), but
// resolving it for a custom domain costs a signed-probe authorization (Redis + HMAC, drawing the shared
// per-nonce probe budget) plus a DNS MX lookup that blocks the error page up to APP_PASSWORD_MX_TIMEOUT.
// A struggling user re-submits the same email repeatedly, so cache the resolved hint (including a
// negative result) by lowercased domain to avoid repeating that work and burning the probe budget on
// cosmetics. Values are static-table constants, so a cached hit is byte-identical to a fresh resolve.
const APP_PASSWORD_HINT_CACHE = new Map();
const APP_PASSWORD_HINT_TTL = 10 * 60 * 1000;
// Bound the memo so a long-lived API worker cannot accumulate one entry per distinct custom domain
// forever. Writes are already gated behind a signed probe + the per-nonce cap, so cardinality tracks
// legitimate setup-link issuance, but this caps the worst case. FIFO eviction (Map preserves insertion
// order) is fine for a cosmetic hint cache.
const APP_PASSWORD_HINT_MAX_ENTRIES = 1000;

function getCachedAppPasswordHint(domain) {
    const entry = APP_PASSWORD_HINT_CACHE.get(domain);
    if (!entry) {
        return false;
    }
    if (entry.expires > Date.now()) {
        return entry;
    }
    APP_PASSWORD_HINT_CACHE.delete(domain);
    return false;
}

function setCachedAppPasswordHint(domain, value) {
    // delete-then-set keeps insertion order meaningful (a refreshed domain becomes newest) and avoids
    // over-evicting when we are only updating an existing entry.
    APP_PASSWORD_HINT_CACHE.delete(domain);
    if (APP_PASSWORD_HINT_CACHE.size >= APP_PASSWORD_HINT_MAX_ENTRIES) {
        const oldest = APP_PASSWORD_HINT_CACHE.keys().next().value;
        if (oldest !== undefined) {
            APP_PASSWORD_HINT_CACHE.delete(oldest);
        }
    }
    APP_PASSWORD_HINT_CACHE.set(domain, { value, expires: Date.now() + APP_PASSWORD_HINT_TTL });
}

async function getMailboxListing(accountObject) {
    let mailboxes = [
        {
            path: 'INBOX',
            listed: true,
            specialUse: '\\Inbox',
            name: 'INBOX',
            subscribed: true
        }
    ];

    try {
        mailboxes = await accountObject.getMailboxListing();
        mailboxes = mailboxes.sort((a, b) => {
            if (a.path === 'INBOX') {
                return -1;
            } else if (b.path === 'INBOX') {
                return 1;
            }

            if (a.specialUse && !b.specialUse) {
                return -1;
            } else if (!a.specialUse && b.specialUse) {
                return 1;
            }

            return a.path.toLowerCase().localeCompare(b.path.toLowerCase());
        });
    } catch (err) {
        // failed to get mailbox list
    }

    return mailboxes;
}

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/admin/accounts',
        async handler(request, h) {
            let accountObject = new Account({ redis, call });

            const runIndex = await call({
                cmd: 'runIndex'
            });

            const accounts = await accountObject.listAccounts(request.query.state, request.query.query, request.query.page - 1, request.query.pageSize);

            for (let account of accounts.accounts) {
                let accountObject = new Account({ redis, account: account.account });
                try {
                    account.data = await accountObject.loadAccountData(null, null, runIndex);

                    if (account.data && account.data.oauth2 && account.data.oauth2.provider) {
                        let oauth2App = await oauth2Apps.get(account.data.oauth2.provider);
                        if (oauth2App) {
                            account.data.oauth2.app = oauth2App;
                        }
                    }
                } catch (err) {
                    // Account has invalid config (e.g., broken delegation)
                    account.data = {
                        delegationError: err.message
                    };
                }
            }

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = (page, state, query) => {
                let url = new URL(`admin/accounts`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize && request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                if (query) {
                    url.searchParams.append('query', query);
                }

                if (state) {
                    url.searchParams.append('state', state);
                }

                return url.pathname + url.search;
            };

            // A page past the end lists nothing, and the view renders its page links only
            // around a non-empty listing, so it would show "No accounts found" with no way
            // back - send it to the last page instead
            if (accounts.pages && request.query.page > accounts.pages) {
                return h.redirect(getPagingUrl(accounts.pages, request.query.state, request.query.query));
            }

            if (accounts.pages > accounts.page + 1) {
                nextPage = getPagingUrl(accounts.page + 2, request.query.state, request.query.query);
            }

            if (accounts.page > 0) {
                prevPage = getPagingUrl(accounts.page, request.query.state, request.query.query);
            }

            let stateOptions = [
                {
                    state: false,
                    label: 'All'
                },

                {
                    state: 'errors',
                    label: 'Needs attention'
                },

                { divider: true },

                ...ACCOUNT_STATE_DISPLAY.map(({ state, label }) => ({ state, label }))
            ].map(entry => {
                let url = getPagingUrl(0, entry.state, request.query.query);
                return Object.assign({ url, selected: entry.state ? entry.state === request.query.state : !request.query.state }, entry);
            });

            return h.view(
                'accounts/index',
                {
                    pageTitle: 'Accounts',
                    menuAccounts: true,

                    query: request.query.query,
                    state: request.query.state,
                    pageSize: request.query.pageSize !== DEFAULT_PAGE_SIZE ? request.query.pageSize : false,

                    selectedState: stateOptions.find(entry => entry.state && entry.state === request.query.state),

                    searchTarget: '/admin/accounts',
                    searchPlaceholder: 'Search for accounts…',
                    total: accounts.total,

                    showPaging: accounts.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: accounts.page === 0,
                    pageLinks: new Array(accounts.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1, request.query.state, request.query.query),
                        title: i + 1,
                        active: i === accounts.page
                    })),

                    stateOptions,

                    accounts: accounts.accounts.map(account => formatAccountData(account.data || account, request.app.gt))
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/accounts').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
                    query: Joi.string().example('user@example.com').description('Filter accounts by name/email match').label('AccountQuery'),
                    state: Joi.string()
                        .trim()
                        .empty('')
                        .valid(...ACCOUNT_DISPLAY_STATES, 'errors')
                        .example('connected')
                        .description('Filter accounts by state, or "errors" for every attention state')
                        .label('AccountState')
                })
            }
        }
    });

    // The data behind the account picker (views/partials/ui/account-picker.hbs), which every admin
    // form that binds something to one account renders. A search endpoint rather than a list
    // shipped with the page: an instance can hold far more accounts than a page could usefully
    // carry, and the whole point of the control is that a person types part of what they are
    // looking for.
    //
    // No auth options of its own: it inherits the admin surface's session default, exactly like the
    // listing it is a narrower view of, and it exposes nothing that listing does not.
    server.route({
        method: 'GET',
        path: '/admin/accounts/suggestions',

        async handler(request) {
            const { accounts, total } = await accountSuggestions(call, { query: request.query.query, logger: request.logger });

            return {
                accounts,
                // What the box could not show, so the picker can say "keep typing" rather than
                // letting a capped list read as the whole instance. The total itself is not
                // returned: nothing renders it, and it would only be a third number to keep
                // consistent with the other two.
                more: Math.max(total - accounts.length, 0)
            };
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                query: Joi.object({
                    query: Joi.string().trim().empty('').max(256).description('Search string matched against account id, name and address')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/new',

        async handler(request, h) {
            let { data, signature } = await getSignedFormData({
                account: request.payload.account,
                name: request.payload.name,

                // identify request
                n: crypto.randomBytes(NONCE_BYTES).toString('base64url'),
                t: Date.now()
            });

            let url = new URL(`accounts/new`, 'http://localhost');

            url.searchParams.append('data', data);
            if (signature) {
                url.searchParams.append('sig', signature);
            }

            let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);

            if (!oauth2apps.length) {
                url.searchParams.append('type', 'imap');
            }

            return h.redirect(url.pathname + url.search);
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Failed to set up account${errors.account ? `: ${errors.account}` : ''}` });
                    request.logger.debug({ msg: 'Failed to update configuration', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                payload: Joi.object({
                    account: accountIdSchema.default(null),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name')
                })
            }
        }
    });

    async function accountFormHandler(request, h) {
        // Intentionally parsed WITHOUT requireNonce (unlike the IMAP-arm endpoints). This OAuth entry must
        // keep accepting legacy / pre-upgrade re-auth blobs that carry no n/t - requiring a nonce here
        // would 403 the account page's "Re-authenticate" button across a rolling upgrade and break
        // still-circulating pre-v2.39 OAuth setup links. Replay safety is enforced downstream instead: the
        // OAuth callback (workers/api.js) claims the form nonce atomically (SET NX before create) when one
        // is present. Do NOT add requireNonce here without re-checking that compat impact.
        const data = await parseSignedFormData(redis, request.payload, request.app.gt);

        const oauth2App = await oauth2Apps.get(request.payload.type);

        if (oauth2App && oauth2App.enabled) {
            // prepare account entry

            let accountData = {
                account: data.account
            };

            for (let key of ['name', 'email', 'syncFrom', 'path']) {
                if (data[key]) {
                    accountData[key] = data[key];
                }
            }

            accountData.notifyFrom = data.notifyFrom || new Date().toISOString();

            for (let key of ['redirectUrl', 'expectedEmail', 'n', 't']) {
                if (!accountData._meta) {
                    accountData._meta = {};
                }
                accountData._meta[key] = data[key];
            }

            if (data.delegated) {
                accountData.delegated = true;
            } else {
                accountData.copy = false;
            }

            accountData.oauth2 = {
                provider: oauth2App.id
            };

            // throws if invalid or unknown app ID
            const oAuth2Client = await oauth2Apps.getClient(oauth2App.id);

            const nonce = data.n || crypto.randomBytes(NONCE_BYTES).toString('base64url');

            // Validate nonce format (base64url, 21-22 chars; also accept base64 for backward compatibility)
            if (!/^[A-Za-z0-9_\-+/]{21,22}={0,2}$/.test(nonce)) {
                throw Boom.badRequest('Invalid nonce format. Please generate a new authentication URL.');
            }

            // store account data with atomic SET + EX
            await redis.set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData), 'EX', Math.floor(MAX_FORM_TTL / 1000));

            // Generate the url that will be used for the consent dialog.

            let requestPayload = {
                state: `account:add:${nonce}`
            };

            if (accountData.email) {
                requestPayload.email = accountData.email;
            }

            // Service providers use client_credentials - no interactive authorization
            if (SERVICE_ACCOUNT_PROVIDERS.has(oAuth2Client.provider)) {
                throw Boom.badRequest('Application-only OAuth providers do not support interactive authorization');
            }

            let authorizeUrl = oAuth2Client.generateAuthUrl(requestPayload);

            return h.redirect(authorizeUrl);
        }

        const expectedEmail = await resolveFormExpectation(data);

        return h.view(
            'accounts/register/imap',
            {
                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                values: {
                    data: request.payload.data,
                    sig: request.payload.sig,

                    // A pinned link fixes the address, so prefill from the expectation rather than from the
                    // editable hint and mark it read-only. Cosmetic - the endpoints below enforce it.
                    email: expectedEmail || data.email,
                    emailPinned: !!expectedEmail,
                    name: data.name
                }
            },
            {
                layout: 'public'
            }
        );
    }

    // signedBlobFields (the base64url data + HMAC sig carried by every hosted-form page) is imported from
    // lib/schemas.js as signedFormBlobFields and spread into each schema below, so the security-relevant
    // field definitions cannot drift across the auth:false endpoints (or from the sibling unsubscribe-routes
    // copy). Both fields are required: every issuer signs unconditionally and every template renders the sig
    // hidden input, so a request without one is always hand-crafted.

    server.route({
        method: 'GET',
        path: '/accounts/new',
        async handler(request, h) {
            if (request.query.type) {
                request.payload = request.query;
                return accountFormHandler(request, h);
            }

            // throws if check fails
            await parseSignedFormData(redis, request.query, request.app.gt);

            let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);
            oauth2apps.forEach(app => {
                app.providerData = oauth2ProviderData(app.provider, app.cloud);
            });

            return h.view(
                'accounts/register/index',
                {
                    pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                    values: {
                        data: request.query.data,
                        sig: request.query.sig
                    },

                    oauth2apps
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.debug({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(request.app.gt.gettext('Invalid request. Check your input and try again.')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    ...signedBlobFields,
                    type: defaultAccountTypeSchema
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new',

        handler: accountFormHandler,
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.debug({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(request.app.gt.gettext('Invalid request. Check your input and try again.')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                payload: Joi.object({
                    ...signedBlobFields,
                    type: Joi.string()
                        .empty('')
                        .allow(false)
                        .default(false)
                        .example('imap')
                        .description(
                            'Display the form for the specified account type (either "imap" or an OAuth2 app ID) instead of allowing the user to choose'
                        )
                })
            }
        }
    });

    // Shared by this route's payload validation and its failAction re-render (same rationale as
    // serverFormSchema below), so the re-rendered first page is built from the same schema that validated
    // the submission rather than echoing the raw payload.
    const firstPageSchema = Joi.object({
        ...signedBlobFields,
        name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
        email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
        password: Joi.string().max(1024).min(1).required().example('secret').label('Password').description('Your account password')
    });

    // Shared IMAP/SMTP connection fields for the hosted form's /imap/test and /imap/server routes, so the
    // two payload schemas (and their failAction re-renders) are built from one definition and cannot drift.
    // The tri-state booleans list '0' as falsy (a string a non-browser client may submit symmetric with the
    // truthy '1'); without it '0' would fail coercion and re-render a checkbox as checked.
    const connectionFields = {
        imap_auth_user: Joi.string().empty('').trim().max(1024).required(),
        imap_auth_pass: Joi.string().empty('').max(1024).required(),
        imap_host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to').label('IMAP host'),
        imap_port: Joi.number()
            .integer()
            .min(1)
            .max(64 * 1024)
            .required()
            .example(993)
            .description('Service port number')
            .label('IMAP port'),
        imap_secure: Joi.boolean()
            .truthy('Y', 'true', '1', 'on')
            .falsy('N', 'false', '0', 0, '')
            .default(false)
            .example(true)
            .description('Should connection use TLS. Usually true for port 993')
            .label('IMAP TLS'),
        imap_disabled: Joi.boolean()
            .truthy('Y', 'true', '1', 'on')
            .falsy('N', 'false', '0', 0, '')
            .default(false)
            .example(true)
            .description('Disable IMAP if you are using this email account to only send emails.')
            .label('IMAP disabled'),
        smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
        smtp_auth_pass: Joi.string().empty('').max(1024).required(),
        smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to').label('SMTP host'),
        smtp_port: Joi.number()
            .integer()
            .min(1)
            .max(64 * 1024)
            .required()
            .example(465)
            .description('Service port number')
            .label('SMTP port'),
        smtp_secure: Joi.boolean()
            .truthy('Y', 'true', '1', 'on')
            .falsy('N', 'false', '0', 0, '')
            .default(false)
            .example(true)
            .description('Should connection use TLS. Usually true for port 465')
            .label('SMTP TLS')
    };

    // Rebuild safe re-render values from the SAME schema that validated the submission: convert coerces the
    // tri-state TLS/disabled checkboxes to real booleans (so {{#if values.X}} cannot re-check a box from the
    // string 'false'), and stripUnknown drops unexpected / prototype keys (and the appPassword_* hint fields)
    // before they can reach the unescaped template sinks. Keys that FAILED validation are dropped too: Joi
    // keeps the raw submitted value for a failed coercion (e.g. the string 'no' for a tri-state boolean, or
    // an array from duplicated form fields), and rendering that raw value would re-check a cleared checkbox
    // or corrupt the hidden data/sig inputs - a failed key re-renders empty instead. The named secret fields
    // are then dropped so a plaintext credential is never echoed back into the HTML. `value` is null when
    // request.payload is null (a bodyless POST), so fall back to {} before mutating.
    const rebuildFormValues = (schema, payload, secretFields) => {
        const { value, error } = schema.validate(payload, { convert: true, stripUnknown: true, abortEarly: false });
        const values = value || {};
        if (error && error.details) {
            for (let detail of error.details) {
                if (detail.path && detail.path.length) {
                    delete values[detail.path[0]];
                }
            }
        }
        for (let field of secretFields || []) {
            delete values[field];
        }
        return values;
    };

    // Bound the number of outbound-probe requests per issued form blob, shared by the auth:false endpoints
    // that drive outbound network from an attacker-controllable host/domain: POST /accounts/new/imap
    // (email autodiscovery) and POST /accounts/new/imap/test (connection test). Both authorize by signature
    // but do not consume the single-use nonce, so without this a leaked signed link is an unlimited
    // SSRF/port-scan oracle. One shared counter per nonce means pivoting between the two endpoints cannot
    // reset the cap. Fail open on a Redis error - the cap is defense-in-depth, not correctness.
    const enforceFormProbeLimit = async (nonce, gt, logger) => {
        let count = 0;
        try {
            const counted = await atomicIncrement(redis, `${REDIS_PREFIX}account:form:probe:${nonce}`, 1, Math.floor(MAX_FORM_TTL / 1000));
            if (counted.success) {
                count = counted.value;
            }
        } catch (err) {
            logger.error({ msg: 'Failed to count outbound form probes', err });
        }
        if (count > MAX_FORM_PROBE_ATTEMPTS) {
            // The cap is keyed on the nonce inside the signed blob, so reloading the same link keeps the
            // same nonce and stays capped - the caller needs a freshly issued setup link.
            //
            // Reviewed, accepted (do not "fix" by removing the cap): for an API-issued link the end user
            // cannot self-recover once exhausted and must go back to the integrator for a fresh link. This
            // is bounded by the link's <=24h TTL, the account-creating submit itself does not draw from the
            // budget, and the app-password hint memo (APP_PASSWORD_HINT_CACHE) keeps error re-renders from
            // burning it on cosmetics. If this ever bites real users, tune MAX_FORM_PROBE_ATTEMPTS or scope
            // the budget per-endpoint rather than dropping the SSRF/port-scan defense.
            throw Boom.boomify(new Error(gt.gettext('Too many attempts for this setup link. Request a new setup link to continue.')), { statusCode: 429 });
        }
    };

    // The authorization gate for every outbound-probe-driving call in this file: a valid signed blob
    // WITH a nonce (requireNonce guarantees data.n) plus the shared per-nonce probe cap. Keep the two
    // paired through this helper - a probe site that checks the signature but skips the cap silently
    // reopens the unbounded-probe hole. Throws Boom 403/429; returns the parsed blob.
    const authorizeSignedProbe = async (payload, gt, logger) => {
        const data = await parseSignedFormData(redis, payload, gt, { requireNonce: true });
        await enforceFormProbeLimit(data.n, gt, logger);
        return data;
    };

    // The expectation that applies to a parsed form blob (lib/account/expected-identity.js owns the
    // precedence and the lazy Redis fallback).
    const resolveFormExpectation = data => resolveExpectedIdentity(redis, { account: data.account, blobExpectation: data.expectedEmail });

    // Expected identity gate for the IMAP arm, mirroring the one the OAuth callback applies in
    // workers/api.js.
    //
    // The evidence here is only the address typed into the form. Working credentials do not prove that
    // the address belongs to the mailbox behind them, so this enforces "the account is registered under
    // the expected address" and nothing stronger - which is exactly what the field documents. Without it
    // the constraint would be trivially sidestepped by choosing the IMAP tab on a form that also offers
    // OAuth2.
    //
    // Returns { expectedEmail, matched } rather than throwing so the caller can name the address that was
    // actually used when it reports the rejection.
    const checkExpectedIdentity = async (data, submittedEmail) => {
        const expectedEmail = await resolveFormExpectation(data);
        return { expectedEmail, matched: !expectedEmail || matchesExpectedIdentity(expectedEmail, [submittedEmail]) };
    };

    // Stop the flow with a way back rather than a redirect to the calling application: entering the wrong
    // address is correctable, and the hosted form only ever redirects on success. The OAuth arm renders
    // the same view (workers/api.js), differing only in where "try again" points.
    //
    // type=imap keeps the user on the arm they already chose: without it /accounts/new re-asks the
    // provider question and offers OAuth apps they passed over. The signed blob is still unspent (the
    // nonce is claimed only on success), so the link works, and the form it returns to prefills the
    // pinned address read-only.
    const renderIdentityError = (request, h, expectedEmail, actualEmail) =>
        identityErrorView(request, h, {
            expectedEmail,
            actualEmail,
            retryUrl: `/accounts/new?data=${encodeURIComponent(request.payload.data)}&sig=${encodeURIComponent(request.payload.sig)}&type=imap`
        });

    // have to use HTML redirect, otherwise samesite=strict cookies are not passed on
    const renderRedirect = (request, h, httpRedirectUrl) =>
        h.view(
            'redirect',
            {
                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                httpRedirectUrl
            },
            {
                layout: 'public'
            }
        );

    server.route({
        method: 'POST',
        path: '/accounts/new/imap',

        async handler(request, h) {
            // Bound outbound autodiscovery per issued blob (shared cap with the connection tester) so a
            // leaked signed link cannot drive unlimited outbound probes to arbitrary domains.
            const data = await authorizeSignedProbe(request.payload, request.app.gt, request.logger);

            // Reject a pinned link early, before autodiscovery runs against the submitted domain, so the
            // user finds out before typing a password. The create endpoint below is the authoritative check.
            const { expectedEmail, matched } = await checkExpectedIdentity(data, request.payload.email);
            if (!matched) {
                return renderIdentityError(request, h, expectedEmail, request.payload.email);
            }

            let serverSettings;
            try {
                serverSettings = await autodetectImapSettings(request.payload.email, request.app.gt);
            } catch (err) {
                request.logger.debug({ msg: 'Failed to resolve email server settings', email: request.payload.email, err });
            }

            let values = Object.assign(
                {
                    name: request.payload.name,
                    email: request.payload.email,
                    password: request.payload.password,
                    data: request.payload.data,
                    sig: request.payload.sig
                },
                flattenObjectKeys(serverSettings)
            );

            values.imap_auth_user = values.imap_auth_user || request.payload.email;
            values.smtp_auth_user = values.smtp_auth_user || request.payload.email;

            values.imap_auth_pass = request.payload.password;
            values.smtp_auth_pass = request.payload.password;

            return h.view(
                'accounts/register/imap-server',
                {
                    pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                    values,
                    // Nothing resolved for the domain, so the server fields come up empty - the
                    // page says why rather than looking like a form that forgot its defaults
                    autodetectFailed: !serverSettings,
                    autodetectDomain: request.payload.email.split('@').pop(),
                    autoTest:
                        values._source &&
                        values.imap_auth_user &&
                        values.smtp_auth_user &&
                        values.imap_auth_pass &&
                        values.smtp_auth_pass &&
                        values.imap_host &&
                        values.smtp_host &&
                        values.imap_port &&
                        values.smtp_port &&
                        true
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: request.app.gt.gettext("Couldn't set up account. Try again.") });
                    request.logger.debug({ msg: 'Failed to process account', err });

                    // Repopulate the form (crucially the signed data/sig blob) from what was submitted;
                    // without it the hidden inputs render empty and the corrected re-submit fails the
                    // required `data` check, leaving the user stuck. rebuildFormValues rebuilds from the same
                    // schema that validated the submission and drops the plaintext password.
                    const values = rebuildFormValues(firstPageSchema, request.payload, ['password']);

                    return h
                        .view(
                            'accounts/register/imap',
                            {
                                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                                errors,
                                values
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: firstPageSchema
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap/test',
        async handler(request) {
            try {
                // Require a valid signed form blob (throws Boom 403 on failure). Without this an
                // unauthenticated caller could drive outbound IMAP/SMTP connections to arbitrary
                // hosts (SSRF / internal port scan / credential relay); the hosted form always
                // submits the signed data/sig it was issued.
                //
                // NB: this is an AUTHORIZATION gate, not egress filtering. A caller holding a valid
                // signed link can still point imap_host/smtp_host at an internal address, because
                // verifyAccountInfo connects to whatever host it is given (see the matching note there).
                // That residual is accepted by design: EmailEngine is normally deployed as an isolated
                // instance with no local mail servers to reach, so blocking private/loopback IPs would
                // break the legitimate "connect to my own mail server" flow far more often than it would
                // stop a real probe. If you run EmailEngine next to sensitive internal services, isolate
                // it at the network layer rather than expecting this gate to filter egress.
                //
                // The gate authorizes the caller but does not consume the single-use nonce: the form
                // legitimately tests a connection several times before submitting, so the shared
                // per-nonce probe cap (inside authorizeSignedProbe) bounds replays instead.
                await authorizeSignedProbe(request.payload, request.app.gt, request.logger);

                let verifyResult = await verifyAccountInfo(
                    redis,
                    {
                        imap: {
                            host: request.payload.imap_host,
                            port: request.payload.imap_port,
                            secure: request.payload.imap_secure,
                            disabled: request.payload.imap_disabled,
                            auth: {
                                user: request.payload.imap_auth_user,
                                pass: request.payload.imap_auth_pass
                            }
                        },
                        smtp: {
                            host: request.payload.smtp_host,
                            port: request.payload.smtp_port,
                            secure: request.payload.smtp_secure,
                            auth: {
                                user: request.payload.smtp_auth_user,
                                pass: request.payload.smtp_auth_pass
                            }
                        }
                    },
                    request.logger.child({ action: 'verify-account' })
                );

                if (verifyResult) {
                    if (verifyResult.imap && verifyResult.imap.error && verifyResult.imap.code) {
                        // The same translation the SMTP branch below does for its codes: the raw
                        // socket or ImapFlow error text is not something the person at the form
                        // can act on. Closed-after-connect keeps the TLS hint the account state
                        // badge shows for it, because a wrong port/TLS pairing is the usual cause.
                        switch (verifyResult.imap.code) {
                            case 'ENOTFOUND':
                            case 'EAI_AGAIN':
                                verifyResult.imap.error = request.app.gt.gettext('Server hostname was not found');
                                break;
                            case 'AUTHENTICATIONFAILED':
                                verifyResult.imap.error = request.app.gt.gettext('Invalid username or password');
                                break;
                            case 'ETIMEDOUT':
                            case 'ETIMEOUT':
                            case 'GREETING_TIMEOUT':
                                verifyResult.imap.error = request.app.gt.gettext('Connection timed out');
                                break;
                            case 'ECONNREFUSED':
                            case 'ECONNRESET':
                            case 'EHOSTUNREACH':
                            case 'ENETUNREACH':
                                verifyResult.imap.error = request.app.gt.gettext('Could not connect to server');
                                break;
                            case 'ClosedAfterConnectTLS':
                            case 'ClosedAfterConnectText':
                                verifyResult.imap.error = closedAfterConnectMessage(verifyResult.imap.code, request.app.gt);
                                break;
                            case 'EPROTO':
                            case 'ERR_TLS_CERT_ALTNAME_INVALID':
                            case 'ERR_SSL_WRONG_VERSION_NUMBER':
                            case 'CERT_HAS_EXPIRED':
                            case 'DEPTH_ZERO_SELF_SIGNED_CERT':
                            case 'SELF_SIGNED_CERT_IN_CHAIN':
                            case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
                                verifyResult.imap.error = request.app.gt.gettext('TLS protocol error');
                                break;
                            default:
                                if (/openssl|ssl routines/i.test(verifyResult.imap.error)) {
                                    verifyResult.imap.error = request.app.gt.gettext('TLS protocol error');
                                }
                                break;
                        }
                    }

                    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
                        switch (verifyResult.smtp.code) {
                            case 'EDNS':
                                verifyResult.smtp.error = request.app.gt.gettext('Server hostname was not found');
                                break;
                            case 'EAUTH':
                                verifyResult.smtp.error = request.app.gt.gettext('Invalid username or password');
                                break;
                            case 'ENOAUTH':
                                verifyResult.smtp.error = request.app.gt.gettext('Authentication credentials were not provided');
                                break;
                            case 'EOAUTH2':
                                verifyResult.smtp.error = request.app.gt.gettext('OAuth2 authentication failed');
                                break;
                            case 'ETLS':
                                verifyResult.smtp.error = request.app.gt.gettext('TLS protocol error');
                                break;
                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = request.app.gt.gettext('TLS protocol error');
                                }
                                break;
                            case 'ETIMEDOUT':
                                verifyResult.smtp.error = request.app.gt.gettext('Connection timed out');
                                break;
                            case 'ECONNECTION':
                                verifyResult.smtp.error = request.app.gt.gettext('Could not connect to server');
                                break;
                            case 'EPROTOCOL':
                                verifyResult.smtp.error = request.app.gt.gettext('Unexpected server response');
                                break;
                        }
                    }
                }

                return verifyResult;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            tags: ['test'],
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    ...signedBlobFields,
                    ...connectionFields
                })
            }
        }
    });

    // Shared by this route's payload validation and its failAction re-render, so the re-rendered form
    // is built from the same schema that validated the submission and cannot drift from it (unlike the
    // earlier hand-maintained truthy Set, which had to be kept in sync by hand).
    const serverFormSchema = Joi.object({
        ...signedBlobFields,
        name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
        tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone for autogenerated date strings'),
        email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
        ...connectionFields
    });

    server.route({
        method: 'POST',
        path: '/accounts/new/imap/server',

        async handler(request, h) {
            const data = await parseSignedFormData(redis, request.payload, request.app.gt, { requireNonce: true });

            // Before the nonce claim below, so a rejected attempt does not consume the setup link and the
            // "try again" link on the error page still works.
            const { expectedEmail, matched } = await checkExpectedIdentity(data, request.payload.email);
            if (!matched) {
                return renderIdentityError(request, h, expectedEmail, request.payload.email);
            }

            const accountData = {
                account: data.account || null,
                name: request.payload.name || data.name,
                email: request.payload.email,

                tz: request.payload.tz,

                notifyFrom: data.notifyFrom ? new Date(data.notifyFrom) : new Date(),

                syncFrom: data.syncFrom || null,
                path: data.path || null,

                imap: {
                    host: request.payload.imap_host,
                    port: request.payload.imap_port,
                    secure: request.payload.imap_secure,
                    disabled: request.payload.imap_disabled,
                    auth: {
                        user: request.payload.imap_auth_user,
                        pass: request.payload.imap_auth_pass
                    }
                },
                smtp: {
                    host: request.payload.smtp_host,
                    port: request.payload.smtp_port,
                    secure: request.payload.smtp_secure,
                    auth: {
                        user: request.payload.smtp_auth_user,
                        pass: request.payload.smtp_auth_pass
                    }
                }
            };

            if (data.subconnections && data.subconnections.length) {
                accountData.subconnections = data.subconnections;
            }

            if (expectedEmail) {
                // Pin the account so later setups are checked even from a link that carries no expectation.
                accountData.expectedEmail = expectedEmail;
            }

            const accountObject = new Account({ redis, call, secret: await getSecret() });

            // Claim the single-use nonce BEFORE creating the account so a concurrent double-submit or
            // a replayed URL cannot create duplicate accounts (SET NX is atomic). parseSignedFormData
            // already rejects a nonce that was fully consumed by an earlier successful submit.
            // requireNonce:true above guarantees data.n and data.t are present.
            // claimFormNonce/releaseFormNonce (lib/tools.js) encapsulate the SET NX + release so the IMAP
            // arm and the OAuth callback (workers/api.js) share one copy of the double-spend semantics.
            let claimed;
            try {
                claimed = await claimFormNonce(redis, data.n, data.t);
            } catch (err) {
                // A Redis failure here is not a consumed nonce. Report it as a retryable server error
                // instead of misdiagnosing a valid setup URL as invalid or expired.
                request.logger.error({ msg: 'Failed to claim nonce for an account form request', err });
                throw Boom.boomify(new Error(request.app.gt.gettext('Temporary error, please try again')), { statusCode: 500 });
            }
            if (!claimed) {
                // SET NX returned null: the nonce key already exists, so this URL was already used.
                //
                // Reviewed, accepted (do not "fix" server-side): the LOSING side of a legitimate concurrent
                // double-submit lands here and sees this 403 even though the winning request created the
                // account. The client-side formSubmitting latch (views/accounts/register/imap-server.hbs) is
                // the primary guard; the residual is a no-JS double-click, and even then this is strictly
                // better than the pre-hardening behavior (two duplicate accounts). A nicer UX (store the
                // created account id under the nonce key and redirect the loser to success) is a possible
                // future enhancement, not a bug.
                throw Boom.boomify(new Error(request.app.gt.gettext('Invalid or expired account setup URL')), { statusCode: 403 });
            }

            let result;
            try {
                result = await accountObject.create(accountData);
            } catch (err) {
                // Release the nonce so the user can fix the form and retry. Accepted residual: if
                // Redis fails here too (it likely failed create() as well), the nonce stays consumed
                // for its remaining TTL and the user needs a freshly issued link - the claim-BEFORE-
                // create ordering is what makes the double-submit dedupe atomic, and this narrow
                // crash window is the price of that.
                await releaseFormNonce(redis, data.n, request.logger);
                throw err;
            }

            let httpRedirectUrl;
            if (data.redirectUrl) {
                const serviceUrl = await settings.get('serviceUrl');
                const url = new URL(data.redirectUrl, serviceUrl);
                url.searchParams.set('account', result.account);
                url.searchParams.set('state', result.state);
                httpRedirectUrl = url.href;
            } else {
                httpRedirectUrl = `/admin/accounts/${result.account}`;
            }

            return renderRedirect(request, h, httpRedirectUrl);
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: request.app.gt.gettext("Couldn't set up account. Try again.") });
                    request.logger.debug({ msg: 'Failed to process account', err });

                    // Rebuild the re-render values from the SAME schema that just validated the submission
                    // (coerces the tri-state checkboxes, strips unknown/prototype keys, drops both plaintext
                    // passwords) - see rebuildFormValues.
                    const values = rebuildFormValues(serverFormSchema, request.payload, ['imap_auth_pass', 'smtp_auth_pass']);

                    // serverFormSchema does not carry the appPassword_* hint fields (they feed unescaped
                    // template sinks), so stripUnknown drops them. Re-derive the hint server-side from the
                    // (trusted) email so the re-rendered form still shows the app-password label and
                    // instructions for Gmail/iCloud/Outlook/etc. The values come from a static table, never
                    // from the submitted payload, so they are safe to render.
                    //
                    // Try the static domain table first: it is synchronous, needs no network, and covers the
                    // canonical provider domains, so a common-domain re-render costs no Redis round trips, no
                    // DNS, and no probe budget.
                    if (values.email) {
                        let appPassword = getAppPassword(values.email, false, request.app.gt);

                        // Custom-domain fallback (e.g. Google Workspace / M365 on their own domain) needs an
                        // MX lookup. failAction runs BEFORE the handler's signature gate, and the lookup
                        // drives outbound DNS, so gate it with the SAME machinery as the handler siblings, not
                        // a bare signature check: authorizeSignedProbe rejects a signature-only blob (e.g. a
                        // leaked tracking/unsubscribe blob) and one past its TTL, and bounds how many lookups
                        // one signed link can drive. Without it, any holder of any validly-signed blob could
                        // turn this re-render into an unbounded DNS oracle. On a normal validation-error
                        // re-render the nonce is not yet consumed (the handler claims it only on success), so
                        // the hint still shows. values.data/values.sig are the schema-validated copies -
                        // rebuildFormValues drops them when malformed (e.g. duplicated fields).
                        if (!appPassword && values.data && values.sig) {
                            // Consult the per-domain memo BEFORE the probe/DNS work: a repeat re-submit of
                            // the same email must not re-run the MX lookup or draw the probe budget again.
                            const domain = values.email.split('@').pop().trim().toLowerCase();
                            const cached = getCachedAppPasswordHint(domain);
                            if (cached) {
                                appPassword = cached.value;
                            } else {
                                try {
                                    await authorizeSignedProbe({ data: values.data, sig: values.sig }, request.app.gt, request.logger);
                                    appPassword = await resolveAppPassword(values.email, request.app.gt);
                                    // Cache the outcome (including a falsy "no hint" result) so subsequent
                                    // re-renders for this domain are free.
                                    setCachedAppPasswordHint(domain, appPassword);
                                } catch (err) {
                                    // The hint is cosmetic; a rejected/expired blob, an exhausted probe cap, or a
                                    // lookup failure must never break the error re-render (failAction must not throw).
                                    // Do NOT cache on failure - an exhausted probe cap or transient DNS error should
                                    // not poison the hint for the whole TTL.
                                    request.logger.debug({ msg: 'Failed to resolve app-password hint for form re-render', err });
                                }
                            }
                        }

                        if (appPassword) {
                            Object.assign(values, flattenObjectKeys({ appPassword }));
                        }
                    }

                    return h
                        .view(
                            'accounts/register/imap-server',
                            {
                                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                                errors,
                                values
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: serverFormSchema
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}',
        async handler(request, h) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            let accountData;

            const runIndex = await call({
                cmd: 'runIndex'
            });

            try {
                // throws if account does not exist
                accountData = await accountObject.loadAccountData(null, null, runIndex);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }

            let subConnectionInfo;
            try {
                subConnectionInfo = await call({ cmd: 'subconnections', account: request.params.account });
                for (let subconnection of subConnectionInfo) {
                    formatAccountData(subconnection, request.app.gt);
                }
            } catch (err) {
                subConnectionInfo = {
                    err
                };
            }

            if (accountData && accountData.oauth2 && accountData.oauth2.provider) {
                let oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
                if (oauth2App) {
                    accountData.oauth2.app = oauth2App;
                    accountData.oauth2.providerData = oauth2ProviderData(oauth2App.provider, oauth2App.cloud);
                }
            }

            accountData = formatAccountData(accountData, request.app.gt);

            accountData.imap = accountData.imap || {
                disabled: !accountData.oauth2
            };

            let gatewayObject = new Gateway({ redis });
            let gateways = await gatewayObject.listGateways(0, 100);

            // the ID response fields come from the remote IMAP server; only expose
            // support-url as a link when it is a plain http(s) URL
            if (accountData.imapServerInfo && accountData.imapServerInfo['support-url'] && !/^https?:\/\//i.test(accountData.imapServerInfo['support-url'])) {
                delete accountData.imapServerInfo['support-url'];
            }

            let capabilities = [];
            if (accountData.imapServerInfo && accountData.imapServerInfo.capabilities) {
                capabilities = await capa(accountData.imapServerInfo.capabilities);
            }

            let authCapabilities = [];
            if (accountData.imapServerInfo && accountData.imapServerInfo.authCapabilities) {
                authCapabilities = await capa(accountData.imapServerInfo.authCapabilities, accountData.imapServerInfo.lastUsedAuthCapability);
            }

            if (accountData.smtpServerEhlo && accountData.smtpServerEhlo.length) {
                let smtpAuthMechanisms = [];
                for (let i = accountData.smtpServerEhlo.length - 1; i >= 0; i--) {
                    let entry = accountData.smtpServerEhlo[i];
                    if (/^auth\b/i.test(entry)) {
                        let authEntries = entry.split(/\s+/).slice(1);
                        if (authEntries.length) {
                            smtpAuthMechanisms = smtpAuthMechanisms.concat(authEntries);
                        }
                        accountData.smtpServerEhlo.splice(i, 1);
                    }
                }
                accountData.smtpAuthMechanisms = Array.from(new Set(smtpAuthMechanisms));

                for (let i = accountData.smtpAuthMechanisms.length - 1; i >= 0; i--) {
                    let entry = accountData.smtpAuthMechanisms[i];
                    switch (entry.toUpperCase()) {
                        case 'LOGIN':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'draft-murchison-sasl-login',
                                url: 'https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login'
                            };
                            break;
                        case 'PLAIN':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'RFC4616',
                                url: 'https://www.rfc-editor.org/rfc/rfc4616.html'
                            };
                            break;
                        case 'XOAUTH2':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'xoauth2-protocol',
                                url: 'https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange'
                            };
                            break;
                        case 'OAUTHBEARER':
                            accountData.smtpAuthMechanisms[i] = {
                                auth: entry,
                                rfc: 'RFC7628',
                                url: 'https://www.rfc-editor.org/rfc/rfc7628.html'
                            };
                            break;
                    }
                }
            }

            // Stored entries outlive the logging switch - turning logging off does not clear what
            // was already collected - so the download control is gated on the entries themselves,
            // not on whether logging is currently enabled. Both are snapshots taken at render
            // time, the same as everything else on this page.
            let [logSettings, storedLogCount] = await Promise.all([settings.get('logs'), redis.llen(accountObject.getLogKey())]);

            let logInfo = logSettings || {
                all: false
            };
            let hasStoredLogs = storedLogCount > 0;

            accountData.path = [].concat(accountData.path || '*');
            if (accountData.path.includes('*')) {
                accountData.path = null;
            }

            let gmailWatch =
                accountData.watchResponse || accountData.watchFailure
                    ? {
                          lastCheckStr: accountData.lastWatch && accountData.lastWatch.toISOString(),
                          expiresStr:
                              accountData.watchResponse && accountData.watchResponse.expiration
                                  ? new Date(Number(accountData.watchResponse.expiration)).toISOString()
                                  : false
                      }
                    : false;

            if (gmailWatch) {
                gmailWatch.active = gmailWatch.expiresStr && new Date(gmailWatch.expiresStr) > new Date();
                gmailWatch.stateLabel = gmailWatch.active ? 'Active' : 'Expired';
                if (accountData.watchFailure) {
                    gmailWatch.error = accountData.watchFailure.err;
                    if (!gmailWatch.active) {
                        gmailWatch.stateLabel = 'Failed';
                    }

                    if (accountData.watchFailure.req) {
                        gmailWatch.request = {
                            url: accountData.watchFailure.req.url,
                            status: accountData.watchFailure.req.status,
                            contentType: accountData.watchFailure.req.contentType,
                            response: accountData.watchFailure.req.response
                        };
                    }
                }
            }

            const canReadMail = (accountData.imap || accountData.oauth2) && !(accountData.imap && accountData.imap.disabled) && !DISABLE_MESSAGE_BROWSER;

            // The auth-failure safety net parks an account by setting imap.disabled, and for a
            // Gmail API or Outlook account that is a flag with nowhere to show: the IMAP and SMTP
            // cards below are hidden for API accounts, so the parked account reported nothing but
            // a neutral "Not syncing" and the operator had no way back that did not involve a raw
            // API call.
            const disabledByAuthFailureAt = authFailureDisabledAt(accountData);

            // Top-of-page alert for the account's primary problem, so a broken account is
            // impossible to miss. Gated on the effective connection state (stateLabel.type) so a
            // recovered account never shows a stale error; a stalled sync is surfaced separately
            // because the account can otherwise be connected.
            let accountAlert = null;
            if (disabledByAuthFailureAt) {
                // Ahead of the state alert: a parked account is not connecting at all, so why it
                // was switched off is the more actionable of the two.
                accountAlert = {
                    title: 'Syncing was switched off',
                    message:
                        'EmailEngine stopped connecting this account after repeated authentication failures. Re-authenticating it turns syncing back on; "Resume syncing" retries with the stored credentials.',
                    timeLabel: 'Switched off',
                    time: disabledByAuthFailureAt
                };
            } else if (accountData.stateLabel && accountData.stateLabel.type === 'error') {
                accountAlert = {
                    title: accountData.stateLabel.name,
                    message: accountData.stateLabel.error
                };
            } else if (accountData.syncError) {
                accountAlert = {
                    title: 'Sync stalled',
                    path: accountData.syncError.path,
                    message: (accountData.syncError.error && (accountData.syncError.error.responseText || accountData.syncError.error.error)) || null
                };
            }

            const [webhookSettings, webhookRoutesList] = await Promise.all([
                settings.getMulti('webhooksEnabled', 'webhooks', 'webhookEvents', 'inboxNewOnly', 'webhooksCustomHeaders'),
                Webhooks.list(0, 1000)
            ]);

            // The listing carries route metadata only, but the worker's delivery gate also
            // requires a filter script, so the card needs the filter-presence markers for the
            // routes it is about to present as delivering
            const routeFilterInfo = await Webhooks.getFilterInfo(webhookRoutesList.webhooks.filter(isDeliverableRoute).map(route => route.id));

            const webhookRouting = describeEffectiveRouting({
                webhooksEnabled: webhookSettings.webhooksEnabled,
                globalWebhooks: webhookSettings.webhooks,
                accountWebhooks: accountData.webhooks,
                webhookEvents: webhookSettings.webhookEvents,
                inboxNewOnly: webhookSettings.inboxNewOnly,
                globalCustomHeaders: webhookSettings.webhooksCustomHeaders,
                accountCustomHeaders: accountData.webhooksCustomHeaders,
                // Non-deliverable routes were not probed; their hasFilter stays undefined, which
                // describeEffectiveRouting() reads as "unknown" (and filters them out anyway)
                routes: webhookRoutesList.webhooks.map(route => Object.assign({}, route, { hasFilter: routeFilterInfo.get(route.id) }))
            });

            return h.view(
                'accounts/account',
                {
                    pageTitle: `Accounts - ${accountData.email}`,

                    menuAccounts: true,
                    account: accountData,
                    accountAlert,
                    accountParked: !!disabledByAuthFailureAt,
                    logs: logInfo,
                    hasStoredLogs,
                    smtpError: accountData.smtpStatus && accountData.smtpStatus.status === 'error',

                    showSmtp: accountData.smtp || (accountData.oauth2 && accountData.oauth2.provider),

                    canReadMail,

                    canSend: !!(
                        accountData.smtp ||
                        (accountData.oauth2 && accountData.oauth2.provider) ||
                        (gateways && gateways.gateways && gateways.gateways.length)
                    ),
                    canUseSmtp: !!(
                        accountData.smtp ||
                        (accountData.oauth2 && (accountData.oauth2.provider || (accountData.oauth2.auth && accountData.oauth2.auth.delegatedAccount)))
                    ),
                    gateways: gateways && gateways.gateways,

                    testSendTemplate: cachedTemplates.testSend,

                    accountForm: await getSignedFormData({
                        account: request.params.account,
                        name: accountData.name,
                        email: accountData.email,
                        redirectUrl: `/admin/accounts/${request.params.account}`,

                        // Single-use nonce + timestamp so this blob (embedded in the account page and
                        // used by the OAuth "Re-authenticate" form) cannot be replayed at the auth:false
                        // /accounts/new/imap/{test,server} endpoints if it leaks. Mirrors the new-account
                        // issuer above. Accepted consequences, BY DESIGN: the blob expires after
                        // MAX_FORM_TTL (24h), and it is consumed by the next successful re-auth (the OAuth
                        // callback and the IMAP form submit both claim account:form:{n}), so a stale tab or
                        // a back-button copy of this page gets a 403 on Re-authenticate until the page is
                        // reloaded - reloading re-mints a fresh blob.
                        n: crypto.randomBytes(NONCE_BYTES).toString('base64url'),
                        t: Date.now()
                    }),

                    showAdvanced: accountData.proxy || accountData.path,

                    webhookRouting,

                    subConnectionInfo,

                    capabilities,
                    authCapabilities,

                    gmailWatch
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/delete',
        async handler(request, h) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, documentsQueue, call, secret: await getSecret() });

                let { deleted } = await accountObject.delete();
                if (deleted) {
                    await request.flash({ type: 'info', message: `Account deleted` });
                } else {
                    await request.flash({ type: 'danger', message: `Requested account was not found` });
                }

                return h.redirect('/admin/accounts');
            } catch (err) {
                if (isClientError(err) && err.output.statusCode === 404) {
                    // Already gone (a stale tab, a double submit): say so and land on the
                    // listing rather than on the deleted account's page
                    await request.flash({ type: 'danger', message: `Requested account was not found` });
                    return h.redirect('/admin/accounts');
                }

                await request.flash({ type: 'danger', message: `Couldn't delete account. Try again.` });
                request.logger.error({ msg: 'Failed to delete the account', err, account: request.params.account, remoteAddress: request.app.ip });
                return h.redirect(adminUrl`/admin/accounts/${request.params.account}`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete account. Try again.` });
                    request.logger.error({ msg: 'Failed to delete the account', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/reconnect',
        async handler(request) {
            let account = request.params.account;
            try {
                request.logger.info({ msg: 'Requesting account reconnect', account });

                // Through requestReconnect() rather than dispatching here, so this button and
                // PUT /v1/account/{account}/reconnect share one answer. It declines for an account
                // the auth-failure safety net switched off, where the dispatch would be a no-op -
                // and since this caller always asks to reconnect, a false is that refusal. The
                // button is also rendered disabled in that state; this is what makes the refusal
                // real rather than cosmetic.
                let accountObject = new Account({ redis, account, call, secret: await getSecret() });

                if (!(await accountObject.requestReconnect({ reconnect: true }))) {
                    return { success: false, error: 'Syncing is switched off for this account. Use "Resume syncing" to turn it back on.' };
                }

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request reconnect', err, account });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    // Turns an account back on after the auth-failure safety net switched it off. The only admin
    // UI route that reaches the flag for a Gmail API or Outlook account: their IMAP card, and with
    // it the "Disable IMAP" checkbox an IMAP account is re-enabled through, is not rendered.
    //
    // Lifts nothing but the safety net's own disable (see Account.clearAuthFailureDisable), so it
    // cannot be used to un-do an operator's deliberate send-only switch.
    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/resume',
        async handler(request) {
            let account = request.params.account;
            try {
                // clearAuthFailureDisable() needs nothing but the account hash, and the reconnect
                // below is dispatched from this module's own channel
                let accountObject = new Account({ redis, account });

                if (!(await accountObject.clearAuthFailureDisable())) {
                    return { success: false, error: 'This account was not switched off by EmailEngine' };
                }

                request.logger.info({ msg: 'Resumed an account that was switched off after authentication failures', account });

                try {
                    await call({ cmd: 'reconnect', account });
                } catch (err) {
                    // The flag is already lifted, so the account is no longer parked. Losing the
                    // dispatch only delays the connection until the next periodic reconnect.
                    request.logger.error({ msg: 'Reconnect request failed', action: 'resume_account', account, err });
                }

                return { success: true };
            } catch (err) {
                request.logger.error({ msg: 'Failed to resume account', err, account });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/sync',
        async handler(request) {
            let account = request.params.account;
            try {
                request.logger.info({ msg: 'Request syncing', account });
                try {
                    await call({ cmd: 'sync', account });
                } catch (err) {
                    request.logger.error({ msg: 'Sync request failed', action: 'request_sync', account, err });
                }

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request syncing', err, account });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/logs',
        async handler(request) {
            let account = request.params.account;
            let accountObject = new Account({ redis, account });
            try {
                request.logger.info({ msg: 'Request to update account logging state', account, enabled: request.payload.enabled });

                await redis.hSetExists(accountObject.getAccountKey(), 'logs', request.payload.enabled ? 'true' : 'false');

                try {
                    await call({ cmd: 'update', account });
                } catch (err) {
                    request.logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                }

                return {
                    success: true,
                    enabled: (await redis.hget(accountObject.getAccountKey(), 'logs')) === 'true'
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to update account logging state', err, account, enabled: request.payload.enabled });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/logs-flush',
        async handler(request) {
            let account = request.params.account;
            let accountObject = new Account({ redis, account });
            try {
                request.logger.info({ msg: 'Request to flush logs', account });

                await redis.del(accountObject.getLogKey());

                return {
                    success: true
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to flush logs', err, account });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/logs.txt',
        async handler(request) {
            return getLogs(redis, request.params.account);
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/browse',
        async handler(request, h) {
            let authData = await settings.get('authData');
            let hasExistingPassword = !!(authData && authData.password);
            if (!hasExistingPassword) {
                await request.flash({ type: 'info', message: `Set a password to access messages` });
                return h.redirect('/admin/account/password');
            }

            if (!request.state.ee || !request.state.ee.sid) {
                // force login to get the sid assigned
                if (request.cookieAuth) {
                    request.cookieAuth.clear();
                }
                await request.flash({ type: 'info', message: `Sign in again to continue.` });
                return h.redirect('/admin/login?next=' + encodeURIComponent(`/admin/accounts/${encodeURIComponent(request.params.account)}/browse`));
            }

            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            let accountData;
            try {
                // throws if account does not exist
                accountData = await accountObject.loadAccountData();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }

            const canReadMail = (accountData.imap || accountData.oauth2) && !(accountData.imap && accountData.imap.disabled) && !DISABLE_MESSAGE_BROWSER;
            if (!canReadMail) {
                await request.flash({ type: 'danger', message: `Mail access is disabled for this account` });
                return h.redirect(adminUrl`/admin/accounts/${request.params.account}`);
            }

            return h.view(
                'accounts/browse',
                {
                    pageTitle: `Browse - ${accountData.email}`,

                    menuAccounts: true,
                    account: request.params.account,

                    sessionToken: await tokens.getSessionToken(request.state.ee.sid, request.params.account, 900)
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/edit',
        async handler(request, h) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            let accountData;
            try {
                // throws if account does not exist
                accountData = await accountObject.loadAccountData();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }

            const values = Object.assign({}, flattenObjectKeys(accountData), {
                imap: true,
                // The checkbox is the operator's own switch, so a park by the auth-failure safety
                // net does not pre-check it: the page alert promises that saving new credentials
                // turns syncing back on, and a pre-checked box would have made every such save an
                // explicit request to keep the account off. Unchecked, the connection fields are
                // shown and the save writes `disabled: false`, which lifts the park.
                imap_disabled: (!accountData.imap && !accountData.oauth2) || isOperatorDisabled(accountData),
                imap_tls_ignoreCertErrors: !!(accountData.imap && accountData.imap.tls && accountData.imap.tls.rejectUnauthorized === false),
                smtp: !!accountData.smtp,
                smtp_tls_ignoreCertErrors: !!(accountData.smtp && accountData.smtp.tls && accountData.smtp.tls.rejectUnauthorized === false),
                oauth2: !!accountData.oauth2,

                imap_auth_pass: '',
                smtp_auth_pass: '',

                customHeaders: []
                    .concat(accountData.webhooksCustomHeaders || [])
                    .map(entry => `${entry.key}: ${entry.value}`.trim())
                    .join('\n')
            });

            let mailboxes = await getMailboxListing(accountObject);

            return h.view(
                'accounts/edit',
                {
                    pageTitle: `Accounts - ${accountData.email}`,

                    menuAccounts: true,
                    account: request.params.account,
                    values,
                    availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                    isApi: accountData.isApi,

                    hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                    hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                    defaultSmtpEhloName: await getServiceHostname()
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Invalid account request: ${err.message}` });
                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/edit',
        async handler(request, h) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

                let oldData = await accountObject.loadAccountData();

                let updates = {
                    account: request.params.account,
                    name: request.payload.name || '',
                    email: request.payload.email,
                    // Empty clears the pin (Account.update hdel's it), which is the only way an operator
                    // can unblock a legitimate mailbox migration on a pinned account.
                    expectedEmail: request.payload.expectedEmail || null,
                    proxy: request.payload.proxy,
                    smtpEhloName: request.payload.smtpEhloName,
                    webhooks: request.payload.webhooks
                };

                updates.webhooksCustomHeaders = request.payload.customHeaders
                    .split(/[\r\n]+/)
                    .map(header => header.trim())
                    .filter(header => header)
                    .map(line => {
                        let sep = line.indexOf(':');
                        if (sep >= 0) {
                            return {
                                key: line.substring(0, sep).trim(),
                                value: line.substring(sep + 1).trim()
                            };
                        }
                        return {
                            key: line,
                            value: ''
                        };
                    });

                if (request.payload.imap) {
                    let imapTls = (oldData.imap && oldData.imap.tls) || {};

                    let updateKeys = {};

                    for (let key of ['host', 'port', 'disabled', 'sentMailPath']) {
                        if (`imap_${key}` in request.payload) {
                            updateKeys[key] = request.payload[`imap_${key}`];
                        }
                    }

                    if ('imap_auth_user' in request.payload) {
                        let imapAuth = Object.assign((oldData.imap && oldData.imap.auth) || {}, { user: request.payload.imap_auth_user });
                        if (request.payload.imap_auth_pass) {
                            imapAuth.pass = request.payload.imap_auth_pass;
                        }
                        updateKeys.auth = imapAuth;
                        updateKeys.secure = request.payload.imap_secure;
                        // The connection settings section is hidden for OAuth2 and disabled
                        // accounts, so like `secure` these only apply when it was submitted.
                        // Written only when the effective state changes - an untouched form
                        // save must not add new keys, as any imap diff forces a reconnect
                        if (request.payload.imap_tls_ignoreCertErrors !== (imapTls.rejectUnauthorized === false)) {
                            imapTls.rejectUnauthorized = !request.payload.imap_tls_ignoreCertErrors;
                        }
                        if (request.payload.imap_disableIMAP4rev2 !== !!(oldData.imap && oldData.imap.disableIMAP4rev2)) {
                            updateKeys.disableIMAP4rev2 = request.payload.imap_disableIMAP4rev2;
                        }
                    }

                    // skipped while empty and absent from the stored account for the same
                    // reason as above - a no-op save must not introduce a tls:{} key
                    if (Object.keys(imapTls).length) {
                        updateKeys.tls = imapTls;
                    }

                    updates.imap = Object.assign(oldData.imap || {}, updateKeys);

                    if (request.payload.imap_resyncDelay) {
                        updates.imap.resyncDelay = request.payload.imap_resyncDelay;
                    }
                }

                if (request.payload.smtp) {
                    let smtpAuth = Object.assign((oldData.smtp && oldData.smtp.auth) || {}, { user: request.payload.smtp_auth_user });
                    let smtpTls = (oldData.smtp && oldData.smtp.tls) || {};

                    if (request.payload.smtp_auth_pass) {
                        smtpAuth.pass = request.payload.smtp_auth_pass;
                    }

                    // written only when the effective state changes, and the tls object is
                    // skipped while empty - same as the IMAP flags, a no-op save must not
                    // modify the stored account
                    if (request.payload.smtp_tls_ignoreCertErrors !== (smtpTls.rejectUnauthorized === false)) {
                        smtpTls.rejectUnauthorized = !request.payload.smtp_tls_ignoreCertErrors;
                    }

                    updates.smtp = Object.assign(oldData.smtp || {}, {
                        host: request.payload.smtp_host,
                        port: request.payload.smtp_port,
                        secure: request.payload.smtp_secure,
                        auth: smtpAuth
                    });

                    if (Object.keys(smtpTls).length) {
                        updates.smtp.tls = smtpTls;
                    }
                }

                await accountObject.update(updates);

                return h.redirect(adminUrl`/admin/accounts/${request.params.account}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save account settings. Try again.` });
                request.logger.error({ msg: 'Failed to update account settings', err, account: request.params.account });

                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                let accountData = await accountObject.loadAccountData();

                let mailboxes = await getMailboxListing(accountObject);

                return h.view(
                    'accounts/edit',
                    {
                        pageTitle: `Accounts - ${accountData.email}`,

                        menuAccounts: true,
                        account: request.params.account,
                        // re-render the form from the submitted payload (the field names
                        // match the template values); without this the form comes back
                        // blank and the IMAP/SMTP cards disappear entirely
                        values: Object.assign({}, request.payload, {
                            oauth2: !!accountData.oauth2,
                            imap_auth_pass: '',
                            smtp_auth_pass: ''
                        }),
                        availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                        isApi: accountData.isApi,

                        hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                        hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                        defaultSmtpEhloName: await getServiceHostname()
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.debug({ msg: 'Failed to update configuration', err });

                    let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                    let accountData = await accountObject.loadAccountData();
                    let mailboxes = await getMailboxListing(accountObject);

                    return h
                        .view(
                            'accounts/edit',
                            {
                                pageTitle: `Accounts - ${accountData.email}`,

                                menuAccounts: true,
                                account: request.params.account,
                                errors,
                                // re-render the form from the (raw, unvalidated) submitted
                                // payload so the entered values and the IMAP/SMTP cards
                                // survive a validation failure
                                values: Object.assign({}, request.payload, {
                                    oauth2: !!accountData.oauth2,
                                    imap_auth_pass: '',
                                    smtp_auth_pass: ''
                                }),
                                availablePaths: JSON.stringify(mailboxes.map(entry => entry.path)),

                                isApi: accountData.isApi,

                                hasIMAPPass: accountData.imap && accountData.imap.auth && !!accountData.imap.auth.pass,
                                hasSMTPPass: accountData.smtp && accountData.smtp.auth && !!accountData.smtp.auth.pass,
                                defaultSmtpEhloName: await getServiceHostname()
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),

                    expectedEmail: accountSchemas.expectedEmail,

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    imap_auth_user: Joi.string().empty('').trim().max(1024),
                    imap_auth_pass: Joi.string().empty('').max(1024),
                    imap_host: Joi.string().hostname().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(993)
                        .description('Service port number'),
                    imap_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),
                    imap_tls_ignoreCertErrors: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Allow connections to servers with invalid TLS certificates for this account'),
                    imap_disableIMAP4rev2: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Do not use IMAP4rev2 even if the server supports it'),
                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    imap_resyncDelay: Joi.number().integer().empty(''),

                    imap_sentMailPath: Joi.string()
                        .empty('')
                        .default(null)
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used. Leave empty to unset."),

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    smtp: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024),
                    smtp_auth_pass: Joi.string().empty('').max(1024),
                    smtp_host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number'),
                    smtp_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465'),
                    smtp_tls_ignoreCertErrors: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Allow connections to servers with invalid TLS certificates for this account'),

                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .description('Custom request headers')
                })
            }
        }
    });
}

module.exports = init;
