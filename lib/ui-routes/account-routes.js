'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const crypto = require('crypto');
const util = require('util');
const psl = require('psl');

const settings = require('../settings');
const tokens = require('../tokens');
const { redis, documentsQueue } = require('../db');
const {
    failAction,
    verifyAccountInfo,
    getLogs,
    flattenObjectKeys,
    getSignedFormData,
    getServiceHostname,
    parseSignedFormData,
    getBoolean,
    readEnvValue
} = require('../tools');
const { Account } = require('../account');
const { Gateway } = require('../gateway');
const { oauth2Apps, oauth2ProviderData } = require('../oauth2-apps');
const { autodetectImapSettings } = require('../autodetect-imap-settings');
const getSecret = require('../get-secret');
const capa = require('../capa');
const consts = require('../consts');
const { settingsSchema, accountIdSchema, defaultAccountTypeSchema } = require('../schemas');
const fs = require('fs');
const pathlib = require('path');

const { DEFAULT_MAX_LOG_LINES, DEFAULT_PAGE_SIZE, REDIS_PREFIX, MAX_FORM_TTL, NONCE_BYTES } = consts;

const DISABLE_MESSAGE_BROWSER = getBoolean(readEnvValue('EENGINE_DISABLE_MESSAGE_BROWSER'));

const cachedTemplates = {
    testSend: fs.readFileSync(pathlib.join(__dirname, '..', '..', 'views', 'partials', 'test_send.hbs'), 'utf-8')
};

function formatAccountData(account, gt) {
    account.type = {};

    if (account.oauth2 && account.oauth2.app) {
        let providerData = oauth2ProviderData(account.oauth2.app.provider);
        account.type = providerData;
    } else if (account.oauth2 && account.oauth2.provider) {
        account.type = oauth2ProviderData(account.oauth2.provider);
    } else if (account.imap && !account.imap.disabled) {
        account.type.icon = 'fa fa-envelope-square';
        account.type.name = 'IMAP';
        account.type.comment = psl.get(account.imap.host) || account.imap.host;
    } else if (account.smtp) {
        account.type.icon = 'fa fa-paper-plane';
        account.type.name = 'SMTP';
        account.type.comment = psl.get(account.smtp.host) || account.smtp.host;
    } else if (account.oauth2 && account.oauth2.auth && account.oauth2.auth.delegatedAccount) {
        account.type.icon = 'fa fa-arrow-alt-circle-right';
        account.type.name = gt.gettext('Delegated');
        account.type.comment = util.format(gt.gettext('Using credentials from "%s"'), account.oauth2.auth.delegatedAccount);
    } else {
        account.type.name = 'N/A';
    }

    switch (account.state) {
        case 'init':
            account.stateLabel = {
                type: 'info',
                name: 'Initializing',
                spinner: true
            };
            break;

        case 'connecting':
            account.stateLabel = {
                type: 'info',
                name: 'Connecting'
            };
            break;

        case 'syncing':
            account.stateLabel = {
                type: 'info',
                name: 'Syncing',
                spinner: true
            };
            break;

        case 'connected':
            account.stateLabel = {
                type: 'success',
                name: 'Connected'
            };
            break;

        case 'disabled':
            account.stateLabel = {
                type: 'secondary',
                name: 'Disabled',
                error: account.disabledReason
            };
            break;

        case 'authenticationError':
        case 'connectError': {
            let errorMessage = account.lastErrorState ? account.lastErrorState.response : false;
            if (account.lastErrorState) {
                switch (account.lastErrorState.serverResponseCode) {
                    case 'ETIMEDOUT':
                        errorMessage = gt.gettext('Connection timed out. This usually occurs if you are behind a firewall or connecting to the wrong port.');
                        break;
                    case 'ClosedAfterConnectTLS':
                        errorMessage = gt.gettext('The server unexpectedly closed the connection.');
                        break;
                    case 'ClosedAfterConnectText':
                        errorMessage = gt.gettext(
                            'The server unexpectedly closed the connection. This usually happens when attempting to connect to a TLS port without TLS enabled.'
                        );
                        break;
                    case 'ECONNREFUSED':
                        errorMessage = gt.gettext(
                            'The server refused the connection. This typically occurs if the server is not running, is overloaded, or you are connecting to the wrong host or port.'
                        );
                        break;
                }
            }

            account.stateLabel = {
                type: 'danger',
                name: 'Failed',
                error: errorMessage
            };
            break;
        }
        case 'unset':
            account.stateLabel = {
                type: 'light',
                name: 'Not syncing'
            };
            break;
        case 'disconnected':
            account.stateLabel = {
                type: 'warning',
                name: 'Disconnected'
            };
            break;
        case 'paused':
            account.stateLabel = {
                type: 'secondary',
                name: 'Paused'
            };
            break;
        default:
            account.stateLabel = {
                type: 'secondary',
                name: 'N/A'
            };
            break;
    }

    // Check if IMAP was disabled due to errors - override state label to show error
    if (account.imap && account.imap.disabled && account.lastErrorState) {
        account.stateLabel = {
            type: 'danger',
            name: 'Failed',
            error: account.lastErrorState.description || account.lastErrorState.response
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
        // ignore
    }

    return mailboxes;
}

function init(args) {
    const { server, call } = args;

    // Account listing route
    server.route({
        method: 'GET',
        path: '/admin/accounts',
        async handler(request, h) {
            let accountObject = new Account({ redis, call });

            const runIndex = await call({
                cmd: 'runIndex'
            });

            const accounts = await accountObject.listAccounts(request.query.state, request.query.query, request.query.page - 1, request.query.pageSize);

            if (accounts.pages < request.query.page) {
                request.query.page = accounts.pages;
            }

            for (let account of accounts.accounts) {
                let accountObj = new Account({ redis, account: account.account });
                account.data = await accountObj.loadAccountData(null, null, runIndex);

                if (account.data && account.data.oauth2 && account.data.oauth2.provider) {
                    let oauth2App = await oauth2Apps.get(account.data.oauth2.provider);
                    if (oauth2App) {
                        account.data.oauth2.app = oauth2App;
                    }
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

                { divider: true },

                {
                    state: 'init',
                    label: 'Initializing'
                },

                {
                    state: 'connecting',
                    label: 'Connecting'
                },

                {
                    state: 'syncing',
                    label: 'Syncing'
                },

                {
                    state: 'connected',
                    label: 'Connected'
                },

                {
                    state: 'disconnected',
                    label: 'Disconnected'
                },

                {
                    state: 'authenticationError',
                    label: 'Authentication failed'
                },

                {
                    state: 'connectError',
                    label: 'Connection failed'
                },

                {
                    state: 'unset',
                    label: 'Unset'
                }
            ].map(entry => {
                let url = getPagingUrl(0, entry.state, request.query.query);
                return Object.assign({ url, selected: entry.state ? entry.state === request.query.state : !request.query.state }, entry);
            });

            return h.view(
                'accounts/index',
                {
                    pageTitle: 'Email Accounts',
                    menuAccounts: true,

                    query: request.query.query,
                    state: request.query.state,
                    pageSize: request.query.pageSize !== DEFAULT_PAGE_SIZE ? request.query.pageSize : false,

                    selectedState: stateOptions.find(entry => entry.state && entry.state === request.query.state),

                    searchTarget: '/admin/accounts',
                    searchPlaceholder: 'Search for accounts...',

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
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState')
                })
            }
        }
    });

    // New account POST handler
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

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

            for (let key of ['redirectUrl', 'n', 't']) {
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

            // store account data with atomic SET + EX
            await redis.set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData), 'EX', Math.floor(MAX_FORM_TTL / 1000));

            // Generate the url that will be used for the consent dialog.

            let requestPayload = {
                state: `account:add:${nonce}`
            };

            if (accountData.email) {
                requestPayload.email = accountData.email;
            }

            let authorizeUrl = oAuth2Client.generateAuthUrl(requestPayload);

            return h.redirect(authorizeUrl);
        }

        return h.view(
            'accounts/register/imap',
            {
                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                values: {
                    data: request.payload.data,
                    sig: request.payload.sig,

                    email: data.email,
                    name: data.name
                }
            },
            {
                layout: 'public'
            }
        );
    }

    // Public GET new account form
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
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(request.app.gt.gettext('Invalid request. Check your input and try again.')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    type: defaultAccountTypeSchema
                })
            }
        }
    });

    // Public POST new account form
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
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(request.app.gt.gettext('Invalid request. Check your input and try again.')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
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

    // IMAP account setup form
    server.route({
        method: 'POST',
        path: '/accounts/new/imap',

        async handler(request, h) {
            await parseSignedFormData(redis, request.payload, request.app.gt);

            let serverSettings;
            try {
                serverSettings = await autodetectImapSettings(request.payload.email, request.app.gt);
            } catch (err) {
                request.logger.error({ msg: 'Failed to resolve email server settings', email: request.payload.email, err });
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
                    request.logger.error({ msg: 'Failed to process account', err });

                    return h
                        .view(
                            'accounts/register/imap',
                            {
                                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
                    password: Joi.string().max(1024).min(1).required().example('secret').label('Password').description('Your account password')
                })
            }
        }
    });

    // Test IMAP settings
    server.route({
        method: 'POST',
        path: '/accounts/new/imap/test',
        async handler(request) {
            try {
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
                        switch (verifyResult.imap.code) {
                            case 'ENOTFOUND':
                                verifyResult.imap.error = request.app.gt.gettext('Server hostname was not found');
                                break;
                            case 'AUTHENTICATIONFAILED':
                                verifyResult.imap.error = request.app.gt.gettext('Invalid username or password');
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
                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = request.app.gt.gettext('TLS protocol error');
                                }
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
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),
                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(465)
                        .description('Service port number')
                        .label('SMTP host'),
                    smtp_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('SMTP port')
                })
            }
        }
    });

    // Submit IMAP server settings
    server.route({
        method: 'POST',
        path: '/accounts/new/imap/server',

        async handler(request, h) {
            const data = await parseSignedFormData(redis, request.payload, request.app.gt);

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

            const accountObject = new Account({ redis, call, secret: await getSecret() });
            const result = await accountObject.create(accountData);

            if (data.n) {
                // store nonce to prevent this URL to be reused
                const keyName = `${REDIS_PREFIX}account:form:${data.n}`;
                try {
                    await redis
                        .multi()
                        .set(keyName, (data.t || '0').toString())
                        .expire(keyName, Math.floor(MAX_FORM_TTL / 1000))
                        .exec();
                } catch (err) {
                    request.logger.error({ msg: 'Failed to set nonce for an account form request', err });
                }
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

            return h.view(
                'redirect',
                {
                    pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                    httpRedirectUrl
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
                    request.logger.error({ msg: 'Failed to process account', err });

                    return h
                        .view(
                            'accounts/register/imap-server',
                            {
                                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true }),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone for autogenerated date strings'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Your account email'),
                    imap_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    imap_auth_pass: Joi.string().empty('').max(1024).required(),
                    imap_host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                    imap_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(993)
                        .description('Service port number'),
                    imap_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 993'),

                    imap_disabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Disable IMAP if you are using this email account to only send emails.'),

                    smtp_auth_user: Joi.string().empty('').trim().max(1024).required(),
                    smtp_auth_pass: Joi.string().empty('').max(1024).required(),
                    smtp_host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
                    smtp_port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .required()
                        .example(465)
                        .description('Service port number'),
                    smtp_secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                })
            }
        }
    });

    // View account details
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

            let logInfo = (await settings.get('logs')) || {
                all: false,
                maxLogLines: DEFAULT_MAX_LOG_LINES
            };

            if (!logInfo.maxLogLines) {
                logInfo.maxLogLines = DEFAULT_MAX_LOG_LINES;
            }

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

            return h.view(
                'accounts/account',
                {
                    pageTitle: `Email Accounts \u2013 ${accountData.email}`,

                    menuAccounts: true,
                    account: accountData,
                    logs: logInfo,
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
                        redirectUrl: `/admin/accounts/${request.params.account}`
                    }),

                    showAdvanced: accountData.proxy || accountData.webhooks,

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

    // Delete account
    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/delete',
        async handler(request, h) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, documentsQueue, call, secret: await getSecret() });

                let deleted = await accountObject.delete();
                if (deleted) {
                    await request.flash({ type: 'info', message: `Account deleted` });
                }

                return h.redirect('/admin/accounts');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete account. Try again.` });
                request.logger.error({ msg: 'Failed to delete the account', err, account: request.payload.account, remoteAddress: request.app.ip });
                return h.redirect(`/admin/accounts/${request.params.account}`);
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
                    request.logger.error({ msg: 'Failed to delete delete the account', err });

                    return h.redirect('/admin/accounts').takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                })
            }
        }
    });

    // Reconnect account
    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/reconnect',
        async handler(request) {
            let account = request.params.account;
            try {
                request.logger.info({ msg: 'Request reconnect for logging', account });
                try {
                    await call({ cmd: 'reconnect', account });
                } catch (err) {
                    request.logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
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

    // Sync account
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

    // Toggle account logs
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

    // Flush account logs
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

    // Get account logs as text
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

    // Browse account messages
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
                await request.flash({ type: 'info', message: `Sign in again to continue` });
                return h.redirect('/admin/login?next=' + encodeURIComponent('/admin/accounts/{account}/browse'));
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
                return h.redirect(`/admin/accounts/${request.params.account}`);
            }

            return h.view(
                'accounts/browse',
                {
                    pageTitle: `Browse \u2013 ${accountData.email}`,

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

    // Edit account (GET)
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
                imap_disabled: (!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled),
                smtp: !!accountData.smtp,
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
                    pageTitle: `Email Accounts \u2013 ${accountData.email}`,

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

    // Edit account (POST)
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

                    let updateKeys = {
                        tls: imapTls
                    };

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

                    updates.smtp = Object.assign(oldData.smtp || {}, {
                        host: request.payload.smtp_host,
                        port: request.payload.smtp_port,
                        secure: request.payload.smtp_secure,
                        auth: smtpAuth,
                        tls: smtpTls
                    });
                }

                await accountObject.update(updates);

                return h.redirect(`/admin/accounts/${request.params.account}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save account settings. Try again.` });
                request.logger.error({ msg: 'Failed to update account settings', err, account: request.params.account });

                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                let accountData = await accountObject.loadAccountData();

                let mailboxes = await getMailboxListing(accountObject);

                return h.view(
                    'accounts/edit',
                    {
                        pageTitle: `Email Accounts \u2013 ${accountData.email}`,

                        menuAccounts: true,
                        account: request.params.account,
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
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                    let accountData = await accountObject.loadAccountData();
                    let mailboxes = await getMailboxListing(accountObject);

                    return h
                        .view(
                            'accounts/edit',
                            {
                                pageTitle: `Email Accounts \u2013 ${accountData.email}`,

                                menuAccounts: true,
                                account: request.params.account,
                                errors,
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
