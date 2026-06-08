'use strict';

// NB! This file is processed by the gettext parser (npm run gettext) and can not use newer syntax like ?.

// Admin UI routes for OAuth2 application config (/admin/config/oauth*): listing apps,
// per-app view/edit/delete, creating apps, adding accounts, provider subscriptions, and
// app verification. Extracted verbatim from lib/routes-ui.js. AZURE_CLOUDS and the
// authMethodContext/getPubSubAppsForSelect render helpers move with the routes (only the
// OAuth app config pages use them).

const Joi = require('joi');
const util = require('util');
const Boom = require('@hapi/boom');

const settings = require('../settings');
const consts = require('../consts');
const { redis } = require('../db');
const getSecret = require('../get-secret');
const { Account } = require('../account');
const { oauth2Apps, OAUTH_PROVIDERS, oauth2ProviderData, SERVICE_ACCOUNT_PROVIDERS } = require('../oauth2-apps');
const { verifyOAuth2App } = require('../oauth/verify-app');
const { oauthCreateSchema, oauthUpdateSchema, accountIdSchema } = require('../schemas');
const { throwAsBoom } = require('./route-helpers');

const { DEFAULT_PAGE_SIZE } = consts;

const AZURE_CLOUDS = [
    {
        id: 'global',
        name: 'Azure global service',
        description: 'Regular Microsoft cloud accounts'
    },

    {
        id: 'gcc-high',
        name: 'GCC High',
        description: 'Microsoft Graph for US Government L4'
    },

    {
        id: 'dod',
        name: 'DoD',
        description: 'Microsoft Graph for US Government L5 (DOD)'
    },

    {
        id: 'china',
        name: 'Azure China',
        description: 'Microsoft Graph China operated by 21Vianet'
    }
];

function init(args) {
    const { server, call } = args;

    // Render-context booleans for the gmailService authMethod tab selector.
    // When `locked` is set the selector is shown but cannot be switched - the
    // authentication method is fixed once an app has been created.
    function authMethodContext(authMethod, locked) {
        return {
            authMethodIsServiceKey: !authMethod || authMethod === 'serviceKey',
            authMethodIsExternalAccount: authMethod === 'externalAccount',
            authMethodLocked: !!locked
        };
    }

    /**
     * Fetch the list of Pub/Sub apps and mark the one matching selectedId as selected.
     * Returns the apps array ready for template rendering.
     */
    async function getPubSubAppsForSelect(selectedId) {
        let result = await oauth2Apps.list(0, 1000, { pubsub: true });
        let apps = (result && result.apps) || [];
        for (let app of apps) {
            if (app.id === selectedId) {
                app.selected = true;
            }
        }
        return apps;
    }

    server.route({
        method: 'GET',
        path: '/admin/config/oauth',
        async handler(request, h) {
            let data = await oauth2Apps.list(request.query.page - 1, request.query.pageSize, { query: request.query.query });

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = (page, query) => {
                let url = new URL(`admin/config/oauth`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                if (query) {
                    url.searchParams.append('query', query);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2, request.query.query);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page, request.query.query);
            }

            data.apps.forEach(app => {
                app.providerData = oauth2ProviderData(app.provider);
                switch (app.baseScopes) {
                    case 'api':
                        app.baseScopesText = 'API';
                        break;
                    case 'pubsub':
                        app.baseScopesText = 'Cloud Pub/Sub';
                        break;
                    case 'imap':
                    default:
                        app.baseScopesText = 'IMAP and SMTP';
                        break;
                }
            });

            let newLink = new URL('/admin/config/oauth/new', 'http://localhost');

            return h.view(
                'config/oauth/index',
                {
                    pageTitle: 'OAuth2',
                    menuConfig: true,
                    menuConfigOauth: true,
                    activeApplications: true,

                    newLink: newLink.pathname + newLink.search,

                    searchTarget: '/admin/config/oauth',
                    searchPlaceholder: 'Search for OAuth2 applications…',
                    query: request.query.query,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1, request.query.query),
                        title: i + 1,
                        active: i === data.page
                    })),

                    apps: data.apps
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
                    query: Joi.string().example('Gmail').description('Filter accounts by search term').label('AppQuery')
                })
            }
        }
    });

    // GET /admin/config/oauth/subscriptions - Gmail Pub/Sub subscriptions list
    server.route({
        method: 'GET',
        path: '/admin/config/oauth/subscriptions',
        async handler(request, h) {
            try {
                let data = await oauth2Apps.list(request.query.page - 1, request.query.pageSize, { pubsub: true });

                let gmailSubscriptionTtl = await settings.get('gmailSubscriptionTtl');

                // Compute human-readable expiration for each app
                // meta.subscriptionExpiration is:
                //   undefined - no data yet (app predates this feature or ensurePubsub hasn't run)
                //   null      - indefinite (no TTL set, ensurePubsub confirmed this)
                //   "Ns"      - TTL in seconds (e.g. "2678400s" for 31 days)
                let gt = request.app.gt;
                for (let app of data.apps) {
                    if (!app.pubSubSubscription) {
                        app.expirationLabel = '';
                        continue;
                    }

                    let meta = app.meta || {};
                    if (!('subscriptionExpiration' in meta)) {
                        app.expirationLabel = gt.gettext('Unknown');
                        continue;
                    }

                    let seconds = parseInt(meta.subscriptionExpiration, 10);
                    if (seconds > 0) {
                        let days = Math.round(seconds / 86400);
                        app.expirationLabel = util.format(gt.ngettext('%d day', '%d days', days), days);
                    } else {
                        app.expirationLabel = gt.gettext('Indefinite');
                    }
                }

                let nextPage = false;
                let prevPage = false;

                let getPagingUrl = page => {
                    let url = new URL(`admin/config/oauth/subscriptions`, 'http://localhost');

                    if (page) {
                        url.searchParams.append('page', page);
                    }

                    if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                        url.searchParams.append('pageSize', request.query.pageSize);
                    }

                    return url.pathname + url.search;
                };

                if (data.pages > data.page + 1) {
                    nextPage = getPagingUrl(data.page + 2);
                }

                if (data.page > 0) {
                    prevPage = getPagingUrl(data.page);
                }

                return h.view(
                    'config/oauth/subscriptions',
                    {
                        pageTitle: 'OAuth2',
                        menuConfig: true,
                        menuConfigOauth: true,
                        activeSubscriptions: true,

                        showPaging: data.pages > 1,
                        nextPage,
                        prevPage,
                        firstPage: data.page === 0,
                        pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                            url: getPagingUrl(i + 1),
                            title: i + 1,
                            active: i === data.page
                        })),

                        apps: data.apps,

                        values: {
                            gmailSubscriptionTtl: typeof gmailSubscriptionTtl === 'number' ? gmailSubscriptionTtl : ''
                        }
                    },
                    {
                        layout: 'app'
                    }
                );
            } catch (err) {
                request.logger.error({ msg: 'Failed to load subscriptions page', err });
                throwAsBoom(err);
            }
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/config/oauth/subscriptions').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/subscriptions',
        async handler(request, h) {
            try {
                // Joi .empty('').allow(null) ensures this is either null or a number
                let ttl = request.payload.gmailSubscriptionTtl != null ? request.payload.gmailSubscriptionTtl : null;
                await settings.set('gmailSubscriptionTtl', ttl);

                await request.flash({ type: 'info', message: 'Configuration updated' });
                return h.redirect('/admin/config/oauth/subscriptions');
            } catch (err) {
                await request.flash({ type: 'danger', message: 'Failed to save settings' });
                request.logger.error({ msg: 'Failed to save subscription settings', err });
                return h.redirect('/admin/config/oauth/subscriptions');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    await request.flash({ type: 'danger', message: 'Invalid setting value' });
                    return h.redirect('/admin/config/oauth/subscriptions').takeover();
                },

                payload: Joi.object({
                    gmailSubscriptionTtl: Joi.number().integer().empty('').allow(null).min(0).max(365),
                    crumb: Joi.string().max(256)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/app/{app}',
        async handler(request, h) {
            let app = await oauth2Apps.get(request.params.app);
            if (!app) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            let providerData = oauth2ProviderData(app.provider);

            let disabledScopes = {};
            if (
                (app.skipScopes && app.skipScopes.includes('SMTP.Send')) ||
                (app.skipScopes && app.skipScopes.includes('https://outlook.office.com/SMTP.Send'))
            ) {
                disabledScopes.SMTP_Send = true;
            }

            if (
                (app.skipScopes && app.skipScopes.includes('Mail.Send')) ||
                (app.skipScopes && app.skipScopes.includes('https://graph.microsoft.com/Mail.Send'))
            ) {
                disabledScopes.Mail_Send = true;
            }

            if (
                (app.skipScopes && app.skipScopes.includes('gmail.modify')) ||
                (app.skipScopes && app.skipScopes.includes('https://www.googleapis.com/auth/gmail.modify'))
            ) {
                disabledScopes.Gmail_Modify = true;
            }

            // Detect send-only Gmail configuration
            let isSendOnlyGmail = false;
            if (app.provider === 'gmail' && app.baseScopes === 'api') {
                // Build scope list from extraScopes (short form or full URLs)
                const scopes = (app.extraScopes || []).map(scope => (scope.startsWith('https://') ? scope : `https://www.googleapis.com/auth/${scope}`));

                // Use Account class helper to check scopes - no need to create full Account instance
                const accountHelper = new Account({ redis, secret: await getSecret() });
                const { hasSendScope, hasReadScope } = accountHelper.checkAccountScopes('gmail', scopes);

                if (hasSendScope && !hasReadScope) {
                    isSendOnlyGmail = true;
                }
            }

            if (app.pubSubApp) {
                let pubSubApp = await oauth2Apps.get(app.pubSubApp);
                app.pubSubAppData = pubSubApp;
            }

            if (app.cloud) {
                app.cloudData = AZURE_CLOUDS.find(entry => entry.id === app.cloud);
            }

            // Service account apps scoped for email access (IMAP/SMTP or Gmail/Graph API) can register
            // accounts directly without an interactive consent flow. Pub/Sub-scoped service apps are for
            // webhook notifications only, so they must not offer the direct add-account shortcut.
            let canAddServiceAccount = SERVICE_ACCOUNT_PROVIDERS.has(app.provider) && app.enabled && app.baseScopes !== 'pubsub';

            return h.view(
                'config/oauth/app',
                {
                    pageTitle: 'OAuth2',
                    menuConfig: true,
                    menuConfigOauth: true,

                    [`active${providerData.caseName}`]: true,

                    app,

                    baseScopesApi: app.baseScopes === 'api',
                    baseScopesImap: app.baseScopes === 'imap' || !app.baseScopes,
                    baseScopesPubsub: app.baseScopes === 'pubsub',

                    appShowAuthMethod: app.provider === 'gmailService',
                    authMethodIsExternalAccount: app.authMethod === 'externalAccount',

                    canAddServiceAccount,

                    disabledScopes,
                    isSendOnlyGmail,

                    providerData
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/delete',
        async handler(request, h) {
            try {
                await oauth2Apps.del(request.payload.app);

                try {
                    await call({ cmd: 'googlePubSubRemove', app: request.payload.app });
                } catch (err) {
                    request.logger.error({ msg: 'Failed to notify workers about OAuth2 app deletion', err, app: request.payload.app });
                }

                await request.flash({ type: 'info', message: `OAuth2 app deleted` });

                return h.redirect('/admin/config/oauth');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete OAuth2 app. Try again.` });
                request.logger.error({ msg: 'Failed to delete OAuth2 application', err, app: request.payload.app, remoteAddress: request.app.ip });
                return h.redirect(`/admin/config/oauth/app/${request.payload.app}`);
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
                    await request.flash({ type: 'danger', message: `Couldn't delete OAuth2 app. Try again.` });
                    request.logger.error({ msg: 'Failed to delete the OAuth2 application', err });

                    return h.redirect('/admin/config/oauth').takeover();
                },

                payload: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/app/{app}/add-account',
        async handler(request, h) {
            const appId = request.params.app;
            try {
                const app = await oauth2Apps.get(appId);
                if (!app) {
                    let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                    throw error;
                }

                // Direct account registration is only valid for email-scoped service account apps. Interactive
                // providers must use the hosted consent flow, and Pub/Sub-scoped apps grant no mailbox access.
                if (!SERVICE_ACCOUNT_PROVIDERS.has(app.provider) || !app.enabled || app.baseScopes === 'pubsub') {
                    let error = Boom.boomify(new Error('This application can not register accounts directly.'), { statusCode: 400 });
                    throw error;
                }

                let accountData = {
                    account: request.payload.account || null,
                    email: request.payload.email,
                    oauth2: {
                        provider: app.id,
                        auth: {
                            user: request.payload.email
                        }
                    }
                };

                if (request.payload.name) {
                    accountData.name = request.payload.name;
                }

                const accountObject = new Account({ redis, call, secret: await getSecret() });
                const result = await accountObject.create(accountData);

                await request.flash({ type: 'info', message: `Account ${result.state === 'existing' ? 'updated' : 'added'}` });

                return h.redirect(`/admin/accounts/${result.account}`);
            } catch (err) {
                request.logger.error({ msg: 'Failed to register service account', err, app: appId, remoteAddress: request.app.ip });
                await request.flash({ type: 'danger', message: `Failed to add account${err.message ? `: ${err.message}` : ''}` });
                return h.redirect(`/admin/config/oauth/app/${appId}`);
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
                    request.logger.error({ msg: 'Failed to register service account', err, app: request.params.app });
                    await request.flash({ type: 'danger', message: `Failed to add account. Provide a valid email address.` });
                    return h.redirect(`/admin/config/oauth/app/${request.params.app}`).takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                }),

                payload: Joi.object({
                    account: accountIdSchema.default(null),
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name'),
                    email: Joi.string().email().required().example('user@example.com').label('Email').description('Mailbox email address')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/verify/{app}',
        async handler(request, h) {
            try {
                return await verifyOAuth2App(request.params.app, {
                    account: request.payload.account,
                    testConnection: request.payload.testConnection
                });
            } catch (err) {
                request.logger.error({ msg: 'Failed to verify OAuth2 application', err, app: request.params.app });
                return h.response({ error: err.message, code: err.code || null }).code(err.statusCode || 500);
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
                    request.logger.error({ msg: 'Invalid verify request', err, app: request.params.app });
                    return h.response({ error: 'Invalid request' }).code(400).takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).required().label('Provider')
                }),

                payload: Joi.object({
                    crumb: Joi.string().optional(),
                    account: Joi.string().trim().empty('').max(256).optional(),
                    testConnection: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(true)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/new',
        async handler(request, h) {
            let { provider } = request.query;
            let providerData = oauth2ProviderData(provider);

            let serviceUrl = await settings.get('serviceUrl');
            let defaultRedirectUrl = `${serviceUrl}/oauth`;
            if (provider === 'outlook') {
                defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
            }

            return h.view(
                'config/oauth/new',
                {
                    pageTitle: 'OAuth2',
                    menuConfig: true,
                    menuConfigOauth: true,

                    actionCreate: true,

                    [`active${providerData.caseName}`]: true,
                    providerData,
                    defaultRedirectUrl,

                    baseScopesImap: true,
                    baseScopesApi: false,
                    baseScopesPubsub: false,

                    ...authMethodContext('serviceKey'),

                    pubSubApps: await getPubSubAppsForSelect(null),

                    azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                        if (entry.id === 'global') {
                            entry.selected = true;
                        }
                        return entry;
                    }),

                    values: {
                        provider,
                        redirectUrl: defaultRedirectUrl,
                        authMethod: 'serviceKey'
                    },

                    authorityCommon: true
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                query: Joi.object({
                    provider: Joi.string()
                        .empty('')
                        .valid(...Object.keys(OAUTH_PROVIDERS))
                        .label('Provider')
                        .required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/new',
        async handler(request, h) {
            try {
                let appData = Object.assign({}, request.payload);
                appData.extraScopes = appData.extraScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                appData.skipScopes = appData.skipScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                if (appData.authority === 'tenant') {
                    appData.authority = appData.tenant;
                }
                delete appData.tenant;

                let oauth2App = await oauth2Apps.create(appData);
                if (!oauth2App || !oauth2App.id) {
                    throw new Error('Unexpected result');
                }

                if (oauth2App && oauth2App.pubsubUpdates && Object.keys(oauth2App.pubsubUpdates).length > 0) {
                    await call({ cmd: 'googlePubSub', app: oauth2App.id });
                }

                await request.flash({ type: 'success', message: `OAuth2 app created` });
                return h.redirect(`/admin/config/oauth/app/${oauth2App.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't register OAuth2 app. Try again.` });
                request.logger.error({ msg: 'Failed to register OAuth2 app', err });

                let { provider, baseScopes } = request.payload;
                if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                    return h.redirect('/admin');
                }

                let providerData = oauth2ProviderData(provider);

                let serviceUrl = await settings.get('serviceUrl');
                let defaultRedirectUrl = `${serviceUrl}/oauth`;
                if (provider === 'outlook') {
                    defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                }

                return h.view(
                    'config/oauth/new',
                    {
                        pageTitle: 'OAuth2',
                        menuConfig: true,
                        menuConfigOauth: true,

                        actionCreate: true,

                        [`active${providerData.caseName}`]: true,
                        providerData,
                        defaultRedirectUrl,

                        pubSubApps: await getPubSubAppsForSelect(request.payload.pubSubApp),

                        baseScopesApi: baseScopes === 'api',
                        baseScopesImap: baseScopes === 'imap' || !baseScopes,
                        baseScopesPubsub: baseScopes === 'pubsub',

                        ...authMethodContext(request.payload.authMethod),

                        azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                            entry.selected = request.payload.cloud === entry.id;
                            return entry;
                        }),

                        authorityCommon: request.payload.authority === 'common',
                        authorityOrganizations: request.payload.authority === 'organizations',
                        authorityConsumers: request.payload.authority === 'consumers',
                        authorityTenant: request.payload.authority === 'tenant'
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

                    await request.flash({ type: 'danger', message: `Couldn't register OAuth2 app. Try again.` });
                    request.logger.error({ msg: 'Failed to register OAuth2 app', err });

                    let { provider, baseScopes } = request.payload;
                    if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                        return h.redirect('/admin').takeover();
                    }

                    let providerData = oauth2ProviderData(provider);

                    let serviceUrl = await settings.get('serviceUrl');
                    let defaultRedirectUrl = `${serviceUrl}/oauth`;
                    if (provider === 'outlook') {
                        defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                    }

                    return h
                        .view(
                            'config/oauth/new',
                            {
                                pageTitle: 'OAuth2',
                                menuConfig: true,
                                menuConfigOauth: true,

                                actionCreate: true,

                                [`active${providerData.caseName}`]: true,
                                providerData,
                                defaultRedirectUrl,

                                pubSubApps: await getPubSubAppsForSelect(request.payload.pubSubApp),

                                baseScopesApi: baseScopes === 'api',
                                baseScopesImap: baseScopes === 'imap' || !baseScopes,
                                baseScopesPubsub: baseScopes === 'pubsub',

                                ...authMethodContext(request.payload.authMethod),

                                azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                                    entry.selected = request.payload.cloud === entry.id;
                                    return entry;
                                }),

                                authorityCommon: request.payload.authority === 'common',
                                authorityOrganizations: request.payload.authority === 'organizations',
                                authorityConsumers: request.payload.authority === 'consumers',
                                authorityTenant: request.payload.authority === 'tenant',

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(oauthCreateSchema).tailor('web')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/oauth/edit/{app}',
        async handler(request, h) {
            let appData = await oauth2Apps.get(request.params.app);
            if (!appData) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            let providerData = oauth2ProviderData(appData.provider, appData.cloud);
            let serviceUrl = await settings.get('serviceUrl');
            let defaultRedirectUrl = `${serviceUrl}/oauth`;
            if (providerData.provider === 'outlook') {
                defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
            }

            let values = Object.assign({}, appData, {
                clientSecret: '',
                serviceKey: '',
                externalAccount: '',
                extraScopes: [].concat(appData.extraScopes || []).join('\n'),
                skipScopes: [].concat(appData.skipScopes || []).join('\n'),

                tenant: appData.authority && !['common', 'organizations', 'consumers'].includes(appData.authority) ? appData.authority : ''
            });

            return h.view(
                'config/oauth/edit',
                {
                    pageTitle: 'OAuth2',
                    menuConfig: true,
                    menuConfigOauth: true,

                    [`active${providerData.caseName}`]: true,
                    providerData,
                    defaultRedirectUrl,

                    appData,

                    hasClientSecret: !!appData.clientSecret,
                    hasServiceKey: !!appData.serviceKey,
                    hasExternalAccount: !!appData.externalAccount,

                    ...authMethodContext(appData.authMethod, !!appData.serviceKey || !!appData.externalAccount),

                    pubSubApps: await getPubSubAppsForSelect(values.pubSubApp),

                    values,

                    baseScopesApi: values.baseScopes === 'api',
                    baseScopesImap: values.baseScopes === 'imap' || !values.baseScopes,
                    baseScopesPubsub: values.baseScopes === 'pubsub',

                    azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                        entry.selected = values.cloud === entry.id;
                        return entry;
                    }),

                    authorityCommon: values.authority === 'common',
                    authorityOrganizations: values.authority === 'organizations',
                    authorityConsumers: values.authority === 'consumers',
                    authorityTenant: !!values.tenant
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
                    return h.redirect('/admin/config/oauth').takeover();
                },

                params: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/oauth/edit',
        async handler(request, h) {
            let appData = await oauth2Apps.get(request.payload.app);
            if (!appData) {
                let error = Boom.boomify(new Error('Application was not found.'), { statusCode: 404 });
                throw error;
            }

            try {
                let updates = Object.assign({}, request.payload);
                updates.extraScopes = updates.extraScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                updates.skipScopes = updates.skipScopes
                    .split(/\s+/)
                    .map(scope => scope.trim())
                    .filter(scope => scope);

                if (updates.authority === 'tenant') {
                    updates.authority = updates.tenant;
                }
                delete updates.tenant;

                let oauth2App = await oauth2Apps.update(appData.id, updates);
                if (!oauth2App || !oauth2App.id) {
                    throw new Error('Unexpected result');
                }

                if (oauth2App && oauth2App.pubsubUpdates && Object.keys(oauth2App.pubsubUpdates).length > 0) {
                    await call({ cmd: 'googlePubSub', app: oauth2App.id });
                }

                await request.flash({ type: 'success', message: `OAuth2 app saved` });
                return h.redirect(`/admin/config/oauth/app/${oauth2App.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save OAuth2 app. Try again.` });
                request.logger.error({ msg: 'Failed to update OAuth2 app', app: request.payload.app, err });

                let providerData = oauth2ProviderData(appData.provider, appData.cloud);

                let serviceUrl = await settings.get('serviceUrl');
                let defaultRedirectUrl = `${serviceUrl}/oauth`;
                if (appData.provider === 'outlook') {
                    defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                }

                return h.view(
                    'config/oauth/edit',
                    {
                        pageTitle: 'OAuth2',
                        menuConfig: true,
                        menuConfigOauth: true,

                        [`active${providerData.caseName}`]: true,
                        providerData,
                        defaultRedirectUrl,
                        appData,

                        hasClientSecret: !!appData.clientSecret,
                        hasServiceKey: !!appData.serviceKey,
                        hasExternalAccount: !!appData.externalAccount,

                        ...authMethodContext(appData.authMethod, !!appData.serviceKey || !!appData.externalAccount),

                        pubSubApps: await getPubSubAppsForSelect(request.payload.pubSubApp),

                        baseScopesApi: request.payload.baseScopes === 'api',
                        baseScopesImap: request.payload.baseScopes === 'imap' || !request.payload.baseScopes,
                        baseScopesPubsub: request.payload.baseScopes === 'pubsub',

                        azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                            entry.selected = request.payload.cloud === entry.id;
                            return entry;
                        }),

                        authorityCommon: request.payload.authority === 'common',
                        authorityOrganizations: request.payload.authority === 'organizations',
                        authorityConsumers: request.payload.authority === 'consumers',
                        authorityTenant: request.payload.authority === 'tenant'
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

                    let appData = await oauth2Apps.get(request.payload.app);
                    if (!appData) {
                        await request.flash({ type: 'danger', message: `Application not found` });
                        request.logger.error({ msg: 'Application was not found.', app: request.payload.app });
                        return h.redirect('/admin').takeover();
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save OAuth2 app. Try again.` });
                    request.logger.error({ msg: 'Failed to update OAuth2 app', err });

                    let { provider } = request.payload;
                    if (!provider || !OAUTH_PROVIDERS.hasOwnProperty(provider)) {
                        return h.redirect('/admin').takeover();
                    }

                    let providerData = oauth2ProviderData(provider);

                    let serviceUrl = await settings.get('serviceUrl');
                    let defaultRedirectUrl = `${serviceUrl}/oauth`;
                    if (provider === 'outlook') {
                        defaultRedirectUrl = defaultRedirectUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                    }

                    return h
                        .view(
                            'config/oauth/edit',
                            {
                                pageTitle: 'OAuth2',
                                menuConfig: true,
                                menuConfigOauth: true,

                                [`active${providerData.caseName}`]: true,
                                providerData,
                                defaultRedirectUrl,

                                appData,

                                hasClientSecret: !!appData.clientSecret,
                                hasServiceKey: !!appData.serviceKey,
                                hasExternalAccount: !!appData.externalAccount,

                                ...authMethodContext(request.payload.authMethod),

                                pubSubApps: await getPubSubAppsForSelect(request.payload.pubSubApp),

                                baseScopesApi: request.payload.baseScopes === 'api',
                                baseScopesImap: request.payload.baseScopes === 'imap' || !request.payload.baseScopes,
                                baseScopesPubsub: request.payload.baseScopes === 'pubsub',

                                azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                                    entry.selected = request.payload.cloud === entry.id;
                                    return entry;
                                }),

                                authorityCommon: request.payload.authority === 'common',
                                authorityOrganizations: request.payload.authority === 'organizations',
                                authorityConsumers: request.payload.authority === 'consumers',
                                authorityTenant: request.payload.authority === 'tenant',

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(oauthUpdateSchema)
            }
        }
    });
}

module.exports = init;
