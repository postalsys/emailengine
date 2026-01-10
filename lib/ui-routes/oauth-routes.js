'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');

const settings = require('../settings');
const { redis } = require('../db');
const { oauth2Apps, LEGACY_KEYS, OAUTH_PROVIDERS, oauth2ProviderData } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const { Account } = require('../account');
const { oauthCreateSchema, googleProjectIdSchema, googleWorkspaceAccountsSchema } = require('../schemas');
const consts = require('../consts');

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

const oauthUpdateSchema = {
    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required(),

    provider: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .valid(...Object.keys(OAUTH_PROVIDERS))
        .example('gmail')
        .required()
        .description('OAuth2 provider'),

    name: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .example('My Gmail App')
        .description('Application name')
        .when('app', {
            not: Joi.string().valid(...LEGACY_KEYS),
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        }),
    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Application description'),

    title: Joi.string().allow('').trim().max(256).example('App title').description('Title for the application button'),

    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable this app'),

    clientId: Joi.string()
        .trim()
        .allow('')
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Client ID'),

    clientSecret: Joi.string()
        .trim()
        .empty('', false, null)
        .max(256)
        .when('provider', {
            not: 'gmailService',
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description('OAuth2 Client Secret'),

    pubSubApp: Joi.string()
        .empty('')
        .base64({ paddingRequired: false, urlSafe: true })
        .max(512)
        .example('AAAAAQAACnA')
        .description('Cloud Pub/Sub app for Gmail API webhooks'),

    extraScopes: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .description('OAuth2 Extra Scopes'),

    skipScopes: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
        .description('OAuth2 scopes to skip from the base set'),

    serviceClient: Joi.string()
        .trim()
        .allow('')
        .max(256)
        .when('provider', {
            is: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Service Client ID'),

    googleProjectId: googleProjectIdSchema,

    googleWorkspaceAccounts: googleWorkspaceAccountsSchema.when('provider', {
        is: 'gmail',
        then: Joi.optional().default(false)
    }),

    serviceClientEmail: Joi.string()
        .trim()
        .allow('')
        .email()
        .when('provider', {
            is: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example('name@project-123.iam.gserviceaccount.com')
        .description('Service Client Email for 2-legged OAuth2 applications'),

    serviceKey: Joi.string()
        .trim()
        .empty('', false, null)
        .max(100 * 1024)
        .when('provider', {
            is: 'gmailService',
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .description('OAuth2 Secret Service Key'),

    authority: Joi.string()
        .trim()
        .empty('')
        .max(1024)
        .when('provider', {
            is: 'outlook',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .example(false)
        .label('SupportedAccountTypes'),

    cloud: Joi.string()
        .trim()
        .empty('')
        .valid('global', 'gcc-high', 'dod', 'china')
        .example('global')
        .description('Azure cloud type for Outlook OAuth2 applications')
        .label('AzureCloud'),

    tenant: Joi.string().trim().empty('').max(1024).example('f8cdef31-a31e-4b4a-93e4-5f571e91255a').label('Directorytenant'),

    redirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .when('provider', {
            not: 'gmailService',
            then: Joi.required(),
            otherwise: Joi.optional().valid(false, null)
        })
        .description('OAuth2 Callback URL')
};

function init({ server, call }) {
    // GET /admin/config/oauth - OAuth applications list
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

                    newLink: newLink.pathname + newLink.search,

                    searchTarget: '/admin/config/oauth',
                    searchPlaceholder: 'Search for OAuth2 applications...',
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

    // GET /admin/config/oauth/app/{app} - View OAuth application details
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

    // POST /admin/config/oauth/delete - Delete OAuth application
    server.route({
        method: 'POST',
        path: '/admin/config/oauth/delete',
        async handler(request, h) {
            try {
                await oauth2Apps.del(request.payload.app);

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
                    request.logger.error({ msg: 'Failed to delete delete the OAuth2 application', err });

                    return h.redirect('/admin/config/oauth').takeover();
                },

                payload: Joi.object({
                    app: Joi.string().empty('').max(255).example('gmail').label('Provider').required()
                })
            }
        }
    });

    // GET /admin/config/oauth/new - New OAuth application form
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

            let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                    pubSubApps: pubSubApps && pubSubApps.apps,

                    azureClouds: structuredClone(AZURE_CLOUDS).map(entry => {
                        if (entry.id === 'global') {
                            entry.selected = true;
                        }
                        return entry;
                    }),

                    values: {
                        provider,
                        redirectUrl: defaultRedirectUrl
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

    // POST /admin/config/oauth/new - Create OAuth application
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

                if (oauth2App && oauth2App.pubsubUpdates && oauth2App.pubsubUpdates.pubSubSubscription) {
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

                let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                        pubSubApps:
                            pubSubApps &&
                            pubSubApps.apps &&
                            pubSubApps.apps.map(app => {
                                if (app.id === request.payload.pubSubApp) {
                                    app.selected = true;
                                }
                                return app;
                            }),

                        baseScopesApi: baseScopes === 'api',
                        baseScopesImap: baseScopes === 'imap' || !baseScopes,
                        baseScopesPubsub: baseScopes === 'pubsub',

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

                    let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                                pubSubApps:
                                    pubSubApps &&
                                    pubSubApps.apps &&
                                    pubSubApps.apps.map(app => {
                                        if (app.id === request.payload.pubSubApp) {
                                            app.selected = true;
                                        }
                                        return app;
                                    }),

                                baseScopesApi: baseScopes === 'api',
                                baseScopesImap: baseScopes === 'imap' || !baseScopes,
                                baseScopesPubsub: baseScopes === 'pubsub',

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

    // GET /admin/config/oauth/edit/{app} - Edit OAuth application form
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
                extraScopes: [].concat(appData.extraScopes || []).join('\n'),
                skipScopes: [].concat(appData.skipScopes || []).join('\n'),

                tenant: appData.authority && !['common', 'organizations', 'consumers'].includes(appData.authority) ? appData.authority : ''
            });

            let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                    pubSubApps:
                        pubSubApps &&
                        pubSubApps.apps &&
                        pubSubApps.apps.map(app => {
                            if (app.id === values.pubSubApp) {
                                app.selected = true;
                            }
                            return app;
                        }),

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

    // POST /admin/config/oauth/edit - Update OAuth application
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

                if (oauth2App && oauth2App.pubsubUpdates && oauth2App.pubsubUpdates.pubSubSubscription) {
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

                let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                        pubSubApps:
                            pubSubApps &&
                            pubSubApps.apps &&
                            pubSubApps.apps.map(app => {
                                if (app.id === request.payload.pubSubApp) {
                                    app.selected = true;
                                }
                                return app;
                            }),

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

                    let pubSubApps = await oauth2Apps.list(0, 1000, { pubsub: true });

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

                                pubSubApps:
                                    pubSubApps &&
                                    pubSubApps.apps &&
                                    pubSubApps.apps.map(app => {
                                        if (app.id === request.payload.pubSubApp) {
                                            app.selected = true;
                                        }
                                        return app;
                                    }),

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
