'use strict';

const Joi = require('joi');
const { failAction } = require('../tools');
const { oauth2Apps } = require('../oauth2-apps');
const { verifyOAuth2App } = require('../oauth/verify-app');
const {
    oauthCreateSchema,
    lastErrorSchema,
    pubSubErrorSchema,
    googleProjectIdSchema,
    googleWorkspaceAccountsSchema,
    googleTopicNameSchema,
    googleSubscriptionNameSchema,
    errorResponses
} = require('../schemas');
const { handleError, throwNotFound, flattenOAuthAppMeta } = require('./route-helpers');

// Stored fields that are returned on OAuth2 application objects in addition to the basic fields
const oauth2AppExtraFields = {
    extraScopes: Joi.array()
        .items(Joi.string().example('https://graph.microsoft.com/.default').label('ExtraScopeEntry'))
        .description('Additional OAuth2 scopes requested for this app')
        .label('AppExtraScopes'),
    skipScopes: Joi.array()
        .items(Joi.string().example('SMTP.Send').label('SkipScopeEntry'))
        .description('OAuth2 scopes excluded from the defaults for this app')
        .label('AppSkipScopes'),
    baseScopes: oauthCreateSchema.baseScopes.description('OAuth2 base scopes for this app').label('AppBaseScopes'),
    pubSubApp: oauthCreateSchema.pubSubApp.description('Cloud Pub/Sub app ID used for Gmail change notifications').label('AppPubSubApp'),
    authMethod: Joi.string().example('serviceKey').description('Authentication method for Gmail service accounts'),
    cloud: Joi.string().example('global').description('Azure cloud type for Outlook OAuth2 applications'),
    tenant: Joi.string()
        .example('f8cdef31-a31e-4b4a-93e4-5f571e91255a')
        .description('Deprecated and unused directory tenant value. Use the authority field instead'),
    externalAccount: Joi.string().example('******').description('External account identifier for 2-legged OAuth2 applications. Actual value is not revealed.'),
    accessToken: Joi.string().example('******').description('Access token for app-based authentication. Actual value is not revealed.'),
    pubSubTopic: Joi.string().example('projects/project-name/topics/ee-pub-12345').description('Cloud Pub/Sub topic name for Gmail change notifications'),
    pubSubSubscription: Joi.string()
        .example('projects/project-name/subscriptions/ee-sub-12345')
        .description('Cloud Pub/Sub subscription name for Gmail change notifications'),
    pubSubIamPolicy: Joi.boolean().example(true).description('Whether the IAM policy for the Cloud Pub/Sub topic has been set up')
};

async function init(args) {
    const { server, call, CORS_CONFIG, OAuth2ProviderSchema } = args;

    // Notify the worker when an app create/update changed Pub/Sub resources, and strip the
    // internal marker from the API response
    let applyPubSubUpdates = async result => {
        if (result && result.pubsubUpdates) {
            if (Object.keys(result.pubsubUpdates).length > 0) {
                await call({ cmd: 'googlePubSub', app: result.id });
            }
            delete result.pubsubUpdates;
        }
        return result;
    };

    server.route({
        method: 'GET',
        path: '/v1/oauth2',

        async handler(request) {
            try {
                let response = await oauth2Apps.list(request.query.page, request.query.pageSize);

                for (let app of response.apps) {
                    for (let secretKey of ['clientSecret', 'serviceKey', 'accessToken', 'externalAccount']) {
                        if (app[secretKey]) {
                            app[secretKey] = '******';
                        }
                    }

                    if (app.extraScopes && !app.extraScopes.length) {
                        delete app.extraScopes;
                    }

                    if (app.app) {
                        delete app.app;
                    }

                    flattenOAuthAppMeta(app);
                }

                return response;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List OAuth2 applications',
            notes: 'Lists registered OAuth2 applications',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('GatewaysFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    apps: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                                name: Joi.string().max(256).example('My OAuth2 App').description('Display name for the app'),
                                description: Joi.string().empty('').trim().max(1024).example('App description').description('OAuth2 application description'),
                                title: Joi.string().empty('').trim().max(256).example('App title').description('Title for the application button'),
                                provider: OAuth2ProviderSchema,
                                enabled: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('Is the application enabled')
                                    .label('AppEnabled'),
                                legacy: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('`true` for older OAuth2 apps set via the settings endpoint'),
                                created: Joi.date()
                                    .iso()
                                    .example('2021-02-17T13:43:18.860Z')
                                    .description('The time this entry was added. Not present for legacy apps'),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was updated'),
                                includeInListing: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('Is the application listed in the hosted authentication form'),

                                clientId: Joi.string()
                                    .example('4f05f488-d858-4f2c-bd12-1039062612fe')
                                    .description('Client or Application ID for 3-legged OAuth2 applications')
                                    .label('OAuth2AppListClientId'),
                                clientSecret: Joi.string()
                                    .example('******')
                                    .description('Client secret for 3-legged OAuth2 applications. Actual value is not revealed.'),
                                authority: Joi.string().example('common').description('Authorization tenant value for Outlook OAuth2 applications'),
                                redirectUrl: Joi.string()
                                    .uri({
                                        scheme: ['http', 'https'],
                                        allowRelative: false
                                    })
                                    .example('https://myservice.com/oauth')
                                    .description('Redirect URL for 3-legged OAuth2 applications')
                                    .label('OAuth2AppListRedirectUrl'),

                                serviceClient: Joi.string()
                                    .example('9103965568215821627203')
                                    .description('Service client ID for 2-legged OAuth2 applications')
                                    .label('OAuth2AppListServiceClient'),

                                googleProjectId: googleProjectIdSchema,
                                googleWorkspaceAccounts: googleWorkspaceAccountsSchema,
                                googleTopicName: googleTopicNameSchema,
                                googleSubscriptionName: googleSubscriptionNameSchema,

                                serviceClientEmail: Joi.string()
                                    .email()
                                    .example('name@project-123.iam.gserviceaccount.com')
                                    .description('Service Client Email for 2-legged OAuth2 applications'),

                                serviceKey: Joi.string()
                                    .example('******')
                                    .description('PEM formatted service secret for 2-legged OAuth2 applications. Actual value is not revealed.'),

                                ...oauth2AppExtraFields,

                                lastError: lastErrorSchema.allow(null),
                                pubSubError: pubSubErrorSchema.allow(null)
                            }).label('OAuth2ResponseItem')
                        )
                        .label('OAuth2Entries')
                }).label('OAuth2FilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                let app = await oauth2Apps.get(request.params.app);
                if (!app) {
                    throwNotFound();
                }

                // remove secrets
                for (let secretKey of ['clientSecret', 'serviceKey', 'accessToken', 'externalAccount']) {
                    if (app[secretKey]) {
                        app[secretKey] = '******';
                    }
                }

                if (app.extraScopes && !app.extraScopes.length) {
                    delete app.extraScopes;
                }

                if (app.app) {
                    delete app.app;
                }

                flattenOAuthAppMeta(app);

                return app;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Get application info',
            notes: 'Returns stored information about an OAuth2 application. Secrets are not included.',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 404, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                })
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    name: Joi.string().max(256).example('My OAuth2 App').description('Display name for the app'),
                    description: Joi.string().empty('').trim().max(1024).example('App description').description('OAuth2 application description'),
                    title: Joi.string().empty('').trim().max(256).example('App title').description('Title for the application button'),
                    provider: OAuth2ProviderSchema,
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Is the application enabled')
                        .label('AppEnabled'),
                    legacy: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('`true` for older OAuth2 apps set via the settings endpoint'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was added. Not present for legacy apps'),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was updated'),
                    includeInListing: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Is the application listed in the hosted authentication form'),

                    clientId: Joi.string()
                        .example('4f05f488-d858-4f2c-bd12-1039062612fe')
                        .description('Client or Application ID for 3-legged OAuth2 applications')
                        .label('OAuth2AppGetClientId'),
                    clientSecret: Joi.string().example('******').description('Client secret for 3-legged OAuth2 applications. Actual value is not revealed.'),
                    authority: Joi.string().example('common').description('Authorization tenant value for Outlook OAuth2 applications'),
                    redirectUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://myservice.com/oauth')
                        .description('Redirect URL for 3-legged OAuth2 applications')
                        .label('OAuth2AppGetRedirectUrl'),

                    googleProjectId: googleProjectIdSchema,
                    googleWorkspaceAccounts: googleWorkspaceAccountsSchema,
                    googleTopicName: googleTopicNameSchema,
                    googleSubscriptionName: googleSubscriptionNameSchema,

                    serviceClientEmail: Joi.string()
                        .email()
                        .example('name@project-123.iam.gserviceaccount.com')
                        .description('Service Client Email for 2-legged OAuth2 applications'),

                    serviceClient: Joi.string()
                        .example('9103965568215821627203')
                        .description('Service client ID for 2-legged OAuth2 applications')
                        .label('OAuth2AppGetServiceClient'),

                    serviceKey: Joi.string()
                        .example('******')
                        .description('PEM formatted service secret for 2-legged OAuth2 applications. Actual value is not revealed.'),

                    accounts: Joi.number()
                        .integer()
                        .example(12)
                        .description('The number of accounts registered with this application. Not available for legacy apps.'),

                    ...oauth2AppExtraFields,

                    lastError: lastErrorSchema.allow(null),
                    pubSubError: pubSubErrorSchema.allow(null)
                }).label('ApplicationResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/oauth2',

        async handler(request) {
            try {
                let result = await oauth2Apps.create(request.payload);
                return await applyPubSubUpdates(result);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Register OAuth2 application',
            notes: 'Registers a new OAuth2 application for a specific provider',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object(oauthCreateSchema).tailor('api').label('CreateOAuth2App')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    created: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the app created')
                }).label('CreateAppResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                let result = await oauth2Apps.update(request.params.app, request.payload);
                return await applyPubSubUpdates(result);
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Update OAuth2 application',
            notes: 'Updates OAuth2 application information',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 404, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                }),

                payload: Joi.object({
                    name: Joi.string().trim().empty('').max(256).example('My Gmail App').description('Application name'),
                    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Application description'),
                    title: Joi.string().allow('').trim().max(256).example('App title').description('Title for the application button'),

                    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').example(true).description('Enable this app'),

                    clientId: Joi.string()
                        .trim()
                        .allow('', null, false)
                        .max(256)
                        .example('52422112755-3uov8bjwlrullq122rdm6l8ui25ho7qf.apps.googleusercontent.com')
                        .description('Client or Application ID for 3-legged OAuth2 applications')
                        .label('UpdateOAuth2ClientId'),

                    clientSecret: Joi.string()
                        .trim()
                        .empty('')
                        .max(256)
                        .example('boT7Q~dUljnfFdVuqpC11g8nGMjO8kpRAv-ZB')
                        .description('Client secret for 3-legged OAuth2 applications'),

                    pubSubApp: Joi.string()
                        .empty('')
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .description('Cloud Pub/Sub app for Gmail API webhooks')
                        .label('UpdatePubSubAppId'),

                    extraScopes: Joi.array()
                        .items(Joi.string().trim().max(255).example('User.Read').label('UpdateExtraScopeEntry'))
                        .description('OAuth2 Extra Scopes')
                        .label('UpdateOAuth2ExtraScopes'),

                    skipScopes: Joi.array()
                        .items(Joi.string().trim().max(255).example('SMTP.Send').label('UpdateSkipScopeEntry'))
                        .description('OAuth2 scopes to skip from the base set')
                        .label('UpdateOAuth2SkipScopes'),

                    serviceClient: Joi.string()
                        .trim()
                        .allow('', null, false)
                        .max(256)
                        .example('7103296518315821565203')
                        .description('Service client ID for 2-legged OAuth2 applications')
                        .label('UpdateServiceClient'),

                    googleProjectId: googleProjectIdSchema,
                    googleWorkspaceAccounts: googleWorkspaceAccountsSchema,
                    googleTopicName: googleTopicNameSchema,
                    googleSubscriptionName: googleSubscriptionNameSchema,

                    serviceClientEmail: Joi.string()
                        .email()
                        .example('name@project-123.iam.gserviceaccount.com')
                        .description('Service Client Email for 2-legged OAuth2 applications'),

                    serviceKey: Joi.string()
                        .trim()
                        .empty('')
                        .max(100 * 1024)
                        .example('-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...')
                        .description('PEM formatted service secret for 2-legged OAuth2 applications'),

                    authority: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024)
                        .example('common')
                        .description('Authorization tenant value for Outlook OAuth2 applications')
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
                        .allow('', null, false)
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .example('https://myservice.com/oauth')
                        .description('Redirect URL for 3-legged OAuth2 applications')
                        .label('UpdateOAuth2RedirectUrl')
                }).label('UpdateOAuthApp')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('example').description('OAuth2 app ID'),
                    updated: Joi.boolean().example(true).description('Was the application updated'),
                    legacy: Joi.boolean().example(false).description('`true` for older OAuth2 apps set via the settings endpoint')
                }).label('UpdateOAuthAppResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                let result = await oauth2Apps.del(request.params.app);

                try {
                    await call({ cmd: 'googlePubSubRemove', app: request.params.app });
                } catch (err) {
                    request.logger.error({ msg: 'Failed to notify workers about OAuth2 app deletion', err, app: request.params.app });
                }

                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove OAuth2 application',
            notes: 'Delete OAuth2 application data',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 404, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                }).label('DeleteAppRequest')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the OAuth2 application deleted'),
                    legacy: Joi.boolean().example(false).description('`true` for older OAuth2 apps set via the settings endpoint'),
                    accounts: Joi.number()
                        .integer()
                        .example(12)
                        .description('The number of accounts registered with this application. Not available for legacy apps.')
                }).label('DeleteAppRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/oauth2/{app}/verify',

        async handler(request) {
            try {
                return await verifyOAuth2App(request.params.app, {
                    account: request.payload.account,
                    testConnection: request.payload.testConnection
                });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Verify OAuth2 application setup',
            notes: 'Runs the provider authentication chain step by step and reports which steps pass or fail, with hints for fixing failures. For service-account apps an optional mailbox address enables the delegation and live mailbox checks.',
            tags: ['api', 'OAuth2 Applications'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 404, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                }),

                payload: Joi.object({
                    account: Joi.string()
                        .trim()
                        .empty('')
                        .max(256)
                        .example('user@example.com')
                        .description('Mailbox address used to verify domain-wide delegation and live mailbox access'),
                    testConnection: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(true)
                        .description('Perform the live IMAP/API connection step when an access token is obtained')
                }).label('VerifyOAuth2AppRequest')
            },

            response: {
                schema: Joi.object({
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    provider: Joi.string().example('gmailService').description('Provider type'),
                    authMethod: Joi.string().allow(null).example('externalAccount').description('Authentication method for service-account apps'),
                    account: Joi.string().allow(null).example('user@example.com').description('Mailbox used for the delegation/mailbox checks'),
                    ok: Joi.boolean().example(true).description('True when no verification step failed'),
                    steps: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().example('signJwt').description('Step identifier'),
                                label: Joi.string().example('Sign assertion (signJwt)').description('Human readable step name'),
                                status: Joi.string().valid('ok', 'fail', 'skip').example('ok').description('Step outcome'),
                                message: Joi.string().allow(null).example('Assertion signed via IAM signJwt').description('Outcome detail'),
                                hint: Joi.string()
                                    .example('Grant roles/iam.serviceAccountTokenCreator to the workload principal')
                                    .description('How to fix a failed step')
                            }).label('OAuth2VerifyStep')
                        )
                        .label('OAuth2VerifySteps')
                }).label('VerifyOAuth2AppResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
