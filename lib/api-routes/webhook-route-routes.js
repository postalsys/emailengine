'use strict';

const Joi = require('joi');
const { webhooks: Webhooks } = require('../webhooks');
const settings = require('../settings');
const { sendTestWebhook, testEventBody } = require('../webhook-test');
const { failAction } = require('../tools');
const { handleError, throwNotFound, maskSecrets, MASK_NOTE } = require('./route-helpers');
const { settingsSchema, apiResponses, listQuerySchema } = require('../schemas');
const { MCP_MAX_PAGE_SIZE } = require('../consts');

const webhookErrorFlagSchema = Joi.object({
    message: Joi.string().example('Request failed with status 500').description('Error message from the last failed delivery')
})
    .unknown()
    .allow(null)
    .description('Information about the last webhook delivery error. Null if no errors have been registered')
    .label('WebhookRouteErrorFlag');

const webhookCustomHeadersSchema = settingsSchema.webhooksCustomHeaders
    .description('Custom HTTP headers added to webhook requests for this route')
    .label('WebhookRouteCustomHeaders');

function registerListWebhookRoutes(server, args) {
    const { CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes',

        async handler(request) {
            try {
                const listing = await Webhooks.list(request.query.page, request.query.pageSize, request.query.query);

                // customHeaders and the target URL both carry credentials for the customer's own
                // receiver, so a reader of this listing could otherwise post forged, correctly
                // authenticated webhooks into it
                for (const entry of listing.webhooks || []) {
                    maskSecrets(entry);
                }

                return listing;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List webhook routes',
            notes: `List custom webhook routes. ${MASK_NOTE}`,
            tags: ['api', 'Webhooks'],

            plugins: {
                mcp: {
                    name: 'list_webhook_routes',
                    title: 'List webhook routes',
                    description:
                        'List the custom webhook routes, paged: per-route targets with their own event filters, beside the global webhook target in the settings. Credentials in target URLs are masked.',
                    bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                },
                openapi: {
                    responses: apiResponses('Returns a page of custom webhook routes.', 400, 401, 403, 429, 500)
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
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    query: listQuerySchema('ID, name, description or target URL', 'WebhookRoutesListQuery')
                }).label('WebhookRoutesListRequest')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    webhooks: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Webhook ID'),
                                name: Joi.string().max(256).example('Send to Slack').description('Name of the route').label('WebhookRouteName').required(),
                                description: Joi.string()
                                    .allow('')
                                    .max(1024)
                                    .example('Something about the route')
                                    .description('Optional description of the webhook route')
                                    .label('WebhookRouteDescription'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was created'),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was last updated'),
                                enabled: Joi.boolean().example(true).description('Is the route enabled').label('WebhookRouteEnabled'),
                                targetUrl: settingsSchema.webhooks,
                                tcount: Joi.number().integer().example(123).description('How many times this route has been applied'),
                                webhookErrorFlag: webhookErrorFlagSchema,
                                customHeaders: webhookCustomHeadersSchema
                            }).label('WebhookRoutesListEntry')
                        )
                        .label('WebhookRoutesList')
                }).label('WebhookRoutesListResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerGetWebhookRoute(server, args) {
    const { CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes/webhookRoute/{webhookRoute}',

        async handler(request) {
            try {
                let webhookRouteData = await Webhooks.get(request.params.webhookRoute);
                if (!webhookRouteData) {
                    throwNotFound();
                }
                maskSecrets(webhookRouteData);
                return webhookRouteData;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get webhook route information',
            notes: `Retrieve webhook route content and information. ${MASK_NOTE}`,
            tags: ['api', 'Webhooks'],

            plugins: {
                mcp: {
                    name: 'get_webhook_route',
                    title: 'Get webhook route',
                    description: 'Get one webhook route: its target URL, the events it forwards, whether it is enabled, and its filter and mapping functions.'
                },
                openapi: {
                    responses: apiResponses('Returns the webhook route, including its filter and transform functions.', 400, 401, 403, 404, 429, 500)
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
                    webhookRoute: Joi.string().max(256).required().example('example').description('Webhook ID')
                }).label('GetWebhookRouteRequest')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Webhook ID'),
                    name: Joi.string().max(256).example('Send to Slack').description('Name of the route').label('WebhookRouteName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the route')
                        .description('Optional description of the webhook route')
                        .label('WebhookRouteDescription'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was created'),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was last updated'),
                    enabled: Joi.boolean().example(true).description('Is the route enabled').label('WebhookRouteEnabled'),
                    targetUrl: settingsSchema.webhooks,
                    tcount: Joi.number().integer().example(123).description('How many times this route has been applied'),
                    v: Joi.number().integer().example(1).description('Internal version counter, increased on every update'),
                    webhookErrorFlag: webhookErrorFlagSchema,
                    customHeaders: webhookCustomHeadersSchema,
                    content: Joi.object({
                        fn: Joi.string().allow(null).example('return true;').description('Filter function. Null if not set'),
                        map: Joi.string().allow(null).example('payload.ts = Date.now(); return payload;').description('Mapping function. Null if not set')
                    }).label('WebhookRouteContent')
                }).label('WebhookRouteResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerTestWebhook(server, args) {
    const { CORS_CONFIG } = args;

    server.route({
        method: 'POST',
        path: '/v1/webhooks/test',

        async handler(request) {
            try {
                const routeId = request.payload && request.payload.webhookRoute;

                // Only ever a configured target: the global one, or a custom route's. The target
                // URL and its headers are credentials of the receiver, so they are neither taken
                // from the request nor echoed back in the result
                let url, customHeaders;
                if (routeId) {
                    const route = await Webhooks.getMeta(routeId);
                    if (!route || !route.id) {
                        throwNotFound('Requested webhook route was not found');
                    }
                    url = route.targetUrl;
                    customHeaders = route.customHeaders;
                } else {
                    const stored = await settings.getMulti('webhooks', 'webhooksCustomHeaders');
                    url = stored.webhooks;
                    customHeaders = stored.webhooksCustomHeaders;
                }

                const target = routeId ? 'route' : 'global';
                if (!url) {
                    return { success: false, target, error: 'Webhook URL is not set', code: 'NoWebhookTarget' };
                }

                const result = await sendTestWebhook({
                    url,
                    customHeaders,
                    body: testEventBody(await settings.get('serviceUrl')),
                    logger: request.logger
                });

                return Object.assign({ target }, result);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Send a test webhook',
            notes: 'Posts a `test` event to the global webhook target, or with `webhookRoute` set to the target of that custom route, with the custom headers configured for it and signed like a real delivery, and reports whether the receiver accepted it. The target is never taken from the request.',
            tags: ['api', 'Webhooks'],

            plugins: {
                openapi: {
                    responses: apiResponses(
                        'Returns the result of the test delivery. A failed delivery is reported in the result, not as an error status.',
                        400,
                        401,
                        403,
                        404,
                        429,
                        500
                    )
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
                payload: Joi.object({
                    webhookRoute: Joi.string()
                        .max(256)
                        .example('AAABgS-UcAYAAAABAA')
                        .description('Custom webhook route to test. Omit to test the global webhook target')
                })
                    .allow(null)
                    .label('TestWebhookRequest')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Did the receiver accept the test event with a 2xx response'),
                    target: Joi.string().valid('global', 'route').example('global').description('Which configured target was tested'),
                    duration: Joi.number().integer().example(182).description('How long the delivery took, in milliseconds'),
                    error: Joi.string().example('Request failed with status 503').description('Why the delivery failed. Only present if success=false'),
                    code: Joi.string().example('ECONNREFUSED').description('Error code. Only present if success=false'),
                    statusCode: Joi.number()
                        .integer()
                        .example(503)
                        .description('HTTP status the receiver answered with. Only present if it answered with an error')
                }).label('TestWebhookResponse'),
                failAction: 'log'
            }
        }
    });
}

async function init(args) {
    const { server } = args;

    registerListWebhookRoutes(server, args);
    registerGetWebhookRoute(server, args);
    registerTestWebhook(server, args);
}

module.exports = init;
