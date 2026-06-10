'use strict';

const Joi = require('joi');
const { webhooks: Webhooks } = require('../webhooks');
const { failAction } = require('../tools');
const { handleError, throwNotFound } = require('./route-helpers');
const { settingsSchema } = require('../schemas');

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

async function init(args) {
    const { server, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes',

        async handler(request) {
            try {
                return await Webhooks.list(request.query.page, request.query.pageSize);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List webhook routes',
            notes: 'List custom webhook routes',
            tags: ['api', 'Webhooks'],

            plugins: {},

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

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes/webhookRoute/{webhookRoute}',

        async handler(request) {
            try {
                let webhookRouteData = await Webhooks.get(request.params.webhookRoute);
                if (!webhookRouteData) {
                    throwNotFound();
                }
                return webhookRouteData;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get webhook route information',
            notes: 'Retrieve webhook route content and information',
            tags: ['api', 'Webhooks'],

            plugins: {},

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

module.exports = init;
