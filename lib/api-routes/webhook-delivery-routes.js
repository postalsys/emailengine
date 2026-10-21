'use strict';

const Joi = require('joi');
const logger = require('../logger');
const webhookFailures = require('../webhook-failures');
const { failAction } = require('../tools');
const { handleError, throwNotFound } = require('./route-helpers');
const { accountIdSchema, apiResponses, apiBoolean } = require('../schemas');
const { IMPACT } = require('./operation-impact');

// The webhook deliveries that failed for good: list, retry, remove. Like the outbox routes they
// exist for the whole instance and for one account, the account form being what an
// account-bound token reaches; every delivery ID it is given has to belong to that account.
const SCOPES = {
    instance: {
        prefix: '/v1/webhooks/failed',
        params: {}
    },
    account: {
        prefix: '/v1/account/{account}/webhooks/failed',
        params: { account: accountIdSchema.required() }
    }
};

const deliveryIdParam = {
    delivery: Joi.string().max(256).example('1543').description('Failed webhook delivery ID, as the listing returns it').required()
};

const failedDeliverySchema = Joi.object({
    id: Joi.string().example('1543').description('Delivery ID'),
    event: Joi.string().example('messageNew').description('Webhook event type'),
    eventId: Joi.string().allow(null).example('c4a2bd7e-3a50-4b5d-a0d1-29fa2c9e2b6c').description('Event identifier, as sent in the webhook payload'),
    account: Joi.string().allow(null).example('user123').description('Account the event is about'),
    path: Joi.string().allow(null).example('INBOX').description('Folder the event is about'),
    messageId: Joi.string().allow(null).example('<test123@example.com>').description('Message-ID of the message the event is about'),
    route: Joi.object({
        id: Joi.string().example('AAABgS-UcAYAAAABAA').description('Webhook route ID'),
        name: Joi.string().allow(null).example('Send to Slack').description('Webhook route name. Null when the route no longer exists')
    })
        .allow(null)
        .description('The custom webhook route the delivery was for. Null for the default webhook target')
        .label('FailedWebhookDeliveryRoute'),
    created: Joi.date().iso().allow(null).example('2026-10-21T08:02:11.120Z').description('When the event was queued'),
    failed: Joi.date().iso().allow(null).example('2026-10-21T09:40:43.301Z').description('When the last attempt failed'),
    attemptsMade: Joi.number().integer().example(10).description('Delivery attempts made'),
    attempts: Joi.number().integer().example(10).description('Delivery attempts allowed'),
    error: Joi.object({
        message: Joi.string().example('Request failed with status 503').description('Why the last attempt failed'),
        code: Joi.string().allow(null).example('ECONNREFUSED').description('Error code, when the failure carried one'),
        statusCode: Joi.number().integer().allow(null).example(503).description('HTTP status the receiver answered with, when it answered'),
        permanent: Joi.boolean().example(false).description('True when retrying could not help, so the delivery was given up on early')
    })
        .allow(null)
        .label('FailedWebhookDeliveryError')
}).label('FailedWebhookDelivery');

function routeParams(scope, extra) {
    const keys = Object.assign({}, scope.params, extra || {});
    return Object.keys(keys).length ? Joi.object(keys) : undefined;
}

function registerListFailed(server, ctx, scope) {
    const { CORS_CONFIG } = ctx;

    const query = {
        page: Joi.number()
            .integer()
            .min(0)
            .max(1024 * 1024)
            .default(0)
            .example(0)
            .description('Page number (zero indexed, so use 0 for first page)')
            .label('PageNumber'),
        pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
    };
    if (scope === SCOPES.instance) {
        query.account = accountIdSchema.description('List only the deliveries of this account');
    }

    server.route({
        method: 'GET',
        path: scope.prefix,

        async handler(request) {
            try {
                return await webhookFailures.list(Object.assign({ logger }, request.query, request.params.account ? { account: request.params.account } : {}));
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: scope === SCOPES.instance ? 'List failed webhook deliveries' : 'List failed webhook deliveries of an account',
            notes: 'Lists webhook deliveries that failed for good, most recent first: every attempt failed, or the failure was permanent. Each entry says what the event was about and why the last attempt failed; the event payload itself is not included. With an account filter, the most recent failed deliveries of the whole queue are scanned for that account, and `scanLimited` says when the scan stopped before the end of the queue. How many failed deliveries are kept is set by EENGINE_QUEUE_KEEP_FAILED and EENGINE_QUEUE_KEEP_FAILED_AGE.',
            tags: ['api', 'Webhooks'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns a page of failed webhook deliveries.', 400, 401, 403, 429, 500)
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

                params: routeParams(scope),
                query: Joi.object(query).label(scope === SCOPES.instance ? 'FailedWebhookDeliveriesFilter' : 'AccountFailedWebhookDeliveriesFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(12).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(1).description('Total page count').label('PagesNumber'),
                    scanLimited: Joi.boolean()
                        .example(false)
                        .description('True when an account filter was applied and the scan stopped before the end of the failed deliveries'),
                    deliveries: Joi.array().items(failedDeliverySchema).label('FailedWebhookDeliveryList')
                }).label('FailedWebhookDeliveriesResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerRetryFailed(server, ctx, scope) {
    const { CORS_CONFIG } = ctx;

    server.route({
        method: 'POST',
        path: `${scope.prefix}/{delivery}/retry`,

        async handler(request) {
            try {
                const result = await webhookFailures.retry({ id: request.params.delivery, account: request.params.account, logger });
                if (!result) {
                    throwNotFound('Requested webhook delivery was not found');
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Retry a failed webhook delivery',
            notes: 'Puts a webhook delivery that failed for good back into the queue with a fresh set of attempts. It is sent to the target the event was queued for, with the payload it was queued with. A delivery that is not in the failed state answers 409 with `code` NotFailed.',
            tags: ['api', 'Webhooks'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns a retry marker. The delivery is waiting for an attempt again.', 400, 401, 403, 404, 409, 429, 500)
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

                params: routeParams(scope, deliveryIdParam).label(
                    scope === SCOPES.instance ? 'FailedWebhookDeliveryParams' : 'AccountFailedWebhookDeliveryParams'
                )
            },

            response: {
                schema: Joi.object({
                    retried: apiBoolean().default(true).description('Was the delivery put back into the queue'),
                    id: Joi.string().example('1543').description('Delivery ID')
                }).label('RetryFailedWebhookDeliveryResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerDeleteFailed(server, ctx, scope) {
    const { CORS_CONFIG } = ctx;

    server.route({
        method: 'DELETE',
        path: `${scope.prefix}/{delivery}`,

        async handler(request) {
            try {
                const result = await webhookFailures.del({ id: request.params.delivery, account: request.params.account, logger });
                if (!result) {
                    throwNotFound('Requested webhook delivery was not found');
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Remove a failed webhook delivery',
            notes: 'Removes a webhook delivery that failed for good from the queue, so it is not kept for inspection or a retry. A delivery that is not in the failed state answers 409 with `code` NotFailed.',
            tags: ['api', 'Webhooks'],

            plugins: {
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    responses: apiResponses('Returns a deletion marker.', 400, 401, 403, 404, 409, 429, 500)
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

                params: routeParams(scope, deliveryIdParam).label(
                    scope === SCOPES.instance ? 'FailedWebhookDeliveryParams' : 'AccountFailedWebhookDeliveryParams'
                )
            },

            response: {
                schema: Joi.object({
                    deleted: apiBoolean().default(true).description('Was the delivery removed'),
                    id: Joi.string().example('1543').description('Delivery ID')
                }).label('DeleteFailedWebhookDeliveryResponse'),
                failAction: 'log'
            }
        }
    });
}

async function init(args) {
    const { server, CORS_CONFIG } = args;
    const ctx = { CORS_CONFIG };

    for (const scope of [SCOPES.instance, SCOPES.account]) {
        registerListFailed(server, ctx, scope);
        registerRetryFailed(server, ctx, scope);
        registerDeleteFailed(server, ctx, scope);
    }
}

module.exports = init;
