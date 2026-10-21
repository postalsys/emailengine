'use strict';

const Joi = require('joi');
const logger = require('../logger');
const webhookFailures = require('../webhook-failures');
const { failAction } = require('../tools');
const { handleError, throwNotFound } = require('./route-helpers');
const { accountIdSchema, apiResponses, apiBoolean } = require('../schemas');
const { routeScopes, routeParams, scopedLabel, mcpFor, pagingQuery } = require('./scoped-routes');
const { IMPACT } = require('./operation-impact');
const { MCP_MAX_PAGE_SIZE } = require('../consts');

// The webhook deliveries that failed for good: list, retry, remove. Like the outbox routes they
// exist for the whole instance and for one account (see scoped-routes.js); every delivery ID the
// account form is given has to belong to that account.
const SCOPES = routeScopes({ instance: '/v1/webhooks/failed', account: '/v1/account/{account}/webhooks/failed' });

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

function registerListFailed(server, ctx, scope) {
    const { CORS_CONFIG } = ctx;

    const query = pagingQuery();
    if (scope.isInstance) {
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
            description: scope.isInstance ? 'List failed webhook deliveries' : 'List failed webhook deliveries of an account',
            notes: 'Lists webhook deliveries that failed for good, most recent first: every attempt failed, or the failure was permanent. Each entry says what the event was about and why the last attempt failed; the event payload itself is not included. With an account filter, the most recent failed deliveries of the whole queue are scanned for that account, and `scanLimited` says when the scan stopped before the end of the queue. How many failed deliveries are kept is set by EENGINE_QUEUE_KEEP_FAILED and EENGINE_QUEUE_KEEP_FAILED_AGE.',
            tags: ['api', 'Webhooks'],

            plugins: {
                mcp: mcpFor(scope, {
                    name: 'list_failed_webhooks',
                    title: 'List failed webhook deliveries',
                    description:
                        'List the webhook deliveries that failed for good, most recent first: the event, the account and message it was about, the route it was for and why the last attempt failed. Use it after a receiver outage to find what to replay with retry_failed_webhook.',
                    bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                }),
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
                query: Joi.object(query).label(scopedLabel(scope, 'FailedWebhookDeliveriesFilter'))
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
                mcp: mcpFor(scope, {
                    name: 'retry_failed_webhook',
                    title: 'Retry failed webhook delivery',
                    description:
                        'Send a failed webhook delivery again, by the id list_failed_webhooks returned, with a fresh set of attempts. It goes to the target it was queued for, with the payload it was queued with.'
                }),
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

                params: routeParams(scope, deliveryIdParam).label(scopedLabel(scope, 'FailedWebhookDeliveryParams'))
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
                mcp: mcpFor(scope, {
                    name: 'remove_failed_webhook',
                    title: 'Remove failed webhook delivery',
                    description:
                        'Remove a failed webhook delivery from the queue, by the id list_failed_webhooks returned, so it is no longer kept for a retry. Confirm with the user before calling this.'
                }),
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

                params: routeParams(scope, deliveryIdParam).label(scopedLabel(scope, 'FailedWebhookDeliveryParams'))
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

    for (const scope of SCOPES.all) {
        registerListFailed(server, ctx, scope);
        registerRetryFailed(server, ctx, scope);
        registerDeleteFailed(server, ctx, scope);
    }
}

module.exports = init;
