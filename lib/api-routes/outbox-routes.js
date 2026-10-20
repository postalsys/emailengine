'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const logger = require('../logger');
const outbox = require('../outbox');
const { failAction } = require('../tools');
const { handleError, maskSecrets, MASK_NOTE } = require('./route-helpers');
const { outboxEntrySchema, apiResponses, apiBoolean } = require('../schemas');
const { IMPACT } = require('./operation-impact');
const { MCP_MAX_PAGE_SIZE } = require('../consts');

function registerListOutbox(server, ctx) {
    const { CORS_CONFIG } = ctx;

    server.route({
        method: 'GET',
        path: '/v1/outbox',

        async handler(request) {
            try {
                const listing = await outbox.list(Object.assign({ logger }, request.query));

                // A queue entry carries the proxy the submission was told to use, and a failed one
                // also records the route it took under progress.networkRouting
                for (const entry of listing.messages || []) {
                    maskSecrets(entry);
                }

                return listing;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List queued messages',
            notes: `Lists messages in the Outbox. ${MASK_NOTE}`,
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: {
                    name: 'get_outbox',
                    title: 'List outbox',
                    description: 'List messages queued for delivery, paged, including scheduled sends and their delivery progress.',
                    bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                },
                openapi: {
                    responses: apiResponses('Returns the messages currently queued for delivery.', 400, 401, 403, 429, 500)
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
                }).label('OutbixListFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    messages: Joi.array().items(outboxEntrySchema).label('OutboxListEntries')
                }).label('OutboxListResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerGetOutboxEntry(server, ctx) {
    const { CORS_CONFIG, outboxEntryParams, notFound } = ctx;

    server.route({
        method: 'GET',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                let outboxEntry = await outbox.get({ queueId: request.params.queueId, logger });
                if (!outboxEntry) {
                    throw notFound();
                }
                return maskSecrets(outboxEntry);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get queued message',
            notes: `Gets a queued message in the Outbox. ${MASK_NOTE}`,
            tags: ['api', 'Outbox'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns the queued message, including its delivery attempts and last error.', 400, 401, 403, 404, 429, 500)
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

                params: outboxEntryParams
            },

            response: {
                schema: outboxEntrySchema,
                failAction: 'log'
            }
        }
    });
}

function registerRetryOutboxEntry(server, ctx) {
    const { CORS_CONFIG, outboxEntryParams, notFound } = ctx;

    server.route({
        method: 'POST',
        path: '/v1/outbox/{queueId}/retry',

        async handler(request) {
            try {
                let result = await outbox.retry({ queueId: request.params.queueId, logger });
                if (!result) {
                    throw notFound();
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Retry a failed message',
            notes: 'Puts a message whose delivery failed for good back into the queue with a fresh set of delivery attempts. Only a failed message whose content is still stored can be retried: the content of the most recent failures is kept for this, within the bounds set by EENGINE_QUEUE_KEEP_FAILED_CONTENT and EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE. A message that cannot be retried answers 409 with `code` NotFailed (the message is not in the failed state) or ContentGone (its content is no longer stored).',
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: {
                    name: 'retry_queued_message',
                    title: 'Retry failed message',
                    description:
                        'Retry a message whose delivery failed for good, by the queue id from get_outbox. Only a message in the failed state whose content is still stored can be retried; the error says when it cannot. A retried message starts over with a full set of delivery attempts.'
                },
                openapi: {
                    responses: apiResponses('Returns a retry marker. The message is waiting for a delivery attempt again.', 400, 401, 403, 404, 409, 429, 500)
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

                params: outboxEntryParams
            },

            response: {
                schema: Joi.object({
                    retried: apiBoolean().default(true).description('Was the message put back into the queue'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier of the message'),
                    messageId: Joi.string().allow(null, '').example('<test123@example.com>').description('Message-ID header value')
                }).label('RetryOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerPromoteOutboxEntry(server, ctx) {
    const { CORS_CONFIG, outboxEntryParams, notFound } = ctx;

    server.route({
        method: 'POST',
        path: '/v1/outbox/{queueId}/promote',

        async handler(request) {
            try {
                let result = await outbox.promote({ queueId: request.params.queueId, logger });
                if (!result) {
                    throw notFound();
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Send a queued message now',
            notes: 'Moves a message out of the delayed set so it is delivered at the next opportunity instead of at its scheduled time, or instead of after the backoff before its next attempt. Any other state answers 409 with `code` NotDelayed.',
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: {
                    name: 'send_queued_message_now',
                    title: 'Send queued message now',
                    description:
                        'Deliver a queued message at the next opportunity instead of waiting for its scheduled time or for the backoff before its next attempt, by the queue id from get_outbox. Only a message in the delayed state can be promoted.'
                },
                openapi: {
                    responses: apiResponses('Returns a promotion marker. The message is waiting for a delivery attempt.', 400, 401, 403, 404, 409, 429, 500)
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

                params: outboxEntryParams
            },

            response: {
                schema: Joi.object({
                    promoted: apiBoolean().default(true).description('Was the message moved out of the delayed set'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier of the message'),
                    messageId: Joi.string().allow(null, '').example('<test123@example.com>').description('Message-ID header value')
                }).label('PromoteOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerDeleteOutboxEntry(server, ctx) {
    const { CORS_CONFIG, outboxEntryParams } = ctx;

    server.route({
        method: 'DELETE',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                return await outbox.del({ queueId: request.params.queueId, logger });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove a message',
            notes: 'Remove a message from the outbox',
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: {
                    name: 'cancel_queued_message',
                    title: 'Cancel queued message',
                    description:
                        'Cancel a message waiting in the sending queue, by the queue id from get_outbox. A message already handed to the mail server cannot be cancelled.'
                },
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    responses: apiResponses('Returns a deletion marker. A message already being delivered cannot be removed.', 400, 401, 403, 429, 500)
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

                params: outboxEntryParams
            },

            response: {
                schema: Joi.object({
                    deleted: apiBoolean().default(true).description('Was the message deleted'),
                    locked: Joi.boolean()
                        .example(true)
                        .description(
                            'Present when the message was not deleted because a delivery attempt is running for it right now. Retry once the attempt has finished'
                        )
                }).label('DeleteOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });
}

async function init(args) {
    const { server, CORS_CONFIG } = args;

    // The queue ID of a message, as every per-message outbox route takes it
    const outboxEntryParams = Joi.object({
        queueId: Joi.string().max(100).example('d41f0423195f271f').description('Queue identifier for scheduled email').required()
    }).label('OutboxEntryParams');

    // What every per-message route answers for an unknown queue ID. The state refusals the
    // outbox module throws (code NotFailed, ContentGone, NotDelayed) carry a 409 of their own
    const notFound = () => Boom.boomify(new Error('Requested queue entry was not found'), { statusCode: 404 });

    const ctx = { CORS_CONFIG, outboxEntryParams, notFound };

    registerListOutbox(server, ctx);
    registerGetOutboxEntry(server, ctx);
    registerRetryOutboxEntry(server, ctx);
    registerPromoteOutboxEntry(server, ctx);
    registerDeleteOutboxEntry(server, ctx);
}

module.exports = init;
