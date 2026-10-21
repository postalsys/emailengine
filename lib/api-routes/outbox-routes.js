'use strict';

const Joi = require('joi');
const logger = require('../logger');
const outbox = require('../outbox');
const { failAction } = require('../tools');
const { handleError, maskSecrets, MASK_NOTE, throwNotFound } = require('./route-helpers');

// What every per-message route answers for an unknown queue ID, and on the account routes for the
// queue ID of another account's message. The state refusals the outbox module throws (code
// NotFailed, ContentGone, NotDelayed) carry a 409 of their own
const QUEUE_ENTRY_NOT_FOUND = 'Requested queue entry was not found';
const { outboxEntrySchema, accountIdSchema, apiResponses, apiBoolean } = require('../schemas');
const { IMPACT } = require('./operation-impact');
const { MCP_MAX_PAGE_SIZE } = require('../consts');

// Every outbox route exists twice: once for the whole instance under /v1/outbox, and once for one
// account under /v1/account/{account}/outbox. The account form is what an account-bound access
// token can reach - its path names the account, which is what the api-token strategy checks the
// binding against - and every queue ID it is given has to belong to that account, so a bound
// credential cannot act on another account's message by its queue ID. The MCP tools stay on the
// instance routes only: the account routes do the same thing for a narrower caller.
const SCOPES = {
    instance: {
        prefix: '/v1/outbox',
        params: {},
        mcp: true
    },
    account: {
        prefix: '/v1/account/{account}/outbox',
        params: { account: accountIdSchema.required() },
        mcp: false
    }
};

const outboxStateSchema = Joi.string()
    .valid(...outbox.JOB_STATES)
    .example('failed')
    .description('List only messages in this state')
    .label('OutboxStateFilter');

function routeParams(scope, extra) {
    const keys = Object.assign({}, scope.params, extra || {});
    return Object.keys(keys).length ? Joi.object(keys) : undefined;
}

function registerListOutbox(server, ctx, scope) {
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
        pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
        state: outboxStateSchema
    };
    if (scope === SCOPES.instance) {
        query.account = accountIdSchema.description('List only messages queued by this account');
    }

    server.route({
        method: 'GET',
        path: scope.prefix,

        async handler(request) {
            try {
                const listing = await outbox.list(Object.assign({ logger }, request.query, request.params.account ? { account: request.params.account } : {}));

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
            description: scope === SCOPES.instance ? 'List queued messages' : 'List queued messages of an account',
            notes:
                scope === SCOPES.instance
                    ? `Lists messages in the Outbox. With \`account\` set, only the messages that account has queued are listed, the same as the account outbox endpoint. ${MASK_NOTE}`
                    : `Lists the messages an account has in the Outbox: scheduled and waiting messages, those being delivered, and failed messages whose content is still stored for a retry. Reachable with an access token bound to the account. ${MASK_NOTE}`,
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: scope.mcp
                    ? {
                          name: 'get_outbox',
                          title: 'List outbox',
                          description: 'List messages queued for delivery, paged, including scheduled sends and their delivery progress.',
                          bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                      }
                    : undefined,
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

                params: routeParams(scope),
                query: Joi.object(query).label(scope === SCOPES.instance ? 'OutboxListFilter' : 'AccountOutboxListFilter')
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

function registerGetOutboxEntry(server, ctx, scope) {
    const { CORS_CONFIG, queueIdParam } = ctx;

    server.route({
        method: 'GET',
        path: `${scope.prefix}/{queueId}`,

        async handler(request) {
            try {
                let outboxEntry = await outbox.get({ queueId: request.params.queueId, account: request.params.account, logger });
                if (!outboxEntry) {
                    throwNotFound(QUEUE_ENTRY_NOT_FOUND);
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
                mcp: scope.mcp
                    ? {
                          name: 'get_queued_message',
                          title: 'Get queued message',
                          description:
                              'Get one message in the sending queue by the queue id that send_message, send_draft or get_outbox returned: its recipients, scheduled time, delivery attempts and the last delivery error.'
                      }
                    : undefined,
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

                params: routeParams(scope, queueIdParam).label(scope === SCOPES.instance ? 'OutboxEntryParams' : 'AccountOutboxEntryParams')
            },

            response: {
                schema: outboxEntrySchema,
                failAction: 'log'
            }
        }
    });
}

function registerRetryOutboxEntry(server, ctx, scope) {
    const { CORS_CONFIG, queueIdParam } = ctx;

    server.route({
        method: 'POST',
        path: `${scope.prefix}/{queueId}/retry`,

        async handler(request) {
            try {
                let result = await outbox.retry({ queueId: request.params.queueId, account: request.params.account, logger });
                if (!result) {
                    throwNotFound(QUEUE_ENTRY_NOT_FOUND);
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Retry a failed message',
            notes: 'Puts a message whose delivery failed for good back into the queue with a fresh set of delivery attempts. Only a failed message whose content is still stored can be retried: the content of the most recent failures is kept for this, within the bounds set by the queueKeepFailedContent and queueKeepFailedContentSize settings (or EENGINE_QUEUE_KEEP_FAILED_CONTENT and EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE, which win when set). A message that cannot be retried answers 409 with `code` NotFailed (the message is not in the failed state) or ContentGone (its content is no longer stored).',
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: scope.mcp
                    ? {
                          name: 'retry_queued_message',
                          title: 'Retry failed message',
                          description:
                              'Retry a message whose delivery failed for good, by the queue id from get_outbox. Only a message in the failed state whose content is still stored can be retried; the error says when it cannot. A retried message starts over with a full set of delivery attempts.'
                      }
                    : undefined,
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

                params: routeParams(scope, queueIdParam).label(scope === SCOPES.instance ? 'OutboxEntryParams' : 'AccountOutboxEntryParams')
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

function registerPromoteOutboxEntry(server, ctx, scope) {
    const { CORS_CONFIG, queueIdParam } = ctx;

    server.route({
        method: 'POST',
        path: `${scope.prefix}/{queueId}/promote`,

        async handler(request) {
            try {
                let result = await outbox.promote({ queueId: request.params.queueId, account: request.params.account, logger });
                if (!result) {
                    throwNotFound(QUEUE_ENTRY_NOT_FOUND);
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
                mcp: scope.mcp
                    ? {
                          name: 'send_queued_message_now',
                          title: 'Send queued message now',
                          description:
                              'Deliver a queued message at the next opportunity instead of waiting for its scheduled time or for the backoff before its next attempt, by the queue id from get_outbox. Only a message in the delayed state can be promoted.'
                      }
                    : undefined,
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

                params: routeParams(scope, queueIdParam).label(scope === SCOPES.instance ? 'OutboxEntryParams' : 'AccountOutboxEntryParams')
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

function registerDeleteOutboxEntry(server, ctx, scope) {
    const { CORS_CONFIG, queueIdParam } = ctx;

    server.route({
        method: 'DELETE',
        path: `${scope.prefix}/{queueId}`,

        async handler(request) {
            try {
                return await outbox.del({ queueId: request.params.queueId, account: request.params.account, logger });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove a message',
            notes: 'Removes a queued message together with its stored content, so it is not sent. A message whose delivery attempt is running right now is not removed and is reported as locked.',
            tags: ['api', 'Outbox'],

            plugins: {
                mcp: scope.mcp
                    ? {
                          name: 'cancel_queued_message',
                          title: 'Cancel queued message',
                          description:
                              'Cancel a message waiting in the sending queue, by the queue id from get_outbox. A message already handed to the mail server cannot be cancelled.'
                      }
                    : undefined,
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

                params: routeParams(scope, queueIdParam).label(scope === SCOPES.instance ? 'OutboxEntryParams' : 'AccountOutboxEntryParams')
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
    const queueIdParam = {
        queueId: Joi.string().max(100).example('d41f0423195f271f').description('Queue identifier for scheduled email').required()
    };

    const ctx = { CORS_CONFIG, queueIdParam };

    for (const scope of [SCOPES.instance, SCOPES.account]) {
        registerListOutbox(server, ctx, scope);
        registerGetOutboxEntry(server, ctx, scope);
        registerRetryOutboxEntry(server, ctx, scope);
        registerPromoteOutboxEntry(server, ctx, scope);
        registerDeleteOutboxEntry(server, ctx, scope);
    }
}

module.exports = init;
