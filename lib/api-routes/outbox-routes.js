'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const logger = require('../logger');
const outbox = require('../outbox');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { outboxEntrySchema, errorResponses } = require('../schemas');

async function init(args) {
    const { server, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/outbox',

        async handler(request) {
            try {
                return await outbox.list(Object.assign({ logger }, request.query));
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List queued messages',
            notes: 'Lists messages in the Outbox',
            tags: ['api', 'Outbox'],

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

    server.route({
        method: 'GET',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                let outboxEntry = await outbox.get({ queueId: request.params.queueId, logger });
                if (!outboxEntry) {
                    let message = 'Requested queue entry was not found';
                    let error = Boom.boomify(new Error(message), { statusCode: 404 });
                    throw error;
                }
                return outboxEntry;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get queued message',
            notes: 'Gets a queued message in the Outbox',
            tags: ['api', 'Outbox'],

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
                    queueId: Joi.string().max(100).example('d41f0423195f271f').description('Queue identifier for scheduled email').required()
                }).label('OutboxEntryParams')
            },

            response: {
                schema: outboxEntrySchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                return {
                    deleted: await outbox.del({ queueId: request.params.queueId, logger })
                };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove a message',
            notes: 'Remove a message from the outbox',
            tags: ['api', 'Outbox'],

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

                params: Joi.object({
                    queueId: Joi.string().max(100).example('d41f0423195f271f').description('Queue identifier for scheduled email').required()
                }).label('OutboxEntryParams')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the message deleted')
                }).label('DeleteOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
