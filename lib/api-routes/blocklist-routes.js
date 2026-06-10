'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { lists } = require('../lists');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { accountIdSchema, errorResponses } = require('../schemas');
const { REDIS_PREFIX } = require('../consts');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/blocklists',

        async handler(request) {
            try {
                return await lists.list(request.query.page, request.query.pageSize);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List blocklists',
            notes: 'List blocklists with blocked addresses',
            tags: ['api', 'Blocklists'],

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
                }).label('PageListsRequest')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    blocklists: Joi.array()
                        .items(
                            Joi.object({
                                listId: Joi.string().max(256).required().example('example').description('List ID'),
                                count: Joi.number().integer().example(12).description('Count of blocked addresses in this list')
                            }).label('BlocklistsResponseItem')
                        )
                        .label('BlocklistsEntries')
                }).label('BlocklistsResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/blocklist/{listId}',

        async handler(request) {
            try {
                return await lists.listContent(request.params.listId, request.query.page, request.query.pageSize);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List blocklist entries',
            notes: 'List blocked addresses for a list',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

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
                }).label('PageListsRequest')
            },

            response: {
                schema: Joi.object({
                    listId: Joi.string().max(256).required().example('example').description('List ID'),
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),
                    addresses: Joi.array()
                        .items(
                            Joi.object({
                                recipient: Joi.string().email().example('user@example.com').description('Listed email address').required(),
                                account: accountIdSchema.required(),
                                messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
                                source: Joi.string().example('api').description('Which mechanism was used to add the entry'),
                                reason: Joi.string().example('block').description('Why this entry was added'),
                                remoteAddress: Joi.string()
                                    .ip({
                                        version: ['ipv4', 'ipv6'],
                                        cidr: 'optional'
                                    })
                                    .description('Which IP address triggered the entry'),
                                userAgent: Joi.string().example('Mozilla/5.0 (Macintosh)').description('Which user agent triggered the entry'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was added or updated').required()
                            }).label('BlocklistListResponseItem')
                        )
                        .label('BlocklistListEntries')
                }).label('BlocklistListResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/blocklist/{listId}',
        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.payload.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();

                let added = await redis.eeListAdd(
                    `${REDIS_PREFIX}lists:unsub:lists`,
                    `${REDIS_PREFIX}lists:unsub:entries:${request.params.listId}`,
                    request.params.listId,
                    request.payload.recipient.toLowerCase().trim(),
                    JSON.stringify({
                        recipient: request.payload.recipient,
                        account: request.payload.account,
                        source: 'api',
                        reason: request.payload.reason,
                        remoteAddress: request.app.ip,
                        userAgent: request.headers['user-agent'],
                        created: new Date().toISOString()
                    })
                );

                return {
                    success: true,
                    added: !!added
                };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Add to blocklist',
            notes: 'Add an email address to a blocklist',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

                payload: Joi.object({
                    account: accountIdSchema.required(),
                    recipient: Joi.string().empty('').email().example('user@example.com').description('Email address to add to the list').required(),
                    reason: Joi.string().empty('').default('block').description('Identifier for the blocking reason')
                }).label('BlocklistListAddPayload')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Was the request successful').label('BlocklistListAddSuccess'),
                    added: Joi.boolean().example(true).description('Was the address added to the list')
                }).label('BlocklistListAddResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/blocklist/{listId}',

        async handler(request) {
            try {
                let exists = await redis.hexists(`${REDIS_PREFIX}lists:unsub:lists`, request.params.listId);
                if (!exists) {
                    let message = 'Requested blocklist was not found';
                    let error = Boom.boomify(new Error(message), { statusCode: 404 });
                    throw error;
                }

                let deleted = await redis.eeListRemove(
                    `${REDIS_PREFIX}lists:unsub:lists`,
                    `${REDIS_PREFIX}lists:unsub:entries:${request.params.listId}`,
                    request.params.listId,
                    request.query.recipient.toLowerCase().trim()
                );

                return {
                    deleted: !!deleted
                };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove from blocklist',
            notes: 'Delete a blocked email address from a list',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

                query: Joi.object({
                    recipient: Joi.string().empty('').email().example('user@example.com').description('Email address to remove from the list').required()
                }).label('RecipientQuery')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the address removed from the list')
                }).label('DeleteBlocklistResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
