'use strict';

const Joi = require('joi');
const { redis } = require('../db');
const { Gateway } = require('../gateway');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { lastErrorSchema } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/gateways',

        async handler(request) {
            try {
                let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });

                return await gatewayObject.listGateways(request.query.page, request.query.pageSize);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List gateways',
            notes: 'Lists registered gateways',
            tags: ['api', 'SMTP Gateway'],

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
                }).label('GatewaysFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    gateways: Joi.array()
                        .items(
                            Joi.object({
                                gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                                name: Joi.string().max(256).example('My Email Gateway').description('Display name for the gateway'),
                                deliveries: Joi.number().integer().empty('').example(100).description('Count of email deliveries using this gateway'),
                                lastUse: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last delivery time'),
                                lastError: lastErrorSchema.allow(null)
                            }).label('GatewayResponseItem')
                        )
                        .label('GatewayEntries')
                }).label('GatewaysFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/gateway/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });
            try {
                let gatewayData = await gatewayObject.loadGatewayData();

                // remove secrets
                if (gatewayData.pass) {
                    gatewayData.pass = '******';
                }

                let result = {};

                for (let key of ['gateway', 'name', 'host', 'port', 'user', 'pass', 'secure', 'deliveries', 'lastUse', 'lastError']) {
                    if (key in gatewayData) {
                        result[key] = gatewayData[key];
                    }
                }

                return result;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Get gateway info',
            notes: 'Returns stored information about the gateway. Passwords are not included.',
            tags: ['api', 'SMTP Gateway'],

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
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                })
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),

                    name: Joi.string().max(256).required().example('My Email Gateway').description('Display name for the gateway'),
                    deliveries: Joi.number().integer().empty('').example(100).description('Count of email deliveries using this gateway'),
                    lastUse: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last delivery time'),

                    user: Joi.string().empty('').trim().max(1024).description('SMTP authentication username').label('UserName'),
                    pass: Joi.string().empty('').max(1024).description('SMTP authentication password').label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('GatewayTlsOptions'),

                    lastError: lastErrorSchema.allow(null)
                }).label('GatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/gateway',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, call, secret: await getSecret() });

            try {
                let result = await gatewayObject.create(request.payload);
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Register new gateway',
            notes: 'Registers a new SMP gateway',
            tags: ['api', 'SMTP Gateway'],

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

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID').required(),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().default(null).max(1024).description('SMTP authentication username').label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).description('SMTP authentication password').label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('GatewayCreateTlsOptions')
                }).label('CreateGateway')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                    state: Joi.string()
                        .required()
                        .valid('existing', 'new')
                        .example('new')
                        .description('Is the gateway new or updated existing')
                        .label('CreateGatewayState')
                }).label('CreateGatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/gateway/edit/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });

            try {
                return await gatewayObject.update(request.payload);
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Update gateway info',
            notes: 'Updates gateway information',
            tags: ['api', 'SMTP Gateway'],

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
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name'),

                    user: Joi.string().empty('').trim().max(1024).allow(null).description('SMTP authentication username').label('UserName'),
                    pass: Joi.string().empty('').max(1024).allow(null).description('SMTP authentication password').label('Password'),

                    host: Joi.string().hostname().empty('').example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .empty('')
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('GatewayUpdateTlsOptions')
                }).label('UpdateGateway')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }).label('UpdateGatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/gateway/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({
                redis,
                gateway: request.params.gateway,
                secret: await getSecret()
            });

            try {
                return await gatewayObject.delete();
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove SMTP gateway',
            notes: 'Delete SMTP gateway data',
            tags: ['api', 'SMTP Gateway'],

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
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }).label('DeleteRequest')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the gateway deleted')
                }).label('DeleteGatewayResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
