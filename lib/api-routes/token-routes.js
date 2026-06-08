'use strict';

const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const tokens = require('../tokens');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { accountIdSchema, tokenRestrictionsSchema, ipSchema, tokenIdSchema } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'POST',
        path: '/v1/token',

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

                let token = await tokens.provision(Object.assign({}, request.payload, { remoteAddress: request.app.ip }));

                return { token };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Provision an access token',
            notes: 'Provisions a new access token for an account',
            tags: ['api', 'Access Tokens'],

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
                    account: accountIdSchema.required(),

                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),

                    scopes: Joi.array()
                        .items(Joi.string().valid('api', 'smtp', 'imap-proxy').label('TokenScope'))
                        .single()
                        .default(['api'])
                        .required()
                        .description(
                            'Token permission scopes: "api" for REST API access, "smtp" for SMTP submission, "imap-proxy" for IMAP proxy authentication'
                        )
                        .label('Scopes'),

                    metadata: Joi.string()
                        .empty('')
                        .max(1024 * 1024)
                        .custom((value, helpers) => {
                            try {
                                // check if parsing fails
                                JSON.parse(value);
                                return value;
                            } catch (err) {
                                return helpers.message('Metadata must be a valid JSON string');
                            }
                        })
                        .example('{"example": "value"}')
                        .description('Related metadata in JSON format')
                        .label('JsonMetaData'),

                    restrictions: tokenRestrictionsSchema,

                    ip: ipSchema.description('IP address of the requester').label('TokenIP')
                }).label('CreateToken')
            },

            response: {
                schema: Joi.object({
                    token: Joi.string().length(64).hex().required().example('123456').description('Access token')
                }).label('CreateTokenResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/token/{token}',

        async handler(request) {
            try {
                return { deleted: await tokens.delete(request.params.token, { remoteAddress: request.app.ip }) };
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove a token',
            notes: 'Delete an access token',
            tags: ['api', 'Access Tokens'],

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
                    token: Joi.string().length(64).hex().required().example('123456').description('Access token')
                }).label('DeleteTokenRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the token deleted')
                }).label('DeleteTokenRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens',

        async handler(request) {
            try {
                // TODO: allow paging
                return { tokens: (await tokens.list(null, 0, 1000)).tokens };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List root tokens',
            notes: 'Lists access tokens registered for root access',
            tags: ['api', 'Access Tokens'],

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
                failAction
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
                                description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                                metadata: Joi.string()
                                    .empty('')
                                    .max(1024 * 1024)
                                    .custom((value, helpers) => {
                                        try {
                                            // check if parsing fails
                                            JSON.parse(value);
                                            return value;
                                        } catch (err) {
                                            return helpers.message('Metadata must be a valid JSON string');
                                        }
                                    })
                                    .example('{"example": "value"}')
                                    .description('Related metadata in JSON format')
                                    .label('JsonMetaData'),
                                ip: ipSchema.description('IP address of the requester').label('TokenIP'),
                                id: tokenIdSchema
                            }).label('RootTokensItem')
                        )
                        .label('RootTokensEntries')
                }).label('RootTokensResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/account/{account}',

        async handler(request) {
            try {
                // TODO: allow paging
                return { tokens: (await tokens.list(request.params.account, 0, 1000)).tokens };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List account tokens',
            notes: 'Lists access tokens registered for an account',
            tags: ['api', 'Access Tokens'],

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
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
                                description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                                metadata: Joi.string()
                                    .empty('')
                                    .max(1024 * 1024)
                                    .custom((value, helpers) => {
                                        try {
                                            // check if parsing fails
                                            JSON.parse(value);
                                            return value;
                                        } catch (err) {
                                            return helpers.message('Metadata must be a valid JSON string');
                                        }
                                    })
                                    .example('{"example": "value"}')
                                    .description('Related metadata in JSON format')
                                    .label('JsonMetaData'),

                                restrictions: tokenRestrictionsSchema,

                                ip: ipSchema.description('IP address of the requester').label('TokenIP'),

                                id: tokenIdSchema
                            }).label('AccountTokensItem')
                        )
                        .label('AccountTokensEntries')
                }).label('AccountsTokensResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
