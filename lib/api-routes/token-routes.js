'use strict';

const Joi = require('joi');
const Boom = require('@hapi/boom');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const tokens = require('../tokens');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { accountIdSchema, tokenRestrictionsSchema, ipSchema, tokenIdSchema, errorResponses } = require('../schemas');

const tokenAccessSchema = Joi.object({
    time: Joi.date().iso().allow(null).example('2021-02-17T13:43:18.860Z').description('Last time this token was used. Null if the token has never been used'),
    ip: ipSchema.allow(null).description('IP address of the last request that used this token. Null if the address was not available')
})
    .unknown()
    .description('Token usage information')
    .label('TokenAccess');

const tokenScopesSchema = Joi.array()
    .items(Joi.string().example('api').label('TokenScopeEntry'))
    .description('Scopes this token is valid for')
    .label('TokenScopes');

const tokenMetadataSchema = Joi.string()
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
    .label('JsonMetaData');

// Both token listings (root and account) return the same item shape from tokens.list(),
// the account listing just adds the account ID
const tokenListItemFields = {
    description: Joi.string().empty('').trim().max(1024).example('Token description').description('Token description'),
    metadata: tokenMetadataSchema,
    ip: ipSchema.description('IP address of the requester').label('TokenIP'),
    remoteAddress: ipSchema.description('IP address of the client that created the token').label('TokenRemoteAddress'),
    scopes: tokenScopesSchema,
    restrictions: tokenRestrictionsSchema,
    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this token was created'),
    access: tokenAccessSchema,
    id: tokenIdSchema
};

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
                // Nothing invalidates an access token once it is minted, so a token handed to an
                // anonymous caller keeps working indefinitely. This route normally requires a real
                // credential (`auth: {strategy: 'api-token', mode: 'required'}`) and a caller
                // presenting one is trusted, but the `disableTokens` setting rewrites a
                // credential-less request to `access_token=preauth` and the strategy accepts it,
                // marking the credentials `{preauth: true}`. That anonymous caller must never mint a
                // lasting token - whether or not an admin password happens to be set - so refuse it
                // here (headless provisioning uses the CLI or EENGINE_PREPARED_TOKEN, not this route).
                if (request.auth.credentials?.preauth) {
                    throw Boom.forbidden('Can not provision an access token for an unauthenticated request');
                }

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

                    metadata: tokenMetadataSchema,

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

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(401, 403, 429, 500)
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
                failAction
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array().items(Joi.object(tokenListItemFields).label('RootTokensItem')).label('RootTokensEntries')
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
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
                                ...tokenListItemFields
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
