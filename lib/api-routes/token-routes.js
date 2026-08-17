'use strict';

const Joi = require('joi');
const Boom = require('@hapi/boom');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const tokens = require('../tokens');
const tokenAuditLog = require('../token-audit-log');
const { failAction } = require('../tools');
const { handleError, throwNotFound } = require('./route-helpers');
const { accountIdSchema, tokenRestrictionsSchema, tokenPermissionsSchema, ipSchema, tokenIdSchema, apiResponses, ENUM_DESCRIPTIONS } = require('../schemas');
const { IMPACT } = require('./operation-impact');

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
    permissions: tokenPermissionsSchema,
    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this token was created'),
    expires: Joi.date()
        .iso()
        .example('2021-02-17T14:43:18.860Z')
        .description('The time this token stops working. Absent for tokens that never expire')
        .label('TokenExpires'),
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
                openapi: {
                    responses: apiResponses('Returns the new token value. This is the only time it is shown - store it now.', 400, 401, 403, 404, 429, 500)
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
                        .items(Joi.string().valid('api', 'smtp', 'imap-proxy').meta({ enumDescriptions: ENUM_DESCRIPTIONS.tokenScope }).label('TokenScope'))
                        .single()
                        .default(['api'])
                        .required()
                        .description(
                            'Token permission scopes: "api" for REST API access, "smtp" for SMTP submission, "imap-proxy" for IMAP proxy authentication'
                        )
                        .label('Scopes'),

                    metadata: tokenMetadataSchema,

                    restrictions: tokenRestrictionsSchema,

                    permissions: tokenPermissionsSchema,

                    // provision() has always accepted an expiry; the route did not, so until now the
                    // API could not mint a short-lived token at all. A narrow token that never
                    // expires is only half of what a per-task credential is for.
                    expires: Joi.date()
                        .iso()
                        .greater('now')
                        .example('2021-02-17T14:43:18.860Z')
                        .description('Optional time when this token stops working. Omit for a token that never expires')
                        // Distinct from the TokenExpires the listing uses: a joi label is a public
                        // type name in the generated document, so reusing it would collide and the
                        // generator would number one of them
                        .label('CreateTokenExpires'),

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
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    responses: apiResponses('Returns a deletion marker. The token stops working immediately.', 400, 401, 403, 429, 500)
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
                openapi: {
                    responses: apiResponses('Returns the root access tokens. Token values are never returned after creation.', 401, 403, 429, 500)
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
                openapi: {
                    responses: apiResponses('Returns the access tokens scoped to the account.', 400, 401, 403, 429, 500)
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

    server.route({
        method: 'GET',
        path: '/v1/token/{token}/log',

        async handler(request) {
            try {
                // Resolved the same way DELETE does, so either the plaintext value or the id from a
                // token listing works - the listing is the only place the id is available, and the
                // plaintext is never shown again after creation.
                const tokenData = await tokens.getRawData(request.params.token);
                if (!tokenData) {
                    throwNotFound('Requested access token was not found');
                }

                return Object.assign({ token: tokenData.id }, await tokenAuditLog.list(tokenData.id, request.query));
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get token audit log',
            notes: 'Lists recent requests made with an access token, newest first. Requires the tokenAuditLog setting to be enabled; it is off by default, and entries only exist from the point it was switched on.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    'x-ee-impact': IMPACT.READONLY,
                    responses: apiResponses('Returns the recorded requests for this token, newest first.', 400, 401, 403, 404, 429, 500)
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
                    token: Joi.string().length(64).hex().required().example('123456').description('Access token, or the token id from a token listing')
                }).label('TokenLogRequest'),

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number()
                        .integer()
                        .min(1)
                        .max(tokenAuditLog.LOG_ENTRIES)
                        .default(20)
                        .example(20)
                        .description('How many entries to return per page')
                        .label('PageSize')
                }).label('TokenLogQuery')
            },

            response: {
                schema: Joi.object({
                    token: tokenIdSchema,
                    total: Joi.number().integer().example(120).description('How many entries are stored for this token'),
                    page: Joi.number().integer().example(0).description('Current page (zero indexed)'),
                    pages: Joi.number().integer().example(6).description('Total page count'),
                    entries: Joi.array()
                        .items(
                            Joi.object({
                                time: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('When the request was made').label('TokenLogTime'),
                                ip: ipSchema.allow(null).description('Address the request came from').label('TokenLogIP'),
                                method: Joi.string()
                                    .allow(null)
                                    .example('get')
                                    .description('HTTP method, or the surface name for SMTP and the IMAP proxy')
                                    .label('TokenLogMethod'),
                                path: Joi.string()
                                    .allow(null)
                                    .example('/v1/account/{account}/messages')
                                    .description('Route that was called')
                                    .label('TokenLogPath'),
                                action: Joi.string()
                                    .allow(null)
                                    .example('read')
                                    .description('Permission action the operation required')
                                    .label('TokenLogAction'),
                                group: Joi.string()
                                    .allow(null)
                                    .example('message')
                                    .description('Permission group the operation belongs to')
                                    .label('TokenLogGroup'),
                                account: accountIdSchema.allow(null).description('Account the request addressed').label('TokenLogAccount'),
                                status: Joi.string()
                                    .valid('allowed', 'denied')
                                    .example('allowed')
                                    .description('Whether the request was served')
                                    .label('TokenLogStatus'),
                                reason: Joi.string()
                                    .allow(null)
                                    .example('group')
                                    .description('Why it was refused. Null when it was allowed')
                                    .label('TokenLogReason')
                            }).label('TokenLogEntry')
                        )
                        .label('TokenLogEntries')
                }).label('TokenLogResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
