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
// Either the plaintext value or the id a listing reports. Both are 64 hex characters, and both
// resolve to the same record - the value is the only one a caller still has right after creating a
// token, and the id is the only one available afterwards.
// DELETE resolves either the plaintext value or the id - it has done since before this, and the
// value is what a caller holds if it never recorded the id. The read routes take the id only: a
// token value in a URL path is written to the access log, and POST /v1/tokens returns the id, so
// there is no case that needs it.
const tokenReferenceSchema = Joi.string()
    .length(64)
    .hex()
    .required()
    .example('1bc12baf7f0d5e51fe0a4e0eda06e1be5b8d6cc2c66b95dc0fbe4d2e9f5d5e1a')
    .description('The access token value, or the token id from a listing')
    .label('TokenReference');

const tokenIdParamSchema = Joi.string()
    .length(64)
    .hex()
    .required()
    .example('1bc12baf7f0d5e51fe0a4e0eda06e1be5b8d6cc2c66b95dc0fbe4d2e9f5d5e1a')
    .description('The token id, as reported by POST /v1/tokens and the token listing')
    .label('TokenIdParam');

/**
 * Resolves a token id to its record, or null when there is no such token.
 *
 * Only the two "there is no such token" outcomes become null. A blanket catch reported a Redis
 * outage as a missing credential, which is the one answer an operator auditing a token must not be
 * given: "this token does not exist" reads as a deletion that already happened.
 *
 * By id, never by the plaintext value. getRawData() would resolve either, but a token value in a URL
 * path lands in the access log and in every reverse proxy in front of it - and nothing needs it
 * here, since POST /v1/tokens returns the id.
 *
 * `allowExpired` because an expired token must still be inspectable: it is exactly the record
 * someone reads to find out why a credential stopped working.
 */
async function loadTokenById(tokenId) {
    try {
        return await tokens.get(tokenId, true, { allowExpired: true });
    } catch (err) {
        if (err.code === 'UnknownToken' || err.code === 'InvalidToken') {
            return null;
        }
        throw err;
    }
}

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

    // The provision and delete routes are registered twice - the current path and the
    // deprecated pre-2.79 alias at the bottom of this file - so the handlers and the request/
    // response schemas are shared. Sharing the schema INSTANCES matters beyond reuse: the
    // OpenAPI generator names components after joi labels, and two different schema objects
    // carrying the same label would come out numbered (CreateToken1).
    const createTokenPayloadSchema = Joi.object({
        account: accountIdSchema.description('Bind the token to one account. Omit for an instance-wide token, which then has to set `permissions`'),

        description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),

        scopes: Joi.array()
            .items(Joi.string().valid('api', 'smtp', 'imap-proxy').meta({ enumDescriptions: ENUM_DESCRIPTIONS.tokenScope }).label('TokenScope'))
            .single()
            .default(['api'])
            .required()
            .description('Token permission scopes: "api" for REST API access, "smtp" for SMTP submission, "imap-proxy" for IMAP proxy authentication')
            .label('Scopes'),

        metadata: tokenMetadataSchema,

        restrictions: tokenRestrictionsSchema,

        // An unbound token reaches instance-wide endpoints and every account, so it may
        // only be issued narrowed. A bound one is already limited to its account, so the
        // narrowing stays optional there.
        // `.invalid(null)` matters as much as `.required()`: tokenPermissionsSchema allows
        // null so the admin form can post "not narrowed", and joi's required() is a
        // presence check that an explicit null satisfies. Without this, sending
        // `permissions: null` with no account - which any template rendering an unset
        // variable produces - passed the rule and minted a full instance-wide token.
        permissions: tokenPermissionsSchema.when('account', {
            is: Joi.exist(),
            otherwise: tokenPermissionsSchema.required().invalid(null).messages({
                'any.required': 'A token with no account must set permissions, so that an instance-wide credential is always a narrowed one',
                'any.invalid': 'A token with no account must set permissions, so that an instance-wide credential is always a narrowed one'
            })
        }),

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
    }).label('CreateToken');

    const createTokenResponseSchema = Joi.object({
        token: Joi.string()
            .length(64)
            .hex()
            .required()
            .example('9a6d24f8f43e01b1f2c4f11a5c5b8e51fe0a4e0eda06e1be5b8d6cc2c66b95dc')
            .description('The access token. This is the only time it is returned - store it now'),
        id: tokenIdSchema.required().description('Identifier for this token, as reported by the token listings')
    }).label('CreateTokenResponse');

    const deleteTokenParamsSchema = Joi.object({
        token: tokenReferenceSchema
    }).label('DeleteTokenRequest');

    const deleteTokenResponseSchema = Joi.object({
        deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the token deleted')
    }).label('DeleteTokenRequestResponse');

    const provisionTokenHandler = async request => {
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

            // An account-bound token is validated against a real account; an instance-wide one has
            // nothing to validate. The schema already refuses an unbound token that is not
            // narrowed, so reaching here without an account means `permissions` is set.
            //
            // Safe because this route sits in the never-grantable `admin` group and has no
            // `{account}` parameter, so an account-bound token is refused by the binding check and
            // a narrowed one by the group check. The caller is therefore always a full-privilege
            // root token, and every token it can mint here is strictly narrower than what it
            // already holds.
            if (request.payload.account) {
                // throws if account does not exist
                await accountObject.loadAccountData();
            }

            let token = await tokens.provision(Object.assign({}, request.payload, { remoteAddress: request.app.ip }));

            // The id as well as the value: the value is never shown again and the listings report
            // only the id, so returning the value alone left a caller unable to say which of its
            // own tokens it had just created without hashing it themselves.
            return { token, id: tokens.tokenId(token) };
        } catch (err) {
            handleError(request, err);
        }
    };

    const deleteTokenHandler = async request => {
        try {
            return { deleted: await tokens.delete(request.params.token, { remoteAddress: request.app.ip }) };
        } catch (err) {
            handleError(request, err);
        }
    };

    server.route({
        method: 'POST',
        path: '/v1/tokens',

        handler: provisionTokenHandler,

        options: {
            description: 'Provision an access token',
            // The conditional requirement is stated here because the schema cannot carry it: a flat
            // `required` array has no way to say "unless `account` is set", and marking `permissions`
            // required outright would describe the ordinary account-bound mint as invalid.
            notes: 'Provisions a new access token. Either bind it to an account, or set `permissions` - an instance-wide token that is not narrowed reaches every account and every endpoint, so the API declines to mint one.',
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

                payload: createTokenPayloadSchema
            },

            response: {
                schema: createTokenResponseSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/tokens/{token}',

        handler: deleteTokenHandler,
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

                params: deleteTokenParamsSchema
            },

            response: {
                schema: deleteTokenResponseSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens',

        async handler(request) {
            try {
                // Every token by default, not just the unbound ones. "Which credentials exist on
                // this instance" was previously unanswerable in one call: root tokens and each
                // account's tokens lived behind separate endpoints, so an audit meant one request
                // per account. `account` narrows it to one account when that is what you want.
                //
                // `total` and `pages` come back too: without them a caller could not tell a complete
                // listing from a truncated one, which is what the previous hardcoded cap of 1000
                // silently produced.
                return await tokens.list(request.query.account, request.query.page, request.query.pageSize, request.query.query, {
                    all: !request.query.account
                });
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List access tokens',
            notes: 'Lists access tokens. Returns every token on the instance unless narrowed with the account argument. Token values are never returned - only the id each token is listed under.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns the matching access tokens. Token values are never returned after creation.', 400, 401, 403, 429, 500)
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
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    query: Joi.string()
                        .empty('')
                        .trim()
                        .max(1024)
                        .example('agent')
                        .description('Filter by description, id or account')
                        .label('TokenSearchQuery'),
                    account: accountIdSchema.description('Only list tokens bound to this account. Omit to list every token on the instance')
                }).label('TokensQuery')
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.allow(null).description('The account filter that was applied, or null when every token was listed'),
                    total: Joi.number().integer().example(12).description('How many tokens match'),
                    page: Joi.number().integer().example(0).description('Current page (zero indexed)'),
                    pages: Joi.number().integer().example(1).description('Total page count'),
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                // Null for an instance-wide token. Always present, so a client has
                                // one type for a token rather than one per listing.
                                account: accountIdSchema.allow(null).description('Account this token is bound to, or null for an instance-wide token'),
                                ...tokenListItemFields
                            }).label('TokensItem')
                        )
                        .label('TokensEntries')
                }).label('TokensResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/{token}',

        async handler(request) {
            try {
                // Both reads at once: the last-use record is keyed by the id the path already
                // carries, so it never needed the record resolved first. tokens.list() puts the
                // same pair in one multi() for every token it lists.
                const [tokenData, access] = await Promise.all([loadTokenById(request.params.token), tokens.getAccess(request.params.token)]);
                if (!tokenData) {
                    throwNotFound('Requested access token was not found');
                }

                // Same shape as an entry in the listings, so a client has one type for a token
                // however it obtained it. `access` lives in a second hash, which is why it is
                // fetched here rather than arriving with the record - leaving it out made the one
                // endpoint that describes a single credential the one that could not say when it
                // was last used.
                const { id, account, description, metadata, ip, remoteAddress, scopes, restrictions, permissions, created, expires } = tokenData;

                return {
                    id,
                    account: account || null,
                    description,
                    metadata,
                    ip,
                    remoteAddress,
                    scopes,
                    restrictions,
                    permissions,
                    created,
                    expires: expires ? new Date(expires) : undefined,
                    access
                };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get token info',
            notes: 'Returns stored information about a single access token. The token value itself is never returned - it is only shown once, when the token is created.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns the stored token record. The token value is not included.', 400, 401, 403, 404, 429, 500)
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
                    token: tokenIdParamSchema
                }).label('GetTokenRequest')
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.allow(null).description('Account this token is bound to, or null for an instance-wide token'),
                    ...tokenListItemFields
                }).label('TokenResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/{token}/log',

        async handler(request) {
            try {
                const tokenData = await loadTokenById(request.params.token);
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
                    token: tokenIdParamSchema
                }).label('TokenLogRequest'),

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number()
                        .integer()
                        .min(1)
                        .max(tokenAuditLog.MAX_PAGE_SIZE)
                        .default(tokenAuditLog.DEFAULT_LOG_PAGE_SIZE)
                        .example(tokenAuditLog.DEFAULT_LOG_PAGE_SIZE)
                        .description('How many entries per page')
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

    // --------------------------------------------------------------------------------------------
    // Deprecated aliases. v2.79.0 renamed the token endpoints (POST /v1/token -> POST /v1/tokens,
    // DELETE /v1/token/{token} -> DELETE /v1/tokens/{token}) and folded the per-account listing
    // into GET /v1/tokens?account=..., which handed every pre-2.79 integration that provisions,
    // revokes or lists tokens a 404 from a minor upgrade - token-rotation pipelines failing
    // first. The old paths stay registered against the same handlers and schema instances, but are
    // left OUT of the published document and the API reference (plugins.openapi.deprecated - see
    // lib/openapi/build-document.js): they exist for old integrations to keep working, and
    // documenting them would steer new ones onto retired paths.

    server.route({
        method: 'POST',
        path: '/v1/token',

        handler: provisionTokenHandler,

        options: {
            description: 'Provision an access token (deprecated)',
            notes: 'Deprecated alias of `POST /v1/tokens`, which behaves identically - use that path instead.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    deprecated: true,
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

                payload: createTokenPayloadSchema
            },

            response: {
                schema: createTokenResponseSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/token/{token}',

        handler: deleteTokenHandler,
        options: {
            description: 'Remove a token (deprecated)',
            notes: 'Deprecated alias of `DELETE /v1/tokens/{token}`, which behaves identically - use that path instead.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    deprecated: true,
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

                params: deleteTokenParamsSchema
            },

            response: {
                schema: deleteTokenResponseSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/account/{account}',

        async handler(request) {
            try {
                // The pre-2.79 response shape: the account's tokens with no paging metadata
                return { tokens: (await tokens.list(request.params.account, 0, 1000)).tokens };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List account tokens (deprecated)',
            notes: 'Deprecated alias for listing the access tokens of one account - use `GET /v1/tokens` with the `account` argument instead, which also pages the listing.',
            tags: ['api', 'Access Tokens'],

            plugins: {
                openapi: {
                    deprecated: true,
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
}

module.exports = init;
