'use strict';

// The public half of the MCP OAuth flow: discovery metadata (RFC 9728 protected resource
// metadata and RFC 8414 authorization server metadata), open dynamic client registration
// (RFC 7591), and the token endpoint. The consent page - the only part with a human in it -
// lives on the admin surface (lib/ui-routes/mcp-consent-routes.js).
//
// Everything here is unauthenticated by design and rate limited per IP: registration mints
// nothing but a client id that only an admin's consent can turn into a credential, and the
// token endpoint redeems single-use PKCE-bound codes. Every route answers 404 while the flow
// is unavailable (MCP disabled, the mcpOAuthEnabled setting off, or no serviceUrl to anchor
// the canonical origin on).
//
// CORS is wide open on these routes on purpose, independent of the instance's CORS setting:
// browser-based MCP clients fetch the metadata and call the token endpoint cross-origin, and
// none of these endpoints reads a cookie or serves per-user state.

const Boom = require('@hapi/boom');
const Joi = require('joi');

const { checkRateLimit } = require('../rate-limit');
const { oauthOrigin, mcpResource, registerClient, redeemAuthorizationCode } = require('../mcp/oauth');

const OPEN_CORS = { origin: ['*'] };

// One OAuth-style error shape for every failure on these routes (RFC 6749 5.2)
function oauthErrorResponse(h, statusCode, error, description) {
    return h.response({ error, error_description: description }).code(statusCode);
}

// Registration and token requests are unauthenticated writes, so both get a per-IP budget that
// no working client comes near: a real flow registers once and redeems one code. Checked before
// any other Redis work in the handlers, so an abusive caller costs one Redis op per request.
// lib/rate-limit directly rather than the h.checkRateLimit toolkit decoration on purpose: the
// decoration routes through a main-thread RPC, the library call is one Redis round trip, and
// both count in the same Redis buckets.
async function assertRateLimit(request, bucket, allowed) {
    const limit = await checkRateLimit(`mcp:oauth:${bucket}:${request.app.ip}`, 1, allowed, 3600);
    if (!limit.success) {
        const err = Boom.tooManyRequests('Rate limit exceeded');
        err.output.payload.ttl = Math.ceil(limit.ttl);
        throw err;
    }
}

async function init(args) {
    const { server } = args;

    // Sends OAuth discovery at MCP clients that authenticate with nothing or with an unusable
    // token: the WWW-Authenticate pointer at the protected resource metadata is how a client
    // finds the authorization server (RFC 9728). Header-only, so token-authenticated clients
    // never notice it.
    server.ext('onPreResponse', async (request, h) => {
        const response = request.response;

        if (request.path !== '/mcp' || !response.isBoom || response.output.statusCode !== 401) {
            return h.continue;
        }

        const origin = await oauthOrigin();
        if (origin) {
            // The exact capitalized key Boom used for the strategy's own challenge: the worker's
            // preResponse extension rebuilds bearer 401s from output.headers['WWW-Authenticate'],
            // so writing any other key would be dropped in the rebuild
            response.output.headers['WWW-Authenticate'] = `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`;
        }

        return h.continue;
    });

    // RFC 9728: served both at the path-suffixed location clients derive from the resource URI
    // (/mcp) and at the root for clients that use the bare origin as the resource identifier
    server.route({
        method: 'GET',
        path: '/.well-known/oauth-protected-resource/{suffix?}',

        async handler(request) {
            if (request.params.suffix && request.params.suffix !== 'mcp') {
                throw Boom.notFound();
            }

            const origin = await oauthOrigin();
            if (!origin) {
                throw Boom.notFound();
            }

            return {
                resource: mcpResource(origin),
                authorization_servers: [origin],
                scopes_supported: ['mcp'],
                bearer_methods_supported: ['header'],
                resource_name: 'EmailEngine MCP'
            };
        },

        options: {
            description: 'MCP OAuth protected resource metadata',
            tags: ['external'],
            auth: false,
            cors: OPEN_CORS
        }
    });

    server.route({
        method: 'GET',
        path: '/.well-known/oauth-authorization-server',

        async handler() {
            const origin = await oauthOrigin();
            if (!origin) {
                throw Boom.notFound();
            }

            return {
                issuer: origin,
                authorization_endpoint: `${origin}/admin/mcp/authorize`,
                token_endpoint: `${origin}/mcp/oauth/token`,
                registration_endpoint: `${origin}/mcp/oauth/register`,
                response_types_supported: ['code'],
                grant_types_supported: ['authorization_code'],
                code_challenge_methods_supported: ['S256'],
                token_endpoint_auth_methods_supported: ['none'],
                scopes_supported: ['mcp'],
                authorization_response_iss_parameter_supported: true
            };
        },

        options: {
            description: 'MCP OAuth authorization server metadata',
            tags: ['external'],
            auth: false,
            cors: OPEN_CORS
        }
    });

    server.route({
        method: 'POST',
        path: '/mcp/oauth/register',

        async handler(request, h) {
            await assertRateLimit(request, 'register', 20);

            if (!(await oauthOrigin())) {
                throw Boom.notFound();
            }

            try {
                const client = await registerClient({
                    redirectUris: request.payload.redirect_uris,
                    clientName: request.payload.client_name
                });
                return h.response(client).code(201);
            } catch (err) {
                if (err.oauthError) {
                    return oauthErrorResponse(h, 400, err.oauthError, err.message);
                }
                throw err;
            }
        },

        options: {
            description: 'MCP OAuth dynamic client registration',
            tags: ['external'],
            auth: false,
            cors: OPEN_CORS,

            payload: {
                maxBytes: 64 * 1024,
                allow: ['application/json']
            },

            validate: {
                payload: Joi.object({
                    redirect_uris: Joi.array().items(Joi.string().max(2048)).max(20).required(),
                    client_name: Joi.string().max(1024),
                    token_endpoint_auth_method: Joi.string().valid('none'),
                    grant_types: Joi.array().items(Joi.string().max(64)).max(10),
                    response_types: Joi.array().items(Joi.string().max(64)).max(10),
                    scope: Joi.string().max(1024)
                }).unknown(true),

                failAction: (request, h, err) =>
                    oauthErrorResponse(h, 400, 'invalid_client_metadata', (err && err.message) || 'Invalid client metadata').takeover()
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/mcp/oauth/token',

        async handler(request, h) {
            await assertRateLimit(request, 'token', 60);

            const origin = await oauthOrigin();
            if (!origin) {
                throw Boom.notFound();
            }

            if (request.payload.grant_type !== 'authorization_code') {
                return oauthErrorResponse(h, 400, 'unsupported_grant_type', 'Only authorization_code is supported');
            }

            try {
                const tokenResponse = await redeemAuthorizationCode({
                    code: request.payload.code,
                    clientId: request.payload.client_id,
                    redirectUri: request.payload.redirect_uri,
                    codeVerifier: request.payload.code_verifier,
                    resource: request.payload.resource,
                    origin,
                    ip: request.app.ip
                });

                return h.response(tokenResponse).header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
            } catch (err) {
                if (err.oauthError) {
                    return oauthErrorResponse(h, 400, err.oauthError, err.message);
                }
                throw err;
            }
        },

        options: {
            description: 'MCP OAuth token endpoint',
            tags: ['external'],
            auth: false,
            cors: OPEN_CORS,

            payload: {
                maxBytes: 64 * 1024,
                allow: ['application/x-www-form-urlencoded', 'application/json']
            },

            validate: {
                payload: Joi.object({
                    grant_type: Joi.string().max(64).required(),
                    code: Joi.string().max(256),
                    client_id: Joi.string().max(256),
                    redirect_uri: Joi.string().max(2048),
                    code_verifier: Joi.string().max(256),
                    resource: Joi.string().max(2048)
                }).unknown(true),

                failAction: (request, h, err) => oauthErrorResponse(h, 400, 'invalid_request', (err && err.message) || 'Invalid request').takeover()
            }
        }
    });
}

module.exports = init;
