'use strict';

// The consent page of the MCP OAuth flow: the one step with a human in it. An MCP client sends
// the operator's browser here; approving mints a single-use authorization code that the client
// exchanges for an mcp-scoped access token at POST /mcp/oauth/token.
//
// Two rules shape the error handling:
//   - A request naming an unknown client or an unregistered redirect_uri renders an error page
//     and never redirects: redirecting would make this an open redirector aimed by whoever
//     composed the link (RFC 6749 4.1.2.1).
//   - Once the redirect_uri is validated against the registration, protocol-level problems are
//     reported by redirecting back to the client with ?error=..., which is how the client
//     learns the flow failed.
//
// Approval requires request.auth.isAuthenticated, exactly like the admin token mint
// (lib/ui-routes/admin-entities-routes.js): a token is never invalidated once issued, and the
// session default is applied conditionally, so the gate has to key on the actual request
// principal rather than the global secured-state.

const Boom = require('@hapi/boom');
const Joi = require('joi');

const { redis } = require('../db');
const { accountExists } = require('../account');
const { accountSuggestions } = require('./route-helpers');
const { failAction } = require('../tools');
const { accountIdSchema } = require('../schemas');
const tokenPermissionView = require('../token-permission-view');
const { mcpFeatureEnabled } = require('../mcp');
const { oauthOrigin, getClient, touchClient, createAuthorizationCode, isAcceptableResource } = require('../mcp/oauth');

// The OAuth request parameters, carried through the GET render and posted back with the
// decision. state is a client-side value with no format promises; the size bounds are only
// there so the consent form cannot be used to store arbitrary blobs in a hidden field.
const oauthParamsSchema = {
    client_id: Joi.string().hex().length(32).required(),
    redirect_uri: Joi.string().uri().max(2048).required(),
    state: Joi.string().max(4096).allow(''),
    code_challenge: Joi.string()
        .pattern(/^[A-Za-z0-9\-._~]{43,128}$/)
        .required(),
    resource: Joi.string().max(2048).allow('')
};

function redirectHostOf(redirectUri) {
    try {
        return new URL(redirectUri).host || redirectUri;
    } catch (err) {
        return redirectUri;
    }
}

// Sends the browser back to the client. `state` and the RFC 9207 `iss` marker ride along on
// every authorization response, success and failure alike, so each call site names only what
// is specific to it.
function redirectToClient(h, { redirectUri, state, origin }, params) {
    const url = new URL(redirectUri);
    for (const [key, value] of Object.entries(Object.assign({ state, iss: origin }, params))) {
        if (value !== undefined && value !== null && value !== '') {
            url.searchParams.set(key, value);
        }
    }
    return h.redirect(url.href);
}

function renderError(h, message) {
    return h.view(
        'mcp/authorize',
        {
            pageTitle: 'Authorize MCP client',
            errorMessage: message
        },
        { layout: 'app' }
    );
}

async function init(args) {
    const { server, call } = args;

    // The one construction of the consent view context, shared by the GET render and the POST
    // re-render, so the two cannot drift on what the page needs.
    async function renderConsent(h, { client, redirectUri, canProvision, values, errors }) {
        // What approving actually grants, derived from the same tables the enforcement reads
        // (SURFACE_GRANTS.mcp through the token form's view model) - hand-written prose here
        // would drift the first time the tool set changes
        const surface = tokenPermissionView.formModel().permissionSurfaces.find(entry => entry.scope === 'mcp');

        const accountOptions = await accountSuggestions(call);

        return h.view(
            'mcp/authorize',
            {
                pageTitle: 'Authorize MCP client',

                clientName: (client && client.client_name) || 'An MCP client',
                redirectHost: redirectHostOf(redirectUri),

                grantActions: surface ? surface.actionList.split(',').join(', ') : '',
                grantGroups: surface ? surface.groupList.split(',').join(', ') : '',

                accountOptions,

                // Mirrors the admin token mint: the form warns instead of letting the operator
                // fill everything in and lose it to a 403
                canProvision,

                values,
                errors
            },
            { layout: 'app' }
        );
    }

    if (!mcpFeatureEnabled) {
        // Same shape as the Document Store UI module: with the deployment gate off, the routes
        // do not exist
        return;
    }

    server.route({
        method: 'GET',
        path: '/admin/mcp/authorize',

        async handler(request, h) {
            const origin = await oauthOrigin();
            if (!origin) {
                return renderError(h, 'MCP OAuth sign-in is not enabled on this instance. Enable it under Configuration > MCP.');
            }

            const client = await getClient(request.query.client_id);
            if (!client) {
                return renderError(h, 'Unknown MCP client. The client registration may have expired - ask the client to register again.');
            }

            if (!client.redirect_uris.includes(request.query.redirect_uri)) {
                return renderError(h, 'The redirect address of this request is not registered for the client, so the request cannot be trusted.');
            }

            // From here on the redirect target is trusted, so the client gets told what failed
            const authRequest = { redirectUri: request.query.redirect_uri, state: request.query.state, origin };

            if (request.query.response_type !== 'code') {
                return redirectToClient(h, authRequest, { error: 'unsupported_response_type' });
            }

            if (request.query.code_challenge_method && request.query.code_challenge_method !== 'S256') {
                return redirectToClient(h, authRequest, {
                    error: 'invalid_request',
                    error_description: 'Only the S256 code challenge method is supported'
                });
            }

            if (!isAcceptableResource(request.query.resource, origin)) {
                return redirectToClient(h, authRequest, {
                    error: 'invalid_target',
                    error_description: 'The resource parameter does not name this server'
                });
            }

            await touchClient(client.client_id);

            return renderConsent(h, {
                client,
                redirectUri: request.query.redirect_uri,
                canProvision: request.auth.isAuthenticated,
                values: {
                    client_id: client.client_id,
                    redirect_uri: request.query.redirect_uri,
                    state: request.query.state,
                    code_challenge: request.query.code_challenge,
                    resource: request.query.resource
                }
            });
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                // A malformed authorization request never reaches a redirect, so the failure
                // renders in place
                failAction: (request, h) => renderError(h, 'This MCP authorization link is malformed or incomplete.').takeover(),

                query: Joi.object(
                    Object.assign({}, oauthParamsSchema, {
                        response_type: Joi.string().max(64).required(),
                        code_challenge_method: Joi.string().max(64),
                        scope: Joi.string().max(1024).allow('')
                    })
                )
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/mcp/authorize',

        async handler(request, h) {
            const origin = await oauthOrigin();
            if (!origin) {
                return renderError(h, 'MCP OAuth sign-in is not enabled on this instance.');
            }

            // The same rule as the admin token mint, for the same reason: this POST creates a
            // lasting credential, so it needs a real authenticated admin session on THIS request
            if (!request.auth.isAuthenticated) {
                throw Boom.forbidden('Can not authorize an MCP client without an authenticated admin session');
            }

            const client = await getClient(request.payload.client_id);
            if (!client || !client.redirect_uris.includes(request.payload.redirect_uri)) {
                return renderError(h, 'Unknown MCP client or unregistered redirect address. The registration may have expired while this page was open.');
            }

            const authRequest = { redirectUri: request.payload.redirect_uri, state: request.payload.state, origin };

            if (request.payload.decision !== 'approve') {
                return redirectToClient(h, authRequest, { error: 'access_denied' });
            }

            const account = request.payload.account || null;
            if (account && !(await accountExists(redis, account))) {
                return renderConsent(h, {
                    client,
                    redirectUri: request.payload.redirect_uri,
                    canProvision: true,
                    values: request.payload,
                    errors: { account: 'No such account' }
                });
            }

            const code = await createAuthorizationCode({
                clientId: client.client_id,
                redirectUri: request.payload.redirect_uri,
                codeChallenge: request.payload.code_challenge,
                resource: request.payload.resource || null,
                account,
                description: `MCP: ${client.client_name || redirectHostOf(request.payload.redirect_uri)}${account ? ` (${account})` : ''}`
            });

            request.logger.info({
                msg: 'Approved an MCP OAuth authorization',
                client: client.client_id,
                clientName: client.client_name,
                account
            });

            return redirectToClient(h, authRequest, { code });
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object(
                    Object.assign({}, oauthParamsSchema, {
                        decision: Joi.string().valid('approve', 'deny').required(),
                        account: accountIdSchema.allow('').default(null)
                    })
                )
            }
        }
    });
}

module.exports = init;
