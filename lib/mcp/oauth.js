'use strict';

// The minimal OAuth 2.1 authorization server behind the MCP endpoint.
//
// It exists for exactly one flow: an MCP client that cannot be configured with a static access
// token (claude.ai web connectors and similar) discovers this server through the protected
// resource metadata, registers itself as a public client, sends the operator's browser to the
// admin consent page, and exchanges the resulting code for an EmailEngine access token with the
// `mcp` scope. Every credential this issues is an ordinary access token: visible on the admin
// tokens page, revocable there, and bounded by SURFACE_GRANTS.mcp like any other mcp-scoped
// token. There are no refresh tokens and no expiry by default - revocation is the lifecycle.
//
// What is implemented, spec-wise: OAuth 2.0 Dynamic Client Registration (RFC 7591, open
// registration for public clients only, rate limited per IP), authorization code + PKCE S256
// (OAuth 2.1 - PKCE is mandatory, `plain` is not accepted), single-use codes with a short TTL,
// exact-match redirect URIs, RFC 8707 resource validation against this instance's canonical
// MCP resource, and the RFC 9207 `iss` authorization-response parameter. Client secrets do not
// exist here: `token_endpoint_auth_method` is always `none`, which is what PKCE is for.

const crypto = require('crypto');

const { redis } = require('../db');
const { REDIS_PREFIX } = require('../consts');
const msgpack = require('../msgpack');
const tokens = require('../tokens');
const settings = require('../settings');
const { constantTimeEqual } = require('../tools');
const { mcpFeatureEnabled } = require('./index');
const { LOOPBACK_HOSTNAMES } = require('./protocol');

// Registered clients and pending codes are throwaway state, not configuration: an unused client
// registration disappears after this long, and re-registering is one unauthenticated call. The
// TTL is refreshed whenever the client starts an authorization, so an actively used client id
// stays stable.
const CLIENT_TTL = 30 * 24 * 3600;

// An authorization code is redeemed within seconds in a working flow; ten minutes is the
// conventional upper bound.
const CODE_TTL = 10 * 60;

// How many redirect URIs one registration may carry. Consumed by the registration route's joi
// schema too, so the validation layer and the policy here cannot drift apart.
const MAX_REDIRECT_URIS = 10;

const clientKey = clientId => `${REDIS_PREFIX}mcp:oauth:client:${clientId}`;
const codeKey = code => `${REDIS_PREFIX}mcp:oauth:code:${code}`;

/**
 * Whether the OAuth flow is available at all: the MCP endpoint must be live, the feature
 * enabled, and a serviceUrl configured - the metadata documents have to name a canonical origin,
 * which a request-derived address cannot provide.
 *
 * @returns {Promise<String|false>} the canonical origin, or false
 */
async function oauthOrigin() {
    if (!mcpFeatureEnabled) {
        return false;
    }

    // One HMGET for the three settings the answer depends on, not three serialized reads - this
    // runs on every discovery request and on every /mcp 401
    const stored = await settings.getMulti('mcpEnabled', 'mcpOAuthEnabled', 'serviceUrl');
    if (!stored.mcpEnabled || !stored.mcpOAuthEnabled || !stored.serviceUrl) {
        return false;
    }

    try {
        return new URL(stored.serviceUrl).origin;
    } catch (err) {
        return false;
    }
}

function mcpResource(origin) {
    return `${origin}/mcp`;
}

/**
 * A redirect URI a public MCP client may register: https anywhere, http only on the loopback
 * (native clients binding a local callback port), or a private-use scheme (desktop apps).
 * Schemes that execute in a browser context are refused outright.
 */
function isAcceptableRedirectUri(value) {
    if (typeof value !== 'string' || value.length > 2048) {
        return false;
    }

    let url;
    try {
        url = new URL(value);
    } catch (err) {
        return false;
    }

    if (url.hash) {
        return false;
    }

    switch (url.protocol) {
        case 'https:':
            return true;
        case 'http:':
            return LOOPBACK_HOSTNAMES.includes(url.hostname);
        case 'javascript:':
        case 'data:':
        case 'file:':
        case 'blob:':
        case 'vbscript:':
            return false;
        default:
            // Anything else is treated as a private-use scheme (com.example.app:/callback,
            // RFC 8252 territory). The URL parser already guarantees scheme syntax, so beyond
            // the browser-context schemes named above there is nothing left to filter.
            return true;
    }
}

/**
 * Registers a public client (RFC 7591).
 *
 * @param {Object} opts
 * @param {Array} opts.redirectUris
 * @param {String} [opts.clientName]
 * @returns {Promise<Object>} the stored client record
 */
async function registerClient({ redirectUris, clientName }) {
    const uris = [].concat(redirectUris || []);

    if (!uris.length || uris.length > MAX_REDIRECT_URIS) {
        throw oauthFailure('invalid_redirect_uri', `redirect_uris must list 1-${MAX_REDIRECT_URIS} redirect URIs`);
    }

    // Any unacceptable URI fails the whole registration (RFC 7591 3.2.2). Silently registering
    // the acceptable subset was tried first, and it just moved the failure to authorize time,
    // where the client sees a generic error page instead of which URI was refused and why.
    const refused = uris.find(uri => !isAcceptableRedirectUri(uri));
    if (refused !== undefined) {
        throw oauthFailure(
            'invalid_redirect_uri',
            `Unacceptable redirect URI (must be https, loopback http, or a private-use scheme): ${String(refused).slice(0, 256)}`
        );
    }

    const client = {
        client_id: crypto.randomBytes(16).toString('hex'),
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: uris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'],
        response_types: ['code'],
        client_name: (clientName || '').toString().slice(0, 256) || undefined
    };

    await redis.set(clientKey(client.client_id), msgpack.encode(client), 'EX', CLIENT_TTL);

    return client;
}

async function getClient(clientId) {
    if (!/^[0-9a-f]{32}$/.test(clientId || '')) {
        return null;
    }

    const encoded = await redis.getBuffer(clientKey(clientId));
    if (!encoded) {
        return null;
    }

    try {
        return msgpack.decode(encoded);
    } catch (err) {
        return null;
    }
}

// A client that reached the consent page is in active use; keep its registration alive
async function touchClient(clientId) {
    await redis.expire(clientKey(clientId), CLIENT_TTL);
}

// Trailing slashes carry no meaning for a resource identifier, so every comparison below runs
// on the stripped form
function normalizeResource(resource) {
    return typeof resource === 'string' ? resource.replace(/\/+$/, '') : resource;
}

/**
 * Validates the resource indicator (RFC 8707) against this instance's canonical MCP resource.
 * Absent is tolerated for interoperability; a present value has to name this instance.
 */
function isAcceptableResource(resource, origin) {
    if (resource === undefined || resource === null || resource === '') {
        return true;
    }
    if (typeof resource !== 'string') {
        return false;
    }

    const normalized = normalizeResource(resource);

    return normalized === mcpResource(origin) || normalized === origin;
}

/**
 * Mints a single-use authorization code after the admin approved the consent page.
 *
 * @param {Object} opts - clientId, redirectUri, codeChallenge, resource, account (optional
 *        binding for the token), description (for the admin tokens listing)
 * @returns {Promise<String>} the code
 */
async function createAuthorizationCode(opts) {
    const code = crypto.randomBytes(32).toString('base64url');

    const record = {
        clientId: opts.clientId,
        redirectUri: opts.redirectUri,
        codeChallenge: opts.codeChallenge,
        resource: opts.resource || null,
        account: opts.account || null,
        // The narrowing the operator approved, applied to the token this code mints. Absent
        // means unnarrowed within the mcp scope, the same shape the admin generator posts.
        permissions: opts.permissions || null,
        description: opts.description,
        created: Date.now()
    };

    await redis.set(codeKey(code), msgpack.encode(record), 'EX', CODE_TTL);

    return code;
}

function oauthFailure(error, description) {
    const err = new Error(description);
    err.oauthError = error;
    return err;
}

function verifyPkce(codeVerifier, codeChallenge) {
    // RFC 7636 verifier alphabet and length, then S256
    if (typeof codeVerifier !== 'string' || codeVerifier.length < 43 || codeVerifier.length > 128 || !/^[A-Za-z0-9\-._~]+$/.test(codeVerifier)) {
        return false;
    }

    const digest = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

    return constantTimeEqual(digest, codeChallenge);
}

/**
 * The token endpoint's whole job: redeem a code for an access token.
 *
 * @param {Object} opts - code, clientId, redirectUri, codeVerifier, resource, origin, ip
 * @returns {Promise<Object>} OAuth token response body
 */
async function redeemAuthorizationCode({ code, clientId, redirectUri, codeVerifier, resource, origin, ip }) {
    if (typeof code !== 'string' || code.length > 256) {
        throw oauthFailure('invalid_grant', 'Unknown authorization code');
    }

    // Single use by construction: whoever gets the record, gets it deleted
    const encoded = await redis.getdelBuffer(codeKey(code));
    if (!encoded) {
        throw oauthFailure('invalid_grant', 'Unknown or expired authorization code');
    }

    let record;
    try {
        record = msgpack.decode(encoded);
    } catch (err) {
        throw oauthFailure('invalid_grant', 'Unknown or expired authorization code');
    }

    if (record.clientId !== clientId) {
        throw oauthFailure('invalid_grant', 'Authorization code was issued to another client');
    }

    if (record.redirectUri !== redirectUri) {
        throw oauthFailure('invalid_grant', 'redirect_uri does not match the authorization request');
    }

    if (!verifyPkce(codeVerifier, record.codeChallenge)) {
        throw oauthFailure('invalid_grant', 'PKCE verification failed');
    }

    if (!isAcceptableResource(resource, origin)) {
        throw oauthFailure('invalid_target', 'The resource parameter does not name this server');
    }

    // RFC 8707: a code issued for a resource named at authorization time is redeemed for that
    // same resource. Absence stays tolerated on either side for interoperability - only one
    // resource exists on this server, so this catches client confusion, not a privilege step.
    if (resource && record.resource && normalizeResource(resource) !== normalizeResource(record.resource)) {
        throw oauthFailure('invalid_target', 'The resource parameter does not match the authorization request');
    }

    const token = await tokens.provision({
        account: record.account || undefined,
        description: record.description,
        scopes: ['mcp'],
        permissions: record.permissions || undefined,
        ip,
        metadata: JSON.stringify({ issuer: 'mcp-oauth', client: record.clientId })
    });

    return {
        access_token: token,
        token_type: 'Bearer',
        scope: 'mcp'
    };
}

module.exports = {
    oauthOrigin,
    mcpResource,
    registerClient,
    getClient,
    touchClient,
    isAcceptableRedirectUri,
    isAcceptableResource,
    createAuthorizationCode,
    redeemAuthorizationCode,
    verifyPkce,
    MAX_REDIRECT_URIS
};
