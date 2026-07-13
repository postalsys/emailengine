'use strict';

// Generic OIDC (OpenID Connect) SSO for the admin UI login.
//
// This is the provider-agnostic counterpart to the built-in Okta integration
// (OKTA_OAUTH2_* in workers/api.js and lib/ui-routes/auth-routes.js). It targets
// any standards-compliant OIDC identity provider - Keycloak, Authentik, Azure
// AD/Entra, Google Workspace, etc. - by reading the provider's discovery document
// (<issuer>/.well-known/openid-configuration) at API-worker startup and building a
// @hapi/bell custom OAuth2 provider from the advertised endpoints.
//
// Configuration is environment-variable only (mirroring OKTA_OAUTH2_*); there is
// no admin-UI/settings storage. All of OIDC_ISSUER / OIDC_CLIENT_ID /
// OIDC_CLIENT_SECRET must be set for SSO to be enabled.
//
// Trust model: identity is taken from the userinfo endpoint, fetched
// server-to-server over TLS with the freshly issued access token after the
// confidential-client authorization-code exchange. We deliberately do NOT parse or
// verify the id_token - CSRF/injection is covered by bell's signed `state` cookie
// plus PKCE (S256), so the id_token adds nothing we consume. This matches the
// shipped Okta integration's trust model exactly.
//
// Explicit endpoint-override env vars (OIDC_AUTHORIZATION_ENDPOINT, ...) were
// considered and deferred: every target IdP ships a working discovery document,
// and config is env-only, so overrides can be added later without a migration.

const { fetch: fetchCmd } = require('undici');
const { readEnvValue, httpAgent } = require('./tools');
const packageData = require('../package.json');

const OIDC_ISSUER = readEnvValue('OIDC_ISSUER');
const OIDC_CLIENT_ID = readEnvValue('OIDC_CLIENT_ID');
const OIDC_CLIENT_SECRET = readEnvValue('OIDC_CLIENT_SECRET');
const OIDC_PROVIDER_NAME = readEnvValue('OIDC_PROVIDER_NAME') || 'SSO';
const OIDC_SCOPES = readEnvValue('OIDC_SCOPES') || null;
const OIDC_ALLOWED_USERS = readEnvValue('OIDC_ALLOWED_USERS') || null;

const USE_OIDC_AUTH = !!(OIDC_ISSUER && OIDC_CLIENT_ID && OIDC_CLIENT_SECRET);

const DISCOVERY_TIMEOUT = 10 * 1000;

// `openid` is what makes the request an OIDC request; `profile` and `email`
// populate the userinfo claims mapped by mapUserinfoProfile().
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

// Parse a scope override string (space- or comma-separated) into an array. Falls
// back to DEFAULT_SCOPES when empty and always guarantees `openid` is present.
function parseScopes(scopeStr) {
    let scopes = (scopeStr || '')
        .split(/[\s,]+/)
        .map(scope => scope.trim())
        .filter(scope => scope);

    if (!scopes.length) {
        scopes = DEFAULT_SCOPES.slice();
    }

    if (!scopes.includes('openid')) {
        scopes.unshift('openid');
    }

    return scopes;
}

// Parse OIDC_ALLOWED_USERS into a normalized list of allow-list entries. Entries
// starting with "@" are treated as domain matches, everything else as an exact
// email match. Matching is case-insensitive.
function parseAllowList(str) {
    return (str || '')
        .split(',')
        .map(entry => entry.trim().toLowerCase())
        .filter(entry => entry)
        .map(entry => (entry.charAt(0) === '@' ? { type: 'domain', value: entry.slice(1) } : { type: 'email', value: entry }));
}

// Decide whether an authenticated OIDC user is allowed into the admin panel. An
// empty allow-list means "anyone the IdP authenticates"; a non-empty allow-list
// with no usable identifier on the profile denies access.
function isAllowedUser(profile, allowList) {
    if (!allowList || !allowList.length) {
        return true;
    }

    let email = ((profile && (profile.email || profile.username)) || '').trim().toLowerCase();
    if (!email) {
        return false;
    }

    let domain = email.indexOf('@') >= 0 ? email.split('@').pop() : null;

    return allowList.some(entry => {
        if (entry.type === 'domain') {
            return domain && entry.value === domain;
        }
        return entry.value === email;
    });
}

function normalizeIssuer(issuer) {
    return (issuer || '').replace(/\/+$/, '');
}

// Build the discovery document URL for an issuer. Trailing slashes are stripped so
// issuers that end with "/" (e.g. Authentik) don't produce a double slash.
function getDiscoveryUrl(issuer) {
    return `${normalizeIssuer(issuer)}/.well-known/openid-configuration`;
}

// Validate an OIDC discovery document: it must advertise the three endpoints we
// use and its `issuer` must match the configured issuer (per the OIDC spec). The
// issuer check also blocks the Azure "common"/multi-tenant footgun where a shared
// issuer would otherwise accept tokens from any tenant.
function validateDiscoveryDocument(doc, issuer) {
    if (!doc || typeof doc !== 'object') {
        throw new Error('OIDC discovery document is empty or not an object');
    }

    for (let key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']) {
        if (!doc[key] || typeof doc[key] !== 'string') {
            throw new Error(`OIDC discovery document is missing "${key}"`);
        }
    }

    if (normalizeIssuer(doc.issuer) !== normalizeIssuer(issuer)) {
        throw new Error(`OIDC issuer mismatch: discovery document reports "${doc.issuer}", expected "${issuer}"`);
    }

    return doc;
}

// Map an OIDC userinfo response to the minimal profile stored in the session
// cookie. Kept small on purpose (no raw claims) to stay well under the iron-sealed
// cookie size limit - IdPs like Keycloak return large tokens/claim sets.
function mapUserinfoProfile(userinfo) {
    userinfo = userinfo || {};
    return {
        id: userinfo.sub,
        username: userinfo.email || userinfo.preferred_username || userinfo.sub,
        displayName: userinfo.name || userinfo.preferred_username || userinfo.email,
        email: userinfo.email
    };
}

// Fetch and validate the discovery document for the configured issuer. Uses the
// shared RetryAgent (transient DNS/socket retries) with a hard timeout so a
// slow/unreachable IdP cannot stall API-worker startup indefinitely.
async function fetchOidcDiscovery() {
    let url = getDiscoveryUrl(OIDC_ISSUER);

    let res = await fetchCmd(url, {
        method: 'GET',
        headers: {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
            Accept: 'application/json'
        },
        dispatcher: httpAgent.retry,
        signal: AbortSignal.timeout(DISCOVERY_TIMEOUT)
    });

    if (!res.ok) {
        throw new Error(`OIDC discovery request failed with HTTP ${res.status}`);
    }

    let doc = await res.json();
    return validateDiscoveryDocument(doc, OIDC_ISSUER);
}

// Build a @hapi/bell custom OAuth2 provider from a validated discovery document.
function buildOidcBellProvider(discoveryDoc, options) {
    options = options || {};
    let scopes = parseScopes(options.scopes || OIDC_SCOPES);
    let userinfoEndpoint = discoveryDoc.userinfo_endpoint;

    return {
        protocol: 'oauth2',
        useParamsAuth: true,
        pkce: 'S256',
        auth: discoveryDoc.authorization_endpoint,
        token: discoveryDoc.token_endpoint,
        scope: scopes,
        profile: async (credentials, params, get) => {
            let userinfo = await get(userinfoEndpoint);
            credentials.profile = mapUserinfoProfile(userinfo);
        }
    };
}

module.exports = {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_PROVIDER_NAME,
    OIDC_ALLOWED_USERS,
    USE_OIDC_AUTH,

    parseScopes,
    parseAllowList,
    isAllowedUser,
    getDiscoveryUrl,
    validateDiscoveryDocument,
    mapUserinfoProfile,
    fetchOidcDiscovery,
    buildOidcBellProvider
};
