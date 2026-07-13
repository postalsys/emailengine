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
//
// Authorization (who may sign in, after authentication) can optionally be
// restricted by an email allow-list (OIDC_ALLOWED_USERS) and/or a group allow-list
// (OIDC_ALLOWED_GROUPS, matched against the OIDC_GROUPS_CLAIM userinfo claim -
// default "groups"). Empty lists mean "anyone the IdP authenticates"; the two are
// OR-ed. Groups are the more portable, IdP-managed control, but the IdP must be
// configured to emit the claim in userinfo (e.g. a Keycloak "Group Membership"
// mapper with "Add to userinfo" enabled). `groups` is a de-facto convention, not a
// standard OIDC claim, which is why the claim name is configurable and may be a
// dotted path (e.g. "realm_access.roles") for IdPs that nest it.

const { fetch: fetchCmd } = require('undici');
const { readEnvValue, httpAgent, getBoolean } = require('./tools');
const packageData = require('../package.json');

const DEFAULT_GROUPS_CLAIM = 'groups';

const OIDC_ISSUER = readEnvValue('OIDC_ISSUER');
const OIDC_CLIENT_ID = readEnvValue('OIDC_CLIENT_ID');
const OIDC_CLIENT_SECRET = readEnvValue('OIDC_CLIENT_SECRET');
const OIDC_PROVIDER_NAME = readEnvValue('OIDC_PROVIDER_NAME') || 'SSO';
const OIDC_SCOPES = readEnvValue('OIDC_SCOPES') || null;
const OIDC_ALLOWED_USERS = readEnvValue('OIDC_ALLOWED_USERS') || null;
const OIDC_ALLOWED_GROUPS = readEnvValue('OIDC_ALLOWED_GROUPS') || null;
const OIDC_GROUPS_CLAIM = readEnvValue('OIDC_GROUPS_CLAIM') || DEFAULT_GROUPS_CLAIM;

// OIDC_FORCED: skip the local login screen entirely - auto-redirect to the OIDC
// provider and refuse local password/passkey login (SSO becomes the only way in).
// A safety net remains: if discovery fails at startup (IdP unreachable) OIDC is not
// usable, so the local login form is shown instead of a dead redirect.
// OIDC_LOGOUT: RP-initiated logout - on sign-out, redirect to the IdP's
// end_session_endpoint to terminate the IdP session too (not just the local cookie).
const OIDC_FORCED = getBoolean(readEnvValue('OIDC_FORCED'));
const OIDC_LOGOUT = getBoolean(readEnvValue('OIDC_LOGOUT'));

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

// Normalize a single group name: coerce to string, trim, and strip leading slashes
// so a configured "emailengine-admins" matches Keycloak's path-style
// "/emailengine-admins" regardless of the IdP's "Full group path" setting. Matching
// is case-sensitive because group names are identifiers.
function normalizeGroup(group) {
    return String(group == null ? '' : group)
        .trim()
        .replace(/^\/+/, '');
}

// Parse OIDC_ALLOWED_GROUPS (comma-separated group names) into a normalized list.
function parseGroupList(str) {
    return (str || '')
        .split(',')
        .map(normalizeGroup)
        .filter(group => group);
}

// Resolve a possibly-dotted claim path (e.g. "realm_access.roles") against a
// userinfo object.
function getNestedClaim(obj, path) {
    return String(path)
        .split('.')
        .reduce((cur, key) => (cur && typeof cur === 'object' ? cur[key] : undefined), obj);
}

// Read and normalize the groups claim from a userinfo response into an array of
// group names. The claim may be an array (the common case) or a single string.
function extractGroups(userinfo, groupsClaim) {
    let raw = getNestedClaim(userinfo || {}, groupsClaim || DEFAULT_GROUPS_CLAIM);
    if (raw === undefined || raw === null) {
        return [];
    }

    return (Array.isArray(raw) ? raw : [raw])
        .filter(group => typeof group === 'string')
        .map(normalizeGroup)
        .filter(group => group);
}

// True when the profile's email (or username fallback) matches the email/domain
// allow-list. Assumes the list is non-empty.
function matchesEmailAllowList(profile, allowList) {
    let email = ((profile && (profile.email || profile.username)) || '').trim().toLowerCase();
    if (!email) {
        return false;
    }

    let domain = email.indexOf('@') >= 0 ? email.split('@').pop() : null;

    return allowList.some(entry => (entry.type === 'domain' ? domain && entry.value === domain : entry.value === email));
}

// True when any of the profile's groups is in the group allow-list. Assumes the
// list is non-empty.
function matchesGroupAllowList(profile, allowGroups) {
    let groups = (profile && Array.isArray(profile.groups) && profile.groups) || [];
    if (!groups.length) {
        return false;
    }

    let owned = new Set(groups.map(normalizeGroup));
    return allowGroups.some(group => owned.has(group));
}

// Decide whether an authenticated OIDC user may access the admin panel. With no
// constraints configured (both allow-lists empty) anyone the IdP authenticates is
// allowed; otherwise the user must match the email allow-list OR the group
// allow-list.
function isAuthorized(profile, allowList, allowGroups) {
    let hasEmailRule = !!(allowList && allowList.length);
    let hasGroupRule = !!(allowGroups && allowGroups.length);

    if (!hasEmailRule && !hasGroupRule) {
        return true;
    }

    if (hasEmailRule && matchesEmailAllowList(profile, allowList)) {
        return true;
    }

    if (hasGroupRule && matchesGroupAllowList(profile, allowGroups)) {
        return true;
    }

    return false;
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
// cookie size limit - IdPs like Keycloak return large tokens/claim sets. Only the
// group names are carried so the per-request authorization re-check works.
function mapUserinfoProfile(userinfo, groupsClaim) {
    userinfo = userinfo || {};
    return {
        id: userinfo.sub,
        username: userinfo.email || userinfo.preferred_username || userinfo.sub,
        displayName: userinfo.name || userinfo.preferred_username || userinfo.email,
        email: userinfo.email,
        groups: extractGroups(userinfo, groupsClaim)
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

// Build an OIDC RP-initiated logout URL against the IdP's end_session_endpoint.
// id_token_hint is included when available so the IdP skips its logout-confirmation
// prompt; client_id + post_logout_redirect_uri (the latter must be registered at the
// IdP) let the IdP return the browser to the app afterwards. Returns null if no
// end_session_endpoint is known.
function buildLogoutUrl(endSessionEndpoint, options) {
    options = options || {};
    if (!endSessionEndpoint) {
        return null;
    }

    let url = new URL(endSessionEndpoint);
    if (options.idToken) {
        url.searchParams.set('id_token_hint', options.idToken);
    }
    if (options.clientId) {
        url.searchParams.set('client_id', options.clientId);
    }
    if (options.postLogoutRedirectUri) {
        url.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
    }
    return url.toString();
}

// Build a @hapi/bell custom OAuth2 provider from a validated discovery document.
function buildOidcBellProvider(discoveryDoc, options) {
    options = options || {};
    let scopes = parseScopes(options.scopes || OIDC_SCOPES);
    let groupsClaim = options.groupsClaim || OIDC_GROUPS_CLAIM;
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
            credentials.profile = mapUserinfoProfile(userinfo, groupsClaim);
        }
    };
}

module.exports = {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_PROVIDER_NAME,
    OIDC_ALLOWED_USERS,
    OIDC_ALLOWED_GROUPS,
    OIDC_GROUPS_CLAIM,
    OIDC_FORCED,
    OIDC_LOGOUT,
    USE_OIDC_AUTH,

    parseScopes,
    parseAllowList,
    parseGroupList,
    extractGroups,
    isAuthorized,
    getDiscoveryUrl,
    validateDiscoveryDocument,
    mapUserinfoProfile,
    fetchOidcDiscovery,
    buildLogoutUrl,
    buildOidcBellProvider
};
