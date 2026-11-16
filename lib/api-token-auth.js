'use strict';

// The decision of the `api-token` auth strategy: which credential a REST request carries and
// whether it may make this request. Moved out of workers/api.js, which cannot be loaded by a test
// (it boots a server on require), so every branch here is unit tested in
// test/api-token-auth-test.js instead of only being reachable through a live server.
//
// The order of the checks is part of the contract: token resolved, scope, permissions, account,
// restrictions. Each refusal is logged and written to the token's audit trail before it is thrown,
// and the accepted path writes one audit row (except at the MCP door, see below).
//
// Everything that does I/O comes in through createApiTokenValidator() so a test can stand it in.

const Boom = require('@hapi/boom');
const { REDIS_PREFIX } = require('./consts');
const { isEndedSession, matcher } = require('./tools');
const { matchIp } = require('./utils/network');
const tokenPermissions = require('./token-permissions');
const { routeGrant, perRequestSurfaceAdmits, sessionTokenAdmits } = require('./api-routes/permission-map');
const { boundRouteBinding } = require('./api-routes/account-binding');
const { mcpOptions } = require('./api-routes/route-metadata');

/**
 * Builds the `validate` function of the api-token strategy.
 *
 * @param {Object} deps
 * @param {Object} deps.settings - settings store (`get()`)
 * @param {Object} deps.tokens - token store (`get()`, `validateSessionToken()`)
 * @param {Object} deps.tokenAuditLog - per-token audit trail (`allowed()`, `denied()`)
 * @param {Object} deps.redis - Redis client, for the template ownership lookup
 * @param {Function} deps.checkRateLimit - async (key, count, allowed, windowSize) => { success, allowed, count, ttl }
 * @param {Function} deps.sessionPasswordVersion - async () => the password version sessions are stamped with
 * @param {Function} deps.sessionAdmitted - (session) => whether the session's SSO provider still admits its user
 * @param {String[]} [deps.adminAccessAddresses] - EENGINE_ADMIN_ACCESS_ADDRESSES, the admin perimeter
 * @param {Object} deps.logger
 * @returns {Function} async (request, token) => { isValid, credentials, artifacts }
 */
function createApiTokenValidator({
    settings,
    tokens,
    tokenAuditLog,
    redis,
    checkRateLimit,
    sessionPasswordVersion,
    sessionAdmitted,
    adminAccessAddresses,
    logger
}) {
    async function authenticateSessionToken(request, token) {
        // seems like a session token
        const session = (request.state && request.state.ee) || {};

        // "Log out all sessions" has to reach this credential too. The session strategy's
        // own passwordVersion check never runs here - an API request authenticates with
        // this strategy and only reads the cookie for its `sid` - and validateSessionToken()
        // slides the token's TTL on every use, so a cookie-plus-token pair left behind on a
        // device the operator no longer controls stayed usable indefinitely after the click
        // that was supposed to end every session. Same predicate as the session strategy,
        // including its "only when a local password exists" condition, so a session stamped
        // before this shipped is not force-expired.
        // The same goes for an SSO user the identity provider's allow-list no longer admits
        if (isEndedSession(await sessionPasswordVersion(), session) || !sessionAdmitted(session)) {
            logger.warn({
                msg: 'Session token presented for an ended session',
                account: request.params.account,
                method: request.route.method,
                path: request.route.path
            });
            throw Boom.unauthorized('Session has ended');
        }

        let isValidSessionToken = await tokens.validateSessionToken(session.sid, token, request.params.account, 900);
        if (!isValidSessionToken) {
            // not a live session token, the token store decides
            return null;
        }

        // The credential was minted for a page inside the admin perimeter, so it is
        // held to that perimeter too. The /v1 path it is presented on is not an admin
        // path, so the request-level check above did not apply.
        if (adminAccessAddresses && adminAccessAddresses.length && !matchIp(request.app.ip, adminAccessAddresses)) {
            logger.warn({
                msg: 'Session token presented from outside the admin address list',
                account: request.params.account,
                remoteAddress: request.app.ip,
                method: request.route.method,
                path: request.route.path
            });
            throw Boom.forbidden('Unauthorized address');
        }

        // A session token is bound to the account whose page minted it (checked above,
        // against request.params.account), but it used to reach every api-tagged route
        // naming that account - it never met the permission model at all. It lives in
        // the page HTML where any script on the page can read it, which the HttpOnly
        // session cookie does not, so it must not be the wider of the two credentials:
        // SESSION_TOKEN_GRANTS is what the browser actually calls, and everything else
        // - the account edit that rewrites a webhook target, the route that hands out
        // the account's provider access token - is refused here.
        if (!sessionTokenAdmits(routeGrant(request.route), { account: request.params.account })) {
            logger.warn({
                msg: 'Session token used outside the message browser grants',
                account: request.params.account,
                method: request.route.method,
                path: request.route.path
            });
            throw Boom.forbidden('Unauthorized permission');
        }

        // The credential is bounded by a grant list rather than by a permissions
        // record, so anything that keys off "is this token narrowed" cannot see it -
        // assertNoNetworkOverride() is the one that matters, since `send/submit` is
        // admitted above and a submit payload's `proxy` decides where the session
        // carrying the account's SMTP credential connects.
        request.app.sessionToken = true;

        return {
            isValid: true,
            credentials: {},
            artifacts: {}
        };
    }

    async function loadTokenData(request, token) {
        let tokenData;
        try {
            // The last-use record is skipped on MCP-dispatched injects: the outer /mcp
            // request just wrote the same credential's entry, and the second write would
            // only repeat it
            tokenData = await tokens.get(token, false, { log: !request.app.mcpInternal && !request.app.authRecheck, remoteAddress: request.app.ip });
        } catch (err) {
            // A thrown Boom reaches the client the way the scope and permission refusals
            // below do (the api-token scheme does not catch it), so the reason travels as a
            // machine-readable code - UnknownToken, ExpiredToken, InvalidToken - while the
            // message stays the generic one the scheme itself would have sent. The scheme
            // name keeps the WWW-Authenticate header the plugin's own refusal carries.
            let error = Boom.unauthorized('Bad token', 'Bearer');
            if (err.code) {
                error.output.payload.code = err.code;
            }
            throw error;
        }

        // Bind the token hash (id) to the request logger so it is included in the per-request
        // log entry, allowing API requests to be correlated to the token that made them.
        if (request.logger && typeof request.logger.setBindings === 'function') {
            request.logger.setBindings({ tokenId: tokenData.id, tokenAccount: tokenData.account || null });
        }

        return tokenData;
    }

    function assertScope(request, tokenData, scopes, grant, auditEntry) {
        // `mcp` and `mcp-manage` are surface scopes like `smtp`: each admits exactly the API
        // operations its half of the MCP tool set wraps (perRequestSurfaceAdmits over
        // SURFACE_GRANTS), and only on requests the MCP endpoint dispatched itself -
        // request.app.mcpInternal is set by lib/mcp/inject.js and cannot be set from the
        // network, so an mcp-scoped token presented to plain REST is refused here like any
        // other missing scope.
        const mcpSurfaceAdmits = scopes.includes('api') && !!request.app.mcpInternal && perRequestSurfaceAdmits(tokenData.scopes, grant);

        const hasRequiredScope =
            !scopes.length || !tokenData.scopes || tokenData.scopes.includes('*') || tokenData.scopes.some(entry => scopes.includes(entry)) || mcpSurfaceAdmits;

        if (hasRequiredScope) {
            return;
        }

        // failed scope validation
        logger.warn({
            msg: 'Trying to use invalid scope for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            requestedScope: scopes.join(', '),
            tokenScopes: tokenData.scopes
        });

        tokenAuditLog.denied(auditEntry, 'scope');

        let error = Boom.forbidden('Unauthorized scope');
        error.output.payload.requestedScope = scopes.join(', ');
        throw error;
    }

    function assertPermission(tokenData, grant, auditEntry, mcpEndpoint) {
        // Narrowing below the scope. Runs after the scope check and before the account binding,
        // so the order is: token resolved, scope, permissions, account, restrictions.
        //
        // Before the account switch on purpose - that switch reads the account from the query or
        // from a Redis membership check for the three /v1/templates special cases, and none of
        // that should happen for a request the permissions already refuse.
        //
        // Only subtracts: a token with no `permissions` field takes the allowed path, which is
        // every token issued before this shipped.
        // The MCP door defers this check: its own routeGrant() resolves to no group on
        // purpose, and the operation a narrowed token must hold a grant for is the injected
        // inner request, which re-runs this strategy with the real route.
        const permissionCheck = mcpEndpoint ? { allowed: true } : tokenPermissions.check({ tokenData, operation: grant });
        if (permissionCheck.allowed) {
            return;
        }

        logger.warn({
            msg: 'Token permissions do not allow this operation',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account: auditEntry.account,
            reason: permissionCheck.reason,
            required: permissionCheck.required
        });

        let error = Boom.forbidden('Unauthorized permission');
        // Mirrors how the scope failure above attaches requestedScope: an agent that gets a
        // 403 needs to know WHICH grant it lacked, not just that it lacked one.
        // A refused call is the interesting record, so it is logged before the throw
        tokenAuditLog.denied(auditEntry, permissionCheck.reason);

        error.output.payload.requiredPermission = permissionCheck.required;
        throw error;
    }

    // The account a bound token's request addresses. Routes that carry an account component
    // somewhere other than their URL params, named by lib/api-routes/account-binding.js. The
    // table is shared with the MCP tool registry, which has to advertise exactly the tools a bound
    // credential can actually call; the resolution of each kind stays here, where the request is.
    async function resolveRequestAccount(request, tokenData, queryAccount) {
        switch (boundRouteBinding(request.method, request.route.path)) {
            case 'query':
                // `/v1/tokens` is in the table because it replaced
                // GET /v1/tokens/account/{account}, which carried the account in the path and so
                // reached a bound token's own tokens through the default branch below - as its
                // deprecated alias registration still does. Both stay under the same rule as
                // everything else: the argument has to name the token's own account, and
                // omitting it still refuses, because a bound credential must not enumerate the
                // instance.
                return queryAccount;

            case 'record': {
                let isAccountTemplate =
                    request.params.template && (await redis.sismember(`${REDIS_PREFIX}tpl:${tokenData.account}:i`, request.params.template));
                return isAccountTemplate ? tokenData.account : undefined;
            }

            case 'token':
                request.app.enforceAccount = tokenData.account;
                return tokenData.account;

            default:
                return request.params && request.params.account;
        }
    }

    async function assertAccountBinding(request, tokenData, queryAccount, auditEntry, mcpEndpoint) {
        if (!tokenData.account) {
            return;
        }

        if (mcpEndpoint) {
            // The door names no account, so the binding cannot be checked here; it is
            // enforced on every injected inner request, which does name one. Parked on the
            // request so the MCP layer can seed resources/list and the agent instructions
            // for a bound credential.
            request.app.mcpBoundAccount = tokenData.account;
            return;
        }

        // account token
        const accountIdSource = await resolveRequestAccount(request, tokenData, queryAccount);

        if (accountIdSource !== tokenData.account) {
            logger.warn({
                msg: 'Trying to use invalid account for a token',
                tokenAccount: tokenData.account,
                tokenId: tokenData.id,
                account: auditEntry.account
            });

            tokenAuditLog.denied(auditEntry, 'account');

            let error = Boom.forbidden('Unauthorized account');
            throw error;
        }
    }

    function assertAddressRestriction(request, tokenData, auditEntry) {
        if (!tokenData.restrictions.addresses || matchIp(request.app.ip, tokenData.restrictions.addresses)) {
            return;
        }

        logger.warn({
            msg: 'Trying to use invalid IP for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account: auditEntry.account,
            remoteAddress: request.app.ip,
            addressAllowlist: tokenData.restrictions.addresses
        });

        tokenAuditLog.denied(auditEntry, 'address');

        let error = Boom.forbidden('Unauthorized address');
        error.output.payload.remoteAddress = request.app.ip;
        throw error;
    }

    function assertReferrerRestriction(request, tokenData, auditEntry) {
        const referrers = tokenData.restrictions.referrers;
        if (!referrers || !referrers.length || matcher(referrers, request.headers.referer)) {
            return;
        }

        logger.warn({
            msg: 'Trying to use invalid referer for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account: auditEntry.account,
            referer: request.headers.referer,
            referrerAllowlist: referrers
        });

        tokenAuditLog.denied(auditEntry, 'referrer');

        let error = Boom.forbidden('Unauthorized referrer');
        throw error;
    }

    async function assertRateLimit(request, tokenData, auditEntry) {
        // Skipped on MCP-dispatched injects like the last-use record above: the outer
        // /mcp request already spent one unit of this token's budget at the door, and
        // counting the inner request too silently halved every restricted token's
        // effective limit over MCP.
        // A re-check of an open stream (request.app.authRecheck) is not a request either.
        if (!tokenData.restrictions.rateLimit || request.app.mcpInternal || request.app.authRecheck) {
            return;
        }

        let rateLimit = await checkRateLimit(
            `api:${tokenData.id}`,
            1,
            tokenData.restrictions.rateLimit.maxRequests,
            tokenData.restrictions.rateLimit.timeWindow
        );

        if (rateLimit.success) {
            request.app.rateLimitHeaders = {
                'X-RateLimit-Limit': rateLimit.allowed,
                'X-RateLimit-Reset': Math.ceil(rateLimit.ttl),
                'X-RateLimit-Remaining': rateLimit.allowed - rateLimit.count
            };
            return;
        }

        logger.warn({ msg: 'Rate limited', token: tokenData.id, rateLimit });
        tokenAuditLog.denied(auditEntry, 'rateLimit');

        let error = Boom.tooManyRequests('Rate limit exceeded');
        error.output.payload.ttl = Math.ceil(rateLimit.ttl);
        error.output.headers = {
            'X-RateLimit-Limit': rateLimit.allowed,
            'X-RateLimit-Reset': Math.ceil(rateLimit.ttl),
            // The conventional header for a 429, so a generic HTTP client backs
            // off without knowing about the ttl field in the body
            'Retry-After': Math.ceil(rateLimit.ttl)
        };
        throw error;
    }

    // In this order: address, referrer, and the rate limit last, so a request refused for
    // another reason spends nothing of the token's budget
    async function assertRestrictions(request, tokenData, auditEntry) {
        if (!tokenData.restrictions) {
            return;
        }

        assertAddressRestriction(request, tokenData, auditEntry);
        assertReferrerRestriction(request, tokenData, auditEntry);
        await assertRateLimit(request, tokenData, auditEntry);
    }

    return async function validateApiToken(request, token) {
        let disableTokens = await settings.get('disableTokens');
        if (disableTokens && (!token || token === 'preauth')) {
            // tokens checks are disabled, allow all if token is not set.
            // `preauth` marks a caller that presented NO credential at all - routes that hand
            // out lasting privilege have to be able to tell that apart from a real token.
            return {
                isValid: true,
                credentials: { preauth: true },
                artifacts: {}
            };
        }

        const scopes = routeScopes(request.route);

        // The MCP endpoint (lib/api-routes/mcp-routes.js) is a protocol multiplexer with no
        // operation of its own: every tools/call becomes an injected API request that runs
        // this whole strategy again against the route it actually targets. Several checks
        // below defer to that inner request, and each says so where it does.
        const mcpEndpoint = !!mcpOptions(request.route).endpoint;

        // Session tokens are refused at the MCP door rather than half-admitted: a session
        // credential carries no bearer token the injected inner requests could forward, so
        // it could initialize and list tools but every tools/call would die on an inner 401.
        // A missing token throws a TypeError here, as it always has: with tokens enabled the
        // scheme never calls this without one.
        if (token.startsWith('sess_') && scopes.includes('api') && !mcpEndpoint) {
            const sessionResult = await authenticateSessionToken(request, token);
            if (sessionResult) {
                return sessionResult;
            }
        }

        const tokenData = await loadTokenData(request, token);
        const grant = routeGrant(request.route);
        const queryAccount = requestQueryAccount(request);
        const auditEntry = buildAuditEntry(request, tokenData, grant, queryAccount);

        // Every refusal from here on writes its audit row before it throws
        assertScope(request, tokenData, scopes, grant, auditEntry);
        assertPermission(tokenData, grant, auditEntry, mcpEndpoint);
        await assertAccountBinding(request, tokenData, queryAccount, auditEntry, mcpEndpoint);
        await assertRestrictions(request, tokenData, auditEntry);

        // The one point every accepted token request passes. "allowed" means the credential was
        // accepted, not that the request succeeded: this runs in the auth strategy, before
        // payload validation and the handler, so a call recorded here can still end in a 400 or
        // a 404. That is the right boundary for a credential trail - it answers what the token
        // was permitted to attempt.
        //
        // Except at the MCP door, where "allowed" describes no operation at all (the permission
        // check above was deferred): every tool call writes its own row as the injected API
        // request it becomes, and a second content-free row per call would halve the capped
        // audit retention for MCP traffic. Denials at the door are still recorded above.
        //
        // Nor for the periodic re-check of an open change stream, which asks whether the token still
        // admits a request it already accepted.
        if (!mcpEndpoint && !request.app.authRecheck) {
            tokenAuditLog.allowed(auditEntry);
        }

        return { isValid: true, credentials: { token }, artifacts: tokenData };
    };
}

// Every scope a route names admits a token that holds it. Single-scope routes behave
// exactly as before; the MCP endpoint is the one route naming two (`scope:api` and
// `scope:mcp`), so both kinds of credential can open it.
function routeScopes(route) {
    let tags = (route && route.settings && route.settings.tags) || [];
    return tags.filter(tag => tag === 'api' || /^scope:/.test(tag)).map(tag => tag.replace(/^scope:/, ''));
}

// This strategy runs before route validation, so `request.query` is whatever the client
// sent: a repeated `?account=` arrives as an array. Only a string can name an account,
// and this value is persisted into the audit log, so anything else is not one.
function requestQueryAccount(request) {
    return request.query && typeof request.query.account === 'string' ? request.query.account : null;
}

// Shared by every audit entry, so an allow and a deny describe the same request.
// Built before the first check that can refuse: a rejection is the strongest signal of
// credential misuse there is, and a trail that only held the calls that succeeded would
// be silent about exactly the ones worth looking at.
function buildAuditEntry(request, tokenData, grant, queryAccount) {
    return {
        tokenId: tokenData.id,
        ip: request.app.ip,
        method: request.route.method,
        path: request.route.path,
        action: grant.action,
        group: grant.group,
        // The account the REQUEST addressed, which is not always the one in the path: the
        // routes that take it as a query argument are the ones a bound token gets refused
        // on, and falling straight through to the token's own account recorded a
        // cross-account attempt against the account it was entitled to reach - the opposite
        // of what the entry exists to show. The token's account is still the answer for the
        // routes that name no account at all.
        //
        // The refusals log this field rather than re-deriving it, so the application
        // log and the audit row cannot disagree about which account a denial concerned.
        account: (request.params && request.params.account) || queryAccount || tokenData.account || null
    };
}

module.exports = { createApiTokenValidator };
