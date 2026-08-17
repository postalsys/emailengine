'use strict';

// Shared token validation for the SMTP and IMAP-proxy submission servers. Both
// servers accept a 64-char hex API token as the password and apply the same
// checks (account binding, scope, permissions, IP allowlist). The logic lives here so the two
// auth handlers (lib/smtp-auth.js, lib/imap-proxy-auth.js) cannot drift apart -
// a token security-policy change is made once and applies to both surfaces.

const logger = require('./logger');
const tokens = require('./tokens');
const tokenPermissions = require('./token-permissions');
const tokenAuditLog = require('./token-audit-log');
const { SURFACE_GRANTS } = require('./api-routes/permission-map');
const { matchIp } = require('./utils/network');

// Reason-specific denial messages, shared verbatim by both auth handlers. The
// generic "failed to authenticate" fallback and any protocol-specific error
// decoration are left to each caller.
const REASON_MESSAGES = {
    username: 'Access denied, invalid username',
    scope: 'Access denied, invalid scope',
    ip: 'Access denied, traffic not accepted from this IP',
    permissions: 'Access denied, token permissions do not allow this'
};

/**
 * Validates a 64-char hex API token supplied as a server password.
 *
 * Performs the token lookup plus the account-binding, scope, permission and
 * IP-allowlist checks. Does NOT throw - the caller maps the returned reason to
 * its own protocol-specific error (SMTP and IMAP use different response shapes).
 *
 * @param {Object} opts
 * @param {String} opts.password - supplied password (candidate token)
 * @param {String} opts.account - username the client authenticated as
 * @param {String} opts.requiredScope - scope the token must hold ('smtp' | 'imap-proxy')
 * @param {String} opts.remoteAddress - client IP, checked against token restrictions
 * @returns {Promise<{authenticated: Boolean, reason: (null|'username'|'scope'|'permissions'|'ip')}>}
 */
async function validateAuthToken({ password, account, requiredScope, remoteAddress }) {
    if (!/^[0-9a-f]{64}$/i.test(password)) {
        return { authenticated: false, reason: null };
    }

    let tokenData;
    try {
        tokenData = await tokens.get(password, false, { log: true, remoteAddress });
    } catch (err) {
        logger.error({ msg: 'Failed to fetch token', err });
    }

    if (!tokenData) {
        return { authenticated: false, reason: null };
    }

    // Built before the first check that can refuse, for the same reason as the HTTP surface: a
    // trail that only held accepted logins would be silent about exactly the ones worth looking at.
    const auditEntry = {
        tokenId: tokenData.id,
        ip: remoteAddress || null,
        method: requiredScope,
        path: requiredScope,
        account
    };

    if (tokenData.account && tokenData.account !== account) {
        // Logged like the refusals below it, rather than only into the per-token trail: a credential
        // presented for someone else's account is the same class of event as a bad scope, and the
        // application log is the record that leaves the instance.
        logger.warn({
            msg: 'Trying to use a token bound to another account',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            requestedScope: requiredScope
        });
        tokenAuditLog.denied(auditEntry, 'username');
        return { authenticated: false, reason: 'username' };
    }

    if (tokenData.scopes && !tokenData.scopes.includes(requiredScope) && !tokenData.scopes.includes('*')) {
        logger.warn({
            msg: 'Trying to use invalid scope for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            requestedScope: requiredScope,
            scopes: tokenData.scopes
        });
        tokenAuditLog.denied(auditEntry, 'scope');
        return { authenticated: false, reason: 'scope' };
    }

    // Narrowing below the scope. Checked here rather than in each handler so a policy change cannot
    // land on one submission surface and miss the other, which is why this module exists.
    //
    // An unknown scope resolves to no operation, which denies: a surface this function does not know
    // how to describe must not be reachable by a narrowed token just because nobody mapped it.
    // Object.hasOwn rather than a bare lookup: SCOPE_OPERATIONS['__proto__'] would otherwise return
    // Object.prototype, and Object.values of that is an empty list - which would pass a
    // "does it hold every grant" loop vacuously. A surface nobody mapped must be refused, not waved
    // through, so an unknown scope resolves to no grants at all and denies below.
    const requiredGrants = Object.hasOwn(SURFACE_GRANTS, requiredScope) ? SURFACE_GRANTS[requiredScope] : null;

    // First refusal wins, so the reported reason names a grant the token actually lacks. An unmapped
    // surface has no grants to check, and check() with no operation denies a narrowed token on
    // UNCLASSIFIED - which is why this passes `null` through rather than skipping the loop.
    //
    // `action`/`group` land on the audit entry only in the refusal branch, and the accept path
    // leaves them null on purpose. These surfaces do not perform an operation: they admit a session
    // that may then exercise every grant the surface carries - five of them for the IMAP proxy - so
    // naming one of the five on an accepted login would report a request that was never made. A
    // refusal is the opposite case: exactly one grant decided it, and that one is worth recording.
    let permissionCheck = { allowed: true, reason: null, required: null };
    for (const operation of requiredGrants || [null]) {
        permissionCheck = tokenPermissions.check({ tokenData, operation });
        if (!permissionCheck.allowed) {
            Object.assign(auditEntry, { action: operation && operation.action, group: operation && operation.group });
            break;
        }
    }

    if (!permissionCheck.allowed) {
        logger.warn({
            msg: 'Token permissions do not allow this operation',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            requestedScope: requiredScope,
            reason: permissionCheck.reason,
            required: permissionCheck.required
        });
        tokenAuditLog.denied(auditEntry, permissionCheck.reason);
        return { authenticated: false, reason: 'permissions' };
    }

    if (tokenData.restrictions && tokenData.restrictions.addresses && !matchIp(remoteAddress, tokenData.restrictions.addresses)) {
        logger.warn({
            msg: 'Trying to use invalid IP for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            remoteAddress,
            addressAllowlist: tokenData.restrictions.addresses
        });
        tokenAuditLog.denied(auditEntry, 'ip');
        return { authenticated: false, reason: 'ip' };
    }

    tokenAuditLog.allowed(auditEntry);

    return { authenticated: true, reason: null };
}

module.exports = { validateAuthToken, REASON_MESSAGES };
