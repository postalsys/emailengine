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
const { ACTION, GROUP } = require('./api-routes/permission-map');
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

// Every grant a surface can exercise once it has authenticated, not the one it nominally performs.
// A token is admitted only if it holds ALL of them, because these surfaces are checked once at
// login and never again.
//
// SMTP really is one operation: the server accepts a message and queues it, so `send` on `submit`
// describes the whole session. A token narrowed to `read` is therefore refused, which is the
// guarantee it looks like it has.
//
// The IMAP proxy is not. After onAuth returns, lib/imapproxy/imap-server.js pipes the two sockets
// straight together, so the session can do anything IMAP can: STORE \Deleted and EXPUNGE, APPEND,
// CREATE, DELETE and RENAME folders. Checking it as `{read, message}` would admit a token narrowed
// to reading and then hand it a session that can destroy the mailbox - a promise the surface cannot
// keep. So it asks for everything it could do, and a token that lacks any of it is refused at login
// rather than admitted under a guarantee that does not hold. Per-command filtering inside the proxy
// is the alternative, and the only thing that would let a genuinely read-only token connect.
const SCOPE_OPERATIONS = {
    smtp: [{ action: ACTION.SEND, group: GROUP.SUBMIT }],
    'imap-proxy': [
        { action: ACTION.READ, group: GROUP.MESSAGE },
        { action: ACTION.WRITE, group: GROUP.MESSAGE },
        { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE },
        { action: ACTION.WRITE, group: GROUP.MAILBOX },
        { action: ACTION.DESTRUCTIVE, group: GROUP.MAILBOX }
    ]
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

    if (tokenData.account && tokenData.account !== account) {
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
    const requiredGrants = Object.hasOwn(SCOPE_OPERATIONS, requiredScope) ? SCOPE_OPERATIONS[requiredScope] : null;

    // The surface stands in for method and path: there is no request line here, and "smtp" says more
    // about what happened than a synthesized one would.
    const auditEntry = {
        tokenId: tokenData.id,
        ip: remoteAddress || null,
        method: requiredScope,
        path: requiredScope,
        account
    };

    // First refusal wins, so the reported reason names a grant the token actually lacks. An unmapped
    // surface has no grants to check, and check() with no operation denies a narrowed token on
    // UNCLASSIFIED - which is why this passes `null` through rather than skipping the loop.
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
        tokenAuditLog.record(Object.assign({ status: 'denied', reason: permissionCheck.reason }, auditEntry));
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
        return { authenticated: false, reason: 'ip' };
    }

    tokenAuditLog.record(Object.assign({ status: 'allowed' }, auditEntry));

    return { authenticated: true, reason: null };
}

module.exports = { validateAuthToken, REASON_MESSAGES };
