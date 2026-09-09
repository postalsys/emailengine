'use strict';

// Unit tests for the IMAP proxy authentication handler (lib/imap-proxy-auth.js,
// extracted from lib/imapproxy/imap-server.js). Auth-bypass surface: covers the
// rejection paths (bad password, token account/scope/IP binding), the accept
// paths (global password and a valid scoped token), and the IMAP-proxy-specific
// rejection of API-only accounts (ACCOUNTDISABLED).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createImapProxyAuthHandler, classifyCredentialFailure, isImapResponseError, toImapResponseError } = require('../lib/imap-proxy-auth');
const { AUTH_FAILURE_LIMIT } = require('../lib/auth-token');
const { trackedWindow, exhaustBudget } = require('./helpers/auth-throttle');
const { oauth2Apps } = require('../lib/oauth2-apps');
const tokens = require('../lib/tokens');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const ACCOUNT = 'imap-proxy-acct';
const API_ACCOUNT = 'imap-proxy-api-acct';

const authenticate = createImapProxyAuthHandler({ call: async () => ({}) });
const session = (overrides = {}) => Object.assign({ remoteAddress: '127.0.0.1' }, overrides);

let proxyToken;
let apiScopeToken;
let ipRestrictedToken;
let readOnlyToken;
let fullMailToken;
let apiAppId;
let prevPassword;
const accountKeys = [];

async function seedAccount(account, fields) {
    const key = `${REDIS_PREFIX}iad:${account}`;
    await redis.hset(key, Object.assign({ account }, fields));
    accountKeys.push(key);
}

test.before(async () => {
    prevPassword = await settings.get('imapProxyServerPassword');

    proxyToken = await tokens.provision({ account: ACCOUNT, scopes: ['imap-proxy'], description: 'proxy test', nolog: true });
    apiScopeToken = await tokens.provision({ account: ACCOUNT, scopes: ['api'], description: 'proxy wrong scope', nolog: true });
    // The proxy is checked once at LOGIN and then pipes the sockets straight together, so a token
    // narrowed to reading would get a session that can EXPUNGE and delete folders. It is refused at
    // login instead, which is the only honest answer while there is no per-command gate.
    readOnlyToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['imap-proxy'],
        permissions: { actions: ['read'] },
        description: 'proxy read-only permissions',
        nolog: true
    });
    fullMailToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['imap-proxy'],
        permissions: { groups: ['message', 'mailbox'] },
        description: 'proxy full mail permissions',
        nolog: true
    });
    ipRestrictedToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['imap-proxy'],
        restrictions: { addresses: ['10.0.0.0/8'] },
        description: 'proxy ip restricted',
        nolog: true
    });

    // A plain IMAP account (accept paths).
    await seedAccount(ACCOUNT, { imap: JSON.stringify({ host: 'imap.test', port: 993, secure: true }) });

    // An API-only account: references an app whose baseScopes === 'api'.
    const app = await oauth2Apps.create({ provider: 'gmail', name: 'API app', baseScopes: 'api', clientId: 'cid', clientSecret: 'csecret', enabled: true });
    apiAppId = app.id;
    await seedAccount(API_ACCOUNT, { oauth2: JSON.stringify({ provider: apiAppId, auth: { user: 'user@example.com' } }) });
});

registerRedisTeardown(redis, async () => {
    for (const tok of [proxyToken, apiScopeToken, ipRestrictedToken, readOnlyToken, fullMailToken]) {
        if (tok) {
            try {
                await tokens.delete(tok);
            } catch (err) {
                // ignore
            }
        }
    }
    if (apiAppId) {
        try {
            await oauth2Apps.del(apiAppId);
        } catch (err) {
            // ignore
        }
    }
    for (const key of accountKeys) {
        try {
            await redis.del(key);
        } catch (err) {
            // ignore
        }
    }
    try {
        await settings.set('imapProxyServerPassword', prevPassword || '');
    } catch (err) {
        // ignore
    }
});

test('IMAP proxy auth handler', async t => {
    await t.test('rejects a wrong non-token password', async () => {
        await settings.set('imapProxyServerPassword', '');
        await assert.rejects(
            () => authenticate({ username: ACCOUNT, password: 'nope' }, session()),
            err => {
                assert.strictEqual(err.serverResponseCode, 'AUTHENTICATIONFAILED');
                return true;
            }
        );
    });

    await t.test('rejects a well-formed but unknown token', async () => {
        await assert.rejects(
            () => authenticate({ username: ACCOUNT, password: 'a'.repeat(64) }, session()),
            err => {
                assert.strictEqual(err.serverResponseCode, 'AUTHENTICATIONFAILED');
                return true;
            }
        );
    });

    await t.test('rejects a token bound to a different account', async () => {
        await assert.rejects(() => authenticate({ username: 'someone-else', password: proxyToken }, session()), /invalid username/);
    });

    await t.test('rejects a token without the imap-proxy scope', async () => {
        await assert.rejects(() => authenticate({ username: ACCOUNT, password: apiScopeToken }, session()), /invalid scope/);
    });

    await t.test('rejects a token from a disallowed IP', async () => {
        await assert.rejects(
            () => authenticate({ username: ACCOUNT, password: ipRestrictedToken }, session({ remoteAddress: '127.0.0.1' })),
            /traffic not accepted from this IP/
        );
    });

    await t.test('accepts the configured global proxy password', async () => {
        await settings.set('imapProxyServerPassword', 'global-proxy-pass');
        try {
            const { accountData } = await authenticate({ username: ACCOUNT, password: 'global-proxy-pass' }, session());
            assert.strictEqual(accountData.account, ACCOUNT);
        } finally {
            await settings.set('imapProxyServerPassword', '');
        }
    });

    await t.test('rejects a token narrowed below what an IMAP session can do', async () => {
        // Holds the imap-proxy scope, so only the permission check stands between this credential and
        // a session that could STORE \\Deleted, EXPUNGE and delete folders. Admitting it as
        // "read-only" would be a guarantee the surface cannot keep.
        await assert.rejects(() => authenticate({ username: ACCOUNT, password: readOnlyToken }, session()), /permissions do not allow/);
    });

    await t.test('accepts a valid scoped token bound to the account', async () => {
        const { accountData } = await authenticate({ username: ACCOUNT, password: proxyToken }, session());
        assert.strictEqual(accountData.account, ACCOUNT);
    });

    await t.test('accepts a narrowed token that holds everything the session can exercise', async () => {
        // Narrowed to the two mail groups with every action, which is exactly what the proxy asks
        // for - so the narrowing is real (it cannot send, export, or touch settings) without being a
        // promise about what it does inside the IMAP session
        const { accountData } = await authenticate({ username: ACCOUNT, password: fullMailToken }, session());
        assert.strictEqual(accountData.account, ACCOUNT);
    });

    await t.test('rejects API-only accounts with ACCOUNTDISABLED', async () => {
        await settings.set('imapProxyServerPassword', 'global-proxy-pass');
        try {
            await assert.rejects(
                () => authenticate({ username: API_ACCOUNT, password: 'global-proxy-pass' }, session()),
                err => {
                    assert.strictEqual(err.serverResponseCode, 'ACCOUNTDISABLED');
                    return true;
                }
            );
        } finally {
            await settings.set('imapProxyServerPassword', '');
        }
    });
});

test('IMAP proxy auth failure throttle', async t => {
    // TEST-NET-3 addresses, never a real client; one per case so the counters cannot interfere
    await t.test('a refused login is recorded against the client address and username', async t => {
        const ip = '203.0.113.21';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);

        await assert.rejects(() => authenticate({ username: ACCOUNT, password: 'nope' }, session({ remoteAddress: ip })));

        assert.strictEqual(await redis.get(windowKey), '1');
    });

    await t.test('an accepted login spends nothing', async t => {
        const ip = '203.0.113.22';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);

        const { accountData } = await authenticate({ username: ACCOUNT, password: proxyToken }, session({ remoteAddress: ip }));
        assert.strictEqual(accountData.account, ACCOUNT);

        assert.strictEqual(await redis.get(windowKey), null);
    });

    await t.test('a valid credential is refused once the budget is spent', async t => {
        const ip = '203.0.113.23';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);
        await exhaustBudget(windowKey);

        await assert.rejects(
            () => authenticate({ username: ACCOUNT, password: proxyToken }, session({ remoteAddress: ip })),
            err => {
                assert.match(err.message, /Too many failed authentication attempts/);
                assert.strictEqual(err.serverResponseCode, 'AUTHENTICATIONFAILED');
                assert.strictEqual(err.responseStatus, 'NO');
                return true;
            }
        );

        assert.strictEqual(await redis.get(windowKey), String(AUTH_FAILURE_LIMIT), 'a throttled attempt is not evaluated and not counted');
    });

    await t.test('the budget is per address: another address is unaffected', async t => {
        await exhaustBudget(await trackedWindow(t, '203.0.113.24', ACCOUNT));

        const { accountData } = await authenticate({ username: ACCOUNT, password: proxyToken }, session({ remoteAddress: '203.0.113.25' }));
        assert.strictEqual(accountData.account, ACCOUNT);
    });

    await t.test('the API-only refusal is about the account, not the credential, and spends nothing', async t => {
        const ip = '203.0.113.26';
        const windowKey = await trackedWindow(t, ip, API_ACCOUNT);

        await settings.set('imapProxyServerPassword', 'global-proxy-pass');
        try {
            await assert.rejects(
                () => authenticate({ username: API_ACCOUNT, password: 'global-proxy-pass' }, session({ remoteAddress: ip })),
                err => err.serverResponseCode === 'ACCOUNTDISABLED'
            );
        } finally {
            await settings.set('imapProxyServerPassword', '');
        }

        assert.strictEqual(await redis.get(windowKey), null);
    });
});

// One authentication server serves every account on the instance, so its 429 or 503 must not reach
// a desktop mail client as a rejected password - the user retypes a working credential and the
// client keeps the login it was told was wrong. The status arrives in the `authRequest` record
// resolveCredentials() attaches, never on err.statusCode, which is read further up as the status
// of the request EmailEngine is itself serving.
test('IMAP proxy credential failure classification', async t => {
    await t.test('a throttled authentication server is a temporary failure', () => {
        const err = classifyCredentialFailure(
            Object.assign(new Error('Invalid response: 429 Too Many Requests'), { code: 'HTTPRequestError', authRequest: { status: 429 } })
        );

        assert.strictEqual(err.authenticationFailed, undefined, 'nothing refused the credential');
        assert.strictEqual(err.serverResponseCode, 'UNAVAILABLE');
        assert.strictEqual(err.responseStatus, 'NO');
    });

    await t.test('an authentication server 5xx is a temporary failure too', () => {
        const err = classifyCredentialFailure(
            Object.assign(new Error('Invalid response: 503 Service Unavailable'), { code: 'HTTPRequestError', authRequest: { status: 503 } })
        );

        assert.strictEqual(err.authenticationFailed, undefined);
        assert.strictEqual(err.serverResponseCode, 'UNAVAILABLE');
    });

    await t.test('an unreachable authentication server is a temporary failure', () => {
        const err = classifyCredentialFailure(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));

        assert.strictEqual(err.serverResponseCode, 'UNAVAILABLE');
        assert.strictEqual(err.responseStatus, 'NO');
    });

    await t.test('a refused account is still an authentication failure', () => {
        const err = classifyCredentialFailure(
            Object.assign(new Error('Invalid response: 401 Unauthorized'), { code: 'HTTPRequestError', authRequest: { status: 401 } })
        );

        assert.strictEqual(err.authenticationFailed, true);
        assert.strictEqual(err.serverResponseCode, 'AUTHENTICATIONFAILED');
        assert.strictEqual(err.responseStatus, 'NO');
    });

    await t.test('both failures are answered on the wire, neither as BAD', () => {
        // imap-core renders an error with no `response` as BAD, which counts against the
        // connection's bad-command budget instead of telling the client anything.
        for (let failure of [
            Object.assign(new Error('Invalid response: 503 Service Unavailable'), { statusCode: 503 }),
            Object.assign(new Error('Invalid response: 403 Forbidden'), { statusCode: 403 })
        ]) {
            const tagged = classifyCredentialFailure(failure);
            assert.ok(isImapResponseError(tagged), 'the proxy must answer this itself');

            const response = toImapResponseError(tagged);
            assert.strictEqual(response.response, 'NO');
            assert.ok(response.message.startsWith(`[${tagged.serverResponseCode}] `), 'the response code rides in brackets');
        }
    });

    await t.test('an internal fault is not answered as an IMAP response', () => {
        assert.strictEqual(isImapResponseError(new Error('Missing or disabled OAuth2 app')), false);
    });
});
