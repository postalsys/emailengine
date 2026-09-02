'use strict';

// Unit tests for the SMTP submission-server authentication handler
// (lib/smtp-auth.js, extracted from workers/smtp.js). This is an auth-bypass
// surface: a regression could let unauthorized clients relay mail. Covers the
// rejection paths (auth disabled, bad password, token account/scope/IP binding)
// and the accept paths (global password and a valid scoped token).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createSmtpAuthHandler, createSmtpAccountResolver } = require('../lib/smtp-auth');
const { AUTH_FAILURE_LIMIT } = require('../lib/auth-token');
const { trackedWindow, exhaustBudget } = require('./helpers/auth-throttle');
const tokens = require('../lib/tokens');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const ACCOUNT = 'smtp-auth-acct';
const OTHER_ACCOUNT = 'smtp-auth-acct-2';
const accountCache = new Map();
const onAuth = createSmtpAuthHandler({ accountCache, call: async () => ({}) });

const session = (overrides = {}) => Object.assign({ eeAuthEnabled: true, remoteAddress: '127.0.0.1' }, overrides);

let smtpToken;
let apiScopeToken;
let ipRestrictedToken;
let readOnlyToken;
let sendPermittedToken;
let prevSmtpPassword;
const accountKeys = [];

async function seedAccount(account) {
    const key = `${REDIS_PREFIX}iad:${account}`;
    await redis.hset(key, 'account', account);
    accountKeys.push(key);
}

test.before(async () => {
    prevSmtpPassword = await settings.get('smtpServerPassword');
    smtpToken = await tokens.provision({ account: ACCOUNT, scopes: ['smtp'], description: 'smtp-auth test', nolog: true });
    apiScopeToken = await tokens.provision({ account: ACCOUNT, scopes: ['api'], description: 'smtp-auth wrong scope', nolog: true });
    ipRestrictedToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['smtp'],
        restrictions: { addresses: ['10.0.0.0/8'] },
        description: 'smtp-auth ip restricted',
        nolog: true
    });
    // A token narrowed to reading must not be able to relay mail, even though it holds the smtp
    // scope. This is the payoff of putting the permission check in lib/auth-token.js rather than in
    // the HTTP strategy: the narrowing follows the credential onto the submission surfaces.
    readOnlyToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['smtp'],
        permissions: { actions: ['read'] },
        description: 'smtp-auth read-only permissions',
        nolog: true
    });
    sendPermittedToken = await tokens.provision({
        account: ACCOUNT,
        scopes: ['smtp'],
        permissions: { actions: ['send'], groups: ['submit'] },
        description: 'smtp-auth send permissions',
        nolog: true
    });
    await seedAccount(ACCOUNT);
    await seedAccount(OTHER_ACCOUNT);
});

registerRedisTeardown(redis, async () => {
    for (const tok of [smtpToken, apiScopeToken, ipRestrictedToken, readOnlyToken, sendPermittedToken]) {
        if (tok) {
            try {
                await tokens.delete(tok);
            } catch (err) {
                // ignore
            }
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
        await settings.set('smtpServerPassword', prevSmtpPassword || '');
    } catch (err) {
        // ignore
    }
});

test('SMTP auth handler', async t => {
    await t.test('rejects when authentication is not enabled', async () => {
        await assert.rejects(() => onAuth({ username: ACCOUNT, password: 'x' }, session({ eeAuthEnabled: false })), /Authentication not enabled/);
    });

    await t.test('rejects a wrong non-token password', async () => {
        await settings.set('smtpServerPassword', '');
        await assert.rejects(() => onAuth({ username: ACCOUNT, password: 'not-the-password' }, session()), /Failed to authenticate user/);
    });

    await t.test('rejects a well-formed but unknown token', async () => {
        const fake = 'f'.repeat(64);
        await assert.rejects(() => onAuth({ username: ACCOUNT, password: fake }, session()), /Failed to authenticate user/);
    });

    await t.test('rejects a token bound to a different account', async () => {
        await assert.rejects(() => onAuth({ username: 'someone-else', password: smtpToken }, session()), /Access denied, invalid username/);
    });

    await t.test('rejects a token without the smtp scope', async () => {
        await assert.rejects(() => onAuth({ username: ACCOUNT, password: apiScopeToken }, session()), /Access denied, invalid scope/);
    });

    await t.test('rejects a token from a disallowed IP', async () => {
        await assert.rejects(
            () => onAuth({ username: ACCOUNT, password: ipRestrictedToken }, session({ remoteAddress: '127.0.0.1' })),
            /traffic not accepted from this IP/
        );
    });

    await t.test('accepts the configured global SMTP password', async () => {
        await settings.set('smtpServerPassword', 'global-smtp-pass');
        try {
            const sess = session();
            const result = await onAuth({ username: ACCOUNT, password: 'global-smtp-pass' }, sess);
            assert.deepStrictEqual(result, { user: ACCOUNT });
            assert.ok(accountCache.has(sess), 'the authenticated account is cached on the session');
        } finally {
            await settings.set('smtpServerPassword', '');
        }
    });

    await t.test('rejects a token whose permissions do not allow sending', async () => {
        // Holds the smtp scope, so the scope check passes and only the permission check stands
        // between this credential and relaying mail
        await assert.rejects(() => onAuth({ username: ACCOUNT, password: readOnlyToken }, session()), /permissions do not allow/);
    });

    await t.test('accepts a valid scoped token bound to the account', async () => {
        const sess = session();
        const result = await onAuth({ username: ACCOUNT, password: smtpToken }, sess);
        assert.deepStrictEqual(result, { user: ACCOUNT });
        assert.ok(accountCache.has(sess));
    });

    await t.test('accepts a token whose permissions allow sending', async () => {
        // The narrowing is an allowlist, so a token that names send/submit is not merely un-refused
        // here - it has to be positively allowed, which is what separates this from the case above
        const sess = session();
        const result = await onAuth({ username: ACCOUNT, password: sendPermittedToken }, sess);
        assert.deepStrictEqual(result, { user: ACCOUNT });
        assert.ok(accountCache.has(sess));
    });
});

test('SMTP auth failure throttle', async t => {
    // TEST-NET-3 addresses, never a real client; one per case so the counters cannot interfere
    await t.test('a refused login is recorded against the client address and username', async t => {
        const ip = '203.0.113.11';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);

        await assert.rejects(() => onAuth({ username: ACCOUNT, password: 'wrong' }, session({ remoteAddress: ip })), /Failed to authenticate user/);

        assert.strictEqual(await redis.get(windowKey), '1');
    });

    await t.test('an accepted login spends nothing', async t => {
        const ip = '203.0.113.12';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);

        const result = await onAuth({ username: ACCOUNT, password: smtpToken }, session({ remoteAddress: ip }));
        assert.deepStrictEqual(result, { user: ACCOUNT });

        assert.strictEqual(await redis.get(windowKey), null, 'only failures count, a busy sender must not throttle itself');
    });

    await t.test('a valid credential is refused once the budget is spent, with a temporary reply code', async t => {
        const ip = '203.0.113.13';
        const windowKey = await trackedWindow(t, ip, ACCOUNT);
        await exhaustBudget(windowKey);

        await assert.rejects(
            () => onAuth({ username: ACCOUNT, password: smtpToken }, session({ remoteAddress: ip })),
            err => {
                assert.match(err.message, /Too many failed authentication attempts/);
                // 454, not 535: the client should try again later, not conclude its credentials are wrong
                assert.strictEqual(err.responseCode, 454);
                return true;
            }
        );

        assert.strictEqual(await redis.get(windowKey), String(AUTH_FAILURE_LIMIT), 'a throttled attempt is not evaluated and not counted');
    });

    await t.test('one failure short of the budget is still evaluated', async t => {
        const ip = '203.0.113.14';
        await exhaustBudget(await trackedWindow(t, ip, ACCOUNT), AUTH_FAILURE_LIMIT - 1);

        const result = await onAuth({ username: ACCOUNT, password: smtpToken }, session({ remoteAddress: ip }));
        assert.deepStrictEqual(result, { user: ACCOUNT });
    });

    await t.test('the budget is per address: another address is unaffected', async t => {
        await exhaustBudget(await trackedWindow(t, '203.0.113.15', ACCOUNT));

        const result = await onAuth({ username: ACCOUNT, password: smtpToken }, session({ remoteAddress: '203.0.113.16' }));
        assert.deepStrictEqual(result, { user: ACCOUNT });
    });

    await t.test('the budget is per username: the same address still logs in as another account', async t => {
        // One application host submits for many accounts; a stale credential for one of them
        // must not lock the others out
        const ip = '203.0.113.17';
        await exhaustBudget(await trackedWindow(t, ip, ACCOUNT));

        await settings.set('smtpServerPassword', 'global-smtp-pass');
        try {
            await assert.rejects(() => onAuth({ username: ACCOUNT, password: 'global-smtp-pass' }, session({ remoteAddress: ip })), /Too many failed/);

            const result = await onAuth({ username: OTHER_ACCOUNT, password: 'global-smtp-pass' }, session({ remoteAddress: ip }));
            assert.deepStrictEqual(result, { user: OTHER_ACCOUNT });
        } finally {
            await settings.set('smtpServerPassword', '');
        }
    });
});

test('SMTP account resolver', async t => {
    const resolveAccount = createSmtpAccountResolver({ accountCache, call: async () => ({}) });

    const prevAuthEnabled = await settings.get('smtpServerAuthEnabled');
    t.after(async () => {
        await settings.set('smtpServerAuthEnabled', prevAuthEnabled || false);
    });

    await t.test('an unauthenticated session names its account with the control header', async () => {
        await settings.set('smtpServerAuthEnabled', false);

        const sess = session({ eeAuthEnabled: false });
        const account = await resolveAccount(sess, { requestedAccount: ACCOUNT });

        assert.strictEqual(account.account, ACCOUNT);
        assert.ok(accountCache.has(sess), 'the resolved account is cached on the session');
    });

    await t.test('an unauthenticated session without the header is refused with 451', async () => {
        await settings.set('smtpServerAuthEnabled', false);

        await assert.rejects(
            () => resolveAccount(session({ eeAuthEnabled: false }), {}),
            err => {
                assert.match(err.message, /Sender account ID not provided/);
                assert.strictEqual(err.responseCode, 451);
                return true;
            }
        );
    });

    await t.test('an unknown account in the header is refused with 451', async () => {
        await settings.set('smtpServerAuthEnabled', false);

        await assert.rejects(
            () => resolveAccount(session({ eeAuthEnabled: false }), { requestedAccount: 'no-such-account' }),
            err => err.responseCode === 451
        );
    });

    await t.test('an unauthenticated session is refused with 530 once authentication has been switched on', async () => {
        // The session was opened while authentication was off and can be held open for as long
        // as the client likes; the operator's change has to reach it
        await settings.set('smtpServerAuthEnabled', true);

        await assert.rejects(
            () => resolveAccount(session({ eeAuthEnabled: false }), { requestedAccount: ACCOUNT }),
            err => {
                assert.match(err.message, /Authentication required/);
                assert.strictEqual(err.responseCode, 530);
                return true;
            }
        );
    });

    await t.test('an authenticated session submits through the account it logged in as', async () => {
        await settings.set('smtpServerAuthEnabled', true);

        const sess = session();
        await onAuth({ username: ACCOUNT, password: smtpToken }, sess);

        // the header must not override the login
        const account = await resolveAccount(sess, { requestedAccount: OTHER_ACCOUNT });
        assert.strictEqual(account.account, ACCOUNT);
    });

    await t.test('an authenticated session that never logged in is refused with 451', async () => {
        await settings.set('smtpServerAuthEnabled', true);

        await assert.rejects(
            () => resolveAccount(session(), { requestedAccount: ACCOUNT }),
            err => err.responseCode === 451
        );
    });
});
