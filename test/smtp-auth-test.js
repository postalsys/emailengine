'use strict';

// Unit tests for the SMTP submission-server authentication handler
// (lib/smtp-auth.js, extracted from workers/smtp.js). This is an auth-bypass
// surface: a regression could let unauthorized clients relay mail. Covers the
// rejection paths (auth disabled, bad password, token account/scope/IP binding)
// and the accept paths (global password and a valid scoped token).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createSmtpAuthHandler } = require('../lib/smtp-auth');
const tokens = require('../lib/tokens');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

const ACCOUNT = 'smtp-auth-acct';
const accountCache = new Map();
const onAuth = createSmtpAuthHandler({ accountCache, call: async () => ({}) });

const session = (overrides = {}) => Object.assign({ eeAuthEnabled: true, remoteAddress: '127.0.0.1' }, overrides);

let smtpToken;
let apiScopeToken;
let ipRestrictedToken;
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
    await seedAccount(ACCOUNT);
});

test.after(async () => {
    for (const tok of [smtpToken, apiScopeToken, ipRestrictedToken]) {
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
    try {
        await redis.quit();
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

    await t.test('accepts a valid scoped token bound to the account', async () => {
        const sess = session();
        const result = await onAuth({ username: ACCOUNT, password: smtpToken }, sess);
        assert.deepStrictEqual(result, { user: ACCOUNT });
        assert.ok(accountCache.has(sess));
    });
});
