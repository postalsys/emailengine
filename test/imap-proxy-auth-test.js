'use strict';

// Unit tests for the IMAP proxy authentication handler (lib/imap-proxy-auth.js,
// extracted from lib/imapproxy/imap-server.js). Auth-bypass surface: covers the
// rejection paths (bad password, token account/scope/IP binding), the accept
// paths (global password and a valid scoped token), and the IMAP-proxy-specific
// rejection of API-only accounts (ACCOUNTDISABLED).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createImapProxyAuthHandler } = require('../lib/imap-proxy-auth');
const { oauth2Apps } = require('../lib/oauth2-apps');
const tokens = require('../lib/tokens');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

const ACCOUNT = 'imap-proxy-acct';
const API_ACCOUNT = 'imap-proxy-api-acct';

const authenticate = createImapProxyAuthHandler({ call: async () => ({}) });
const session = (overrides = {}) => Object.assign({ remoteAddress: '127.0.0.1' }, overrides);

let proxyToken;
let apiScopeToken;
let ipRestrictedToken;
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

test.after(async () => {
    for (const tok of [proxyToken, apiScopeToken, ipRestrictedToken]) {
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
    try {
        await redis.quit();
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

    await t.test('accepts a valid scoped token bound to the account', async () => {
        const { accountData } = await authenticate({ username: ACCOUNT, password: proxyToken }, session());
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
