'use strict';

// Integration tests for the api-token auth strategy in workers/api.js, exercising
// the two security boundaries that the existing smoke tests do not: scope
// enforcement and per-account token binding. Both were previously only verified
// at the "401 without any token" level, which proves nothing about a valid token
// with the wrong scope or one bound to a different account.
//
// Scoped/bound tokens are provisioned directly into the shared test Redis via
// lib/tokens.provision(); the live server (config/test.toml, port 7077) shares
// that Redis and the same secret, so it validates them. No mailbox is required -
// authentication runs before any handler logic.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;

const tokens = require('../../lib/tokens');
const { redis } = require('../../lib/db');
const registerRedisTeardown = require('../helpers/redis-teardown');

const baseUrl = `http://127.0.0.1:${config.api.port}`;
const ACCOUNT = 'scope-test-account';

let apiToken;
let smtpToken;
let accountToken;

const get = (path, tok) => supertest(baseUrl).get(path).auth(tok, { type: 'bearer' });

// Force the process to exit once tests finish; lib/db keeps connections open.
registerRedisTeardown();

test('API token scope and account binding', async t => {
    t.before(async () => {
        // provision() refuses to mint a token unless an admin password is set, so that a credential
        // issued during the unprotected first-run window cannot outlive it (see lib/tokens.js).
        // This harness provisions in-process against the shared test Redis rather than over HTTP,
        // which is the same trusted-local position the CLI is exempted for. Setting authData
        // instead would gate the live server's admin UI mid-run and break the UI smoke tests that
        // share it.
        const local = { allowWithoutAdminAuth: true };
        apiToken = await tokens.provision({ scopes: ['api'], description: 'scope-test api', nolog: true }, local);
        smtpToken = await tokens.provision({ scopes: ['smtp'], description: 'scope-test smtp', nolog: true }, local);
        accountToken = await tokens.provision({ account: ACCOUNT, scopes: ['api'], description: 'scope-test account', nolog: true }, local);
    });

    t.after(async () => {
        for (const tok of [apiToken, smtpToken, accountToken]) {
            if (tok) {
                try {
                    await tokens.delete(tok);
                } catch (err) {
                    // ignore
                }
            }
        }
        try {
            await redis.quit();
        } catch (err) {
            // ignore
        }
    });

    await t.test('api-scope token can read a global endpoint', async () => {
        const res = await get('/v1/settings', apiToken);
        assert.equal(res.status, 200, `expected 200, got ${res.status}`);
    });

    await t.test('smtp-only token is rejected with 403 Unauthorized scope on /v1 API routes', async () => {
        const res = await get('/v1/settings', smtpToken);
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
        assert.equal(res.body.message, 'Unauthorized scope');
        assert.equal(res.body.requestedScope, 'api');
    });

    await t.test('smtp-only token is rejected on a second API route too', async () => {
        const res = await get('/v1/stats', smtpToken);
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
        assert.equal(res.body.message, 'Unauthorized scope');
    });

    await t.test('account-bound token cannot access a different account (403 Unauthorized account)', async () => {
        const res = await get('/v1/account/some-other-account/mailboxes', accountToken);
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
        assert.equal(res.body.message, 'Unauthorized account');
    });

    await t.test('account-bound token cannot access global (non-account) routes', async () => {
        // The route has no {account} param, so the bound account can never match.
        const res = await get('/v1/settings', accountToken);
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
        assert.equal(res.body.message, 'Unauthorized account');
    });

    await t.test('account-bound token clears the auth layer for its own account', async () => {
        // The account does not exist, so the handler will not return 200, but the
        // request must clear authentication: no 401, and not "Unauthorized account".
        const res = await get(`/v1/account/${ACCOUNT}/mailboxes`, accountToken);
        assert.notEqual(res.status, 401, 'should pass authentication');
        assert.notEqual(res.body && res.body.message, 'Unauthorized account', 'should pass account binding');
    });
});
