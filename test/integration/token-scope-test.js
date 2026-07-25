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
const settings = require('../../lib/settings');
const { redis } = require('../../lib/db');
const registerRedisTeardown = require('../helpers/redis-teardown');

const baseUrl = `http://127.0.0.1:${config.api.port}`;
const ACCOUNT = 'scope-test-account';

let apiToken;
let smtpToken;
let accountToken;
let metricsToken;
let wildcardToken;
let ipRestrictedToken;
let referrerRestrictedToken;

const get = (path, tok) => supertest(baseUrl).get(path).auth(tok, { type: 'bearer' });

// Force the process to exit once tests finish; lib/db keeps connections open.
registerRedisTeardown();

test('API token scope and account binding', async t => {
    t.before(async () => {
        apiToken = await tokens.provision({ scopes: ['api'], description: 'scope-test api', nolog: true });
        smtpToken = await tokens.provision({ scopes: ['smtp'], description: 'scope-test smtp', nolog: true });
        accountToken = await tokens.provision({ account: ACCOUNT, scopes: ['api'], description: 'scope-test account', nolog: true });
        metricsToken = await tokens.provision({ scopes: ['metrics'], description: 'scope-test metrics', nolog: true });
        wildcardToken = await tokens.provision({ scopes: ['*'], description: 'scope-test wildcard', nolog: true });
        // The server runs on loopback, so an allowlist that excludes loopback rejects every
        // request this suite can make, and one that includes it accepts them.
        ipRestrictedToken = await tokens.provision({
            scopes: ['api'],
            restrictions: { addresses: ['198.51.100.0/24'] },
            description: 'scope-test ip',
            nolog: true
        });
        referrerRestrictedToken = await tokens.provision({
            scopes: ['api'],
            restrictions: { referrers: ['https://allowed.example.com/*'] },
            description: 'scope-test referrer',
            nolog: true
        });
    });

    t.after(async () => {
        for (const tok of [apiToken, smtpToken, accountToken, metricsToken, wildcardToken, ipRestrictedToken, referrerRestrictedToken]) {
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

    await t.test('a wildcard-scope token is accepted everywhere', async () => {
        assert.equal((await get('/v1/settings', wildcardToken)).status, 200);
        assert.equal((await get('/metrics', wildcardToken)).status, 200);
    });

    await t.test('the Prometheus endpoint requires the metrics scope', async () => {
        // /metrics is tagged scope:metrics rather than api, so an api-only token must not
        // reach it and a metrics-only token must. This is also the one route deliberately
        // exempt from the CSRF crumb, so a regression here is reachable from a browser.
        const allowed = await get('/metrics', metricsToken);
        assert.equal(allowed.status, 200, `expected 200 for a metrics-scoped token, got ${allowed.status}`);
        assert.match(allowed.headers['content-type'], /text\/plain/);

        const refused = await get('/metrics', apiToken);
        assert.equal(refused.status, 403, `expected 403 for an api-only token, got ${refused.status}`);
        // The route is not tagged `api`, so preResponse renders the themed HTML error page
        // rather than a JSON body - assert on what actually distinguishes the two responses.
        assert.doesNotMatch(refused.text || '', /^# HELP/m, 'no metrics may leak in the refusal body');
    });

    await t.test('the Prometheus endpoint still rejects an unauthenticated request', async () => {
        assert.equal((await supertest(baseUrl).get('/metrics')).status, 401);
    });

    await t.test('a token restricted to other addresses is refused from this IP', async () => {
        const res = await get('/v1/settings', ipRestrictedToken);
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
        assert.equal(res.body.message, 'Unauthorized address');
        assert.ok(res.body.remoteAddress, 'the response should name the address that was refused');
    });

    await t.test('a token restricted by referrer is refused without a matching Referer header', async () => {
        const missing = await get('/v1/settings', referrerRestrictedToken);
        assert.equal(missing.status, 403, `expected 403 with no Referer, got ${missing.status}`);
        assert.equal(missing.body.message, 'Unauthorized referrer');

        const wrong = await get('/v1/settings', referrerRestrictedToken).set('Referer', 'https://evil.example.net/page');
        assert.equal(wrong.status, 403, `expected 403 for a non-matching Referer, got ${wrong.status}`);
        assert.equal(wrong.body.message, 'Unauthorized referrer');
    });

    await t.test('a token restricted by referrer is accepted with a matching Referer header', async () => {
        const res = await get('/v1/settings', referrerRestrictedToken).set('Referer', 'https://allowed.example.com/dashboard');
        assert.equal(res.status, 200, `expected 200 for an allowlisted Referer, got ${res.status}`);
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

    await t.test('a credential-less (preauth) caller cannot mint a token', async () => {
        // With `disableTokens` on, workers/api.js rewrites a request carrying no Authorization
        // header to `access_token=preauth` and the api-token strategy accepts it, marking the
        // credentials `{preauth: true}` - so this route, which normally requires a real credential,
        // becomes reachable unauthenticated. A token minted there is never invalidated, so an
        // anonymous caller must be refused regardless of whether an admin password is set.
        //
        // Safe to flip a global setting here: the integration tier runs serially
        // (--test-concurrency=1), and it is restored in the finally below.
        const previous = await settings.get('disableTokens');
        await settings.set('disableTokens', true);
        try {
            const res = await supertest(baseUrl)
                .post('/v1/token')
                .send({ account: ACCOUNT, description: 'unauthenticated mint attempt', scopes: ['api'] });

            assert.equal(res.status, 403, `expected 403, got ${res.status}`);
            assert.match(res.body.message, /unauthenticated/i, 'should name the missing precondition');
        } finally {
            await settings.set('disableTokens', previous);
        }
    });

    await t.test('a real token is not blocked by the preauth gate', async () => {
        // The other half of the boundary: a caller presenting an actual credential is trusted and
        // must get PAST the gate (its credentials do not carry the `preauth` marker). ACCOUNT does
        // not exist, so the handler fails later at loadAccountData() - reaching that failure is the
        // proof, because the gate runs before it.
        const res = await supertest(baseUrl)
            .post('/v1/token')
            .auth(apiToken, { type: 'bearer' })
            .send({ account: ACCOUNT, description: 'authenticated mint', scopes: ['api'] });

        assert.notEqual(res.status, 403, 'an authenticated caller must not be refused by the admin-password gate');
        assert.equal(res.status, 404, `expected the account lookup to be what fails, got ${res.status}`);
    });
});
