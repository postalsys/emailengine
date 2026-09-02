'use strict';

// Drives the real Gmail API and Graph API request layers (lib/email-client/gmail/gmail-api.js,
// lib/email-client/outlook/graph-api.js) with a fake client context to pin how a provider 401
// is handled: a token served from the cache is invalidated and the request repeated exactly
// once, a token fresh from the token endpoint is not retried, and a 401 that survives is
// reported as a coded 403 so the API caller does not read it as their own EmailEngine token
// being rejected.

const test = require('node:test');
const assert = require('node:assert').strict;

const gmailApi = require('../lib/email-client/gmail/gmail-api');
const graphApi = require('../lib/email-client/outlook/graph-api');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createOAuth2Context } = require('./helpers/oauth-context');

registerRedisTeardown(redis);

function unauthorized() {
    const err = new Error('OAuth2 request failed');
    err.statusCode = 401;
    err.oauthRequest = { status: 401, response: { error: { code: 'InvalidAuthenticationToken', message: 'Access token has expired' } } };
    return err;
}

for (const [name, request] of [
    ['Gmail API request', (context, options) => gmailApi.request(context, 'https://gmail.googleapis.com/gmail/v1/users/me/profile', 'get', {}, options)],
    ['Graph API request', (context, options) => graphApi.request(context, '/me', 'get', {}, options)]
]) {
    test(name, async t => {
        await t.test('renews a cached token the provider rejects and repeats the request once', async () => {
            const { context, calls } = createOAuth2Context({ cached: true, responses: [unauthorized(), { ok: true }] });

            const result = await request(context, {});

            assert.deepEqual(result, { ok: true });
            assert.equal(calls.invalidations, 1);
            assert.equal(calls.requests, 2);
        });

        await t.test('a 401 that survives the renewal is a coded 403, with no second renewal', async () => {
            const { context, calls } = createOAuth2Context({ cached: true, responses: [unauthorized()] });

            await assert.rejects(request(context, {}), err => err.code === 'OAuthTokenRejected' && err.statusCode === 403 && err.oauthRequest.status === 401);
            assert.equal(calls.invalidations, 1);
            assert.equal(calls.requests, 2);
        });

        await t.test('a token fresh from the token endpoint is not renewed again', async () => {
            const { context, calls } = createOAuth2Context({ cached: false, responses: [unauthorized()] });

            await assert.rejects(request(context, {}), err => err.code === 'OAuthTokenRejected' && err.statusCode === 403);
            assert.equal(calls.invalidations, 0);
            assert.equal(calls.requests, 1);
        });
    });
}

test('Graph API request Prefer header', async t => {
    await t.test('the immutable-id preference is added once however often the options are reused', async () => {
        const { context } = createOAuth2Context({ cached: true, responses: [unauthorized(), { ok: true }] });
        const options = { headers: { Prefer: 'outlook.body-content-type="text"' } };

        await graphApi.request(context, '/me', 'get', {}, options);
        await graphApi.request(context, '/me', 'get', {}, options);

        assert.equal(options.headers.Prefer, 'IdType="ImmutableId", outlook.body-content-type="text"');
    });
});
