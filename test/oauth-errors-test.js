'use strict';

// Covers lib/email-client/oauth-errors.js: RFC 6750 `invalid_token` is the status that actually
// means the access token is stale or revoked. It was not handled at all, so a genuinely stale token
// was never proactively cleared.

const test = require('node:test');
const assert = require('node:assert').strict;

const { shouldInvalidateAccessToken } = require('../lib/email-client/oauth-errors');

test('shouldInvalidateAccessToken', async t => {
    await t.test('invalid_token invalidates the cached access token', () => {
        // RFC 6750: the status that actually means expired, revoked or malformed.
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'invalid_token' }), true);
    });

    await t.test('invalid_request still invalidates', () => {
        // Kept for compatibility - providers do send it for stale credentials in practice.
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'invalid_request' }), true);
    });

    await t.test('an unrelated status does not invalidate', () => {
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'insufficient_scope' }), false);
    });

    await t.test('a numeric XOAUTH2 401 invalidates', () => {
        // XOAUTH2 is what Gmail and Exchange Online actually negotiate - ImapFlow only sends
        // OAUTHBEARER when the server advertises it - and XOAUTH2 puts an HTTP status here instead
        // of a symbolic code. Matching only the symbolic codes made the stale-token fix a no-op for
        // the two providers that dominate OAuth2-IMAP.
        assert.strictEqual(shouldInvalidateAccessToken({ status: '401', schemes: 'Bearer' }), true);
        assert.strictEqual(shouldInvalidateAccessToken({ status: 401 }), true);
    });

    await t.test('a non-401 numeric status does not invalidate', () => {
        // 401 is the only status that means "this token was rejected". A 400 is a malformed request
        // and a 5xx is the server's own problem; a fresh token fixes neither, and refetching on
        // those would add a token-endpoint round trip to every pass of the reconnect loop.
        for (let status of ['400', '403', '500', '503']) {
            assert.strictEqual(shouldInvalidateAccessToken({ status }), false, `status ${status} must not invalidate`);
        }
    });

    await t.test('a missing or empty payload does not invalidate', () => {
        assert.strictEqual(shouldInvalidateAccessToken(undefined), false);
        assert.strictEqual(shouldInvalidateAccessToken({}), false);
    });
});
